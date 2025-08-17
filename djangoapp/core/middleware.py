# core/middleware.py
import hashlib
import logging
import secrets
import time
import unicodedata
import re

from core.utils.security import enforce_content_type
from django.middleware.csrf import CSRF_SESSION_KEY  # noqa: F401 (mantido caso seja necessário no futuro)
from typing import Dict, Tuple, List, Any
from urllib.parse import urlparse
from django.http import HttpResponseForbidden, HttpResponse
from django.conf import settings
from django.core.cache import cache
from django.shortcuts import render, redirect
from django.utils.deprecation import MiddlewareMixin

from core.utils.waf import waf_qs_size_guard, QSSizeViolation
from core.context_processors import set_csp_nonce
from core.utils.security import get_client_ip
from core.utils.waf import (
    inspect_dict, waf_raw_qs_guard, waf_headers_guard,
    is_safe_redirect_target, suspicious_host, waf_check_all
)

logger = logging.getLogger(__name__)

BLACKLISTED_IPS = {"192.168.0.250"}
_PUBLIC_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
PUBLIC_PATHS = ['/', '/login', '/logout']
SENSITIVE_PATHS = ['/login']

PROTECTED_VIEWS: Dict[str, str] = {
    'attachment_list': 'Administrador',
    'establishment_list': 'Administrador',
    'document_list': 'Administrador',
}

PROTECTED_ROUTES: Dict[str, str] = {
    'administrador/anexos': 'Administrador',
    'administrador/estabelecimento': 'Administrador',
    'administrador/documento': 'Administrador',
}

REDIRECT_PARAMS = {"next", "redirect", "returnTo"}

def _nfkc(s: str) -> str:
    return unicodedata.normalize("NFKC", s or "")

def _sanitize_for_log(value: str, max_len: int = 120) -> str:
    if value is None:
        return ""
    cleaned = ''.join(ch for ch in str(value) if 32 <= ord(ch) < 127)
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len] + "…"
    return cleaned

def _same_site_request(request) -> bool:
    try:
        host = request.get_host()
        origin = (request.headers.get("Origin") or "").strip()
        referer = (request.headers.get("Referer") or "").strip()
        return (host and (host in origin or host in referer))
    except Exception:
        return False

def hash_session(ip: str, ua: str) -> str:
    return hashlib.sha256(f"{ip}|{ua}".encode()).hexdigest()

def _strong_fingerprint(request, ip: str) -> str:
    ua = request.META.get('HTTP_USER_AGENT', '') or ''
    skey = getattr(request, "session", None) and request.session.session_key or ""
    salt = getattr(settings, "SECRET_KEY", "salt")
    return hashlib.sha256(f"{skey}|{ua}|{salt}".encode()).hexdigest()

def _compute_fingerprints(request, ip: str) -> List[str]:
    return [hash_session(ip, request.META.get('HTTP_USER_AGENT', '') or ''), _strong_fingerprint(request, ip)]

class SimpleRateLimitMiddleware(MiddlewareMixin):
    WINDOW = 10     # segundos
    MAX_REQ = 50    # por IP por janela

    def process_request(self, request):
        ip = request.META.get("REMOTE_ADDR", "0.0.0.0")
        key = f"rl:{ip}"
        data = cache.get(key, {"t0": time.time(), "n": 0})
        now = time.time()
        if now - data["t0"] > self.WINDOW:
            data = {"t0": now, "n": 0}
        data["n"] += 1
        cache.set(key, data, timeout=self.WINDOW)
        if data["n"] > self.MAX_REQ:
            return HttpResponse(b"Too Many Requests", status=429)
        return None

class QueryStringSizeMiddleware(MiddlewareMixin):
    """
    Bloqueia requests com URL/QUERY_STRING excessivos (DoS de LargeValue).
    Deve vir BEM no topo da cadeia de middlewares, antes de qualquer view.
    """

    # Ajuste os limites aqui se preferir centralizar
    MAX_URL_LEN = 2048
    MAX_QS_BYTES = 1024
    MAX_KEYS = 20
    MAX_VALUE_BYTES = 256
    MAX_KEY_BYTES = 64

    def process_request(self, request):
        # 0) Limite da URL completa
        full_path = request.get_full_path()  # inclui ?query...
        if len(full_path.encode("utf-8")) > self.MAX_URL_LEN:
            logger.warning("[WAF] URL too large: %s bytes", len(full_path.encode("utf-8")))
            return HttpResponse(b"Request-URI Too Large", status=414)

        raw_qs = request.META.get("QUERY_STRING", "")

        try:
            waf_qs_size_guard(
                raw_qs,
                max_url_len=self.MAX_URL_LEN,
                max_qs_bytes=self.MAX_QS_BYTES,
                max_keys=self.MAX_KEYS,
                max_value_bytes=self.MAX_VALUE_BYTES,
                max_key_bytes=self.MAX_KEY_BYTES,
            )
        except QSSizeViolation as e:
            logger.warning("[WAF] QS size violation: %s | detail=%s | path=%s", e.reason, getattr(e, "detail", {}), request.path)
            # 414 para manter coerência com request-line/URI grande; 406/400 também são válidos
            return HttpResponse(b"Request-URI Too Large", status=414)

        return None  # segue o fluxo normal

class CSPMiddleware(MiddlewareMixin):
    def process_request(self, request):
        nonce = secrets.token_urlsafe(16)
        request.csp_nonce = nonce
        set_csp_nonce(nonce)

    def process_response(self, request, response):
        nonce = getattr(request, 'csp_nonce', None)
        if nonce:
            csp = (
                "default-src 'self'; "
                "script-src 'self' 'nonce-%s' https://cdn.jsdelivr.net https://cdn.lineicons.com; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdn.lineicons.com https://fonts.googleapis.com; "
                "img-src 'self' data:; "
                "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com https://cdn.lineicons.com; "
                "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; "
                "object-src 'none'; "
            ) % nonce
            if not settings.DEBUG:
                csp += "upgrade-insecure-requests"
            response['Content-Security-Policy'] = csp
            response['Permissions-Policy'] = (
                "geolocation=(), microphone=(), camera=(), payment=(), usb=(), interest-cohort=()"
            )
        return response

LOGIN_URL = "/login"
DEFAULT_LOGIN_LOOP_MAX = 5
DEFAULT_LOGIN_LOOP_WINDOW = 10

class LoginLoopGuardMiddleware(MiddlewareMixin):
    """
    Evita loops de redirect para LOGIN_URL sem bloquear o primeiro acesso ao /login.
      - Não conta GET/HEAD ao /login (sem ?next=).
      - Conta apenas redirects (3xx) para /login.
      - Usa janela temporal e limite; excedendo => 403.
      - Reseta contador em qualquer resposta que não seja redirect para /login.
    """
    def __init__(self, get_response=None):
        super().__init__(get_response)
        login_url = getattr(settings, "LOGIN_URL", "/login")
        self.login_path = urlparse(login_url).path or "/login"
        self.max_hits = int(getattr(settings, "LOGIN_LOOP_MAX", DEFAULT_LOGIN_LOOP_MAX))
        self.window = int(getattr(settings, "LOGIN_LOOP_WINDOW", DEFAULT_LOGIN_LOOP_WINDOW))
        self.static_prefix = getattr(settings, "STATIC_URL", "/static/") or "/static/"
        self.media_prefix = getattr(settings, "MEDIA_URL", "/media/") or "/media/"

    def _reset(self, request):
        if hasattr(request, "session"):
            request.session.pop("_ll_ts", None)
            request.session.pop("_ll_cnt", None)

    def process_request(self, request):
        path = (request.path or "")
        if path.startswith(self.static_prefix) or path.startswith(self.media_prefix):
            return None
        if path == self.login_path and request.method in ("GET", "HEAD") and "next" not in request.GET:
            self._reset(request)
        return None

    def process_response(self, request, response):
        try:
            path = (request.path or "")
            if path.startswith(self.static_prefix) or path.startswith(self.media_prefix):
                return response

            if response.status_code in (301, 302, 303, 307, 308) and response.has_header("Location"):
                loc_path = urlparse(response["Location"]).path
                if loc_path == self.login_path and hasattr(request, "session"):
                    now = time.time()
                    ts = float(request.session.get("_ll_ts") or now)
                    cnt = int(request.session.get("_ll_cnt") or 0)

                    if (now - ts) > self.window:
                        ts, cnt = now, 0

                    cnt += 1
                    request.session["_ll_ts"] = ts
                    request.session["_ll_cnt"] = cnt

                    if cnt > self.max_hits:
                        logger.warning("[SECURITY] Loop de login detectado.")
                        return HttpResponseForbidden("Loop de login detectado.")
            else:
                self._reset(request)
        except Exception:
            logger.exception("[SECURITY] erro no LoginLoopGuardMiddleware")
        return response

def _cors_allowed(origin: str) -> bool:
    allowed = set(getattr(settings, "CORS_ALLOWED_ORIGINS", []) or [])
    return origin in allowed

def _apply_cors_headers(request, response):
    origin = request.headers.get("Origin")
    if not origin:
        return response
    if _cors_allowed(origin):
        response["Vary"] = (response.get("Vary", "") + ", Origin").strip(", ")
        response["Access-Control-Allow-Origin"] = origin
        # Como usamos cookies/sessão, é importante habilitar credenciais:
        response["Access-Control-Allow-Credentials"] = "true"
        if request.method == "OPTIONS":
            response["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
            response["Access-Control-Allow-Headers"] = "Content-Type, X-Requested-With, Authorization"
            response["Access-Control-Max-Age"] = "600"
    return response

def _waf_inspect_params(params: Dict[str, Any], ajax_lenient_enabled: bool) -> Tuple[list, list]:
    try:
        rep = inspect_dict(
            params,
            allow_numeric=settings.WAF_NUMERIC_FIELDS or [],
            allow_safe=settings.WAF_SAFE_FIELDS or [],
            ajax=ajax_lenient_enabled
        )
    except TypeError:
        rep = inspect_dict(
            params,
            allow_numeric_fields=settings.WAF_NUMERIC_FIELDS or [],
            allow_safe_fields=settings.WAF_SAFE_FIELDS or [],
            ajax=ajax_lenient_enabled
        )

    findings_block, findings_warn = [], []
    if isinstance(rep, dict):
        if rep.get("critical"):
            findings_block.append(("params", "critical", "params"))
        for s in rep.get("samples", []):
            key  = s.get("key", "")
            cats = set(s.get("report", {}).get("categories", []))
            if "noncrit" in cats and key in {"q", "search", "term"} and not ajax_lenient_enabled:
                findings_block.append((key, "noncrit", "search-tautology"))
            elif "noncrit" in cats:
                findings_warn.append((key, "noncrit", "excerpt"))
        return findings_block, findings_warn

    if isinstance(rep, (list, tuple)):
        if len(rep) >= 2:
            return list(rep[0] or []), list(rep[1] or [])
        if len(rep) == 1:
            return list(rep[0] or []), []
        return [], []
    return (list(rep) if rep else []), []

class AuthRequiredMiddleware(MiddlewareMixin):
    def process_request(self, request):
        raw_path = request.path or "/"
        path = _nfkc(raw_path).rstrip('/')

        if not enforce_content_type(request, json_only_paths=settings.JSON_ONLY_PATHS, form_paths=settings.FORM_ONLY_PATHS):
            return render(request, 'others/acesso_negado.html', status=415)

        ip = get_client_ip(request)
        ua = request.META.get('HTTP_USER_AGENT', '') or ''

        if ip in BLACKLISTED_IPS:
            logger.warning(f"[SECURITY] IP bloqueado: {ip}")
            return render(request, 'others/acesso_negado.html', status=403)

        if waf_headers_guard(request.META):
            return render(request, 'others/acesso_negado.html', status=403)

        raw_qs = request.META.get('QUERY_STRING', '')
        if waf_raw_qs_guard(raw_qs):
            return render(request, 'others/acesso_negado.html', status=403)

        def _csrf_present(req):
            # aceita cookie + header ou campo de form
            return (
                req.META.get('CSRF_COOKIE') or req.COOKIES.get(settings.CSRF_COOKIE_NAME)
            ) and (
                req.POST.get('csrfmiddlewaretoken') or
                req.META.get('HTTP_X_CSRFTOKEN') or
                req.META.get('HTTP_X_CSRF_TOKEN')
            )

        def _owner_checker(record_id: str, request):
            try:
                from core.models import Attachment, RelationCenterUser
                uid = request.session.get('user_id')
                user_centers = set(RelationCenterUser.objects.filter(rcu_fk_user_id=uid)
                                .values_list('rcu_center', flat=True))
                obj = Attachment.objects.filter(att_id=record_id).first()
                return bool(obj and obj.att_center in user_centers)
            except Exception:
                return False

        def _tenant_checker(params: dict, request):
            try:
                from core.models import RelationCenterUser
                uid = request.session.get('user_id')
                qs = RelationCenterUser.objects.filter(rcu_fk_user_id=uid)
                if 'att_center' in params:
                    return qs.filter(rcu_center=str(params['att_center'])).exists()
                if 'center_id' in params:
                    return qs.filter(rcu_center=str(params['center_id'])).exists()
                return True
            except Exception:
                return False

        is_state_change = request.method in ('POST','PUT','PATCH','DELETE')
        is_form_path = any((request.path or '').startswith(p) for p in settings.FORM_ONLY_PATHS)

        if is_state_change and is_form_path and not _csrf_present(request):
            return render(request, 'others/acesso_negado.html', status=403)

        if suspicious_host(request.META.get("HTTP_HOST", "")):
            return render(request, 'others/acesso_negado.html', status=403)

        # Preflight CORS: responder 204 diretamente com headers (sem template)
        if request.method == "OPTIONS" and request.headers.get("Origin"):
            if not _cors_allowed(request.headers["Origin"]):
                return render(request, 'others/acesso_negado.html', status=403)
            resp = HttpResponse(status=204)
            return _apply_cors_headers(request, resp)

        public_norm = [_nfkc(p).rstrip('/') for p in PUBLIC_PATHS]
        if path in public_norm and request.method in _PUBLIC_SAFE_METHODS:
            return None

        is_ajax = (request.headers.get('X-Requested-With') == 'XMLHttpRequest')
        ajax_lenient_enabled = is_ajax and _same_site_request(request) and (settings.WAF_AJAX_MODE == 'lenient')

        merged = {}
        try:
            for k, v in request.GET.items():
                merged[k] = v
            for k, v in request.POST.items():
                merged[k] = v
        except Exception as e:
            logger.exception(f"[WAF] erro ao ler params: {e}")
            return render(request, 'others/acesso_negado.html', status=406)

        for p in REDIRECT_PARAMS:
            if p in merged:
                val = str(merged.get(p) or "")
                if not is_safe_redirect_target(val):
                    merged[p] = "/"
                else:
                    merged[p] = val

        blocked, details = waf_check_all(request, owner_checker=_owner_checker, tenant_checker=_tenant_checker)
        if blocked:
            try:
                from core.models import SecurityEvent
                SecurityEvent.objects.create(
                    sec_action='WAF Block',
                    sec_description=f"Bloqueio WAF: {details}",
                    sec_ip=ip,
                    sec_user_agent=ua,
                    sec_payload=f"path={path}"
                )
            except Exception:
                pass
            return render(request, 'others/acesso_negado.html', status=403)

        if path == '/login' and request.method == 'POST':
            return None

        if path.startswith('/media') or path.startswith('/static'):
            if settings.DEBUG:
                return None
            if not request.session.get('user_id') or not request.session.get('user_profile'):
                return redirect('login')

        user_id = request.session.get('user_id')
        user_profile = request.session.get('user_profile')
        if not user_id or not user_profile:
            request.session.flush()
            return redirect('login')

        expected_fp = request.session.get('session_fingerprint')
        current_candidates = set(_compute_fingerprints(request, ip))

        prev_candidates = set()
        try:
            sk_at_login = request.session.get('session_key_at_login') or ''
            if sk_at_login:
                salt = getattr(settings, "SECRET_KEY", "salt")
                prev_strong = hashlib.sha256(f"{sk_at_login}|{ua}|{salt}".encode()).hexdigest()
                prev_candidates.add(prev_strong)
        except Exception:
            pass

        all_candidates = current_candidates | prev_candidates
        if not expected_fp or expected_fp not in all_candidates:
            logger.warning(f"[SECURITY] Fingerprint alterado: {ip}")
            request.session.flush()
            return redirect('login')

        last_rot = request.session.get('last_rotation')
        if last_rot is not None:
            try:
                last_rot = float(last_rot)
            except (TypeError, ValueError):
                last_rot = None

        now_ts = time.time()
        if last_rot and (now_ts - last_rot) > 900:
            request.session.cycle_key()
            request.session['last_rotation'] = now_ts
        elif not last_rot:
            request.session['last_rotation'] = now_ts

        try:
            if getattr(request, "resolver_match", None):
                view_name = request.resolver_match.view_name or ""
                expected = PROTECTED_VIEWS.get(view_name)
                if expected and _nfkc(str(user_profile)) != _nfkc(expected):
                    logger.warning("[AUTHZ] 403(view) em %s | user_id=%s profile_raw=%r esperado=%r",
                                   path, user_id, user_profile, expected)
                    return render(request, 'others/acesso_negado.html', status=403)
        except Exception:
            logger.exception("[AUTHZ] erro ao resolver view_name")

        for prefix, expected in PROTECTED_ROUTES.items():
            if path.startswith(f"/{_nfkc(prefix)}"):
                if _nfkc(str(user_profile)) != _nfkc(expected):
                    logger.warning("[AUTHZ] 403(path) em %s | user_id=%s profile_raw=%r esperado=%r",
                                   path, user_id, user_profile, expected)
                    return render(request, 'others/acesso_negado.html', status=403)

        return None

    def process_response(self, request, response):
        response = _apply_cors_headers(request, response)
        return response
