# core/decorators.py
from functools import wraps
import logging
import time
import unicodedata
from typing import List

from django.shortcuts import render, redirect
from django.utils import timezone
from django.core.cache import cache
from django.conf import settings

from core.models import Users, SecurityEvent
from core.utils.security import get_client_ip
from core.middleware import hash_session  # fingerprint legado

logger = logging.getLogger(__name__)

BLACKLISTED_IPS = {"192.168.0.250"}
PUBLIC_LIST_PATHS = []  
SESSION_MAX_IDLE_SECONDS = 15 * 60
SESSION_ROTATE_SECONDS   = 15 * 60
RATE_LIMIT_WINDOW        = 60
RATE_LIMIT_MAX_CALLS     = 60


def _security_event(action, desc, request, payload=None):
    try:
        SecurityEvent.objects.create(
            sec_action=action,
            sec_description=desc,
            sec_ip=get_client_ip(request),
            sec_user_agent=request.META.get('HTTP_USER_AGENT', ''),
            sec_payload=payload or ''
        )
    except Exception:
        logger.exception("[SECURITY] falha ao persistir SecurityEvent")


def _rate_limit_key(request, view_name):
    uid = request.session.get('user_id') or 'anon'
    ip  = get_client_ip(request) or 'ip?'
    return f"rl:{uid}:{ip}:{view_name}"


def _hit_rate_limit(request, view_name):
    key = _rate_limit_key(request, view_name)
    now = int(time.time())
    bucket = cache.get(key, {'ts': now, 'count': 0})
    if now - bucket['ts'] >= RATE_LIMIT_WINDOW:
        bucket = {'ts': now, 'count': 0}
    bucket['count'] += 1
    cache.set(key, bucket, timeout=RATE_LIMIT_WINDOW + 5)
    return bucket['count'] > RATE_LIMIT_MAX_CALLS


def _strong_fingerprint(request, ip: str) -> str:
    """
    Fingerprint reforçado: session_key|UA|SECRET_KEY (compat com middleware).
    """
    ua = request.META.get('HTTP_USER_AGENT', '') or ''
    skey = getattr(request, "session", None) and request.session.session_key or ""
    salt = getattr(settings, "SECRET_KEY", "salt")
    import hashlib
    return hashlib.sha256(f"{skey}|{ua}|{salt}".encode()).hexdigest()


def _valid_fingerprints(request, ip: str) -> List[str]:
    ua = request.META.get('HTTP_USER_AGENT', '') or ''
    vals: List[str] = [
        hash_session(ip, ua),             
        _strong_fingerprint(request, ip), 
    ]

    try:
        sk_at_login = request.session.get('session_key_at_login') or ''
        if sk_at_login:
            from django.conf import settings
            import hashlib
            salt = getattr(settings, "SECRET_KEY", "salt")
            prev = hashlib.sha256(f"{sk_at_login}|{ua}|{salt}".encode()).hexdigest()
            vals.append(prev)
    except Exception:
        pass

    return vals


def _normalize_profile(p: str) -> str:
    return unicodedata.normalize("NFKC", p or "").strip()


def only_for(*profiles: str, allow_public_list: bool = False, require_login: bool = True, strict: bool = True):
    profiles = tuple(_normalize_profile(p) for p in profiles if p)

    def decorator(view_func):
        view_name = getattr(view_func, '__name__', 'view')

        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            path = request.path.rstrip('/')
            ip = get_client_ip(request)
            ua = request.META.get('HTTP_USER_AGENT', '') or ''

            if ip in BLACKLISTED_IPS:
                msg = f"IP bloqueado: {ip} em {path}"
                logger.warning(f"[SECURITY] {msg}")
                _security_event(SecurityEvent.ActionType.IP_BLOCK, msg, request)
                return render(request, 'others/acesso_negado.html', status=403)

            if allow_public_list and path in [p.rstrip('/') for p in PUBLIC_LIST_PATHS]:
                if request.method in ('GET', 'HEAD', 'OPTIONS'):
                    return view_func(request, *args, **kwargs)

            user_id = request.session.get('user_id')
            profile_raw = request.session.get('user_profile')

            if require_login and (not user_id or not profile_raw):
                request.session.flush()
                if strict:
                    return render(request, 'others/acesso_negado.html', status=403)
                return redirect('login')

            profile = _normalize_profile(profile_raw)

            if require_login and profiles and profile not in profiles:
                msg = f"Acesso negado: perfil={profile} exige={profiles} path={path}"
                logger.warning(f"[SECURITY] {msg}")
                _security_event(SecurityEvent.ActionType.OTHER, msg, request, payload=f"user_id={user_id}")
                if strict:
                    return render(request, 'others/acesso_negado.html', status=403)
                return redirect('login')

            try:
                user = Users.objects.get(u_id=user_id)
            except Users.DoesNotExist:
                request.session.flush()
                if strict:
                    return render(request, 'others/acesso_negado.html', status=403)
                return redirect('login')

            if user.u_status != 'Ativo' or (user.u_time_out and user.u_time_out < timezone.now().date()):
                msg = f"Conta inativa/expirada user_id={user_id}"
                logger.warning(f"[SECURITY] {msg}")
                _security_event(SecurityEvent.ActionType.OTHER, msg, request)
                request.session.flush()
                if strict:
                    return render(request, 'others/acesso_negado.html', status=403)
                return redirect('login')

            expected_fp = request.session.get('session_fingerprint')
            valid_fps = _valid_fingerprints(request, ip)
            if not expected_fp or expected_fp not in valid_fps:
                msg = f"Fingerprint alterado user_id={user_id} ip={ip}"
                logger.warning(f"[SECURITY] {msg}")
                _security_event(SecurityEvent.ActionType.SESSION_HIJACK, msg, request)
                request.session.flush()
                if strict:
                    return render(request, 'others/acesso_negado.html', status=403)
                return redirect('login')

            now_ts = int(time.time())
            last_seen = request.session.get('last_activity_ts')
            last_rot  = request.session.get('last_rotation_ts')

            if last_seen and (now_ts - int(last_seen) > SESSION_MAX_IDLE_SECONDS):
                msg = f"Sessão expirada por inatividade user_id={user_id}"
                logger.info(f"[SECURITY] {msg}")
                _security_event(SecurityEvent.ActionType.OTHER, msg, request)
                request.session.flush()
                if strict:
                    return render(request, 'others/acesso_negado.html', status=403)
                return redirect('login')

            request.session['last_activity_ts'] = now_ts

            if not last_rot or (now_ts - int(last_rot) > SESSION_ROTATE_SECONDS):
                try:
                    request.session.cycle_key()
                    request.session['last_rotation_ts'] = now_ts
                except Exception:
                    logger.exception("[SECURITY] falha ao rotacionar sessão")

            if _hit_rate_limit(request, view_name):
                msg = f"Rate limit excedido user_id={user_id} rota={view_name}"
                logger.warning(f"[RATE] {msg}")
                _security_event(SecurityEvent.ActionType.OTHER, msg, request, payload=f"path={path}")
                return render(request, 'others/acesso_negado.html', status=429)

            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator


only_administrador     = only_for('Administrador', allow_public_list=False)
only_auditor           = only_for('Auditor', allow_public_list=False)
only_gerente_regional  = only_for('Gerente Regional', allow_public_list=False)
only_usuario           = only_for('Usuário', allow_public_list=False)
