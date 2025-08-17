from __future__ import annotations
import re, urllib.parse, html, hmac, hashlib, time, ipaddress, json, socket
from typing import Any, Dict, Optional, Iterable, List
from django.conf import settings
from .waf import waf_detect

_SAFE_SPACE_RE = re.compile(r"\s+")
_CT_JSON = {"application/json", "text/json", "application/ld+json", "application/problem+json"}
_CT_FORM = {"application/x-www-form-urlencoded"}
_CT_MULTIPART = {"multipart/form-data"}

def get_client_ip(request):
    xff = request.META.get('HTTP_X_FORWARDED_FOR')
    remote = request.META.get('REMOTE_ADDR', '') or ''
    trusted = set(getattr(settings, 'TRUSTED_PROXIES', []) or [])
    if remote in trusted and xff:
        first = xff.split(',')[0].strip()
        return first or remote
    return remote

def normalize_input(value: str) -> str:
    if not value:
        return ''
    for _ in range(3):
        value = urllib.parse.unquote_plus(value)
    value = html.unescape(value)
    value = value.replace("\x00", "")
    value = _SAFE_SPACE_RE.sub(' ', value).strip()
    return value

# ---------- URL assinada (PDF) ----------
def _hmac(secret: str, value: str) -> str:
    return hmac.new(secret.encode(), value.encode(), hashlib.sha256).hexdigest()

def sign_url_params(attachment_id: int, user_id: int, exp: int, *, ua: str = "", ip: str = "") -> str:
    base = f"{attachment_id}|{user_id}|{exp}"
    if getattr(settings, "SIGNED_URL_BIND_UA", False):
        base += f"|ua={ua or ''}"
    if getattr(settings, "SIGNED_URL_BIND_IP", False):
        base += f"|ip={ip or ''}"
    return _hmac(settings.SECRET_KEY, base)

def build_signed_pdf_params(attachment_id: int, user_id: int, *, ttl_seconds: Optional[int] = None, ua: str = "", ip: str = "") -> dict:
    ttl = int(ttl_seconds or getattr(settings, "SIGNED_URL_TTL_SECONDS", 60))
    exp = int(time.time()) + ttl
    sig = sign_url_params(attachment_id, user_id, exp, ua=ua, ip=ip)
    return {"exp": exp, "sig": sig}

def verify_signed_pdf_params(attachment_id: int, user_id: int, exp: str, sig: str, *, ua: str = "", ip: str = "") -> bool:
    try:
        exp_int = int(exp)
    except (TypeError, ValueError):
        return False
    if exp_int + int(getattr(settings, "SIGNED_URL_CLOCK_SKEW", 15)) < int(time.time()):
        return False
    expected = sign_url_params(attachment_id, user_id, exp_int, ua=ua, ip=ip)
    return hmac.compare_digest(expected, sig)

# ---------- Content-Type ----------
def _base_content_type(request) -> str:
    ctype = (request.META.get("CONTENT_TYPE") or getattr(request, "content_type", "") or "")
    return ctype.split(";", 1)[0].strip().lower()

def _content_length(request) -> int:
    try:
        return int(request.META.get("CONTENT_LENGTH") or "0")
    except ValueError:
        return 0

def _is_safe_method(request) -> bool:
    return request.method in ("GET", "HEAD", "OPTIONS")

def content_type_is_one_of(request, allowed: Iterable[str]) -> bool:
    base = _base_content_type(request)
    allowed_set = {c.strip().lower() for c in (allowed or ())}
    if not base:
        if _is_safe_method(request) or _content_length(request) == 0:
            return True
        return False
    if base in allowed_set:
        return True
    if any(ct in _CT_JSON for ct in allowed_set):
        if base.endswith("+json") or base == "application/problem+json":
            return True
    return False

def _dedupe_prefixes(*iters: Iterable[str]) -> tuple[str, ...]:
    seen = set(); out: List[str] = []
    for it in iters:
        for p in (it or ()):
            p = (p or "").strip().lower()
            if p and p not in seen:
                seen.add(p); out.append(p)
    return tuple(out)

def enforce_content_type(request, *, json_only_paths: Iterable[str] = (), form_paths: Iterable[str] = ()) -> bool:
    try:
        content_len = int(request.META.get("CONTENT_LENGTH") or "0")
    except ValueError:
        content_len = 0
    if request.method in ("GET", "HEAD", "OPTIONS") or content_len == 0:
        return True
    path = (getattr(request, "path", "") or "").lower()
    json_prefixes = _dedupe_prefixes(getattr(settings, "JSON_ONLY_PATHS", ()), json_only_paths)
    form_prefixes = _dedupe_prefixes(getattr(settings, "FORM_ONLY_PATHS", ()), form_paths)
    def _matches(prefixes: Iterable[str]) -> bool:
        return any(path.startswith(p) for p in (prefixes or ()))
    if _matches(json_prefixes):
        return content_type_is_one_of(request, _CT_JSON)
    if _matches(form_prefixes):
        return content_type_is_one_of(request, _CT_FORM | _CT_MULTIPART)
    return True

def json_size_depth_guard(body: bytes, *, max_bytes: int = 1_000_000, max_depth: int = 64, max_keys: int = 10_000) -> bool:
    if body is None:
        return False
    if len(body) > max_bytes:
        return True
    try:
        obj = json.loads(body.decode("utf-8", "strict"))
    except Exception:
        return False
    from collections import deque
    q = deque([(obj, 1)])
    keys = 0
    while q:
        node, depth = q.popleft()
        if depth > max_depth:
            return True
        if isinstance(node, dict):
            keys += len(node)
            if keys > max_keys:
                return True
            for v in node.values():
                q.append((v, depth + 1))
        elif isinstance(node, list):
            if len(node) > max_keys:
                return True
            for v in node:
                q.append((v, depth + 1))
    return False

# ---------- SSRF ----------
def _is_private_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return (ip.is_private or ip.is_link_local or ip.is_loopback or ip.is_multicast)
    except ValueError:
        return False

def _resolve_host(hostname: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(hostname, None)
        addrs = []
        for fam, _, _, _, sockaddr in infos:
            ip = sockaddr[0]
            addrs.append(ip)
        return list(dict.fromkeys(addrs))
    except Exception:
        return []

def ssrf_url_allowed(url: str) -> bool:
    try:
        u = urllib.parse.urlsplit(url)
    except Exception:
        return False
    if u.scheme not in ("http", "https"):
        return False
    if not u.hostname:
        return False
    if u.username or u.password:
        return False
    allow = set(getattr(settings, "SSRF_HOST_ALLOWLIST", []) or [])
    if allow and u.hostname not in allow:
        return False
    for ip in _resolve_host(u.hostname):
        if _is_private_ip(ip):
            return False
    bad_ports = set(getattr(settings, "SSRF_BAD_PORTS", [21, 25, 110, 143, 1900, 2049, 3306, 5432, 6379, 11211]))
    if u.port and u.port in bad_ports:
        return False
    return True

def waf_detect_login(username: str = "", password: str = "") -> bool:
    raw_user = username or ""
    raw_pass = password or ""
    if waf_detect is None:
        return False
    return bool(waf_detect(f"{raw_user} {raw_pass}", ajax=False))
