from django.http import HttpRequest
import ipaddress
import hashlib

def _normalize_ip(ip: str) -> str:
    try:
        ip_obj = ipaddress.ip_address(ip)
        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
            return str(ip_obj.ipv4_mapped)
        return str(ip_obj)
    except Exception:
        return ip or ""

def get_client_ip(request: HttpRequest) -> str:
    cf = request.META.get("HTTP_CF_CONNECTING_IP")
    if cf:
        return _normalize_ip(cf)

    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff:
        return _normalize_ip(xff.split(",")[0].strip())

    return _normalize_ip(request.META.get("REMOTE_ADDR", ""))

def _ua_family(ua: str) -> str:
    ua_l = (ua or "").lower()
    for token in ("chrome", "firefox", "safari", "edge", "opera"):
        if token in ua_l:
            return token
    return ua_l[:20]

def session_fingerprint(ip: str, ua: str, secret: str) -> str:
    base = f"{_normalize_ip(ip)}|{_ua_family(ua)}|{(secret or '')[:16]}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()
