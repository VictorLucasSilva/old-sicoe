from __future__ import annotations
import re
import html
import time
import math
import urllib.parse
import unicodedata
from typing import Any, Dict, List, Tuple, Callable, Optional
from collections import defaultdict, deque
from django.core.cache import cache

__all__ = [
    "waf_detect", "waf_detect_ajax", "inspect_value", "inspect_dict",
    "waf_raw_qs_guard", "waf_headers_guard", "waf_qs_size_guard", "QSSizeViolation",
    "is_safe_redirect_target", "sanitize_redirect_param", "suspicious_host",
    "waf_check_all",
    "QS_MAX_LENGTH", "HEADERS_MAX_COUNT", "HEADER_NAME_MAX_LEN", "HEADER_VALUE_MAX_LEN",
]

# =========================
# Normalização e utilidades
# =========================

_INVISIBLE = r"[\u0000-\u001F\u007F\u200B-\u200F\u202A-\u202E\u2066-\u2069\ufeff]"
_MULTI_SPACE = re.compile(r"\s+", re.UNICODE)

def _normalize(value: str) -> str:
    if not value:
        return ""

    for _ in range(3):
        try:
            value = urllib.parse.unquote_plus(value)
        except Exception:
            break
    value = html.unescape(value)
    value = unicodedata.normalize("NFKC", value)
    value = re.sub(r"[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]", "", value)
    value = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", value)
    value = re.sub(_INVISIBLE, "", value)
    value = _MULTI_SPACE.sub(" ", value).strip().lower()
    return value

def _clip(s: str, n: int = 128) -> str:
    return s if len(s) <= n else (s[:n] + "…")

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter
    counts = Counter(s)
    length = len(s)
    return -sum((c/length) * math.log2(c/length) for c in counts.values())

# =========================
# Padrões críticos (avançados)
# =========================

CRITICAL_SQLI = [
    r"\bunion\s+(?:all\s+)?select\b",
    r"\b(?:sleep|benchmark|pg_sleep)\s*\(",
    r"\bwaitfor\s+delay\b",
    r"\binformation_schema\b",
    r"(?:--|/\*|\*/|#)",
    r"\bextractvalue\s*\(", r"\bupdatexml\s*\(",
    r"\bload_file\s*\(", r"\boutfile\b",
    r"\bxp_cmdshell\b|\bsp_oacreate\b|\bopenrowset\b",
    r"\bsysobjects\b|\bsys\.user_tables\b|\bdba_tables\b",
    r"(?<![a-z])cast\(", r"\bcase\s+when\b",
    r"(?:;|\b)\s*select\b.+\bfrom\b",
    r"'\s*(?:or|and)\s*'?1'?\s*=\s*'?1'?",
    r"'?\s*(?:or|and)\s*'?\d+'?\s*=\s*'?\d+'?",
    r"'?\s*(?:or|and)\s*'?[a-z0-9_\.]+'?\s*=\s*'?[a-z0-9_\.]+'?",
    r"chr\(\d+\)\s*\|\|\s*chr\(\d+\)",
]

CRITICAL_XSS = [
    r"<\s*script\b[^>]*>.*?<\s*/\s*script\s*>",
    r"\bjavascript\s*:\s*",
    r"\bon(?:error|load|click|mouseover|focus|blur|input|change|submit|pointer\w*)\s*=",
    r"<\s*(?:img|svg|iframe|object|embed|link|meta|base|body)\b[^>]*>",
    r"\bsrcdoc\s*=",
    r"src\s*=\s*data:text/html",
    r"\balert\s*\(|\bconfirm\s*\(|\bprompt\s*\(",
    r"\bdocument\.(?:cookie|domain|location|write|writeln)\b",
    r"(?:\"|')\s*[><]\s*(?:svg|img|iframe)\b",
]

CRITICAL_DOM_XSS = [
    r"\binnerhtml\b\s*=",
    r"\bouterhtml\b\s*=",
    r"\bdocument\.write(?:ln)?\s*\(",
    r"\b(?:eval|Function)\s*\(\s*['\"]",
    r"\bset(?:timeout|interval)\s*\(\s*['\"]\s*[a-z0-9_$]",
    r"\blocation\.(?:hash|search)\b.*(?:=|%3d)",
    r"\baddEventListener\s*\(\s*['\"][a-z]+['\"]\s*,\s*['\"]",
    r"\bURLSearchParams\s*\(",
]

CRITICAL_TEMPLATE = [
    r"\{\{[\s\S]*?(?:__import__|os\.|popen|eval|__class__|mro\b|builtins|globals|request|config|url_for|attr\()\s*[\s\S]*?\}\}",
    r"\{\%[\s\S]*?(?:include|with|setattr|import|load)\s*[\s\S]*?\%\}",
]

CRITICAL_PATH = [
    r"\.\./", r"\.\.\\", r"%2e%2e%2f", r"\.\.%2f", r"%2f\.\.%2f",
    r"/etc/passwd", r"boot\.ini", r"\bwin\.ini\b",
    r"\bfile://", r"\bphp://", r"\bdata://",
]

CRITICAL_SHELL = [
    r"(?:;|\||&&|\|\|)\s*(?:sh|bash|zsh|powershell|cmd\.exe)\b",
    r";\s*rm\s+-rf\b",
    r"\b(?:wget|curl|nc|netcat|bash|sh|powershell)\b",
    r"\b(?:whoami|uname|cat|ls|id)\b\s*(?:[|;&]|\Z)",
]

CRITICAL_OBFUSC = [
    r"%[0-9a-f]{2}",
    r"\\x[0-9a-f]{2}",
    r"&#[0-9]{2,5};", r"&#x[0-9a-f]{2,5};",
]

CRITICAL_SSRF = [
    r"\bhttps?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[?::1\]?)\b",
    r"\bhttps?://(?:169\.254\.169\.254|metadata\.googleinternal|metadata\.azure\.internal)\b",
    r"\bhttps?://(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
    r"\b(?:gopher|ftp|file|dict|ldap|smb)://",
    r"\bhttps?://\d{8,}\b",
]

CRITICAL_ENCODING = [
    r"%00", r"%25%30%30", r"%ff%fe", r"%fe%ff",
    r"%25[0-9a-f]{2}",
    r"[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]",
    r"[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]",
    r"[\uff10-\uff19\uff21-\uff3a\uff41-\uff5a]",
]

NONCRIT_SQLI = [r"\bor\b", r"\band\b", r"\blike\b", r"\bin\b"]
NONCRIT_MISC = [r";"]

def _rc(patterns: List[str]) -> List[re.Pattern]:
    return [re.compile(p, re.IGNORECASE | re.DOTALL) for p in patterns]

R_CRIT_SQLI     = _rc(CRITICAL_SQLI)
R_CRIT_XSS      = _rc(CRITICAL_XSS)
R_CRIT_DOMXSS   = _rc(CRITICAL_DOM_XSS)
R_CRIT_TEMPLATE = _rc(CRITICAL_TEMPLATE)
R_CRIT_PATH     = _rc(CRITICAL_PATH)
R_CRIT_SHELL    = _rc(CRITICAL_SHELL)
R_CRIT_OBFUSC   = _rc(CRITICAL_OBFUSC)
R_CRIT_SSRF     = _rc(CRITICAL_SSRF)
R_CRIT_ENCODING = _rc(CRITICAL_ENCODING)
R_NONCRIT       = _rc(NONCRIT_SQLI + NONCRIT_MISC)

R_CRIT_ALL = (
    R_CRIT_SQLI + R_CRIT_XSS + R_CRIT_DOMXSS + R_CRIT_TEMPLATE +
    R_CRIT_PATH + R_CRIT_SHELL + R_CRIT_OBFUSC + R_CRIT_SSRF + R_CRIT_ENCODING
)

CRITICAL_CATS = {"sqli", "xss", "domxss", "tpl", "path", "shell", "obfusc", "ssrf", "encoding"}

SAFE_AJAX_TEXT = re.compile(r"^[\w\sÀ-ÖØ-öø-ÿ.,:_@\-()/\\]{0,10240}$", re.UNICODE)

RAW_FULLWIDTH_RE   = re.compile(r"[\uff10-\uff19\uff21-\uff3a\uff41-\uff5a]")
RAW_INVIS_CTRL_RE  = re.compile(r"[\u200B-\u200F\u202A-\u202E\u2060-\u206F\ufeff\x00-\x1F\x7F]")

# =========================
# Limites globais (DoS/Headers/QS)
# =========================

QS_MAX_LENGTH        = 8_192
HEADERS_MAX_COUNT    = 120
HEADER_NAME_MAX_LEN  = 64
HEADER_VALUE_MAX_LEN = 8_192

# =========================
# Rate limiting e DoS guard
# =========================

DOS_MAX_PARAMS            = 200
DOS_MAX_VALUE_LEN         = 100_000
DOS_MAX_TOTAL_SIZE        = 2_000_000
DOS_MAX_DUP_KEYS          = 20
DOS_MIN_ENTROPY_SUSP      = 4.2

RATE_WINDOW_SECONDS       = 60
RATE_MAX_REQUESTS_PER_IP  = 300

_RATE_BUCKETS: Dict[str, deque] = defaultdict(deque)

def _rate_limit(ip: str, now: float | None = None) -> bool:
    if not ip:
        return False
    key = f"waf:rl:{ip}"
    data = cache.get(key, {'t0': time.time(), 'n': 0})
    t = now or time.time()
    if t - data['t0'] > RATE_WINDOW_SECONDS:
        data = {'t0': t, 'n': 0}
    data['n'] += 1
    cache.set(key, data, timeout=RATE_WINDOW_SECONDS + 5)
    return data['n'] > RATE_MAX_REQUESTS_PER_IP

def _dos_payload_guard(params: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    if not params:
        return (False, {"reason": "empty"})
    total_params = 0
    total_size = 0
    max_value_len = 0
    dup_keys = 0
    entropy_scores: List[float] = []

    key_counts = defaultdict(int)
    for k, v in params.items():
        key_counts[k] += 1
        if key_counts[k] > 1:
            dup_keys += 1
        s = str(v)
        total_params += 1
        total_size += len(s)
        max_value_len = max(max_value_len, len(s))
        if len(s) >= 256:
            entropy_scores.append(_shannon_entropy(s[:4096]))

    avg_entropy = (sum(entropy_scores) / len(entropy_scores)) if entropy_scores else 0.0

    if total_params > DOS_MAX_PARAMS:
        return True, {"reason": "params>limit", "total_params": total_params}
    if max_value_len > DOS_MAX_VALUE_LEN:
        return True, {"reason": "value_len>limit", "max_value_len": max_value_len}
    if total_size > DOS_MAX_TOTAL_SIZE:
        return True, {"reason": "total_size>limit", "total_size": total_size}
    if dup_keys > DOS_MAX_DUP_KEYS:
        return True, {"reason": "dup_keys>limit", "dup_keys": dup_keys}
    if avg_entropy >= DOS_MIN_ENTROPY_SUSP:
        return True, {"reason": "high_entropy", "avg_entropy": avg_entropy}

    return False, {
        "reason": "ok",
        "total_params": total_params,
        "total_size": total_size,
        "max_value_len": max_value_len,
        "dup_keys": dup_keys,
        "avg_entropy": avg_entropy,
    }

# =========================
# IDOR/BOLA heurística
# =========================

SENSITIVE_ID_KEYS = { "id", "u_id", "rcd_id", "rcu_id", "em_id", "sec_id", "est_id", "estaux_id", "ndest_id", "aud_id", "u_id", "att_id"}

def _collect_ids_from_params(params: Dict[str, Any]) -> List[str]:
    ids = []
    for k, v in params.items():
        if k.lower() in SENSITIVE_ID_KEYS:
            ids.append(str(v))
    return ids

def _looks_like_foreign_id(v: str) -> bool:
    if re.fullmatch(r"[0-9]{1,18}", v):
        return False
    if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", v, re.I):
        return False
    if re.search(r"[^\w\-]", v):
        return True
    return False

def _idor_bola_guard(
    params: Dict[str, Any],
    request: Any,
    owner_checker: Optional[Callable[[str, Any], bool]] = None,
    tenant_checker: Optional[Callable[[Dict[str, Any], Any], bool]] = None
) -> Tuple[bool, Dict[str, Any]]:
    if not params:
        return False, {"reason": "ok"}

    user = getattr(request, "user", None)
    is_auth = bool(getattr(user, "is_authenticated", False))

    ids = _collect_ids_from_params(params)
    if ids and not is_auth:
        return True, {"reason": "idor:anonymous_with_sensitive_ids", "ids": ids}

    suspicious_ids = [i for i in ids if _looks_like_foreign_id(i)]
    if suspicious_ids:
        return True, {"reason": "idor:suspicious_ids", "ids": suspicious_ids}

    if tenant_checker:
        try:
            if not tenant_checker(params, request):
                return True, {"reason": "idor:tenant_mismatch"}
        except Exception:
            return False, {"reason": "idor:tenant_checker_error"}

    if owner_checker:
        try:
            for rid in ids:
                if not owner_checker(rid, request):
                    return True, {"reason": "idor:owner_mismatch", "id": rid}
        except Exception:
            return False, {"reason": "idor:owner_checker_error"}

    return False, {"reason": "ok"}

# =========================
# Detectores principais
# =========================

def waf_detect(raw_value: str, *, ajax: bool = False) -> bool:
    if not raw_value:
        return False
    v = _normalize(str(raw_value))

    for rx in R_CRIT_ALL:
        if rx.search(v):
            return True

    if ajax and SAFE_AJAX_TEXT.fullmatch(str(raw_value)):
        return False

    for rx in R_NONCRIT:
        if rx.search(v) and re.search(r"(=|<|>|\(|\)|\d)", v):
            return True
    return False

def inspect_value(raw_value: Any) -> Dict[str, Any]:
    categories: set = set()
    matches: List[Tuple[str, str]] = []
    raw = '' if raw_value is None else str(raw_value)

    if RAW_FULLWIDTH_RE.search(raw):
        categories.add("encoding"); matches.append(("encoding", "fullwidth"))
    if RAW_INVIS_CTRL_RE.search(raw):
        categories.add("encoding"); matches.append(("encoding", "invis/ctrl"))

    v = _normalize(raw)

    for rx in R_CRIT_SQLI:
        if rx.search(v): categories.add("sqli");   matches.append(("sqli", rx.pattern))
    for rx in R_CRIT_XSS:
        if rx.search(v): categories.add("xss");    matches.append(("xss", rx.pattern))
    for rx in R_CRIT_DOMXSS:
        if rx.search(v): categories.add("domxss"); matches.append(("domxss", rx.pattern))
    for rx in R_CRIT_TEMPLATE:
        if rx.search(v): categories.add("tpl");    matches.append(("tpl", rx.pattern))
    for rx in R_CRIT_PATH:
        if rx.search(v): categories.add("path");   matches.append(("path", rx.pattern))
    for rx in R_CRIT_SHELL:
        if rx.search(v): categories.add("shell");  matches.append(("shell", rx.pattern))
    for rx in R_CRIT_OBFUSC:
        if rx.search(v): categories.add("obfusc"); matches.append(("obfusc", rx.pattern))
    for rx in R_CRIT_SSRF:
        if rx.search(v): categories.add("ssrf");   matches.append(("ssrf", rx.pattern))
    for rx in R_CRIT_ENCODING:
        if rx.search(v): categories.add("encoding"); matches.append(("encoding", rx.pattern))

    critical = any(c in categories for c in CRITICAL_CATS)

    if not critical:
        for rx in R_NONCRIT:
            if rx.search(v):
                categories.add("noncrit"); matches.append(("noncrit", rx.pattern))
                break

    return {
        "critical": critical,
        "categories": sorted(categories),
        "matched": matches,
        "normalized": v,
    }

def inspect_dict(
    data: Dict[str, Any],
    allow_numeric=None,
    allow_safe=None,
    ajax: bool=False,
    **kwargs
):
    if allow_numeric is None:
        allow_numeric = kwargs.get("allow_numeric_fields")
    if allow_safe is None:
        allow_safe = kwargs.get("allow_safe_fields")
    allow_numeric = set(allow_numeric or [])
    allow_safe = set(allow_safe or [])

    agg = {"critical": False, "categories": set(), "samples": []}
    block, warn = [], []

    if not data:
        return {"block": block, "warn": warn, "critical": False, "categories": set(), "samples": []}

    for k, v in data.items():
        rep = inspect_value(str(v))
        if rep["critical"]:
            agg["critical"] = True
        agg["categories"].update(rep["categories"])

        excerpt = _clip(rep["normalized"])
        if rep["categories"]:
            agg["samples"].append({"key": k, "report": rep})

        if rep["critical"]:
            for cat, _pat in rep["matched"]:
                if cat in CRITICAL_CATS:
                    block.append((k, cat, excerpt))
        else:
            if "noncrit" in rep["categories"]:
                warn.append((k, "noncrit", excerpt))

    return {"block": block, "warn": warn, "critical": agg["critical"], "categories": agg["categories"], "samples": agg["samples"]}

# =========================
# Guards de QS/Headers
# =========================

_QS_SUSPECT = re.compile(r"%25[0-9a-f]{2}|%00|%ff%fe|%fe%ff", re.I)
_QS_FULLWIDTH = re.compile(r"%ef%(?:bc|bd)%[0-9a-f]{2}", re.I)
_QS_TAUTOLOGY = re.compile(
    r"(?:^|[^a-z0-9])(?:or|and)(?:(?:%20)|\s)+\d+(?:(?:%20)|\s)*(?:=|%3d)(?:(?:%20)|\s)*\d+",
    re.I
)
_QS_INVIS = re.compile(r"[\u200B-\u200F\u202A-\u202E\u2060-\u206F\ufeff]")

def waf_raw_qs_guard(raw_qs: str, *, max_len: int = QS_MAX_LENGTH) -> bool:
    if raw_qs is None:
        return False
    s = str(raw_qs)
    if len(s) > max_len:   return True
    if _QS_SUSPECT.search(s):   return True
    if _QS_FULLWIDTH.search(s): return True
    if _QS_TAUTOLOGY.search(s): return True
    if _QS_INVIS.search(s):     return True
    return False

def waf_headers_guard(meta: Dict[str, Any]) -> bool:
    if not meta:
        return False
    http_headers = [(k, v) for k, v in meta.items() if k.startswith("HTTP_")]
    if len(http_headers) > HEADERS_MAX_COUNT:
        return True
    for k, v in http_headers:
        if len(k) > HEADER_NAME_MAX_LEN: return True
        vv = "" if v is None else str(v)
        if len(vv) > HEADER_VALUE_MAX_LEN: return True
        if "\r" in vv or "\n" in vv:
            return True
    return False

# =========================
# Helpers de Redirect/CORS/Host
# =========================

_RELATIVE_SAFE = re.compile(r"^/[^/].*")
_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+\-.]*:", re.I)

def is_safe_redirect_target(v: str) -> bool:
    if not v: return False
    v = v.strip()
    if _SCHEME_RE.match(v): return False
    if v.startswith("//"):  return False
    return bool(_RELATIVE_SAFE.match(v))

def sanitize_redirect_param(v: str) -> str:
    return v if is_safe_redirect_target(v) else "/"

def waf_detect_ajax(raw_value: str) -> bool:
    return waf_detect(raw_value, ajax=True)

def suspicious_host(host: str) -> bool:
    if not host:
        return True
    host = host.strip()
    if any(c in host for c in ("\\", "\"", "'", " ")):
        return True
    m = re.fullmatch(r"[A-Za-z0-9.-]+(?::\d{1,5})?", host)
    if not m:
        return True
    if host.startswith(".") or host.endswith("."):
        return True
    return False

# =========================
# Check principal WAF (para middleware usar de uma vez)
# =========================

def waf_check_all(
    request: Any,
    *,
    owner_checker: Optional[Callable[[str, Any], bool]] = None,
    tenant_checker: Optional[Callable[[Dict[str, Any], Any], bool]] = None
) -> Tuple[bool, Dict[str, Any]]:
    details: Dict[str, Any] = {"why": []}

    meta = getattr(request, "META", {}) or {}
    if waf_headers_guard(meta):
        details["why"].append({"headers": "anomalies"})
        return True, details

    raw_qs = meta.get("QUERY_STRING", "")
    if waf_raw_qs_guard(raw_qs):
        details["why"].append({"qs": "suspect"})
        return True, details

    host = meta.get("HTTP_HOST", "")
    if suspicious_host(host):
        details["why"].append({"host": "suspect"})
        return True, details

    ip = meta.get("REMOTE_ADDR") or meta.get("HTTP_X_FORWARDED_FOR", "").split(",")[0].strip()
    if _rate_limit(ip):
        details["why"].append({"dos": "rate_limit", "ip": ip})
        return True, details

    parts: List[str] = []
    path = getattr(request, "path", "") or ""
    parts.append(path)

    get_vals = getattr(request, "GET", {}) or {}
    post_vals = getattr(request, "POST", {}) or {}
    parts.extend([str(v) for v in getattr(get_vals, "values", lambda: [])()])
    parts.extend([str(v) for v in getattr(post_vals, "values", lambda: [])()])

    if hasattr(request, "resolver_match") and request.resolver_match:
        try:
            parts.extend([str(v) for v in request.resolver_match.kwargs.values()])
        except Exception:
            pass

    raw = " ".join(parts)

    ajax_header = False
    headers = getattr(request, "headers", None)
    if isinstance(headers, dict):
        ajax_header = headers.get("X-Requested-With") == "XMLHttpRequest"
    if meta.get("HTTP_X_REQUESTED_WITH") == "XMLHttpRequest":
        ajax_header = True

    if waf_detect(raw, ajax=ajax_header):
        details["why"].append({"critical_patterns": True})
        return True, details

    all_params = {}
    try:
        for k in getattr(get_vals, "keys", lambda: [])():
            all_params[k] = get_vals.get(k)
    except Exception:
        pass
    try:
        for k in getattr(post_vals, "keys", lambda: [])():
            all_params[k] = post_vals.get(k)
    except Exception:
        pass

    blocked, dos_info = _dos_payload_guard(all_params)
    if blocked:
        details["why"].append({"dos": dos_info})
        return True, details

    idor_block, idor_info = _idor_bola_guard(all_params, request, owner_checker, tenant_checker)
    if idor_block:
        details["why"].append({"idor": idor_info})
        return True, details

    details["why"].append({"ok": True})
    return False, details

# =========================
# Guard de tamanho do QS (exceção explícita)
# =========================

class QSSizeViolation(Exception):
    def __init__(self, reason: str, detail: dict | None = None):
        super().__init__(reason)
        self.reason = reason
        self.detail = detail or {}

def waf_qs_size_guard(
    raw_qs: str,
    *,
    max_url_len: int = 2048,
    max_qs_bytes: int = 1024,
    max_keys: int = 20,
    max_value_bytes: int = 256,
    max_key_bytes: int = 64,
) -> None:
    """
    Lança QSSizeViolation se estourar limites. Protege contra DoS de URL/Query gigante.
    """
    if len(raw_qs.encode("utf-8")) > max_qs_bytes:
        raise QSSizeViolation("QUERY_STRING too large", {"qs_bytes": len(raw_qs)})

    # Parse seguro (se exceder max_num_fields, levanta ValueError)
    try:
        parsed = urllib.parse.parse_qs(
            raw_qs,
            keep_blank_values=True,
            strict_parsing=False,
            max_num_fields=max_keys + 1
        )
    except ValueError:
        raise QSSizeViolation("Too many query parameters")

    if len(parsed) > max_keys:
        raise QSSizeViolation("Too many query parameters", {"keys": len(parsed)})

    for k, vals in parsed.items():
        k_dec = urllib.parse.unquote_plus(k)
        if len(k_dec.encode("utf-8")) > max_key_bytes:
            raise QSSizeViolation("Query key too large", {"key": k, "key_bytes": len(k_dec.encode("utf-8"))})
        for v in vals:
            v_dec = urllib.parse.unquote_plus(v)
            if len(v_dec.encode("utf-8")) > max_value_bytes:
                raise QSSizeViolation("Query value too large", {"key": k, "value_bytes": len(v_dec.encode("utf-8"))})
