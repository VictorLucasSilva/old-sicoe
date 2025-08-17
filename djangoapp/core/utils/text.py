import re
import unicodedata
import urllib.parse

RE_INVISIBLES = re.compile(
    r"[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF\u00AD\u034F]"
    r"|[\u0000-\u001F\u007F]",
    re.UNICODE
)

def strip_invisible(s: str) -> str:
    return RE_INVISIBLES.sub("", s)

def nfkc_casefold(s: str) -> str:
    return unicodedata.normalize("NFKC", s).casefold()

def collapse_ws(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()

def super_normalize(s: str) -> str:
    if not s:
        return ""
    for _ in range(3):
        try:
            s = urllib.parse.unquote_plus(s)
        except Exception:
            break
    s = strip_invisible(s)
    s = nfkc_casefold(s)
    s = s.replace("\x00", "")
    s = collapse_ws(s)
    return s

def clip(s: str, n: int = 256) -> str:
    return s if len(s) <= n else (s[:n] + "…")

def is_probably_binary(s: str) -> bool:
    return sum(1 for ch in s if ord(ch) < 9 or (13 < ord(ch) < 32)) > 8
