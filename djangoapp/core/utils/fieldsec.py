from __future__ import annotations
import re
from django.core.exceptions import ValidationError
from django.conf import settings

from core.utils.security import normalize_input  
from core.utils.waf import inspect_value        

RE_INVISIBLES = re.compile(
    r"[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF\u00AD\u034F]"
    r"|[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]",
    re.UNICODE
)

def strip_invisibles(s: str) -> str:
    return RE_INVISIBLES.sub("", s or "")

def collapse_ws(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").strip()

def sanitize_for_form(raw: str, *, max_len: int = 50) -> str:
    """
    Normaliza (URL/HTML), remove invisíveis e colapsa espaços.
    Corta no servidor (defensivo).
    """
    s = normalize_input(raw or "")
    s = strip_invisibles(s)
    s = collapse_ws(s)
    return s[:max_len]

def waf_validate_text(value: str, *, block_noncrit_on_forms: bool = True):
    """
    Usa o WAF para classificar a string. Bloqueia critical sempre.
    Opcionalmente bloqueia 'noncrit' (tautology leve) em forms.
    """
    rep = inspect_value(value or "")
    cats = set(rep.get("categories", []))

    CRIT = {"sqli", "xss", "tpl", "path", "shell", "obfusc", "ssrf"}
    if cats & CRIT:
        raise ValidationError("Conteúdo inválido.")

    if block_noncrit_on_forms and "noncrit" in cats:
        raise ValidationError("Conteúdo inválido.")

def ensure_regex(value: str, pattern: re.Pattern, message: str):
    if not pattern.match(value or ""):
        raise ValidationError(message)

def forbid_quotes_and_comments(value: str):
    if any(ch in (value or "") for ch in ("'", '"')):
        raise ValidationError('Não use aspas.')
    if any(tok in (value or "") for tok in ("--", "/*", "*/", ";")):
        raise ValidationError('Conteúdo inválido.')

def smart_titlecase(s: str) -> str:
    words = []
    for w in (s or "").split(" "):
        parts = [p.capitalize() for p in w.split("-") if p]
        words.append("-".join(parts))
    return " ".join(words)
