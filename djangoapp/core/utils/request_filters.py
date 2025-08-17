import re
from typing import Any, Dict, Tuple
from django.conf import settings
from .search import SEARCH_FIELDS, clean_search_q
from .waf import inspect_value 

_NUMERIC_RX = re.compile(r"^\d{1,9}$")

def _waf_inspect_params(params: Dict[str, Any], ajax_lenient_enabled: bool) -> Tuple[list, list]:
    findings_block, findings_warn = [], []
    numeric_fields = set(getattr(settings, "WAF_NUMERIC_FIELDS", ["page","id","offset","limit"]))

    for key, value in (params or {}).items():
        raw = "" if value is None else str(value)

        if key in numeric_fields:
            if not _NUMERIC_RX.fullmatch(raw):
                findings_block.append((key, "numeric", "invalid"))
            continue

        rep = inspect_value(raw)  
        cats = set(rep.get("categories", set()))

        if cats & {"sqli","xss","path","shell","ssrf","encoding","obfusc","tpl"}:
            findings_block.append((key, next(iter(cats)), "match"))
            continue

        if key in SEARCH_FIELDS:
            sanitized = clean_search_q(raw)
            if raw and not sanitized:
                findings_block.append((key, "encoding", "invalid-search"))
                continue

            if "noncrit" in cats:
                if ajax_lenient_enabled:
                    findings_warn.append((key, "noncrit", "excerpt"))
                else:
                    findings_block.append((key, "noncrit", "search-tautology"))
            continue

        if "noncrit" in cats:
            findings_warn.append((key, "noncrit", "excerpt"))

    return findings_block, findings_warn
