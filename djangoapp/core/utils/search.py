import re
from .security import normalize_input

SAFE_Q_RE   = re.compile(r"^[\w\sÀ-ÖØ-öø-ÿ.,:/@\-()]{0,80}$", re.UNICODE)
HEX_BYTE_RE = re.compile(r"%[0-9a-fA-F]{2}")
INVIS_RE    = re.compile(r"[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF\x00-\x1F\x7F]")

SEARCH_FIELDS = {
    "d_doc",

    "est_center", "est_region", "est_state", "est_city", "est_address",
    "est_manage", "est_property",

    "ndest_units", "ndest_cnpj", "ndest_nire", "ndest_reg_state", "ndest_reg_city",

    "att_doc", "att_region", "att_state", "att_city", "att_center",
    "att_situation", "att_data_inserted", "att_data_expire",

    "document", "region", "state", "city", "center",
    "situation", "data_inserted", "data_expire",
    "number_doc", "file",

    "em_id", "em_subject", "em_email", "em_center", "data_shipping",

    "id", "subject", "email",

    "u_name", "u_login", "u_email", "u_profile", "u_status",

    "login", "profile", "status", "time_in", "time_out",

    "cod", "action", "object", "description",

    "rcd_fk_establishment", "rcd_fk_document",
    "rcu_center", "rcu_state", "rcu_region",
}

def clean_search_q(raw: str, maxlen: int = 80) -> str:
    q = normalize_input(raw or "")
    q = INVIS_RE.sub("", q)
    if HEX_BYTE_RE.search(q):
        return ""
    if not SAFE_Q_RE.match(q):
        return ""
    return q[:maxlen]

def clean_search_params(data: dict) -> dict:
    out = {}
    for k in SEARCH_FIELDS:
        if k in data:
            v = clean_search_q(data.get(k))
            if v:
                out[k] = v
    return out
