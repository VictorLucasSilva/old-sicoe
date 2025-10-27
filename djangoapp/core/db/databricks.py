from __future__ import annotations
from functools import lru_cache
from typing import Optional, Sequence, Any, List

from django.conf import settings

try:
    from databricks import sql as dbsql
except Exception:
    dbsql = None

class DatabricksConfigError(RuntimeError):
    pass

@lru_cache(maxsize=1)
def _cfg() -> dict:
    cfg = getattr(settings, "DATABRICKS", {})
    if not cfg.get("HOST"):
        raise DatabricksConfigError("DATABRICKS_HOST não configurado.")
    return cfg

def sql_connect():
    """
    Conexão DBAPI para SQL Warehouse. Use com 'with' e feche sempre.
    """
    if dbsql is None:
        raise DatabricksConfigError("databricks-sql-connector não instalado.")

    cfg = _cfg()
    host = cfg["HOST"].replace("https://", "").replace("http://", "")
    http_path = cfg.get("HTTP_PATH")
    token = cfg.get("TOKEN")
    if not (host and http_path and token):
        raise DatabricksConfigError("HOST/HTTP_PATH/TOKEN ausentes para SQL.")

    return dbsql.connect(
        server_hostname=host,
        http_path=http_path,
        access_token=token,
        user_agent_entry="pde-django",
    )

def _maybe_use_catalog_schema(cur) -> None:
    """Se DATABRICKS.CATALOG/SCHEMA estiverem no settings, aplica o contexto."""
    cfg = _cfg()
    catalog = (cfg.get("CATALOG") or "").strip()
    schema = (cfg.get("SCHEMA") or "").strip()
    if catalog:
        cur.execute(f'USE CATALOG `{catalog}`')
    if schema:
        cur.execute(f'USE SCHEMA `{schema}`')

def sql_query(
    sql: str,
    params: Optional[Sequence[Any]] = None,
    as_dict: bool = True,
    max_rows: Optional[int] = None,
) -> List[Any]:
    """
    Executa uma query no Warehouse e retorna lista de dicts (default) ou tuplas.
    Use parâmetros posicionais para evitar SQL injection (placeholders "?").
    """
    with sql_connect() as conn:
        with conn.cursor() as cur:
            _maybe_use_catalog_schema(cur)
            cur.execute(sql, params or [])
            rows = cur.fetchmany(size=max_rows) if max_rows else cur.fetchall()
            desc = getattr(cur, "description", None)

            if as_dict and desc:
                cols = [d[0] for d in desc]
                return [dict(zip(cols, r)) for r in rows]
            return rows


def sql_query_one(sql: str, params: Optional[Sequence[Any]] = None) -> Optional[dict]:
    res = sql_query(sql, params=params, as_dict=True, max_rows=1)
    return res[0] if res else None
