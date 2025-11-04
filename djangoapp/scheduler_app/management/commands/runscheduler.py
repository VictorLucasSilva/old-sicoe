import logging, signal, time, os, hashlib, requests, re

from django.db.models import Q
from zoneinfo import ZoneInfo
from datetime import timedelta
from apscheduler.schedulers.blocking import BlockingScheduler
from core.db.databricks import sql_query, DatabricksConfigError
from django.http import JsonResponse, HttpResponseBadRequest
from apscheduler.events import (
    EVENT_JOB_EXECUTED, EVENT_JOB_ERROR, EVENT_JOB_MISSED
)
from django.apps import apps
from django.conf import settings
from django.core.cache import cache
from django.core.mail import EmailMultiAlternatives, get_connection
from django.core.management.base import BaseCommand
from django.db import close_old_connections, transaction, connection
from django.template.loader import render_to_string
from django.template import TemplateDoesNotExist
from django.db.models import Subquery, OuterRef, F
from django.utils import timezone
from django_apscheduler.jobstores import DjangoJobStore, register_events
from django_apscheduler.models import DjangoJob, DjangoJobExecution

logger = logging.getLogger("core")

_RE_SEP_STD = re.compile(r"-\s*>\s*")

ANEXOS_ATUALIZAR_STATUS_EVERY_MINUTES = 1 # Status Anexos
USUARIOS_ATUALIZAR_STATUS_EVERY_MINUTES = 720 # Status Usuário
EMAIL_JOB_EVERY_MINUTES = 1 # Email Usuários
PSFT_ESTAB_JOB_EVERY_MINUTES = 0 # DB Estabelecimento >> (Segunda a sexta - 9:00)
PSFT_FUNC_JOB_EVERY_MINUTES = 0 # DB Funcionario >> (Segunda a sexta - 9:30)
RSQ_JOB_EVERY_MINUTES = 0 # DB Relacionamento >> (Segunda a sexta - 10:00)
EMAIL_ADMIN_MINUTES = 0 # Email ADM
UPDATE_RELATION_USER_EVERY_MINUTES = 1 # Relação Estabelecimento x Usuário

def _to_str(x):
    return (str(x).strip() or None) if x is not None else None

def _normalize_separators(s: str | None) -> str | None:

    if s is None:
        return None
    s = str(s)

    s = s.replace("\\u003E", ">").replace("\\u003e", ">")
    s = s.replace("\\u043A", "к").replace("\\u043a", "к") 
    s = s.replace("\\u2192", "→")

    ALT_CHARS = [">", "к", "→", "›", "»"]
    for ch in ALT_CHARS:
        s = re.sub(rf"-\s*{re.escape(ch)}\s*", "->", s)

    return s

def split_triplet(value):
    if value in (None, ""):
        return (None, None, None)
    s = _normalize_separators(value)
    if not s:
        return (None, None, None)
    parts = _RE_SEP_STD.split(s)
    if len(parts) >= 3:
        return (parts[0].strip() or None,
                parts[1].strip() or None,
                parts[2].strip() or None)
    return (None, None, None)

def _db_guard(fn):
    def wrapper(*args, **kwargs):
        close_old_connections()
        try:
            return fn(*args, **kwargs)
        finally:
            close_old_connections()
    return wrapper

def _advisory_key(name: str) -> int:
    h8 = hashlib.sha1(name.encode("utf-8")).digest()[:8]

    return int.from_bytes(h8, "big", signed=True)

def _dist_lock(lock_key: str, seconds: int = 60):
    def deco(fn):
        def inner(*args, **kwargs):
            engine = settings.DATABASES["default"]["ENGINE"]
            if "postgresql" in engine:
                k = _advisory_key(lock_key)
                with connection.cursor() as cur:
                    cur.execute("SELECT pg_try_advisory_lock(%s::bigint)", [k])
                    acquired = cur.fetchone()[0]
                if not acquired:
                    logger.info("[LOCK-DB] Pulando %s: lock indisponível.", lock_key)
                    return "locked"
                try:
                    return fn(*args, **kwargs)
                finally:
                    try:
                        with connection.cursor() as cur:
                            cur.execute("SELECT pg_advisory_unlock(%s::bigint)", [k])
                    except Exception:
                        pass
            else:
                if not cache.add(lock_key, "1", timeout=seconds):
                    logger.info("[LOCK] Pulando %s: já em execução.", lock_key)
                    return "locked"
                try:
                    return fn(*args, **kwargs)
                finally:
                    cache.delete(lock_key)
        return inner
    return deco

def _job_log(name: str):
    def deco(fn):
        def inner(*args, **kwargs):
            start = time.monotonic()
            start_dt = timezone.localtime(timezone.now())
            logger.info("[JOB %s] início %s", name, start_dt)
            try:
                result = fn(*args, **kwargs)
                dur = time.monotonic() - start
                logger.info("[JOB %s] fim em %.2fs -> %s", name, dur, result)
                return result
            except Exception:
                dur = time.monotonic() - start
                logger.exception("[JOB %s] FALHOU em %.2fs", name, dur)
                raise
        return inner
    return deco

def _to_str(val, default=""):
    if val is None:
        return default
    if isinstance(val, (int, float)):
        return str(val)
    return str(val).strip()

def _models():
    return {
        "Attachment": apps.get_model("core", "Attachment"),
        "RelationCenterUser": apps.get_model("core", "RelationCenterUser"),
        "User": apps.get_model("core", "User"),
        "Establishment": apps.get_model("core", "Establishment"),
        "Email": apps.get_model("core", "Email"),
        "EstAux": apps.get_model("core", "EstAux"),
        "Document": apps.get_model("core", "Document"),
        "PsFuncionario": apps.get_model("core", "PsFuncionario"),
        "rs_q_emp": apps.get_model("core", "rs_q_emp")
    }


@_db_guard # OK
@_dist_lock("job:anexos_atualizar_status", seconds=600)
@_job_log("Anexos • Atualizar Status")
def update_status_attachment():
    M = _models()
    Attachment = M["Attachment"]
    try:
        with transaction.atomic():
            attachments = Attachment.objects.all()
            atualizados = 0
            for att in attachments:
                if att.att_situation == "Invalidado":
                    att.att_situation = "Invalidado"
                elif timezone.now().date() > att.att_data_expire:
                    if att.att_situation != "Vencido" and not att.att_situation == "Em Análise" and not att.att_situation == "Invalidado":
                        att.att_situation = "Vencido"
                        att.save(update_fields=['att_situation'])
                        atualizados += 1
                elif (timezone.now().date() > (att.att_data_expire - timedelta(days=60))) and (timezone.now().date() < att.att_data_expire):
                    if att.att_situation != "A Vencer" and not att.att_situation == "Em Análise" and not att.att_situation == "Invalidado":
                        att.att_situation = "A Vencer"
                        att.save(update_fields=['att_situation'])
                        atualizados += 1
                elif timezone.now().date() < (att.att_data_expire - timedelta(days=60)):
                    if att.att_situation != "Regular" and not att.att_situation == "Em Análise" and not att.att_situation == "Invalidado":
                        att.att_situation = "Regular"
                        att.save(update_fields=['att_situation'])
                        atualizados += 1
            logger.info(f'Atualização concluída.')
            return f'Atualização concluída.'
    except Exception as e:
        logger.error(f'Falha ao atualizar. Erro: {str(e)}')
        return f'Falha ao atualizar. Erro: {str(e)}'


@_db_guard # OK
@_dist_lock("job:usuarios_atualizar_status", seconds=600)
@_job_log("Usuários • Atualizar Status")
def update_status_user():
    M = _models()
    User = M["User"]
    try:
        with transaction.atomic():
            user = User.objects.all()

            for u in user:
                if timezone.now().date() > u.u_time_out:
                    if u.u_status != "Inativo":
                        u.u_status = "Inativo"
                        u.save()
                elif timezone.now().date() < u.u_time_out:
                    if u.u_status != "Ativo":
                        u.u_status = "Ativo"
                        u.save()
                        
            logger.info(f'Atualização concluída.')
            return f'Atualização concluída.'

    except Exception as e:
        logger.error(f'Falha ao atualizar. Erro: {str(e)}')
        return f'Falha ao atualizar. Erro: {str(e)}'


@_db_guard # OK
@_dist_lock("job:update_relation_user", seconds=600)
@_job_log("RelationUser • Atualizar RCU")
def update_relation_user():
    M = _models()
    RsQEmp = M["rs_q_emp"]
    RCU = M["RelationCenterUser"]
    Establishment = M["Establishment"]
    User = M["User"]

    created = 0
    updated = 0
    skipped = 0
    missing_user = set()
    missing_estab = set()

    try:
        pairs = (RsQEmp.objects
                 .values_list("rs_q_emplid", "rs_q_estabid")
                 .distinct())

        emplids = {emplid for (emplid, _) in pairs if emplid is not None}
        estabids = set()
        normalized_pairs = []
        for emplid, estabid_raw in pairs:
            if emplid is None or not estabid_raw:
                skipped += 1
                continue
            try:
                estabid = int(str(estabid_raw).strip())
            except ValueError:
                skipped += 1
                continue
            normalized_pairs.append((emplid, estabid))
            estabids.add(estabid)

        users_by_emp = {u.u_num_employee: u for u in User.objects.filter(u_num_employee__in=emplids)}
        estab_by_id  = {e.est_id: e for e in Establishment.objects.filter(est_id__in=estabids)}

        with transaction.atomic():
            for emplid, estabid in normalized_pairs:
                u = users_by_emp.get(emplid)
                e = estab_by_id.get(estabid)

                if not u:
                    missing_user.add(emplid)
                    skipped += 1
                    continue
                if not e:
                    missing_estab.add(estabid)
                    skipped += 1
                    continue

                obj, was_created = RCU.objects.get_or_create(
                    rcu_fk_user=u,
                    rcu_fk_estab=e,
                    defaults={
                        "rcu_center": e.est_center or "-",
                        "rcu_state":  e.est_state  or "-",
                        "rcu_region": e.est_region or "-",
                        "rcu_active": True, 
                    },
                )

                if was_created:
                    created += 1
                else:
                    to_update = {}
                    center = e.est_center or "-"
                    state  = e.est_state  or "-"
                    region = e.est_region or "-"

                    if obj.rcu_center != center:
                        to_update["rcu_center"] = center
                    if obj.rcu_state != state:
                        to_update["rcu_state"] = state
                    if obj.rcu_region != region:
                        to_update["rcu_region"] = region

                    if to_update:
                        RCU.objects.filter(pk=obj.pk).update(**to_update)
                        updated += 1

        msg = (
            f"RCU: {created} criados, {updated} atualizados."
            f"{skipped} ignorados. "
            f"Usuários ausentes: {len(missing_user)}; Estabelecimentos ausentes: {len(missing_estab)}."
        )
        if missing_user:
            logger.warning(f"Sem User para matrículas: {sorted(list(missing_user))[:20]}{' ...' if len(missing_user)>20 else ''}")
        if missing_estab:
            logger.warning(f"Sem Establishment para estabs: {sorted(list(missing_estab))[:20]}{' ...' if len(missing_estab)>20 else ''}")

        logger.info(msg)
        return msg

    except Exception as e:
        logger.error(f"Falha ao atualizar. Erro: {e}")
        return f"Falha ao atualizar. Erro: {e}"


@_db_guard # OK
@_dist_lock("job:psft_sync_funcionarios", seconds=900)
@_job_log("PSFT • Funcionários")
def sync_psft_funcionarios():
    M = _models()
    PsFuncionario = M["PsFuncionario"]

    try:
        try:
            limite = 50000
        except ValueError:
            return HttpResponseBadRequest("limit inválido (use inteiro)")

        if limite <= 0 or limite > 50001:
            return HttpResponseBadRequest("limit inválido (1..501)")

        sql = '''
            SELECT *
            FROM `colaborativo_gesap`.`refined`.`rst_sicoe_funcionario`
            LIMIT ?
        '''
        try:
            dados = sql_query(sql, params=[limite], as_dict=True)
        except DatabricksConfigError as e:
            return JsonResponse({"error": str(e)}, status=500)
        except Exception as e:
            logger.exception("Erro consultando Databricks")
            return JsonResponse({"error": "Falha ao consultar Databricks"}, status=502)

        dados = sql_query(sql, params=[limite], as_dict=True)

        with transaction.atomic():
            for func in dados:
                if isinstance(func, dict):
                    PsFuncionario.objects.update_or_create(
                        func_matricula=(func.get("nu_matricula")),
                        defaults={
                            "func_nm_cargo": _to_str(func.get("ds_cargo")).strip(),
                            "func_nm_funcao": _to_str(func.get("ds_cargo")).strip(),
                            "func_nm_email": (_to_str(func.get("tx_email")) or "").strip().lower(),
                        },
                    )
                else:
                    print(f"Item inválido (não é dicionário): {func}")
                    
            return 'ok'
    except requests.exceptions.RequestException as e:
        return f'Falha ao atualizar: {str(e)}'


@_db_guard #OK
@_dist_lock("job:rsq_emp_refresh", seconds=600)
@_job_log("PSFT • Relacionamento")
def rsq_emp_refresh():
    M = _models()
    RsQEmp = M["rs_q_emp"]

    limite = 30000
    if limite <= 0 or limite > 30001:
        return HttpResponseBadRequest("limit inválido (1..30001)")

    sql = '''
        SELECT *
        FROM `colaborativo_gesap`.`refined`.`rst_sicoe_relacionamento`
        LIMIT ?
    '''
    try:
        dados = sql_query(sql, params=[limite], as_dict=True)
    except DatabricksConfigError as e:
        return JsonResponse({"error": str(e)}, status=500)
    except Exception:
        logger.exception("Erro consultando Databricks")
        return JsonResponse({"error": "Falha ao consultar Databricks"}, status=502)

    created = updated = skipped = 0

    with transaction.atomic():
        for row in dados:
            if not isinstance(row, dict):
                logger.warning("Item inválido (não é dicionário): %r", row)
                skipped += 1
                continue

            nu_matricula = row.get("nu_matricula")
            id_estab = row.get("id_estabelecimento")

            if not nu_matricula or not id_estab:
                skipped += 1
                continue

            try:
                emplid = int(nu_matricula)
                estabid = int(id_estab)
            except (TypeError, ValueError):
                logger.warning("Campos numéricos inválidos, pulando: %r", row)
                skipped += 1
                continue

            uor = str(row.get("id_departamento") or "").strip()
            sigla_uor = str(row.get("ds_departamento") or "").strip()
            depen_uor = str(row.get("id_departamento_dependente") or "").strip()
            depen_sigla_uor = str(row.get("ds_departamento_dependente") or "").strip()

            try:
                try:
                    obj = RsQEmp.objects.get(rs_q_emplid=emplid, rs_q_estabid=estabid)
                    obj.rs_q_uor = uor
                    obj.rs_q_sigla_uor = sigla_uor
                    obj.rs_q_depen_uor = depen_uor
                    obj.rs_q_depen_sigla_uor = depen_sigla_uor
                    obj.save()
                    updated += 1
                except RsQEmp.DoesNotExist:
                    RsQEmp.objects.create(
                        rs_q_emplid=emplid,
                        rs_q_estabid=estabid,
                        rs_q_uor=uor,
                        rs_q_sigla_uor=sigla_uor,
                        rs_q_depen_uor=depen_uor,
                        rs_q_depen_sigla_uor=depen_sigla_uor,
                    )
                    created += 1
            except Exception:
                logger.exception("Erro salvando registro emplid=%s estabid=%s", emplid, estabid)
                skipped += 1
                continue

    logger.info("rsq_emp_refresh finalizado: created=%d updated=%d skipped=%d", created, updated, skipped)
    return "ok"


@_db_guard # OK
@_dist_lock("job:psft_sync_estabelecimentos", seconds=60)
@_job_log("PSFT • Estabelecimentos")
def sync_psft_estabelecimentos():
    M = _models()
    Establishment = M["Establishment"]
    EstAux        = M["EstAux"]
    Attachment    = M["Attachment"]

    try:
        try:
            limite = 500
        except ValueError:
            return HttpResponseBadRequest("limit inválido (use inteiro)")

        if limite <= 0 or limite > 501:
            return HttpResponseBadRequest("limit inválido (1..501)")

        sql = '''
            SELECT *
            FROM `colaborativo_gesap`.`refined`.`rst_sicoe_estabelecimento`
            LIMIT ?
        '''
        try:
            dados = sql_query(sql, params=[limite], as_dict=True)
        except DatabricksConfigError as e:
            return JsonResponse({"error": str(e)}, status=500)
        except Exception as e:
            logger.exception("Erro consultando Databricks")
            return JsonResponse({"error": "Falha ao consultar Databricks"}, status=502)

        dados = sql_query(sql, params=[limite], as_dict=True)

        with transaction.atomic():
            for item in dados:
                if isinstance(item, dict):
                    
                    id = int(item.get('id_estabelecimento', ''))
                    center = str(item.get('no_estabelecimento', '')).strip()
                    city = str(item.get('no_cidade', '')).strip()
                    state = str(item.get('sg_estado', '')).strip()
                    code_postal = str(item.get('cd_postal', '')).strip()
                    sigla = str(item.get('sg_estabelecimento', '')).strip()
                    enderec = str(item.get('tx_endereco', '')).strip()

                    est_all = Establishment.objects.all()
                    
                    if not est_all.filter(est_id=id).exists():
                        Establishment.objects.create(
                            est_id=id,
                            est_center=center,
                            est_city=city,
                            est_state=state,
                            est_region='',
                            est_address=enderec,
                            est_cep=code_postal,
                            est_sigla=sigla,
                            est_manage='-',
                            est_property='-',
                        )

                    est_filtered = Establishment.objects.filter(est_id=id).first()
                    att = Attachment.objects.filter(att_center=est_filtered.est_center).exists()

                    est = est_all.filter(est_id=id).first()
                    if not est.est_region:
                        uf_region = EstAux.objects.filter(estaux_uf=est.est_state).first()
                        est.est_region=uf_region.estaux_region
                        est.save()

                    Establishment.objects.update_or_create(
                        est_id=id,
                        defaults={
                            'est_center': center,
                            'est_city': city,
                            'est_state': state,
                            'est_region': est.est_region,
                            'est_address': enderec,
                            'est_cep': code_postal,
                            'est_sigla': sigla,
                            'est_manage': est.est_manage,
                            'est_property': est.est_property,
                        }
                    )
                    
                    attup = Attachment.objects.filter(att_center=est_filtered.est_center)
                    if not att:
                        attup.update(
                            att_center=center
                        )
                else:
                    print(f"Item inválido (não é dicionário): {item}")
            
            return 'ok'
    except requests.exceptions.RequestException as e:
        return f'Falha ao atualizar: {str(e)}'


PENDING_STATUSES = ("Vencido", "Invalidado", "A Vencer")
GRP_USER = "Usuário"
GRP_GR   = "Gerente Regional"

def _latest_problematic_attachments_qs():
    M = _models()
    Attachment = M["Attachment"]

    latest_id_sq = (
        Attachment.objects
        .filter(att_doc=OuterRef("att_doc"), att_center=OuterRef("att_center"))
        .order_by("-att_data_inserted", "-att_id")
        .values("att_id")[:1]
    )

    qs = (
        Attachment.objects
        .annotate(_latest_id=Subquery(latest_id_sq))
        .filter(att_id=F("_latest_id"), att_situation__in=PENDING_STATUSES)
    )
    return qs

def _collect_docs_for_scope(base_qs, *, region=None, state=None, center=None):
    qs = base_qs
    if region and region != "-":
        qs = qs.filter(att_region=region)
    if state and state != "-":
        qs = qs.filter(att_state=state)
    if center and center != "-":
        qs = qs.filter(att_center=center)
    return sorted(set(qs.values_list("att_doc", flat=True)))

def _aggregate_scopes_for_user(latest_qs, user, user_relations):
    """
    Retorna (role, scopes_docs):
      role: "USR" ou "GR"
      scopes_docs: { label_scope -> [docs pendentes] }
    - Usuário  => por Estabelecimento (center)
    - GR       => por UF e por Região
    """
    gnames = set(user.groups.values_list("name", flat=True))
    is_usr = GRP_USER in gnames
    is_gr  = GRP_GR in gnames
    role = "GR" if is_gr else ("USR" if is_usr else None)
    if not role:
        return None, {}

    scopes_docs = {}

    if role == "USR":
        centers = sorted({
            (rel.rcu_center or getattr(rel.rcu_fk_estab, "est_center", "") or "").strip()
            for rel in user_relations
        })
        for center in centers:
            if not center or center == "-":
                continue
            docs = _collect_docs_for_scope(latest_qs, center=center)
            if docs:
                scopes_docs[center] = docs
    else:
        states = sorted({
            (rel.rcu_state or "").strip()
            for rel in user_relations if (rel.rcu_state or "").strip() and (rel.rcu_state or "").strip() != "-"
        })
        for uf in states:
            label = f"UF {uf}"
            docs = _collect_docs_for_scope(latest_qs, state=uf)
            if docs:
                scopes_docs[label] = docs

        regions = sorted({
            (rel.rcu_region or "").strip()
            for rel in user_relations if (rel.rcu_region or "").strip() and (rel.rcu_region or "").strip() != "-"
        })
        for reg in regions:
            label = f"Região {reg}"
            docs = _collect_docs_for_scope(latest_qs, region=reg)
            if docs:
                scopes_docs[label] = docs

    return role, scopes_docs

def _summarize_scopes_for_email_record(ordered_scopes: dict, max_len: int = 256) -> str:
    parts = []
    for scope, docs in ordered_scopes.items():
        parts.append(f"{scope}: {', '.join(docs[:3])}") 
    out = " | ".join(parts)
    return out if len(out) <= max_len else (out[:max_len-1] + "…")


@_db_guard #OK
@_dist_lock("job:emails_enviar_pendencias", seconds=1800)
@_job_log("E-mails • Enviar Pendências por Escopo")
def send_emails_to_users():
    force_send = os.getenv("EMAIL_JOB_FORCE_SEND", "0") == "1"

    M = _models()
    RelationCenterUser = M["RelationCenterUser"]
    Establishment = M["Establishment"]
    Email = M["Email"]

    latest_qs = _latest_problematic_attachments_qs()

    centers_qs = latest_qs.values_list("att_center", flat=True).distinct()
    _ = list(Establishment.objects.filter(est_center__in=centers_qs))

    relations = (
        RelationCenterUser.objects
        .select_related("rcu_fk_user", "rcu_fk_estab")
        .filter(
            rcu_active=True,
            rcu_fk_user__is_active=True,
            rcu_fk_user__u_status="Ativo",
            rcu_fk_user__email__isnull=False,
            rcu_fk_user__groups__name__in=[GRP_USER, GRP_GR],
        )
        .exclude(rcu_fk_user__email="")
        .distinct()
    )

    rels_by_user = {}
    for rel in relations:
        u = rel.rcu_fk_user
        if not u:
            continue
        rels_by_user.setdefault(u.id, {"user": u, "rels": []})["rels"].append(rel)

    log_body   = bool(getattr(settings, "SCHEDULER_LOG_EMAIL_BODY", False))
    from_email = getattr(settings, "EMAIL_HOST_USER", None) or getattr(settings, "DEFAULT_FROM_EMAIL", None)
    address_url = getattr(settings, "PDE_ADDRESS_URL", "https://painel-estabelecimento0.bbts.com.br")
    today = timezone.localdate()

    sent = 0
    with get_connection() as conn:
        for bucket in rels_by_user.values():
            user = bucket["user"]
            role, scopes_docs = _aggregate_scopes_for_user(latest_qs, user, bucket["rels"])
            if not role or not scopes_docs:
                continue

            ordered_scopes = dict(sorted(
                ((scope, sorted(set(docs))) for scope, docs in scopes_docs.items()),
                key=lambda x: x[0]
            ))

            subject = "SICOE - Documentos Pendentes" if role == "GR" else "SICOE - Documentos Pendentes"

            if not force_send and Email.objects.filter(
                em_email=user.email,
                em_subject=subject,
                em_data_shipping=today,
            ).exists():
                if log_body:
                    logger.info("[EMAIL] skip (já enviado hoje) to=%s", user.email)
                continue

            first_name = (user.first_name or "").strip() or user.username
            ctx = {"first_name": first_name, "address_url": address_url, "role": role, "scopes": ordered_scopes}
            try:
                text_content = render_to_string("others/notification.txt", ctx)
            except TemplateDoesNotExist:
                linhas = [f"Olá {first_name},", ""]
                if role == "USR":
                    linhas.append("Documentos pendentes nos estabelecimentos sob sua responsabilidade:")
                else:
                    linhas.append("Documentos pendentes nos seus escopos de atuação (UFs/Regiões):")
                linhas.append("")
                for scope, docs in ordered_scopes.items():
                    linhas.append(f"- {scope}: {', '.join(docs)}")
                linhas += ["", f"Acesse: {address_url}", ""]
                text_content = "\n".join(linhas)

            if log_body:
                preview = text_content if len(text_content) <= 2000 else (text_content[:2000] + "…")
                logger.info("[EMAIL BODY] to=%s >>>\n%s\n<<< [END EMAIL BODY]", user.email, preview)

            msg = EmailMultiAlternatives(subject, text_content, from_email, [user.email], connection=conn)
            msg.send()

            em_center_summary = _summarize_scopes_for_email_record(ordered_scopes, max_len=256)
            first_scope = next(iter(ordered_scopes.keys()))
            first_docs  = ordered_scopes[first_scope]
            em_doc_preview = (", ".join(list(first_docs)[:5])[:50]) if first_docs else "-"

            Email.objects.create(
                em_from=from_email,
                em_email=user.email,
                em_subject=subject,
                em_doc=em_doc_preview,
                em_center=em_center_summary,
                em_login=user.username,
                em_send_email="true",
            )
            sent += 1

    return f"{sent} e-mail(s) enviados."


@_db_guard #OK
@_dist_lock("job:emails_enviar_analise_admin", seconds=1800)
@_job_log("E-mails • Administradores • Aviso 'Em Análise'")
def send_emails_to_admin():
    force_send = os.getenv("EMAIL_JOB_FORCE_SEND", "0") == "1"

    M = _models()
    Attachment = M["Attachment"]
    User = M["User"]
    Email = M["Email"]
    
    admins_qs = (
        User.objects.filter(
            is_active=True,
            u_status="Ativo",
            groups__name__in=["Administrador", "Administrador Master"],
        )
        .only("email", "first_name", "last_name", "username")
        .distinct()
    )
    admins = [a for a in admins_qs if (a.email or "").strip()]
    if not admins:
        logger.info("[EMAIL ADMIN] nenhum administrador ativo com e-mail; abortando.")
        return "sem administradores com e-mail"
    pending_qs = Attachment.objects.filter(att_situation="Em Análise")
    if not pending_qs.exists():
        logger.info("[EMAIL ADMIN] nenhum anexo 'Em Análise' no momento.")
        return "sem anexos 'Em Análise'"
    groups = pending_qs.values("att_center", "att_doc").distinct()

    from_email = getattr(settings, "EMAIL_HOST_USER", None) or getattr(settings, "DEFAULT_FROM_EMAIL", None)
    address_url = getattr(settings, "PDE_ADDRESS_URL", "https://painel-estabelecimento0.bbts.com.br")
    log_body = bool(getattr(settings, "SCHEDULER_LOG_EMAIL_BODY", False))
    today = timezone.localdate()

    sent = 0

    with get_connection() as conn:
        for g in groups:
            center = (g.get("att_center") or "").strip()
            doc = (g.get("att_doc") or "").strip()
            if not center or not doc:
                continue

            subject = "SICOE - Documentos em análise"
            items = list(
                pending_qs.filter(att_center=center, att_doc=doc)
                .order_by("-att_data_inserted")
                .values(
                    "att_id",
                    "att_attached_by",
                    "att_data_inserted",
                    "att_region",
                    "att_state",
                    "att_city",
                )
            )
            for adm in admins:
                sent_qs = (
                    Email.objects.filter(
                        em_email=adm.email,
                        em_subject=subject,
                        em_center=center[:50],
                        em_doc=doc[:50],
                    )
                    .order_by("-em_data_shipping")
                )

                if sent_qs.filter(em_send_email__iexact="true").exists() and not force_send:
                    logger.info(
                        "[EMAIL ADMIN] skip (já enviado) to=%s center=%s doc=%s",
                        adm.email, center, doc
                    )
                    continue

                admin_name = (adm.get_full_name() or "").strip() or adm.username

                ctx = {
                    "center": center,
                    "document": doc,
                    "address_url": address_url,
                    "items": items,
                    "admin_name": admin_name,
                }

                try:
                    text_content = render_to_string("others/notification_admin.txt", ctx)
                except TemplateDoesNotExist:
                    linhas = [f"Olá, {admin_name}!", ""]
                    linhas += [f"Há {len(items)} anexo(s) 'Em Análise' para {doc} em {center}.", ""]
                    for it in items[:50]:
                        try:
                            dt = timezone.localtime(it["att_data_inserted"]).strftime("%d/%m/%Y %H:%M")
                        except Exception:
                            dt = str(it["att_data_inserted"])
                        cidade_uf = f"{(it.get('att_city') or '-')}-{(it.get('att_state') or '-')}"
                        linhas.append(
                            f"- #{it['att_id']} anexado por {it.get('att_attached_by') or '-'} "
                            f"em {dt} ({cidade_uf})"
                        )
                    linhas += ["", f"Acesse: {address_url}"]
                    text_content = "\n".join(linhas)

                if log_body:
                    preview = text_content if len(text_content) <= 2000 else (text_content[:2000] + "…")
                    logger.info("[EMAIL ADMIN BODY] to=%s >>>\n%s\n<<< [END EMAIL ADMIN BODY]", adm.email, preview)

                msg = EmailMultiAlternatives(
                    subject,
                    text_content,
                    from_email,
                    [adm.email],
                    connection=conn,
                )
                msg.send()

                logger.info(
                    "[EMAIL ADMIN] ENVIADO para %s (%s) center=%s doc=%s",
                    adm.email, admin_name, center, doc
                )
                try:
                    rec = sent_qs.first()
                    if rec and (rec.em_send_email or "").lower() == "false":
                        rec.em_send_email = "true"
                        rec.em_data_shipping = today
                        rec.em_from = from_email
                        rec.em_login = adm.username
                        rec.save(update_fields=["em_send_email", "em_data_shipping", "em_from", "em_login"])
                    elif not rec:
                        Email.objects.create(
                            em_from=from_email,
                            em_email=adm.email,
                            em_subject=subject,
                            em_doc=doc[:50],
                            em_center=center[:50],
                            em_login=adm.username,
                            em_send_email="true",
                        )
                    else:
                        rec.em_data_shipping = today
                        rec.em_login = adm.username
                        rec.save(update_fields=["em_data_shipping", "em_login"])
                except Exception:
                    logger.exception(
                        "[EMAIL ADMIN] Falha ao registrar envio to=%s center=%s doc=%s",
                        adm.email, center, doc
                    )

                sent += 1

    return f"{sent} e-mail(s) enviados para administradores (individualmente)."

def cleanup_job_executions(max_age=60*60*24*7):
    deleted = DjangoJobExecution.objects.delete_old_job_executions(max_age)
    return f"limpeza ok ({deleted})"

@_db_guard
@_job_log("Scheduler • Batimento")
def quick_healthcheck():
    logger.info("scheduler vivo (local): %s", timezone.localtime(timezone.now()))
    return "ok"

class Command(BaseCommand):
    help = "Executa o APScheduler como um processo dedicado."

    def _purge_existing_jobs(self, interval_flags):
        ids = [
            "anexos_atualizar_status_diario",
            "usuarios_atualizar_status",
            "psft_sync_estabelecimentos",
            "psft_sync_funcionarios",
            "emails_enviar_pendencias",
            "emails_enviar_analise_admin",
            "update_relation_user",
            "rsq_emp_refresh",
            "scheduler_batimento_30s",
            "scheduler_limpar_execucoes",
            "emails_enviar_analise_admin_interval",
            "emails_enviar_pendencias_interval",
            "anexos_atualizar_status_interval",
            "usuarios_atualizar_status_interval",
            "psft_sync_estabelecimentos_interval",
            "psft_sync_funcionarios_interval",
            "psft_sync_departamentos_interval",
            "psft_sync_hierarquias_interval",
            "update_relation_user_interval",
            "rsq_emp_refresh_interval",
        ]
        ids += [jid for jid, enabled in interval_flags.items() if enabled]
        seen = set()
        ids = [x for x in ids if not (x in seen or seen.add(x))]

        k = _advisory_key("scheduler:init:purge")
        with connection.cursor() as cur:
            cur.execute("SELECT pg_advisory_lock(%s::bigint)", [k])
            try:
                with transaction.atomic():
                    deleted, _ = DjangoJob.objects.filter(id__in=ids).delete()
                    if deleted:
                        logger.warning("[INIT] Removidos %s job(s) antigos do django_apscheduler_djangojob.", deleted)
            finally:
                cur.execute("SELECT pg_advisory_unlock(%s::bigint)", [k])

    def handle(self, *args, **options):
        k_singleton = _advisory_key("scheduler:singleton:startup")
        with connection.cursor() as cur:
            cur.execute("SELECT pg_try_advisory_lock(%s::bigint)", [k_singleton])
            got = cur.fetchone()[0]
        if not got:
            logger.warning("[INIT] Outra instância do scheduler já está ativa. Abortando este processo.")
            self.stdout.write(self.style.WARNING("Outra instância detectada; não inicializando."))
            return

        tz = ZoneInfo(settings.TIME_ZONE)
        cfg = getattr(settings, "SCHEDULER_CONFIG", {})
        scheduler = BlockingScheduler(
            timezone=tz,
            executors=cfg.get("executors"),
            job_defaults=cfg.get("job_defaults"),
        )

        scheduler.add_jobstore(DjangoJobStore(), "default")
        register_events(scheduler)

        def _listener(event):
            when = timezone.localtime(timezone.now())
            if event.code == EVENT_JOB_EXECUTED:
                logger.info("[APS] job=%s EXECUTADO em=%s agendado=%s",
                            event.job_id, when, event.scheduled_run_time)
            elif event.code == EVENT_JOB_ERROR:
                logger.exception("[APS] job=%s ERRO em=%s agendado=%s exc=%s",
                                 event.job_id, when, event.scheduled_run_time, event.exception)
            elif event.code == EVENT_JOB_MISSED:
                logger.warning("[APS] job=%s PERDIDO em=%s agendado=%s",
                               event.job_id, when, event.scheduled_run_time)
        scheduler.add_listener(_listener, EVENT_JOB_EXECUTED | EVENT_JOB_ERROR | EVENT_JOB_MISSED)


        interval_flags = {
            "anexos_atualizar_status_interval": ANEXOS_ATUALIZAR_STATUS_EVERY_MINUTES > 0, # Status anexos
            "usuarios_atualizar_status_interval": USUARIOS_ATUALIZAR_STATUS_EVERY_MINUTES > 0, # Status usuário
            
            
            "emails_enviar_pendencias_interval": EMAIL_JOB_EVERY_MINUTES > 0, # Email Usuário
            "psft_sync_estabelecimentos_interval": PSFT_ESTAB_JOB_EVERY_MINUTES > 0, # DB Estabelecimento
            
            "rsq_emp_refresh_interval": RSQ_JOB_EVERY_MINUTES > 0, # DB Relacionamento 
            "psft_sync_funcionarios_interval": PSFT_FUNC_JOB_EVERY_MINUTES > 0, # DB Funcionario
            
            "emails_enviar_analise_admin_interval": EMAIL_ADMIN_MINUTES > 0, # Email ADM

            "update_relation_user_interval": UPDATE_RELATION_USER_EVERY_MINUTES > 0, # Relação Estabelecimento x Usuário
        }

        self._purge_existing_jobs(interval_flags)

        scheduler.add_job(
            "scheduler_app.management.commands.runscheduler:update_status_attachment",
            trigger="cron", hour=7, minute=30,
            id="anexos_atualizar_status_diario",
            name="Anexos • Atualizar Status (diário)",
            replace_existing=True, max_instances=1
        )
        
        scheduler.add_job(
            "scheduler_app.management.commands.runscheduler:update_status_user",
            trigger="cron", hour=0, minute=10,
            id="usuarios_atualizar_status",
            name="Usuários • Atualizar Status (diário)",
            replace_existing=True, max_instances=1
        )
        scheduler.add_job(
            "scheduler_app.management.commands.runscheduler:update_relation_user",
            trigger="cron", hour=7, minute=0,  
            id="update_relation_user",
            name="RelationUser • Atualizar RCU (diário)",
            replace_existing=True, max_instances=100,
        )
        scheduler.add_job(
            "scheduler_app.management.commands.runscheduler:sync_psft_estabelecimentos",
            trigger="cron",
            day_of_week="mon,tue,wed,thu,fri", 
            hour=9,                     
            minute=20,
            id="psft_sync_estabelecimentos",
            name="PSFT • Estabelecimentos",
            replace_existing=True,
            max_instances=1,
        )
        if not interval_flags["emails_enviar_pendencias_interval"]:
            scheduler.add_job(
                "scheduler_app.management.commands.runscheduler:send_emails_to_users",
                trigger="cron", hour=0, minute=10,
                id="emails_enviar_pendencias",
                name="E-mails • Enviar Pendências por Escopo (diário)",
                replace_existing=True, max_instances=500
            )
        scheduler.add_job(
            "scheduler_app.management.commands.runscheduler:quick_healthcheck",
            trigger="interval", seconds=120,
            id="scheduler_batimento_30s",
            name="Scheduler • Batimento (30s)",
            replace_existing=True
        )
        scheduler.add_job(
            "scheduler_app.management.commands.runscheduler:cleanup_job_executions",
            trigger="cron", day_of_week="sun", hour=0, minute=1,
            id="scheduler_limpar_execucoes",
            name="Scheduler • Limpar Execuções antigas (semanal)",
            replace_existing=True
        )
        scheduler.add_job(
            "scheduler_app.management.commands.runscheduler:send_emails_to_admin",
            trigger="interval",
            minutes=1,
            id="emails_enviar_analise_admin_interval",
            name="E-mails • Administradores • 'Em Análise' (3 min)",
            replace_existing=True,
            max_instances=100,
        )
        scheduler.add_job(
            "scheduler_app.management.commands.runscheduler:sync_psft_funcionarios",
            trigger="cron",
            day_of_week="mon-fri", 
            hour=9,
            minute=30,
            id="psft_sync_funcionarios",
            name="PSFT • Funcionários",
            replace_existing=True,
            max_instances=100,
        )
        scheduler.add_job(
            "scheduler_app.management.commands.runscheduler:rsq_emp_refresh",
            trigger="cron",
            day_of_week="mon-fri",  
            hour=10,
            minute=0,
            id="rsq_emp_refresh",
            name="RSQ • Func->Estab (materializar) (seg a sex às 10h)",
            replace_existing=True,
            max_instances=1,
        )

        def _maybe_interval(job_path, job_id, job_name, minutes):
            if minutes and minutes > 0:
                scheduler.add_job(
                    job_path,
                    trigger="interval",
                    minutes=minutes,
                    id=f"{job_id}_interval",
                    name=f"{job_name} ({minutes} min)",
                    replace_existing=True,
                    max_instances=1,
                )
                logger.info("Intervalo habilitado para %s: %s min", job_id, minutes)

        _maybe_interval(
            "scheduler_app.management.commands.runscheduler:update_status_attachment",
            "anexos_atualizar_status", "Anexos • Atualizar Status",
            ANEXOS_ATUALIZAR_STATUS_EVERY_MINUTES, # Status Anexos
        )
        _maybe_interval(
            "scheduler_app.management.commands.runscheduler:update_status_user",
            "usuarios_atualizar_status", "Usuários • Atualizar Status",
            USUARIOS_ATUALIZAR_STATUS_EVERY_MINUTES, # Status Usuário
        )


        _maybe_interval(
            "scheduler_app.management.commands.runscheduler:send_emails_to_users",
            "emails_enviar_pendencias", "E-mails • Enviar Pendências por Escopo",
            EMAIL_JOB_EVERY_MINUTES, # Email Usuários
        )
        
        
        _maybe_interval(
            "scheduler_app.management.commands.runscheduler:sync_psft_estabelecimentos",
            "psft_sync_estabelecimentos", "PSFT • Estabelecimentos",
            PSFT_ESTAB_JOB_EVERY_MINUTES, # DB Estabelecimento
        )
        
        _maybe_interval(
            "scheduler_app.management.commands.runscheduler:send_emails_to_admin",
            "emails_enviar_analise_admin", "E-mails • Administradores • Aviso 'Em Análise",
            EMAIL_ADMIN_MINUTES, # Email ADM
        )
        _maybe_interval(
            "scheduler_app.management.commands.runscheduler:rsq_emp_refresh",
            "rsq_emp_refresh", "RSQ • Func->Estab (materializar)",
            RSQ_JOB_EVERY_MINUTES, # DB Relacionamento 
        )
        _maybe_interval(
            "scheduler_app.management.commands.runscheduler:sync_psft_funcionarios",
            "psft_sync_funcionarios", "PSFT • Funcionários",
            PSFT_FUNC_JOB_EVERY_MINUTES, # DB Funcionario
        )
        
        _maybe_interval(
            "scheduler_app.management.commands.runscheduler:update_relation_user",
            "update_relation_user", "RelationUser • Atualizar RCU",
            UPDATE_RELATION_USER_EVERY_MINUTES, # Relação Estabelecimento x Usuário
        )
        
        try:
            jobs = scheduler.get_jobs()
        except Exception:
            jobs = []
        for job in jobs:
            nx = getattr(job, "next_run_time", None) or getattr(job, "next_fire_time", None)
            try:
                nx_local = timezone.localtime(nx) if (nx and getattr(nx, "tzinfo", None)) else nx
            except Exception:
                nx_local = nx
            logger.info("Agendado: %s (%s) -> próximo disparo: %s",
                        job.id, getattr(job, "name", ""), nx_local)

        def _shutdown(signum, frame):
            logger.info("Sinal %s recebido. Encerrando APScheduler...", signum)
            try:
                scheduler.shutdown(wait=False)
            except Exception:
                pass

        signal.signal(signal.SIGINT, _shutdown)
        signal.signal(signal.SIGTERM, _shutdown)

        self.stdout.write(self.style.SUCCESS("APScheduler inicializando..."))
        try:
            scheduler.start()
        except (KeyboardInterrupt, SystemExit):
            pass
        finally:
            with connection.cursor() as cur:
                cur.execute("SELECT pg_advisory_unlock(%s::bigint)", [k_singleton])
            self.stdout.write(self.style.WARNING("APScheduler finalizado."))
