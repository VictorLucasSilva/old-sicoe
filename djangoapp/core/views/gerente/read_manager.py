from django.shortcuts import render, redirect
from datetime import datetime, date, time, timedelta
from django.core.paginator import Paginator
from django.http import JsonResponse
from django.contrib import messages
from datetime import datetime as _dt, date as _date
from django.db.models import Q, Exists, Max, OuterRef, Subquery, F, Case, When, Value, IntegerField
from django.utils import timezone
from django.utils.dateformat import format as dj_format
from django.utils.safestring import mark_safe
from core.models import Establishment, Attachment, NumDocsEstab, RelationCenterUser, Document, RelationCenterDoc, Audit, Email
from core.decorators import only_gerente_regional
from collections import defaultdict
from django.urls import reverse
import json

def _get(param):
    return (param or '').strip()[:100]

def _parse_iso_date(value: str):
    try:
        return date.fromisoformat(value)
    except Exception:
        return None

def _day_bounds_local(d: date):
    tz = timezone.get_current_timezone()
    start_naive = datetime.combine(d, time.min)
    start = timezone.make_aware(start_naive, tz)
    end = start + timedelta(days=1)
    return start, end

@only_gerente_regional
def attachment_list(request):
    user = request.user
    if not user.is_authenticated:
        return redirect('login')

    active_rcu_exists = (
        RelationCenterUser.objects
        .filter(rcu_fk_user=user, rcu_fk_estab__est_center=OuterRef("att_center"))
        .exclude(rcu_active=False)
    )

    ALLOWED_SITUATIONS = ["Regular", "Vencido", "A Vencer", "Invalidado", "Em Análise"]

    base_qs = (
        Attachment.objects
        .filter(att_situation__in=ALLOWED_SITUATIONS)
        .annotate(_has_active_rcu=Exists(active_rcu_exists))
        .filter(_has_active_rcu=True)
    )

    latest_sub = (
        Attachment.objects
        .filter(att_doc=OuterRef('att_doc'), att_center=OuterRef('att_center'))
        .values('att_doc', 'att_center')
        .annotate(max_dt=Max('att_data_inserted'))
        .values('max_dt')[:1]
    )

    attachments = (
        base_qs
        .annotate(latest_date=Subquery(latest_sub))
        .filter(att_data_inserted=F('latest_date'))
    )

    f_document  = _get(request.GET.get('document'))
    f_region    = _get(request.GET.get('region'))
    f_state     = _get(request.GET.get('state'))
    f_center    = _get(request.GET.get('center'))
    f_inserted  = _get(request.GET.get('data_inserted'))
    f_expire    = _get(request.GET.get('data_expire'))
    f_situation = _get(request.GET.get('situation'))

    q = Q()
    if f_document:
        q &= Q(att_doc__icontains=f_document)
    if f_region:
        q &= Q(att_region__icontains=f_region)
    if f_state:
        q &= Q(att_state__icontains=f_state)
    if f_center:
        q &= Q(att_center__icontains=f_center)
    if f_situation:
        q &= Q(att_situation__icontains=f_situation)

    other_filters_active = any([f_document, f_region, f_state, f_center, f_situation, f_expire])
    if f_inserted and not other_filters_active:
        d = _parse_iso_date(f_inserted)
        if d:
            start, end = _day_bounds_local(d)
            q &= Q(att_data_inserted__gte=start, att_data_inserted__lt=end)

    if f_expire:
        d = _parse_iso_date(f_expire)
        if d:
            q &= Q(att_data_expire=d)

    if q.children:
        attachments = attachments.filter(q)

    status_rank = Case(
        When(att_situation__iexact="Vencido",      then=Value(0)),
        When(att_situation__iexact="A Vencer",     then=Value(1)),
        When(att_situation__iexact="Invalidado",   then=Value(2)),
        When(att_situation__iexact="Em Análise",   then=Value(3)),
        When(att_situation__iexact="Regular",      then=Value(4)),
        default=Value(5),
        output_field=IntegerField(),
    )

    attachments = (
        attachments
        .annotate(_status_rank=status_rank)
        .order_by('_status_rank', '-att_data_inserted', 'att_center')
    )

    paginator   = Paginator(attachments, 10)
    page_number = request.GET.get('page')
    page_obj    = paginator.get_page(page_number)

    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        def fmt_dt(dt):
            if not dt:
                return ''
            try:
                dt = timezone.localtime(dt)
            except Exception:
                pass
            return dt.strftime('%d/%m/%Y %H:%M')

        results = []
        for a in page_obj:
            units = NumDocsEstab.objects.filter(
                ndest_fk_establishment__est_center=a.att_center
            )
            unit_info = [{
                'ndest_units': u.ndest_units,
                'ndest_cnpj': u.ndest_cnpj,
                'ndest_nire': u.ndest_nire,
                'ndest_reg_state': u.ndest_reg_state,
                'ndest_reg_city': u.ndest_reg_city,
            } for u in units]

            results.append({
                'id': a.att_id,
                'document': a.att_doc,
                'region': a.att_region,
                'state': a.att_state,
                'center': a.att_center,
                'data_inserted': fmt_dt(a.att_data_inserted),
                'data_expire': a.att_data_expire.strftime('%d/%m/%Y') if a.att_data_expire else '',
                'situation': a.att_situation or '',
                'file_url': a.att_file.url if getattr(a, "att_file", None) else '',
                'attached_by': a.att_attached_by or '',
                'checked_by': a.att_checked_by or '',
                'data_conference': fmt_dt(a.att_data_conference),
                'unit_info': unit_info,
                'justification': a.att_just or '',
            })

        return JsonResponse({
            'results': results,
            'count': paginator.count,
            'start_index': page_obj.start_index() if paginator.count else 0,
            'end_index': page_obj.end_index() if paginator.count else 0,
            'num_pages': paginator.num_pages or 1,
            'current_page': page_obj.number if paginator.count else 1,
        })

    return render(request, 'main/gerente/attachment_list.html', {
        'page_obj': page_obj
    })

    
@only_gerente_regional
def attachment_history(request, document, region, center=None):
    if not request.user.is_authenticated:
        return redirect('login')

    base_q = Q(att_doc=document, att_region=region)
    if center:
        base_q &= Q(att_center=center)

    active_rcu_exists = (
        RelationCenterUser.objects
        .filter(rcu_fk_user=request.user, rcu_fk_estab__est_center=OuterRef("att_center"))
        .exclude(rcu_active=False) 
    )

    attachments_qs = (
        Attachment.objects
        .filter(base_q)
        .annotate(_has_active_rcu=Exists(active_rcu_exists))
        .filter(_has_active_rcu=True)
    )

    f_state     = _get(request.GET.get('state'))
    f_center    = _get(request.GET.get('center'))
    f_inserted  = _get(request.GET.get('data_inserted'))
    f_expire    = _get(request.GET.get('data_expire'))
    f_situation = _get(request.GET.get('situation'))

    q = Q()
    if f_state:
        q &= Q(att_state__icontains=f_state)
    if f_center:
        q &= Q(att_center__icontains=f_center)
    if f_situation:
        q &= Q(att_situation__icontains=f_situation)
    if f_inserted:
        d = _parse_iso_date(f_inserted)
        if d:
            start, end = _day_bounds_local(d)
            q &= Q(att_data_inserted__gte=start, att_data_inserted__lt=end)
    if f_expire:
        d = _parse_iso_date(f_expire)
        if d:
            q &= Q(att_data_expire=d)

    if q.children:
        attachments_qs = attachments_qs.filter(q)

    state_display = f_state or (attachments_qs.values_list('att_state', flat=True).first() or '')

    attachments = attachments_qs.order_by('-att_data_inserted', 'att_center', 'att_doc')
    paginator   = Paginator(attachments, 7)
    page_obj    = paginator.get_page(request.GET.get('page'))

    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        def fmt_dt(dt):
            if not dt:
                return ''
            try:
                dt_local = timezone.localtime(dt)
            except Exception:
                dt_local = dt
            return dt_local.strftime('%d/%m/%Y %H:%M')

        results = []
        for a in page_obj:
            units = NumDocsEstab.objects.filter(
                ndest_fk_establishment__est_center=a.att_center
            )
            unit_info = [{
                'ndest_units': u.ndest_units,
                'ndest_cnpj': u.ndest_cnpj,
                'ndest_nire': u.ndest_nire,
                'ndest_reg_state': u.ndest_reg_state,
                'ndest_reg_city': u.ndest_reg_city,
            } for u in units]

            results.append({
                'id': a.att_id,
                'document': a.att_doc,
                'region': a.att_region,
                'state': a.att_state,
                'center': a.att_center,
                'data_inserted': fmt_dt(a.att_data_inserted),
                'data_expire': a.att_data_expire.strftime('%d/%m/%Y') if a.att_data_expire else '',
                'situation': a.att_situation or '',
                'conference': a.att_checked_by or '',
                'file_url': a.att_file.url if getattr(a, "att_file", None) else '',
                'attached_by': a.att_attached_by or '',
                'checked_by': a.att_checked_by or '',
                'data_conference': fmt_dt(a.att_data_conference),
                'unit_info': unit_info,
                'justification': a.att_just or '',
            })

        return JsonResponse({
            'results': results,
            'count': paginator.count,
            'start_index': page_obj.start_index() if paginator.count else 0,
            'end_index': page_obj.end_index() if paginator.count else 0,
            'num_pages': paginator.num_pages or 1,
            'current_page': page_obj.number if paginator.count else 1,
        })

    return render(request, 'main/gerente/attachment_history.html', {
        'page_obj': page_obj,
        'document': document,
        'region': region,
        'center': center or '',
        'state': state_display,
    })
    
    
PENDING_STATUSES = ("Vencido", "Invalidado", "A Vencer")
ORDERED_SEVERITY = {"Vencido": 3, "Invalidado": 2, "A Vencer": 1}

STATUS_TO_BTN = {
    "Vencido": "danger",
    "Invalidado": "invalidado",
    "A Vencer": "warning",
}

REGIONS_ORDER = ["NORTE", "NORDESTE", "CENTRO-OESTE", "SUDESTE", "SUL"]

def _estab_ids_allowed_for_user(user):
    return list(
        RelationCenterUser.objects
        .filter(rcu_fk_user=user)
        .exclude(rcu_active=False)            
        .exclude(rcu_fk_estab__isnull=True)
        .values_list("rcu_fk_estab_id", flat=True)
        .distinct()
    )

def _centers_allowed_names_by_ids(est_ids):
    est_qs = Establishment.objects.filter(pk__in=est_ids)
    est_by_center = {
        e.est_center: {
            "region": (e.est_region or "-").upper(),
            "manage": e.est_manage or "-",
        }
        for e in est_qs
        if (e.est_center or "").strip() not in ("", "-")
    }
    return est_by_center 

@only_gerente_regional
def overview(request):
    if not request.user.is_authenticated:
        return redirect("login")

    allowed_ids = _estab_ids_allowed_for_user(request.user)

    est_by_center = _centers_allowed_names_by_ids(allowed_ids)
    centers_allowed = list(est_by_center.keys())

    regions_with_access = {
        v["region"] for v in est_by_center.values()
        if v.get("region") in REGIONS_ORDER
    }

    if not est_by_center:
        context = {
            "regularity": "0%",
            "count_expire": 0,
            "count_invalid": 0,
            "count_avencer": 0,
            "count_analise": 0,
            "count_regular": 0,
            "region_centers_json": json.dumps({r: [] for r in REGIONS_ORDER}, ensure_ascii=False),
            "centers_data_json": json.dumps({}, ensure_ascii=False),
            "invalid_by_document_json": json.dumps({}, ensure_ascii=False),
            "regions_with_access_json": json.dumps([], ensure_ascii=False),
        }
        return render(request, "main/gerente/index.html", context)

    base_qs = Attachment.objects.filter(att_center__in=centers_allowed)

    latest_sub = (
        Attachment.objects
        .filter(att_doc=OuterRef("att_doc"), att_center=OuterRef("att_center"))
        .values("att_doc", "att_center")
        .annotate(max_dt=Max("att_data_inserted"))
        .values("max_dt")[:1]
    )

    latest = (
        base_qs
        .annotate(_latest=Subquery(latest_sub))
        .filter(att_data_inserted=F("_latest"))
    )

    latest_info = {
        (row["att_center"], row["att_doc"]): {
            "situation": row["att_situation"],
            "justification": (row.get("att_just") or "").strip(),
        }
        for row in latest.values("att_center", "att_doc", "att_situation", "att_just")
    }

    count_expire   = latest.filter(att_situation="Vencido").count()
    count_invalid  = latest.filter(att_situation="Invalidado").count()
    count_avencer  = latest.filter(att_situation="A Vencer").count()
    count_analise  = latest.filter(att_situation="Em Análise").count()
    count_regular  = latest.filter(att_situation="Regular").count()

    total_for_regularity = (
        count_expire + count_invalid + count_avencer + count_analise + count_regular
    ) or 1
    regularity_pct = round((count_regular * 100) / total_for_regularity)
    regularity = f"{regularity_pct}%"

    pending_qs = (
        latest.filter(att_situation__in=PENDING_STATUSES)
              .values("att_center", "att_doc", "att_situation")
    )
    pend_docs_by_center = defaultdict(set)
    worst_status_by_center = {}

    for row in pending_qs:
        c = row["att_center"]
        d = row["att_doc"]
        st = row["att_situation"]
        pend_docs_by_center[c].add(d)
        prev = worst_status_by_center.get(c)
        if (prev is None) or (ORDERED_SEVERITY[st] > ORDERED_SEVERITY[prev]):
            worst_status_by_center[c] = st

    rcu_users = (
        RelationCenterUser.objects
        .filter(rcu_fk_estab_id__in=allowed_ids)
        .exclude(rcu_active=False)
        .select_related("rcu_fk_user", "rcu_fk_estab")
    )
    users_by_center = defaultdict(list)
    for r in rcu_users:
        u = r.rcu_fk_user
        name = (u.get_full_name() or u.username or "-").strip()
        email = u.email or "-"
        groups = list(u.groups.values_list("name", flat=True))
        profile = ", ".join(groups) if groups else ("Administrador" if getattr(u, "is_superuser", False) else "Usuário")
        center_name = (getattr(r.rcu_fk_estab, "est_center", None) or "-").strip()
        if center_name in est_by_center: 
            users_by_center[center_name].append({"name": name, "email": email, "profile": profile})

    region_centers = {r: [] for r in REGIONS_ORDER}
    centers_data = {}

    for center, docs in pend_docs_by_center.items():
        if center not in est_by_center:
            continue

        region = est_by_center[center]["region"]
        manage = est_by_center[center]["manage"]

        worst = worst_status_by_center.get(center)
        btn_class = STATUS_TO_BTN.get(worst, "secondary")

        if region in region_centers:
            region_centers[region].append({"name": center, "status": btn_class})

        invalidado_list = []
        for d in sorted(docs):
            meta = latest_info.get((center, d), {})
            invalidado_list.append({
                "document": d,
                "situation": meta.get("situation"),
                "justification": meta.get("justification", ""),
            })

        centers_data[center] = {
            "manage": manage,
            "region": region,
            "center": center,
            "invalidado": invalidado_list,
            "users": users_by_center.get(center, []),
        }

    invalid_by_document = defaultdict(list)
    for c, docs in pend_docs_by_center.items():
        if c not in est_by_center:
            continue
        for d in docs:
            invalid_by_document[d].append(c)

    context = {
        "regularity": regularity,
        "count_expire": count_expire,
        "count_invalid": count_invalid,
        "count_avencer": count_avencer,
        "count_analise": count_analise,
        "count_regular": count_regular,
        "region_centers_json": json.dumps(region_centers, ensure_ascii=False),
        "centers_data_json": json.dumps(centers_data, ensure_ascii=False),
        "invalid_by_document_json": json.dumps(invalid_by_document, ensure_ascii=False),
        "regions_with_access_json": json.dumps(sorted(list(regions_with_access)), ensure_ascii=False),
    }
    return render(request, "main/gerente/index.html", context)