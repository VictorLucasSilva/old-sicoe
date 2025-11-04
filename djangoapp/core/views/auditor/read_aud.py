from django.shortcuts import render, redirect
from datetime import datetime, date, time, timedelta
from django.core.paginator import Paginator
from django.http import JsonResponse
from django.contrib import messages
from datetime import datetime as _dt, date as _date
from django.db.models import Q, Max, OuterRef, Subquery, F, Case, When, Value, IntegerField
from django.utils import timezone
from django.utils.dateformat import format as dj_format
from django.utils.safestring import mark_safe
from core.models import Establishment, Attachment, NumDocsEstab, RelationCenterUser, Document, RelationCenterDoc, Audit, Email
from core.decorators import only_auditor
from collections import defaultdict
import json

ALLOWED_SITUATIONS = ["Regular", "Vencido", "A Vencer", "Invalidado"]

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


@only_auditor
def attachment_list(request):
    user = request.user
    if not user.is_authenticated:
        return redirect('login')
    if getattr(user, 'u_status', 'Inativo') != 'Ativo' and not user.is_superuser:
        messages.error(request, "Usuário inativo.")
        return redirect('login')

    ALLOWED_SITUATIONS = ["Regular", "Vencido", "A Vencer", "Invalidado", "Em Análise"]

    base_qs = Attachment.objects.filter(att_situation__in=ALLOWED_SITUATIONS)

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

    attachments = attachments.filter(q)

    status_rank = Case(
        When(att_situation__iexact="Vencido",    then=Value(0)),
        When(att_situation__iexact="Invalidado", then=Value(1)),
        When(att_situation__iexact="A Vencer",   then=Value(2)),
        When(att_situation__iexact="Regular",    then=Value(4)),
        When(att_situation__iexact="Em Análise",    then=Value(3)),
        default=Value(4),
        output_field=IntegerField(),
    )

    attachments = (
        attachments
        .annotate(_status_rank=status_rank)
        .order_by('_status_rank', 'att_center', 'att_doc','-att_data_inserted', '-att_id')
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
                'file_url': a.att_file.url if getattr(a, 'att_file', None) else '',
                'attached_by': a.att_attached_by or '',
                'checked_by': a.att_checked_by or '',
                'data_conference': fmt_dt(a.att_data_conference),
                'unit_info': unit_info,
                'justification': a.att_just or '',
            })

        return JsonResponse({
            'results': results,
            'count': paginator.count,
            'start_index': page_obj.start_index(),
            'end_index': page_obj.end_index(),
            'num_pages': paginator.num_pages,
            'current_page': page_obj.number,
        })

    return render(request, 'main/auditor/attachment_list.html', {
        'page_obj': page_obj
    })


def _is_auditor(user):
    if not user.is_authenticated:
        return False
    if getattr(user, "u_status", "Inativo") != "Ativo":
        return False
    if user.is_superuser:
        return True
    return user.groups.filter(name="Auditor").exists()


@only_auditor
def attachment_history(request, document, region, center=None):
    base_q = Q(att_doc=document, att_region=region)
    if center:
        base_q &= Q(att_center=center)

    f_state     = _get(request.GET.get("state"))
    f_center    = _get(request.GET.get("center"))
    f_inserted  = _get(request.GET.get("data_inserted"))
    f_expire    = _get(request.GET.get("data_expire"))
    f_situation = _get(request.GET.get("situation"))

    state_display = f_state or (
        Attachment.objects.filter(base_q)
        .values_list("att_state", flat=True)
        .first() or ""
    )

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

    attachments_qs = Attachment.objects.filter(base_q)
    if q.children:
        attachments_qs = attachments_qs.filter(q)

    attachments = attachments_qs.order_by("-att_data_inserted", "att_center", "att_doc")

    paginator   = Paginator(attachments, 10)
    page_number = request.GET.get("page")
    page_obj    = paginator.get_page(page_number)

    if request.headers.get("x-requested-with") == "XMLHttpRequest":
        def fmt_dt(dt):
            if not dt:
                return ""
            try:
                dt_local = timezone.localtime(dt)
            except Exception:
                dt_local = dt
            return dt_local.strftime("%d/%m/%Y %H:%M")

        results = []
        for a in page_obj:
            units = NumDocsEstab.objects.filter(
                ndest_fk_establishment__est_center=a.att_center
            )
            unit_info = [{
                "ndest_units": u.ndest_units,
                "ndest_cnpj": u.ndest_cnpj,
                "ndest_nire": u.ndest_nire,
                "ndest_reg_state": u.ndest_reg_state,
                "ndest_reg_city": u.ndest_reg_city,
            } for u in units]

            results.append({
                "id": a.att_id,
                "document": a.att_doc,
                "region": a.att_region,
                "state": a.att_state,
                "center": a.att_center,
                "data_inserted": fmt_dt(a.att_data_inserted),
                "data_expire": a.att_data_expire.strftime("%d/%m/%Y") if a.att_data_expire else "",
                "situation": a.att_situation or "",
                "conference": a.att_checked_by or "",
                "file_url": a.att_file.url if getattr(a, "att_file", None) else "",
                "attached_by": a.att_attached_by or "",
                "checked_by": a.att_checked_by or "",
                "data_conference": fmt_dt(a.att_data_conference),
                "unit_info": unit_info,
                "justification": a.att_just or "",
            })

        return JsonResponse({
            "results": results,
            "count": paginator.count,
            "start_index": page_obj.start_index(),
            "end_index": page_obj.end_index(),
            "num_pages": paginator.num_pages,
            "current_page": page_obj.number,
        })

    return render(request, "main/auditor/attachment_history.html", {
        "page_obj": page_obj,
        "document": document,
        "region": region,
        "center": center or "",
        "state": state_display,
    }) 
  
    
@only_auditor
def attachment_history_all(request):
    attachments = (
        Attachment.objects
        .filter(att_situation__in=ALLOWED_SITUATIONS)
        .order_by('-att_data_inserted', 'att_center', 'att_doc')
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
        attachments = attachments.filter(q)

    paginator   = Paginator(attachments, 10)
    page_number = request.GET.get('page')
    page_obj    = paginator.get_page(page_number)

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
            item = {
                'id': a.att_id,
                'document': a.att_doc,
                'region': a.att_region,
                'state': a.att_state,
                'center': a.att_center,
                'data_inserted': fmt_dt(a.att_data_inserted),
                'data_expire': a.att_data_expire.strftime('%d/%m/%Y') if a.att_data_expire else '',
                'situation': a.att_situation or '',
                'conference': a.att_checked_by or '',
                'file_url': a.att_file.url if getattr(a, 'att_file', None) else '',
                'attached_by': a.att_attached_by or '',
                'checked_by': a.att_checked_by or '',
                'data_conference': fmt_dt(a.att_data_conference),
                'justification': a.att_just or '',
            }

            try:
                units = NumDocsEstab.objects.filter(
                    ndest_fk_establishment__est_center=a.att_center
                )
                item['unit_info'] = [{
                    'ndest_units': u.ndest_units,
                    'ndest_cnpj': u.ndest_cnpj,
                    'ndest_nire': u.ndest_nire,
                    'ndest_reg_state': u.ndest_reg_state,
                    'ndest_reg_city': u.ndest_reg_city,
                } for u in units]
            except Exception:
                item['unit_info'] = []

            results.append(item)

        return JsonResponse({
            'results': results,
            'count': paginator.count,
            'start_index': page_obj.start_index(),
            'end_index': page_obj.end_index(),
            'num_pages': paginator.num_pages,
            'current_page': page_obj.number,
        })

    return render(request, 'main/auditor/attachment_history_all.html', {
        'page_obj': page_obj,
        'url_history_template': '/auditor/attachment/history/__doc__/__region__/__center__/'
    })   
  
    
@only_auditor
def audit_list(request):

    def _fmt_dt(dt):
        if not dt:
            return ''
        try:
            dt = timezone.localtime(dt)
        except Exception:
            pass
        return dt.strftime('%d/%m/%Y %H:%M')

    audits = Audit.objects.all()

    f_cod         = _get(request.GET.get('cod'))
    f_login       = _get(request.GET.get('login'))
    f_profile     = _get(request.GET.get('profile'))
    f_action      = _get(request.GET.get('action'))
    f_object      = _get(request.GET.get('object'))
    f_description = _get(request.GET.get('description'))
    f_inserted    = _get(request.GET.get('data_inserted')) 

    q = Q()
    if f_cod:
        try:
            q &= Q(aud_id=int(f_cod))
        except ValueError:
            q &= Q(pk__in=[]) 
    if f_login:
        q &= Q(aud_login__icontains=f_login)
    if f_profile:
        q &= Q(aud_profile__icontains=f_profile)
    if f_action:
        q &= Q(aud_action__icontains=f_action)
    if f_object:
        q &= Q(aud_obj_modified__icontains=f_object)
    if f_description:
        q &= Q(aud_description__icontains=f_description)

    other_filters_active = any([f_cod, f_login, f_profile, f_action, f_object, f_description])
    if f_inserted and not other_filters_active:
        d = _parse_iso_date(f_inserted)
        if d:
            start, end = _day_bounds_local(d)
            q &= Q(aud_data_inserted__gte=start, aud_data_inserted__lt=end)

    audits = audits.filter(q).order_by('-aud_data_inserted', '-aud_id')
    paginator   = Paginator(audits, 10)
    page_number = request.GET.get('page')
    page_obj    = paginator.get_page(page_number)
    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        results = [{
            'aud_id':            e.aud_id,
            'aud_login':         e.aud_login,
            'aud_profile':       e.aud_profile,
            'aud_action':        e.aud_action,
            'aud_obj_modified':  e.aud_obj_modified,
            'aud_description':   e.aud_description,
            'aud_data_inserted': _fmt_dt(e.aud_data_inserted),
        } for e in page_obj]

        return JsonResponse({
            'results': results,
            'count': paginator.count,
            'start_index': page_obj.start_index(),
            'end_index': page_obj.end_index(),
            'num_pages': paginator.num_pages,
            'current_page': page_obj.number,
        })
    context = {
        'page_obj': page_obj,
        'audit_l': page_obj,
    }
    return render(request, 'main/auditor/audit_list.html', context)


@only_auditor
def email_list(request):
    def _get(v):
        return (v or '').strip()

    def _parse_date_any(s: str):
        if not s:
            return None
        for fmt in ('%Y-%m-%d', '%d/%m/%Y'):
            try:
                return _dt.strptime(s, fmt).date()
            except ValueError:
                continue
        return None

    def _fmt_date(d: _date):
        if not d:
            return ''
        return d.strftime('%d/%m/%Y')

    emails = Email.objects.all()

    f_cod     = _get(request.GET.get('cod'))
    f_subject = _get(request.GET.get('subject'))
    f_doc     = _get(request.GET.get('doc'))
    f_email   = _get(request.GET.get('email'))
    f_center  = _get(request.GET.get('center'))
    f_ship    = _get(request.GET.get('data_shipping'))

    q = Q()
    if f_cod and f_cod.isdigit():
        q &= Q(em_id=int(f_cod))
    if f_subject:
        q &= Q(em_subject__icontains=f_subject)
    if f_doc:
        q &= Q(em_doc__icontains=f_doc)
    if f_email:
        q &= Q(em_email__icontains=f_email)
    if f_center:
        q &= Q(em_center__icontains=f_center)

    other_filters_active = any([f_cod, f_subject, f_doc, f_email, f_center])
    if f_ship and not other_filters_active:
        d = _parse_date_any(f_ship)
        if d:
            q &= Q(em_data_shipping=d)

    emails = emails.filter(q).order_by('-em_data_shipping', '-em_id')

    paginator   = Paginator(emails, 10)
    page_number = request.GET.get('page') or 1
    page_obj    = paginator.get_page(page_number)

    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        results = [{
            'em_id':            e.em_id,
            'em_subject':       e.em_subject,
            'em_doc':           e.em_doc,
            'em_email':         e.em_email,
            'em_center':        e.em_center,
            'em_data_shipping': _fmt_date(e.em_data_shipping),
        } for e in page_obj]

        start_idx = page_obj.start_index() if paginator.count else 0
        end_idx   = page_obj.end_index() if paginator.count else 0

        return JsonResponse({
            'results': results,
            'count': paginator.count,
            'start_index': start_idx,
            'end_index': end_idx,
            'num_pages': paginator.num_pages,
            'current_page': page_obj.number,
        })

    context = {
        'page_obj': page_obj,
        'email_l': page_obj,
    }
    return render(request, 'main/auditor/email_list.html', context)


@only_auditor
def overview(request):
    def dt_fmt(dt):
        if not dt:
            return ""
        try:
            dt = timezone.localtime(dt)
        except Exception:
            pass
        return dt.strftime("%d/%m/%Y %H:%M")

    NEG = ["Vencido", "Invalidado", "A Vencer"]
    POS = ["Em Análise", "Regular"]

    latest = (
        Attachment.objects
        .values('att_doc', 'att_center')
        .annotate(latest_date=Max('att_data_inserted'))
    )

    if latest:
        neg_q = Q()
        pos_q = Q()
        for item in latest:
            base = dict(att_doc=item['att_doc'],
                        att_center=item['att_center'],
                        att_data_inserted=item['latest_date'])
            neg_q |= Q(**base, att_situation__in=NEG)
            pos_q |= Q(**base, att_situation__in=POS)

        latest_attachments = Attachment.objects.filter(neg_q).order_by('att_center', '-att_data_inserted')
        latest_attachments_posi = Attachment.objects.filter(pos_q).order_by('att_center', '-att_data_inserted')
    else:
        latest_attachments = Attachment.objects.none()
        latest_attachments_posi = Attachment.objects.none()
        
    centers_names = list(latest_attachments.values_list('att_center', flat=True).distinct())
    centers = Establishment.objects.filter(est_center__in=centers_names)
    count_expire  = latest_attachments.filter(att_situation='Vencido').count()
    count_invalid = latest_attachments.filter(att_situation='Invalidado').count()
    count_avencer = latest_attachments.filter(att_situation='A Vencer').count()
    count_analise = latest_attachments_posi.filter(att_situation='Em Análise').count()
    count_regular = latest_attachments_posi.filter(att_situation='Regular').count()

    tt_situation = count_expire + count_invalid + count_avencer + count_analise
    total_considerado = tt_situation + count_regular

    if total_considerado > 0:
        regularity_pct = round((count_regular / total_considerado) * 100, 2)
        irregular_pct = round((tt_situation / total_considerado) * 100, 2)
    else:
        regularity_pct = 0.0
        irregular_pct = 0.0

    regularity = f"{regularity_pct}%"

    neg_centers_set = set(latest_attachments.values_list('att_center', flat=True))
    center_status = {c.est_center: ("warning" if c.est_center in neg_centers_set else "success") for c in centers}

    region_centers = {}
    for center in centers:
        reg = (center.est_region or "-").upper()
        name = center.est_center
        region_centers.setdefault(reg, []).append({
            "name": name,
            "status": center_status.get(name, "secondary")
        })

    relation_users = RelationCenterUser.objects.select_related('rcu_fk_user')

    centers_data = {}
    for center in centers:
        name   = center.est_center
        manage = center.est_manage or "-"
        region = center.est_region or "-"
        grouped = {}
        for attach in latest_attachments.filter(att_center=name).order_by('att_doc', '-att_data_inserted'):
            doc = attach.att_doc
            if doc not in grouped:
                grouped[doc] = {
                    "document": doc,
                    "data_inserted": dt_fmt(attach.att_data_inserted),
                }
        invalidado_info = list(grouped.values())
        users_added = set()
        user_list = []

        def add_user(u, profile_label):
            if not u or u.username in users_added:
                return
            users_added.add(u.username)
            user_list.append({
                "name": (u.get_full_name() or u.first_name or u.username),
                "login": u.username,
                "email": u.email or "",
                "profile": profile_label,
            })

        for rel in relation_users.filter(rcu_region=region):
            u = rel.rcu_fk_user
            if u.groups.filter(name='Gerente Regional').exists():
                add_user(u, 'Gerente Regional')

        for rel in relation_users.filter(rcu_state=center.est_state):
            u = rel.rcu_fk_user
            if u.groups.filter(name='Gerente Regional').exists():
                add_user(u, 'Gerente Regional')

        for rel in relation_users.filter(rcu_center=name):
            u = rel.rcu_fk_user
            if u.groups.filter(name='Usuário').exists():
                add_user(u, 'Usuário')

        centers_data[name] = {
            "invalidado": invalidado_info,
            "users": user_list,
            "manage": manage,
            "region": region,
        }

    invalid_by_document = defaultdict(list)
    seen_pairs = set()
    for attach in latest_attachments.order_by('-att_data_inserted'):
        key = (attach.att_doc, attach.att_center)
        if key in seen_pairs:
            continue
        seen_pairs.add(key)
        invalid_by_document[attach.att_doc].append({
            "center": attach.att_center,
            "data_inserted": dt_fmt(attach.att_data_inserted),
        })

    return render(request, 'main/auditor/index.html', {
        'region_centers_json':       mark_safe(json.dumps(region_centers)),
        'centers_data_json':         mark_safe(json.dumps(centers_data)),
        'invalid_by_document_json':  mark_safe(json.dumps(invalid_by_document)),
        'count_expire': count_expire,
        'count_invalid': count_invalid,
        'count_avencer': count_avencer,
        'count_analise': count_analise,
        'count_regular': count_regular,
        'tt_situation': tt_situation,
        'regularity': regularity,
        'regularity_pct': regularity_pct,
        'irregular_pct': irregular_pct,
        'total_considerado': total_considerado,
    })
    