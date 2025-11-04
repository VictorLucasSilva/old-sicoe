from django.shortcuts import render, redirect
from datetime import datetime, date, time, timedelta
from django.core.paginator import Paginator
from django.http import JsonResponse
from django.contrib import messages
from django.db.models.functions import Lower
from datetime import datetime as _dt, date as _date
from django.db.models import Q, Max, OuterRef, Subquery, F, Case, When, Value, IntegerField
from django.utils import timezone
from django.utils.dateformat import format as dj_format
from django.utils.safestring import mark_safe
from core.models import Establishment, Attachment, NumDocsEstab, RelationCenterUser, Document, RelationCenterDoc, Audit, Email, User
from core.decorators import only_administrador
from collections import defaultdict
from django.db.models.functions import Concat
from django.db.models import Value, Min
from django.db.models.functions import Lower, Coalesce
from django.contrib.auth import get_user_model
from django.urls import reverse
import json

@only_administrador
def home(request):
    establishments = Establishment.objects.all().order_by('est_id')
    return render(request, 'main/administrador/index.html', {
        'establishment_l': establishments,
    })

@only_administrador
def establishment_list(request):
    establishments = Establishment.objects.all().order_by('est_region', 'est_state', 'est_city')

    filters = Q()
    if request.GET.get('region'):
        filters &= Q(est_region__icontains=request.GET['region'])
    if request.GET.get('state'):
        filters &= Q(est_state__icontains=request.GET['state'])
    if request.GET.get('city'):
        filters &= Q(est_city__icontains=request.GET['city'])
    if request.GET.get('center'):
        filters &= Q(est_center__icontains=request.GET['center'])
    if request.GET.get('address'):
        filters &= Q(est_address__icontains=request.GET['address'])
    if request.GET.get('manage'):
        filters &= Q(est_manaegge__icontains=request.GET['manage'])
    if request.GET.get('property'):
        filters &= Q(est_property__icontains=request.GET['property'])
    establishments = establishments.filter(filters)

    paginator = Paginator(establishments, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        results = [{
            'est_id': e.est_id,
            'est_region': e.est_region,
            'est_state': e.est_state,
            'est_city': e.est_city,
            'est_center': e.est_center,
            'est_address': e.est_address,
            'est_property': e.est_property,
            'est_manage': e.est_manage,
        } for e in page_obj]
        return JsonResponse({
            'results': results,
            'count': paginator.count,
            'start_index': page_obj.start_index(),
            'end_index': page_obj.end_index(),
            'num_pages': paginator.num_pages,
            'current_page': page_obj.number,
        })

    return render(request, 'main/administrador/establishment_list.html', {
        'page_obj': page_obj,
        'establishment_l': page_obj,
    })

@only_administrador
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
        'email_l' : page_obj,
    }
    return render(request, 'main/administrador/email_list.html', context)
 
@only_administrador
def overview(request):
    latest_dt = (
        Attachment.objects
        .filter(att_doc=OuterRef('att_doc'), att_center=OuterRef('att_center'))
        .order_by('-att_data_inserted')
        .values('att_data_inserted')[:1]
    )

    latest_qs = (
        Attachment.objects
        .annotate(latest_date=Subquery(latest_dt))
        .filter(att_data_inserted=F('latest_date'))
    )

    NEGATIVAS = ["Vencido", "Invalidado", "A Vencer"]
    POSITIVAS = ["Em Análise", "Regular"]

    latest_attachments     = latest_qs.filter(att_situation__in=NEGATIVAS).order_by('att_center', '-att_data_inserted')
    latest_attachments_pos = latest_qs.filter(att_situation__in=POSITIVAS).order_by('att_center', '-att_data_inserted')
    centers_names = latest_attachments.values_list('att_center', flat=True).distinct()
    centers = Establishment.objects.filter(est_center__in=centers_names)
    count_expire  = latest_attachments.filter(att_situation='Vencido').count()
    count_invalid = latest_attachments.filter(att_situation='Invalidado').count()
    count_avencer = latest_attachments.filter(att_situation='A Vencer').count()
    count_analise = latest_attachments_pos.filter(att_situation='Em Análise').count()
    count_regular = latest_attachments_pos.filter(att_situation='Regular').count()

    tt_situation = count_expire + count_invalid + count_avencer + count_analise
    total_considerado = tt_situation + count_regular

    if total_considerado > 0:
        regularity_pct = round((count_regular / total_considerado) * 100, 2)
        irregular_pct  = round((tt_situation  / total_considerado) * 100, 2)
    else:
        regularity_pct = 0.0
        irregular_pct  = 0.0

    regularity = f"{regularity_pct}%"
    center_status = {c.est_center: "warning" for c in centers}

    region_centers = {}
    for c in centers:
        reg = (c.est_region or '-').upper()
        name = c.est_center
        region_centers.setdefault(reg, []).append({
            "name": name,
            "status": center_status.get(name, "secondary")
        })

    rel_qs = (
        RelationCenterUser.objects
        .select_related('rcu_fk_user')
        .prefetch_related('rcu_fk_user__groups')
    )

    rels_by_region = defaultdict(list)
    rels_by_state  = defaultdict(list)
    rels_by_center = defaultdict(list)
    for rel in rel_qs:
        rels_by_region[rel.rcu_region.upper()].append(rel)
        rels_by_state[rel.rcu_state.upper()].append(rel)
        rels_by_center[rel.rcu_center].append(rel)

    def get_profile(user: User) -> str:
        if user.is_superuser:
            return "Administrador"
        for gname in ("Administrador", "Auditor", "Gerente Regional", "Usuário"):
            if user.groups.filter(name=gname).exists():
                return gname
        return "Usuário" 

    def user_payload(u: User, manage: str):
        nome = (u.get_full_name() or u.first_name or u.username).strip()
        return {
            "name": nome,
            "login": u.username,
            "email": u.email or "",
            "profile": get_profile(u),
            "manage": manage or "-"
        }

    centers_data = {}
    for center in centers:
        center_name = center.est_center
        manage      = center.est_manage
        region      = (center.est_region or '-').upper()

        grouped = {}
        for attach in latest_attachments.filter(att_center=center_name).order_by('att_doc', '-att_data_inserted'):
            doc = attach.att_doc
            if doc not in grouped:
                grouped[doc] = {
                    "document": doc,
                    "data_inserted": dj_format(attach.att_data_inserted, 'd/m/Y H:i'),
                    "situation": attach.att_situation,
                    "justification": attach.att_just or ""
                }

        invalidado_info = [
            d for d in grouped.values()
            if d["situation"] in ("Vencido", "Invalidado", "A Vencer")
        ]

        seen_users = set()
        user_list = []

        for rel in rels_by_region.get(region, []):
            u = rel.rcu_fk_user
            if get_profile(u) == "Gerente Regional" and u.id not in seen_users:
                seen_users.add(u.id)
                user_list.append(user_payload(u, manage))

        for rel in rels_by_state.get((center.est_state or '').upper(), []):
            u = rel.rcu_fk_user
            if get_profile(u) == "Gerente Regional" and u.id not in seen_users:
                seen_users.add(u.id)
                user_list.append(user_payload(u, manage))

        for rel in rels_by_center.get(center_name, []):
            u = rel.rcu_fk_user
            if get_profile(u) == "Usuário" and u.id not in seen_users:
                seen_users.add(u.id)
                user_list.append(user_payload(u, manage))

        centers_data[center_name] = {
            "invalidado": invalidado_info,
            "users": user_list,
            "manage": manage,
            "region": region
        }

    invalid_by_document = defaultdict(list)
    seen = set()
    for attach in latest_attachments.order_by('-att_data_inserted'):
        key = (attach.att_doc, attach.att_center)
        if key in seen:
            continue
        seen.add(key)
        invalid_by_document[attach.att_doc].append({
            "center": attach.att_center,
            "data_inserted": dj_format(attach.att_data_inserted, 'd/m/Y H:i')
        })

    return render(request, 'main/administrador/index.html', {
        'region_centers_json': mark_safe(json.dumps(region_centers)),
        'centers_data_json': mark_safe(json.dumps(centers_data)),
        'invalid_by_document_json': mark_safe(json.dumps(invalid_by_document)),
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
    
def document_list(request):
    name = (request.GET.get('name') or '').strip()

    qs = Document.objects.all()
    if name:
        qs = qs.filter(d_doc__icontains=name)
    qs = qs.order_by('d_doc')

    paginator = Paginator(qs, 10)
    page_number = request.GET.get('page') or 1
    page_obj = paginator.get_page(page_number)

    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        results = [{
            'd_id': doc.d_id,
            'd_doc': doc.d_doc,
            'edit_url': reverse('document_update', args=[doc.d_id]),
            'delete_url': reverse('document_delete', args=[doc.d_id]),
        } for doc in page_obj.object_list]

        if paginator.count:
            start_index = page_obj.start_index()
            end_index = page_obj.end_index()
        else:
            start_index = 0
            end_index = 0

        return JsonResponse({
            'results': results,
            'count': paginator.count,
            'start_index': start_index,
            'end_index': end_index,
            'num_pages': paginator.num_pages,
            'current_page': page_obj.number,
        })

    return render(request, 'main/administrador/document_list.html', {
        'page_obj': page_obj
    })

@only_administrador
def center_user_list(request):
    qs = (
        RelationCenterUser.objects
        .select_related('rcu_fk_user', 'rcu_fk_estab')
        .exclude(rcu_active=False)
        .exclude(rcu_fk_estab__isnull=True)
        .annotate(
            _user_norm   = Lower('rcu_fk_user__username'),
            _center_norm = Lower(Coalesce('rcu_fk_estab__est_center', 'rcu_center')),
            _region_norm = Lower(Coalesce('rcu_fk_estab__est_region', 'rcu_region')),
            _state_norm  = Lower(Coalesce('rcu_fk_estab__est_state',  'rcu_state')),
        )
        .order_by(
            '_user_norm',         # 1) Usuário
            '_region_norm',       # 3) Região
            '_state_norm',        # 4) Estado
            '_center_norm',       # 2) Estabelecimento
        )
    ) 

    user   = (request.GET.get('user')   or '').strip()
    center = (request.GET.get('center') or '').strip()
    state  = (request.GET.get('state')  or '').strip()
    region = (request.GET.get('region') or '').strip()

    def q_text(field, value):
        if not value:
            return Q()
        if value == '-':
            return (
                Q(**{f'{field}': '-'}) |
                Q(**{f'{field}': ''}) |
                Q(**{f'{field}__isnull': True})
            )
        return Q(**{f'{field}__icontains': value})

    q = Q()
    if user:
        q &= q_text('rcu_fk_user__username', user)

    if center:
        q &= (
            q_text('rcu_fk_estab__est_center', center) |
            q_text('rcu_center', center)
        )

    if state:
        q &= q_text('rcu_state', state)

    if region:
        q &= q_text('rcu_region', region)

    qs = qs.filter(q)

    paginator = Paginator(qs, 10)
    page_number = request.GET.get('page') or 1
    page_obj = paginator.get_page(page_number)

    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        results = []
        for obj in page_obj.object_list:
            center_name = getattr(obj.rcu_fk_estab, 'est_center', None) or (obj.rcu_center or '-')
            results.append({
                'rcu_id': obj.rcu_id,
                'rcu_login': getattr(obj.rcu_fk_user, 'username', '') or '-',
                'rcu_center': center_name,
                'rcu_state': obj.rcu_state or '-',
                'rcu_region': obj.rcu_region or '-',
                'edit_url': reverse('center_user_update', args=[obj.rcu_id]),
                'delete_url': reverse('center_user_delete', args=[obj.rcu_id]),
            })

        start_index = page_obj.start_index() if paginator.count else 0
        end_index = page_obj.end_index() if paginator.count else 0

        return JsonResponse({
            'results': results,
            'count': paginator.count,
            'start_index': start_index,
            'end_index': end_index,
            'num_pages': paginator.num_pages,
            'current_page': page_obj.number,
        })

    context = {
        'page_obj': page_obj,
        'center_user_l': page_obj,
    }
    return render(request, 'main/administrador/center_user_list.html', context)
    
def center_doc_list(request):
    qs = (RelationCenterDoc.objects
          .select_related('rcd_fk_establishment', 'rcd_fk_document')
          .order_by('rcd_id'))

    center = (request.GET.get('center') or '').strip()
    doc    = (request.GET.get('doc') or '').strip()

    filters = Q()
    if center:
        filters &= Q(rcd_fk_establishment__est_center__icontains=center)
    if doc:
        filters &= Q(rcd_fk_document__d_doc__icontains=doc)

    qs = qs.filter(filters)
    
    qs = (
        qs
        .annotate(
            _doc_norm    = Lower('rcd_fk_document__d_doc'),
            _center_norm = Lower(Coalesce('rcd_fk_establishment__est_center', Value('')))
        )
        .order_by(
            '_doc_norm',     # 1) Documento (A→Z)
            '_center_norm',  # 2) Estabelecimento (A→Z)
            'rcd_id',        # desempate estável
        )
    ) 

    paginator = Paginator(qs, 10)
    page_number = request.GET.get('page') or 1
    page_obj = paginator.get_page(page_number)

    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        results = [{
            'rcd_id': obj.rcd_id,
            'rcd_center': obj.rcd_fk_establishment.est_center,
            'rcd_doc': obj.rcd_fk_document.d_doc,
            'edit_url': reverse('center_doc_update', args=[obj.rcd_id]),
            'delete_url': reverse('center_doc_delete', args=[obj.rcd_id]),
        } for obj in page_obj.object_list]

        if paginator.count:
            start_index = page_obj.start_index()
            end_index = page_obj.end_index()
        else:
            start_index = 0
            end_index = 0

        return JsonResponse({
            'results': results,
            'count': paginator.count,
            'start_index': start_index,
            'end_index': end_index,
            'num_pages': paginator.num_pages,
            'current_page': page_obj.number,
        })

    context = {
        'page_obj': page_obj,
        'center_doc_l': page_obj,
    }
    return render(request, 'main/administrador/center_doc_list.html', context) 

@only_administrador
def user_list(request):
    User = get_user_model()
    users = (
        User.objects
        .exclude(groups__name="Sem Acesso")
        .order_by("u_status", "-u_time_in")
        .prefetch_related("groups")
    )

    filters = Q()

    name = (request.GET.get('name') or '').strip()
    login = (request.GET.get('login') or '').strip()
    email = (request.GET.get('email') or '').strip()
    time_in = (request.GET.get('time_in') or '').strip()
    time_out = (request.GET.get('time_out') or '').strip()
    status = (request.GET.get('status') or '').strip()
    profile = (request.GET.get('profile') or '').strip()
    users = users.annotate(full_name=Concat('first_name', Value(' '), 'last_name'))

    if name:
        filters &= (Q(full_name__icontains=name) | Q(username__icontains=name))
    if login:
        filters &= Q(username__icontains=login)
    if email:
        filters &= Q(email__icontains=email)

    def _parse_br_date(s: str):
        try:
            return datetime.strptime(s, "%d/%m/%Y").date()
        except Exception:
            return None

    if time_in:
        d = _parse_br_date(time_in)
        if d:
            filters &= Q(u_time_in=d)

    if time_out:
        d = _parse_br_date(time_out)
        if d:
            filters &= Q(u_time_out=d)

    if status:
        filters &= Q(u_status__icontains=status)

    if profile:
        filters &= Q(groups__name__icontains=profile)

    users = users.filter(filters).distinct()
    users = (
        users
        .annotate(
            # normaliza status (case-insensitive)
            _status_norm = Lower(Coalesce('u_status', Value(''))),

            # pega o menor nome de grupo != "Sem Acesso" (se existir)…
            _group_pref = Min('groups__name', filter=~Q(groups__name='Sem Acesso')),
            # …senão, qualquer grupo (menor em ordem alfabética)
            _group_any  = Min('groups__name'),
        )
        .annotate(
            _group_norm = Lower(Coalesce(F('_group_pref'), F('_group_any'), Value(''))),

            # nome: first→last (fallback ordena por username)
            _fname_norm = Lower(Coalesce('first_name', Value(''))),
            _lname_norm = Lower(Coalesce('last_name', Value(''))),
            _uname_norm = Lower('username'),
        )
        .order_by(
            '_status_norm',   # 1) Status
            '_group_norm',    # 2) Grupo
            '_fname_norm',    # 3) Nome (primeiro)
            '-u_time_in',     # 4) Data de entrada (mais recente primeiro)
            '_uname_norm',    # desempate estável
            'id',             # fallback final
        )
    ) 
    paginator = Paginator(users, 10)
    page_number = request.GET.get('page') or 1
    page_obj = paginator.get_page(page_number)

    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        results = []
        for u in page_obj.object_list:
            all_groups = list(u.groups.values_list('name', flat=True))
            display_profile = next((g for g in all_groups if g != 'Sem Acesso'),
                                   (all_groups[0] if all_groups else ''))

            results.append({
                'id': u.pk,
                'name': (u.get_full_name() or u.username),
                'login': u.username,
                'email': u.email,
                'time_in': u.u_time_in.strftime('%d/%m/%Y') if getattr(u, 'u_time_in', None) else '',
                'time_out': u.u_time_out.strftime('%d/%m/%Y') if getattr(u, 'u_time_out', None) else '',
                'profile': display_profile or '',
                'status': u.u_status,
                'edit_url': reverse('user_edit', args=[u.pk]),
            })

        if paginator.count:
            start_index = page_obj.start_index()
            end_index = page_obj.end_index()
        else:
            start_index = 0
            end_index = 0

        return JsonResponse({
            'results': results,
            'count': paginator.count,
            'start_index': start_index,
            'end_index': end_index,
            'num_pages': paginator.num_pages,
            'current_page': page_obj.number,
        })

    context = {
        'page_obj': page_obj,
        'users_l': page_obj,  
    }
    return render(request, 'main/administrador/user_list.html', context)

@only_administrador
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
        q &= Q(aud_id__icontains=f_cod)
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
    return render(request, 'main/administrador/audit_list.html', context)

@only_administrador
def attachment_list(request):

    ALLOWED_SITUATIONS = ["Regular", "Vencido", "A Vencer", "Invalidado"]

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

    def _get(v): return (v or '').strip()

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
        When(att_situation__iexact="Regular",    then=Value(3)),
        default=Value(4),
        output_field=IntegerField(),
    )

    attachments = (
        attachments
        .annotate(_status_rank=status_rank, _center_norm=Lower('att_center'), _doc_norm=Lower('att_doc'))
        .order_by('_status_rank', 'att_center', 'att_doc','-att_data_inserted', 'att_id')
    )

    paginator   = Paginator(attachments, 10)
    page_number = request.GET.get('page')
    page_obj    = paginator.get_page(page_number)

    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        results = []

        def fmt_dt(dt):
            if not dt:
                return ''
            try:
                dt = timezone.localtime(dt)
            except Exception:
                pass
            return dt.strftime('%d/%m/%Y %H:%M')

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

    return render(request, 'main/administrador/attachment_list.html', {
        'page_obj': page_obj
    })

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

@only_administrador
def attachment_history_all(request):

    attachments = Attachment.objects.filter(
        att_situation__in=["Regular", "Vencido", "A Vencer", "Invalidado"],
        ).order_by('-att_data_inserted', 'att_center', 'att_doc', 'att_situation', '-att_id')

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

    attachments = attachments.filter(q)

    paginator = Paginator(attachments, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        results = []
        for a in page_obj:
            def fmt_dt(dt):
                if not dt:
                    return ''
                try:
                    dt_local = timezone.localtime(dt)
                except Exception:
                    dt_local = dt
                return dt_local.strftime('%d/%m/%Y %H:%M')

            item = {
                'id': a.att_id,
                'document': a.att_doc,
                'region': a.att_region,
                'state': a.att_state,
                'center': a.att_center,
                'data_inserted': fmt_dt(a.att_data_inserted),
                'data_expire': a.att_data_expire.strftime('%d/%m/%Y') if a.att_data_expire else '',
                'situation': a.att_situation,
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

    return render(request, 'main/administrador/attachment_history_all.html', {
        'page_obj': page_obj,
        'url_history_template': '/admin/attachment/history/__doc__/__region__/__center__/'
    })
  
@only_administrador
def attachment_history(request, document, region, center=None):
    base_q = Q(att_doc=document, att_region=region)
    if center:
        base_q &= Q(att_center=center)

    f_state     = _get(request.GET.get('state'))
    f_center    = _get(request.GET.get('center'))
    f_inserted  = _get(request.GET.get('data_inserted')) 
    f_expire    = _get(request.GET.get('data_expire'))   
    f_situation = _get(request.GET.get('situation'))

    state_display = f_state or (
        Attachment.objects.filter(base_q)
        .values_list('att_state', flat=True)
        .first() or ''
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
    status_rank = Case(
    When(att_situation__iexact="Vencido",    then=Value(0)),
    When(att_situation__iexact="Invalidado", then=Value(1)),
    When(att_situation__iexact="A Vencer",   then=Value(2)),
    When(att_situation__iexact="Regular",    then=Value(3)),
    default=Value(4),
    output_field=IntegerField(),
    )

    attachments = (
        attachments_qs
        .annotate(_status_rank=status_rank)
        .order_by(
            '-att_data_inserted',  # 1) Data de Anexo (mais recente primeiro)
            'att_center',          # 2) Estabelecimento (A→Z)
            'att_doc',             # 3) Documento (A→Z)
            '_status_rank',        # 4) Situação (Vencido, Invalidado, A Vencer, Regular)
            '-att_id',             # desempate estável (opcional)
        )
    )

    paginator = Paginator(attachments, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

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
                'situation': a.att_situation,
                'conference': a.att_checked_by or '',
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

    return render(request, 'main/administrador/attachment_history.html', {
        'page_obj': page_obj,
        'document': document,
        'region': region,
        'center': center or '',
        'state': state_display,
    })
   
@only_administrador
def number_doc_list(request):
    qs = (NumDocsEstab.objects
          .select_related('ndest_fk_establishment')
          .order_by('ndest_id'))

    center    = (request.GET.get('center') or '').strip()
    unit      = (request.GET.get('unit') or '').strip()
    cnpj      = (request.GET.get('cnpj') or '').strip()
    nire      = (request.GET.get('nire') or '').strip()
    reg_city  = (request.GET.get('reg_city') or '').strip()   
    reg_state = (request.GET.get('reg_state') or '').strip()  

    def q_text(field, value):
        if not value:
            return Q()
        if value == '-':
            return (Q(**{f"{field}": '-'}) |
                    Q(**{f"{field}": ''}) |
                    Q(**{f"{field}__isnull": True}))
        return Q(**{f"{field}__icontains": value})

    q = (
        q_text('ndest_fk_establishment__est_center', center) &
        q_text('ndest_units', unit) &
        q_text('ndest_cnpj', cnpj) &
        q_text('ndest_nire', nire) &
        q_text('ndest_reg_city', reg_city) &
        q_text('ndest_reg_state', reg_state)
    )

    qs = qs.filter(q)

    paginator = Paginator(qs, 10)
    page_number = request.GET.get('page') or 1
    page_obj = paginator.get_page(page_number)

    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        results = [{
            'ndest_id': obj.ndest_id,
            'ndest_fk_establishment__est_center': obj.ndest_fk_establishment.est_center or '-',
            'ndest_units': obj.ndest_units or '-',
            'ndest_cnpj': obj.ndest_cnpj or '-',
            'ndest_nire': obj.ndest_nire or '-',
            'ndest_reg_city': obj.ndest_reg_city or '-',
            'ndest_reg_state': obj.ndest_reg_state or '-',
            'edit_url': reverse('cnpj_update', args=[obj.ndest_id]),
            'delete_url': reverse('num_docs_delete', args=[obj.ndest_id]),
        } for obj in page_obj.object_list]

        if paginator.count:
            start_index = page_obj.start_index()
            end_index = page_obj.end_index()
        else:
            start_index = 0
            end_index = 0

        return JsonResponse({
            'results': results,
            'count': paginator.count,
            'start_index': start_index,
            'end_index': end_index,
            'num_pages': paginator.num_pages,
            'current_page': page_obj.number,
        })

    context = {
        'page_obj': page_obj,
        'cnpjs_l': page_obj,
    }
    return render(request, 'main/administrador/cnpj_list.html', context)