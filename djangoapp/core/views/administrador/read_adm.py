import json

from django.shortcuts import render, redirect
from django.core.paginator import Paginator, EmptyPage
from django.http import JsonResponse
from django.contrib import messages
from django.db.models import Q, Max
from django.utils import timezone
from django.utils.dateformat import format as dj_format
from django.utils.safestring import mark_safe
from core.utils.search import clean_search_q
from core.utils.waf import waf_raw_qs_guard, inspect_dict
from django.views.decorators.http import require_GET, require_http_methods
from core.utils.search import clean_search_q
from django.conf import settings
from django.urls import reverse
from core.models import Establishment, Attachment, SecurityEvent, Users, NumDocsEstab, RelationCenterUser, Document, RelationCenterDoc, Audit, Email
from core.decorators import only_administrador
from collections import defaultdict

@require_http_methods(["GET","POST"])
@only_administrador
def home(request):
    establishments = Establishment.objects.all().order_by('est_id')
    return render(request, 'main/administrador/index.html', {
        'establishment_l': establishments,
    })

@require_http_methods(["GET","POST"])
@only_administrador
def establishment_list(request):
    establishments = Establishment.objects.all().order_by('est_id')

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
        filters &= Q(est_manage__icontains=request.GET['manage'])
    if request.GET.get('property'):
        filters &= Q(est_property__icontains=request.GET['property'])
    establishments = establishments.filter(filters)

    paginator = Paginator(establishments, 8)
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

@require_http_methods(["GET","POST"])
@only_administrador
def email_list(request):
    ema = Email.objects.all().order_by('-em_id')
    
    filters = Q()
    if request.GET.get('cod'):
        filters &= Q(em_id__icontains=request.GET['cod'])
    if request.GET.get('email'):
        filters &= Q(em_email__icontains=request.GET['email'])
    if request.GET.get('subject'):
        filters &= Q(em_subject__icontains=request.GET['subject'])
    if request.GET.get('data_shipping'):
        filters &= Q(em_data_shipping__icontains=request.GET['data_shipping'])
    if request.GET.get('center'):
        filters &= Q(em_center__icontains=request.GET['center'])
    if request.GET.get('doc'):
        filters &= Q(em_doc__icontains=request.GET['doc'])
    ema = ema.filter(filters)
        
    paginator = Paginator(ema, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        results = [{
            'em_cod': e.em_cod,
            'em_email': e.em_email,
            'em_subject': e.em_subject,
            'em_data_shipping': e.em_data_shipping,
            'em_center': e.em_center,
            'em_doc': e.em_doc,
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
        'email_l': page_obj
    }
    return render(request, 'main/administrador/email_list.html', context)

@require_http_methods(["GET","POST"])
@only_administrador
def attachment_list(request):
    user_id = request.session.get('user_id')
    user = Users.objects.get(u_id=user_id, u_status='Ativo', u_profile='Administrador')

    authorized_documents = Attachment.objects.values_list('att_doc', flat=True)
    latest = Attachment.objects.filter(
        att_situation__in=["Regular", "Vencido", "A Vencer"],
        att_doc__in=authorized_documents
    ).values('att_doc', 'att_center').annotate(latest_date=Max('att_data_inserted'))

    q = Q()
    for row in latest:
        q |= Q(att_doc=row['att_doc'], att_center=row['att_center'], att_data_inserted=row['latest_date'])
    attachments = latest.filter(q).order_by('att_center', '-att_data_inserted', '-att_situation')

    filters = {
        'att_doc':        clean_search_q(request.GET.get('document')),
        'att_region':     clean_search_q(request.GET.get('region')),
        'att_state':      clean_search_q(request.GET.get('state')),
        'att_center':     clean_search_q(request.GET.get('center')),
        'att_data_inserted__date': clean_search_q(request.GET.get('data_inserted')),
        'att_data_expire':         clean_search_q(request.GET.get('data_expire')),
        'att_situation':  clean_search_q(request.GET.get('situation')),
    }

    for field, val in filters.items():
        if val:
            attachments = attachments.filter(**{f"{field}__icontains": val})
            
    paginator = Paginator(attachments, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        center_filter = request.GET.get("center")
        filtered_results = [a for a in page_obj if a.center == center_filter] if center_filter else page_obj

        results = [{
            'id': a.att_id,
            'document': a.att_document,
            'region': a.att_region,
            'state': a.att_state,
            'center': a.att_center,
            'data_inserted': a.att_data_inserted.strftime('%d/%m/%Y %H:%M') if a.att_data_inserted else '',
            'data_expire': a.att_data_expire.strftime('%d/%m/%Y') if a.att_data_expire else '',
            'situation': a.att_situation or '',
            'file_url': a.att_file.url if a.file else '',
            'document_attached': a.att_document_attached or '',
            'document_checked': a.att_document_checked or '',
            'data_conference': a.att_data_conference.strftime('%d/%m/%Y %H:%M') if a.att_data_conference else '',
            'unit_info': [{
                'unit': u.ndest_units,
                'cnpj': u.ndest_cnpj,
                'nire': u.ndest_nire,
                'registration_state': u.ndest_reg_state,
                'registration_municipal': u.ndest_reg_city,
            } for u in NumDocsEstab.objects.filter(ndest_center=a.att_center)]
        } for a in filtered_results]

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
 
@require_http_methods(["GET","POST"])
@only_administrador
def overview(request):
    latest = Attachment.objects.values('att_doc', 'att_center').annotate(
        latest_date=Max('att_data_inserted')
    )

    query = Q()
    for item in latest:
        query |= Q(
            att_doc=item['att_doc'],
            att_center=item['att_center'],
            att_data_inserted=item['latest_date'],
            att_situation__in=["Vencido", "Invalidado", "A Vencer"]
        )

    latest_attachments = Attachment.objects.filter(query).order_by('att_center', '-att_data_inserted')

    query_posi = Q()
    for item in latest:
        query_posi |= Q(
            att_doc=item['att_doc'],
            att_center=item['att_center'],
            att_data_inserted=item['latest_date'],
            att_situation__in=["Em Análise", "Regular"]
        )

    latest_attachments_posi = Attachment.objects.filter(query_posi).order_by('att_center', '-att_data_inserted')

    centers_names = latest_attachments.values_list('att_center', flat=True).distinct()
    centers = Establishment.objects.filter(est_center__in=centers_names)

    count_expire = latest_attachments.filter(att_situation='Vencido').count()
    count_invalid = latest_attachments.filter(att_situation='Invalidado').count()
    count_avencer = latest_attachments.filter(att_situation='A Vencer').count()
    count_analise = latest_attachments_posi.filter(att_situation='Em Análise').count()
    count_regular = latest_attachments_posi.filter(att_situation='Regular').count()
    
    tt_situation = count_expire + count_invalid + count_avencer + count_analise + count_regular
    ttbad = count_expire + count_invalid + count_avencer + count_analise
    regularity = ttbad / tt_situation

    center_status = {}
    for center in centers:
        center_name = center.est_center
        center_status[center_name] = "warning"

    region_centers = {}
    for center in centers:
        reg = center.est_region.upper()
        name = center.est_center
        region_centers.setdefault(reg, []).append({
            "name": name,
            "status": center_status.get(name, "secondary")
        })

    users = Users.objects.all()
    users_dict = {u.u_login.strip().lower(): u for u in users}
    relation_users = RelationCenterUser.objects.all()

    centers_data = {}
    for center in centers:
        center_name = center.est_center
        manage = center.est_manage
        region = center.est_region

        grouped = {}
        for attach in latest_attachments.filter(att_center=center_name).order_by('att_doc', '-att_data_inserted'):
            doc = attach.att_doc
            if doc not in grouped:
                grouped[doc] = {
                    "document": doc,
                    "data_inserted": dj_format(attach.att_data_inserted, 'd/m/Y H:i')
                }
        invalidado_info = list(grouped.values())

        user_list = []
        for rel in relation_users.filter(rcu_region=region):
            login = rel.rcu_fk_user.u_login.strip().lower()
            user_obj = users_dict.get(login)
            if user_obj and user_obj.u_profile == "Gerente Regional":
                user_list.append({
                    "name": user_obj.u_name,
                    "login": user_obj.u_login,
                    "email": user_obj.u_email or "",
                    "profile": user_obj.u_profile
                })

        for rel in relation_users.filter(rcu_state=center.est_state):
            login = rel.rcu_fk_user.u_login.strip().lower()
            user_obj = users_dict.get(login)
            if user_obj and user_obj.u_profile == "Gerente Regional":
                user_list.append({
                    "name": user_obj.u_name,
                    "login": user_obj.u_login,
                    "email": user_obj.u_email or "",
                    "profile": user_obj.u_profile
                })

        for rel in relation_users.filter(rcu_center=center_name):
            login = rel.rcu_fk_user.u_login.strip().lower()
            user_obj = users_dict.get(login)
            if user_obj and user_obj.u_profile == "Usuário":
                user_list.append({
                    "name": user_obj.u_name,
                    "login": user_obj.u_login,
                    "email": user_obj.u_email or "",
                    "profile": user_obj.u_profile
                })

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
        if key not in seen:
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
        'ttbad': ttbad,
        'regularity': regularity,
    })


@require_http_methods(["GET", "POST"])
@only_administrador
def document_list(request):
    # Sanitiza 'name' usando o mesmo pipeline de busca (bloqueia invisíveis/encoding/HPP)
    raw_name = request.GET.get('name', '') or ''
    name = clean_search_q(raw_name, maxlen=80)  # retorna "" se inválido

    qs = Document.objects.all()
    if name:
        qs = qs.filter(d_doc__icontains=name)

    qs = qs.order_by('d_doc')

    # Página segura (numérica, default 1)
    page_str = request.GET.get('page') or '1'
    try:
        page = max(1, int(page_str))
    except (TypeError, ValueError):
        page = 1

    paginator = Paginator(qs, 10)
    try:
        page_obj = paginator.page(page)
    except EmptyPage:
        page_obj = paginator.page(paginator.num_pages if paginator.num_pages else 1)

    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        # Retorna URLs calculadas no servidor para evitar hardcode de rotas no JS
        results = [{
            'd_id': d.d_id,
            'd_doc': d.d_doc,
            'update_url': reverse('document_update', args=[d.d_id]),
            'delete_url': reverse('document_delete', args=[d.d_id]),
        } for d in page_obj]

        return JsonResponse({
            'results': results,
            'count': paginator.count,
            'start_index': page_obj.start_index(),
            'end_index': page_obj.end_index(),
            'num_pages': paginator.num_pages,
            'current_page': page_obj.number,
        })

    return render(request, 'main/administrador/document_list.html', {
        'page_obj': page_obj
    })


"""
@only_administrador
def overview(request):
    centers = Establishment.objects.all()
    # Seleciona apenas documentos de 'Attachment' com as situações "Invalidado" ou "Vencido"
    latest_attachments = Attachment.objects.filter(
        att_situation__in=["Invalidado", "Vencido"]
    ).values('att_doc', 'att_center').annotate(latest_date=Max('att_data_inserted'))

    query = Q()
    for item in latest_attachments:
        query |= Q(att_doc=item['att_doc'], att_center=item['att_center'], att_data_inserted=item['latest_date'])

    latest_invalid = Attachment.objects.filter(query, att_situation="Invalidado")
    latest_expire = Attachment.objects.filter(query, att_situation="Vencido")

    center_status = {}
    for center in centers:
        center_name = center.est_center
        has_invalid = latest_invalid.filter(att_center=center_name).exists()
        has_expire = latest_expire.filter(att_center=center_name).exists()
        has_any = latest_attachments.filter(att_center=center_name).exists()
        
        # Só processa centros que tenham anexos "Invalidado" ou "Vencido"
        if has_invalid or has_expire:
            center_status[center_name] = "warning"
    
    # Agora, só lista centros que têm anexos pendentes
    region_centers = {}
    for center in centers:
        reg = center.est_region.upper()
        name = center.est_center
        if center_name in center_status:  # Verifica se o centro tem anexos pendentes
            region_centers.setdefault(reg, []).append({
                "name": name,
                "status": center_status.get(name, "secondary")
            })

    users = Users.objects.all()
    users_dict = {u.u_login.strip().lower(): u for u in users}
    relation_users = RelationCenterUser.objects.all()
    centers_data = {}

    for center in centers:
        center_name = center.est_center
        if center_name not in center_status:  # Ignora centros sem anexos pendentes
            continue

        manage = center.est_manage
        region = center.est_region
        grouped = {}
        
        # Adiciona documentos pendentes (Invalidado ou Vencido) para cada centro
        for attach in latest_invalid.filter(att_center=center_name).order_by('att_doc', '-att_data_inserted'):
            doc = attach.att_doc
            if doc not in grouped:
                grouped[doc] = {
                    "document": doc,
                    "data_inserted": dj_format(attach.att_data_inserted, 'd/m/Y H:i')
                }
        for attach in latest_expire.filter(att_center=center_name).order_by('att_doc', '-att_data_inserted'):
            doc = attach.att_doc
            if doc not in grouped:
                grouped[doc] = {
                    "document": doc,
                    "data_inserted": dj_format(attach.att_data_inserted, 'd/m/Y H:i')
                }

        invalidado_info = list(grouped.values())
        user_list = []

        # Associar usuários ao centro
        for rel in relation_users.filter(rcu_region=center.est_region):
            login = str(rel.rcu_fk_user).strip().lower()
            user_obj = users_dict.get(login)
            if user_obj and user_obj.u_profile == "Gerente Regional":
                user_list.append({
                    "name": user_obj.u_name,
                    "login": user_obj.u_login,
                    "email": user_obj.u_email or "",
                    "profile": user_obj.u_profile
                })

        # Adicionar os dados de usuários por estado e centro
        for rel in relation_users.filter(rcu_state=center.est_state):
            login = str(rel.rcu_fk_user).strip().lower()
            user_obj = users_dict.get(login)
            if user_obj and user_obj.u_profile == "Gerente Regional":
                user_list.append({
                    "name": user_obj.u_name,
                    "login": user_obj.u_login,
                    "email": user_obj.u_email or "",
                    "profile": user_obj.u_profile
                })

        for rel in relation_users.filter(rcu_center=center_name):
            login = str(rel.rcu_fk_user).strip().lower()
            user_obj = users_dict.get(login)
            if user_obj and user_obj.u_profile == "Usuário":
                user_list.append({
                    "name": user_obj.u_name,
                    "login": user_obj.u_login,
                    "email": user_obj.u_email or "",
                    "profile": user_obj.u_profile
                })

        centers_data[center_name] = {
            "invalidado": invalidado_info,
            "users": user_list,
            "manage": manage,
            "region": region
        }
    
    invalid_by_document = defaultdict(list)
    seen = set()
    for attach in latest_invalid.order_by('-att_data_inserted'):
        key = (attach.att_doc, attach.att_center)
        if key not in seen:
            seen.add(key)
            invalid_by_document[attach.att_doc].append({
                "center": attach.att_center,
                "data_inserted": dj_format(attach.att_data_inserted, 'd/m/Y H:i')
            })

    return render(request, 'main/administrador/overview.html', {
        'region_centers_json': mark_safe(json.dumps(region_centers)),
        'centers_data_json': mark_safe(json.dumps(centers_data)),
        'invalid_by_document_json': mark_safe(json.dumps(invalid_by_document)),
    })
"""

@require_http_methods(["GET","POST"])
@only_administrador
def center_user_list(request):
    center_users = RelationCenterUser.objects.select_related('rcu_fk_user').all().order_by('rcu_id')

    user = request.GET.get('user', '')
    center = request.GET.get('center', '')
    state = request.GET.get('state', '')
    region = request.GET.get('region', '')

    q = Q()
    if user:
        q &= Q(rcu_fk_user__u_login__icontains=user)
    if center:
        q &= Q(rcu_center__icontains=center)
    if state:
        q &= Q(rcu_state__icontains=state)
    if region:
        q &= Q(rcu_region__icontains=region)

    center_users = center_users.filter(q)

    paginator = Paginator(center_users, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        results = [{
            'rcu_id': rcu.rcu_id,
            'rcu_fk_user__u_login': rcu.rcu_fk_user.u_login,
            'rcu_center': rcu.rcu_center,
            'rcu_state': rcu.rcu_state,
            'rcu_region': rcu.rcu_region,
        } for rcu in page_obj]

        return JsonResponse({
            'results': results,
            'count': paginator.count,
            'start_index': page_obj.start_index(),
            'end_index': page_obj.end_index(),
            'num_pages': paginator.num_pages,
            'current_page': page_obj.number,
        })

    return render(request, 'main/administrador/center_user_list.html', {
        'page_obj': page_obj,
        'center_user_l': page_obj,
    })
    
@require_http_methods(["GET","POST"])
@only_administrador
def center_doc_list(request):
    rcd = RelationCenterDoc.objects.all().order_by('rcd_id')
    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        filters = Q()
        if request.GET.get('center'):
            filters &= Q(rcd_fk_establishment__est_center__icontains=request.GET['center'])
        if request.GET.get('doc'):
            filters &= Q(rcd_fk_document__d_doc__icontains=request.GET['doc'])
        rcd = rcd.filter(filters)
        results = list(rcd.values('rcd_id', 'rcd_fk_establishment__est_center', 'rcd_fk_document__d_doc'))
        return JsonResponse({'results': results})
    
    paginator = Paginator(rcd, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    context = {
        'page_obj': page_obj,
        'center_doc_l': page_obj,
    }
    return render(request, 'main/administrador/center_doc_list.html', context)   

ALLOWED_FILTERS = ("name","login","email","time_in","time_out","status","profile")

@require_GET
@only_administrador
def user_list(request):
    is_ajax = (request.headers.get('X-Requested-With') == 'XMLHttpRequest')
    ajax_lenient = (settings.WAF_AJAX_MODE == 'lenient' and is_ajax)

    raw_qs = request.META.get("QUERY_STRING", "")
    if waf_raw_qs_guard(raw_qs):
        if is_ajax:
            return JsonResponse({'error': 'not acceptable'}, status=406, headers={'Cache-Control': 'no-store'})
        return render(request, 'others/acesso_negado.html', status=406)

    rep = inspect_dict(
        request.GET,
        allow_numeric=settings.WAF_NUMERIC_FIELDS,
        allow_safe=settings.WAF_SAFE_FIELDS,
        ajax=is_ajax,
    )
    if rep.get("block"):
        if is_ajax:
            return JsonResponse({'error': 'forbidden'}, status=403, headers={'Cache-Control': 'no-store'})
        return render(request, 'others/acesso_negado.html', status=403)

    if rep.get("warn") and not ajax_lenient:
        warn_on_search = any(k in settings.WAF_SAFE_FIELDS for (k, _cat, _ex) in rep["warn"])
        if warn_on_search:
            if is_ajax:
                return JsonResponse({'error': 'forbidden'}, status=403, headers={'Cache-Control': 'no-store'})
            return render(request, 'others/acesso_negado.html', status=403)

    params = {k: clean_search_q(request.GET.get(k)) for k in ALLOWED_FILTERS if request.GET.get(k)}
    qs = (Users.objects
          .exclude(u_profile="Sem Acesso")
          .only('u_id','u_name','u_login','u_email','u_time_in','u_time_out','u_profile','u_status')
          .order_by('u_id'))

    f = Q()
    if params.get('name'):     f &= Q(u_name__icontains=params['name'])
    if params.get('login'):    f &= Q(u_login__icontains=params['login'])
    if params.get('email'):    f &= Q(u_email__icontains=params['email'])
    if params.get('time_in'):  f &= Q(u_time_in__icontains=params['time_in'])
    if params.get('time_out'): f &= Q(u_time_out__icontains=params['time_out'])
    if params.get('status'):   f &= Q(u_status__icontains=params['status'])
    if params.get('profile'):  f &= Q(u_profile__icontains=params['profile'])
    qs = qs.filter(f)

    try:
        page = int(request.GET.get('page') or 1)
    except (TypeError, ValueError):
        page = 1

    paginator = Paginator(qs, 10)
    page_obj  = paginator.get_page(page)

    if is_ajax:
        results = [{
            'id': u.u_id,
            'name': u.u_name or '',
            'login': u.u_login or '',
            'email': u.u_email or '',
            'time_in':  u.u_time_in.strftime('%d/%m/%Y') if u.u_time_in else '',
            'time_out': u.u_time_out.strftime('%d/%m/%Y') if u.u_time_out else '',
            'profile': u.u_profile or '',
            'status':  u.u_status or '',
        } for u in page_obj]
        return JsonResponse({
            'results': results,
            'count': paginator.count,
            'start_index': page_obj.start_index(),
            'end_index': page_obj.end_index(),
            'num_pages': paginator.num_pages,
            'current_page': page_obj.number,
        }, headers={'Cache-Control': 'no-store'})

    return render(request, 'main/administrador/user_list.html', {
        'page_obj': page_obj,
        'users_l': page_obj,
    })
    
@require_http_methods(["GET","POST"])  
@only_administrador
def audit_list(request):
    audits = Audit.objects.all().order_by('-aud_id')
    filters = Q()
    if request.GET.get('cod'):
        filters &= Q(aud_id__icontains=request.GET['cod'])
    if request.GET.get('login'):
        filters &= Q(aud_login__icontains=request.GET['login'])
    if request.GET.get('profile'):
        filters &= Q(aud_profile__icontains=request.GET['profile'])
    if request.GET.get('action'):
        filters &= Q(aud_action__icontains=request.GET['action'])
    if request.GET.get('object'):
        filters &= Q(aud_obj_modified__icontains=request.GET['object'])
    if request.GET.get('description'):
        filters &= Q(aud_description__icontains=request.GET['description'])
    if request.GET.get('data_inserted'):
        filters &= Q(aud_data_inserted__icontains=request.GET['data_inserted'])
    audits = audits.filter(filters)
    
    paginator = Paginator(audits, 8)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        results = [{
            'aud_id': e.aud_id,
            'aud_login': e.aud_login,
            'aud_profile': e.aud_profile,
            'aud_action': e.aud_action,
            'aud_obj_modified': e.aud_obj_modified,
            'aud_description': e.aud_description,
            'aud_data_inserted': e.aud_data_inserted,
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

"""@only_administrador
def attachment_list(request):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')
    try:
        user = Users.objects.get(u_id=user_id, u_status='Ativo', u_profile="Administrador")
    except Users.DoesNotExist:
        messages.error(request, "Usuário não encontrado ou inativo.")
        return redirect('login')

    authorized_documents = Attachment.objects.values_list('att_doc', flat=True)
    latest_docs = Attachment.objects.filter(
        att_situation__in=["Regular", "Vencido", "A Vencer"],
        att_doc__in=authorized_documents
    ).values('att_doc', 'att_center').annotate(latest_date=Max('att_data_inserted'))

    query = Q()
    for item in latest_docs:
        query |= Q(att_doc=item['att_doc'], att_center=item['att_center'], att_data_inserted=item['latest_date'])

    attachments = Attachment.objects.filter(
        att_situation__in=["Regular", "Vencido", "A Vencer"]
    ).filter(query).order_by('att_center', '-att_data_inserted', '-att_situation')

    filters = {
        'document': request.GET.get('document', ''),
        'region': request.GET.get('region', ''),
        'state': request.GET.get('state', ''),
        'center': request.GET.get('center', ''),
        'data_inserted': request.GET.get('data_inserted', ''),
        'data_expire': request.GET.get('data_expire', ''),
        'situation': request.GET.get('situation', ''),
    }

    if filters['region']:
        attachments = attachments.filter(att_region__icontains=filters['region'])
    for key, value in filters.items():
        if value and key != 'region':
            attachments = attachments.filter(**{f"{key}__icontains": value})

    paginator = Paginator(attachments, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        center_filter = request.GET.get("center")
        filtered_results = [a for a in page_obj if a.att_center == center_filter] if center_filter else page_obj

        results = [{
            'id': a.att_id,
            'document': a.att_doc,
            'region': a.att_region,
            'state': a.att_state,
            'center': a.att_center,
            'data_inserted': a.att_data_inserted.strftime('%d/%m/%Y %H:%M') if a.att_data_inserted else '',
            'data_expire': a.att_data_expire.strftime('%d/%m/%Y') if a.att_data_expire else '',
            'situation': a.att_situation or '',
            'file_url': a.att_file.url if a.file else '',
            'document_attached': a.att_attached_by or '',
            'document_checked': a.att_checked_by or '',
            'data_conference': a.att_data_conference.strftime('%d/%m/%Y %H:%M') if a.att_data_conference else '',
            'unit_info': [{
                'unit': u.ndest_units,
                'cnpj': u.ndest_cnpj,
                'nire': u.ndest_nire,
                'registration_state': u.ndest_reg_state,
                'registration_municipal': u.ndest_reg_city,
            } for u in NumDocsEstab.objects.filter(ndest_fk_establishment__est_center=a.att_center)]
        } for a in filtered_results]

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
"""

@require_http_methods(["GET","POST"])
@only_administrador
def attachment_list(request):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')
    try:
        user = Users.objects.get(u_id=user_id, u_status='Ativo', u_profile="Administrador")
    except Users.DoesNotExist:
        messages.error(request, "Usuário não encontrado ou inativo.")
        return redirect('login')

    authorized_documents = Attachment.objects.values_list('att_doc', flat=True)
    latest_docs = Attachment.objects.filter(
        att_doc__in=authorized_documents,
        att_situation__in=["Regular", "Vencido", "A Vencer"]
    ).values('att_doc', 'att_center').annotate(latest_date=Max('att_data_inserted'))

    query = Q()
    for item in latest_docs:
        query |= Q(att_doc=item['att_doc'], att_center=item['att_center'], att_data_inserted=item['latest_date'])

    attachments = Attachment.objects.filter(att_situation__in=["Regular", "Vencido", "A Vencer"]).filter(query)

    filters = {
        'att_doc': request.GET.get('document', ''),
        'att_region': request.GET.get('region', ''),
        'att_state': request.GET.get('state', ''),
        'att_center': request.GET.get('center', ''),
        'att_data_inserted': request.GET.get('data_inserted', ''),
        'att_data_expire': request.GET.get('data_expire', ''),
        'att_situation': request.GET.get('situation', ''),
    }

    for key, value in filters.items():
        if value:
            attachments = attachments.filter(**{f"{key}__icontains": value})

    paginator = Paginator(attachments.order_by('att_center', '-att_data_inserted'), 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        results = [{
            'id': a.att_id,
            'document': a.att_doc,
            'region': a.att_region,
            'state': a.att_state,
            'center': a.att_center,
            'data_inserted': a.att_data_inserted.strftime('%d/%m/%Y %H:%M') if a.att_data_inserted else '',
            'data_expire': a.att_data_expire.strftime('%d/%m/%Y') if a.att_data_expire else '',
            'situation': a.att_situation,
            'conference': a.att_checked_by or '',
            'file_url': a.att_file.url if a.att_file else '',
            'attached_by': a.att_attached_by or '',
            'checked_by': a.att_checked_by or '',
            'data_conference': a.att_data_conference.strftime('%d/%m/%Y %H:%M') if a.att_data_conference else '',
            'unit_info': [{
                'unit': u.ndest_units,
                'cnpj': u.ndest_cnpj,
                'nire': u.ndest_nire,
                'registration_state': u.ndest_reg_state,
                'registration_municipal': u.ndest_reg_city,
            } for u in NumDocsEstab.objects.filter(ndest_fk_establishment__est_center=a.att_center)]
        } for a in page_obj]

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

@require_http_methods(["GET","POST"])
@only_administrador
def attachment_history_all(request):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')
    try:
        Users.objects.get(u_id=user_id, u_status='Ativo', u_profile='Administrador')
    except Users.DoesNotExist:
        messages.error(request, "Usuário não encontrado ou inativo.")
        return redirect('login')

    attachments = Attachment.objects.all()

    filters = {
        'att_doc': request.GET.get('document', ''),
        'att_region': request.GET.get('region', ''),
        'att_state': request.GET.get('state', ''),
        'att_center': request.GET.get('center', ''),
        'att_data_inserted': request.GET.get('data_inserted', ''),
        'att_data_expire': request.GET.get('data_expire', ''),
        'att_situation': request.GET.get('situation', ''),
    }

    for key, value in filters.items():
        if value:
            if key in ['att_data_inserted', 'att_data_expire']:
                attachments = attachments.filter(**{key: value})
            else:
                attachments = attachments.filter(**{f"{key}__icontains": value})

    paginator = Paginator(attachments, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        results = []
        for a in page_obj:
            units = NumDocsEstab.objects.filter(ndest_fk_establishment__est_center=a.att_center)
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
                'data_inserted': a.att_data_inserted.strftime('%d/%m/%Y %H:%M') if a.att_data_inserted else '',
                'data_expire': a.att_data_expire.strftime('%d/%m/%Y') if a.att_data_expire else '',
                'situation': a.att_situation,
                'conference': a.att_checked_by or '',
                'file_url': a.att_file.url if a.att_file else '',
                'attached_by': a.att_attached_by or '',
                'checked_by': a.att_checked_by or '',
                'data_conference': a.att_data_conference.strftime('%d/%m/%Y %H:%M') if a.att_data_conference else '',
                'unit_info': unit_info,
            })

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

    
"""

@only_administrador
def attachment_list(request):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')
    try:
        user = Users.objects.get(u_id=user_id, u_status='Ativo', u_profile='Administrador')
    except Users.DoesNotExist:
        messages.error(request, "Usuário não encontrado ou inativo.")
        return redirect('login')

    authorized_documents = Attachment.objects.values_list('att_doc', flat=True)
    latest_docs = Attachment.objects.filter(
        att_situation__in=["Regular", "Vencido", "A Vencer"],
        att_doc__in=authorized_documents
    ).values('att_doc', 'att_center').annotate(latest_date=Max('att_data_inserted'))

    query = Q()
    for item in latest_docs:
        query |= Q(document=item['document'], center=item['center'], data_inserted=item['latest_date'])

    attachments = Attachment.objects.filter(
        att_situation__in=["Regular", "Vencido", "A Vencer"]
    ).filter(query).order_by('att_center', '-att_data_inserted', '-att_situation')

    filters = {
        'document': request.GET.get('document', ''),
        'region': request.GET.get('region', ''),
        'state': request.GET.get('state', ''),
        'center': request.GET.get('center', ''),
        'data_inserted': request.GET.get('data_inserted', ''),
        'data_expire': request.GET.get('data_expire', ''),
        'situation': request.GET.get('situation', ''),
    }

    if filters['region']:
        attachments = attachments.filter(att_region__icontains=filters['region'])
    for key, value in filters.items():
        if value and key != 'region':
            attachments = attachments.filter(**{f"{key}__icontains": value})
    
    paginator = Paginator(attachments, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        center_filter = request.GET.get("center")
        filtered_results = [a for a in page_obj if a.center == center_filter] if center_filter else page_obj

        results = [{
            'id': a.att_id,
            'document': a.att_document,
            'region': a.att_region,
            'state': a.att_state,
            'center': a.att_center,
            'data_inserted': a.att_data_inserted.strftime('%d/%m/%Y %H:%M') if a.att_data_inserted else '',
            'data_expire': a.att_data_expire.strftime('%d/%m/%Y') if a.att_data_expire else '',
            'situation': a.att_situation or '',
            'file_url': a.att_file.url if a.file else '',
            'document_attached': a.att_document_attached or '',
            'document_checked': a.att_document_checked or '',
            'data_conference': a.att_data_conference.strftime('%d/%m/%Y %H:%M') if a.att_data_conference else '',
            'unit_info': [{
                'unit': u.ndest_units,
                'cnpj': u.ndest_cnpj,
                'nire': u.ndest_nire,
                'registration_state': u.ndest_reg_state,
                'registration_municipal': u.ndest_reg_city,
            } for u in NumDocsEstab.objects.filter(ndest_center=a.att_center)]
        } for a in filtered_results]

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
"""

@require_http_methods(["GET","POST"])
@only_administrador
def attachment_history(request, document, region, center=None):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')

    try:
        Users.objects.get(u_id=user_id, u_status='Ativo', u_profile='Administrador')
    except Users.DoesNotExist:
        messages.error(request, "Usuário não encontrado ou inativo.")
        return redirect('login')

    query = Q(att_doc=document, att_region=region)
    if center:
        query &= Q(att_center=center)

    attachments = Attachment.objects.filter(query)

    filters = {
        'att_state': request.GET.get('state', ''),
        'att_center': request.GET.get('center', ''),
        'att_data_inserted': request.GET.get('data_inserted', ''),
        'att_data_expire': request.GET.get('data_expire', ''),
        'att_situation': request.GET.get('situation', ''),
    }

    for key, value in filters.items():
        if value:
            if key in ['att_data_inserted', 'att_data_expire']:
                attachments = attachments.filter(**{key: value})
            else:
                attachments = attachments.filter(**{f"{key}__icontains": value})

    paginator = Paginator(attachments, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        results = []
        for a in page_obj:
            units = NumDocsEstab.objects.filter(ndest_fk_establishment__est_center=a.att_center)
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
                'data_inserted': a.att_data_inserted.strftime('%d/%m/%Y %H:%M') if a.att_data_inserted else '',
                'data_expire': a.att_data_expire.strftime('%d/%m/%Y') if a.att_data_expire else '',
                'situation': a.att_situation,
                'conference': a.att_checked_by or '',
                'file_url': a.att_file.url if a.att_file else '',
                'attached_by': a.att_attached_by or '',
                'checked_by': a.att_checked_by or '',
                'data_conference': a.att_data_conference.strftime('%d/%m/%Y %H:%M') if a.att_data_conference else '',
                'unit_info': unit_info,
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
    })

@require_http_methods(["GET","POST"])
@only_administrador
def establishment_attachment_list(request, region, center=None):
    filters = Q(att_region=region)
    if center:
        filters &= Q(att_center=center)

    latest_docs = (
        Attachment.objects.filter(filters)
        .values('att_doc', 'att_center', 'att_region')
        .annotate(latest_date=Max('att_data_inserted'))
    )
    
    query = Q()
    for item in latest_docs:
        query |= Q(att_doc=item['att_doc'], att_center=item['att_center'], att_region=item['att_region'], att_data_inserted=item['latest_date'])

    attachments = Attachment.objects.filter(query).order_by('att_center', '-att_data_inserted')
    state = request.GET.get('state', '')
    situation = request.GET.get('situation', '')
    data_expire = request.GET.get('data_expire', '')
    data_inserted = request.GET.get('data_inserted', '')

    if state:
        attachments = attachments.filter(att_state__icontains=state)
    if situation:
        attachments = attachments.filter(att_situation__icontains=situation)
    if data_expire:
        attachments = attachments.filter(att_data_expire__icontains=data_expire)
    if data_inserted:
        attachments = attachments.filter(att_data_inserted__icontains=data_inserted)
        

    paginator = Paginator(attachments, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        results = []
        for attachment in page_obj:
            results.append({
                'id': attachment.att_id,
                'document': attachment.att_doc,
                'region': attachment.att_region,
                'state': attachment.att_state,
                'center': attachment.att_center,
                'data_expire': attachment.att_data_expire.strftime('%d/%m/%Y') if attachment.data_expire else '',
                'situation': attachment.att_situation or '',
                'file_url': attachment.att_file.url if attachment.att_file else '',
                'document_attached': attachment.att_attached_by or '',
                'document_checked': attachment.att_checked_by or '',
                'data_inserted': timezone.localtime(attachment.att_data_inserted).strftime('%d/%m/%Y %H:%M') if attachment.att_data_inserted else '',
                'data_conference': timezone.localtime(attachment.att_data_conference).strftime('%d/%m/%Y %H:%M') if attachment.att_data_conference else '',
            })
        return JsonResponse({
            'results': results,
            'count': paginator.count,
            'start_index': page_obj.start_index(),
            'end_index': page_obj.end_index(),
            'num_pages': paginator.num_pages,
            'current_page': page_obj.number,
        })
    return render(request, 'main/administrador/establishment_attachment_list.html', {
        'page_obj': page_obj
    })
    
@require_http_methods(["GET","POST"])
@only_administrador
def number_doc_list(request):
    number_doc = NumDocsEstab.objects.all().order_by('ndest_id')
    filters = Q()
    
    if request.GET.get('center'):
        filters &= Q(ndest_fk_establishment__est_center__icontains=request.GET['center'])
    if request.GET.get('unit'):
        filters &= Q(ndest_units__icontains=request.GET['unit'])
    if request.GET.get('cnpj'):
        filters &= Q(ndest_cnpj__icontains=request.GET['cnpj'])
    if request.GET.get('nire'):
        filters &= Q(ndest_nire__icontains=request.GET['nire'])
    if request.GET.get('reg_city'):
        filters &= Q(ndest_reg_city__icontains=request.GET['reg_city'])
    if request.GET.get('reg_state'):
        filters &= Q(ndest_reg_state__icontains=request.GET['reg_state'])

    number_doc = number_doc.filter(filters)
    
    paginator = Paginator(number_doc, 8)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        results = [{
            'ndest_id': e.ndest_id,
            'ndest_fk_establishment__est_center': e.ndest_fk_establishment.est_center,
            'ndest_units': e.ndest_units, 
            'ndest_cnpj': e.ndest_cnpj, 
            'ndest_nire': e.ndest_nire,
            'ndest_reg_city': e.ndest_reg_city,
            'ndest_reg_state': e.ndest_reg_state,
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
        'cnpjs_l': page_obj,
    }
    return render(request, 'main/administrador/cnpj_list.html', context)

@require_http_methods(["GET","POST"])
def security_list(request):
    filters = {
        'sec_id': request.GET.get('id', '').strip(),
        'sec_action': request.GET.get('action', '').strip(),
        'sec_description': request.GET.get('description', '').strip(),
        'sec_ip': request.GET.get('ip', '').strip(),
        'sec_user_agent': request.GET.get('ua', '').strip(),
        'sec_payload': request.GET.get('payload', '').strip(),
        'sec_data': request.GET.get('date', '').strip(),
    }

    queryset = SecurityEvent.objects.all().order_by('-sec_data')

    if filters['sec_id']:
        queryset = queryset.filter(sec_id__icontains=filters['sec_id'])
    if filters['sec_action']:
        queryset = queryset.filter(sec_action__icontains=filters['sec_action'])
    if filters['sec_description']:
        queryset = queryset.filter(sec_description__icontains=filters['sec_description'])
    if filters['sec_ip']:
        queryset = queryset.filter(sec_ip__icontains=filters['sec_ip'])
    if filters['sec_user_agent']:
        queryset = queryset.filter(sec_user_agent__icontains=filters['sec_user_agent'])
    if filters['sec_payload']:
        queryset = queryset.filter(sec_payload__icontains=filters['sec_payload'])
    if filters['sec_data']:
        queryset = queryset.filter(sec_data__date=filters['sec_data'])

    paginator = Paginator(queryset, 15)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        results = []
        for e in page_obj:
            results.append({
                'sec_id': e.sec_id,
                'sec_action': e.sec_action,
                'sec_description': e.sec_description,
                'sec_ip': e.sec_ip,
                'sec_user_agent': e.sec_user_agent or '',
                'sec_payload': e.sec_payload or '',
                'sec_data': e.sec_data.strftime('%d/%m/%Y %H:%M')
            })

        return JsonResponse({
            'results': results,
            'count': paginator.count,
            'num_pages': paginator.num_pages,
            'current_page': page_obj.number,
            'start_index': page_obj.start_index(),
            'end_index': page_obj.end_index(),
        })

    return render(request, 'main/administrador/security_list.html', {
        'security_list': page_obj,
        'page_obj': page_obj,
    })