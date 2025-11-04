from django.shortcuts import render, redirect, get_object_or_404
from django.http import FileResponse, Http404
from django.core.paginator import Paginator
from django.http import JsonResponse
from django.contrib import messages
from django.utils import timezone
from core.models import Establishment, Document, Attachment, Audit, NumDocsEstab
from django.views.decorators.http import require_http_methods, require_GET
from core.decorators import only_administrador
from django.db import transaction
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
import requests
import os
import logging
import requests
from django.db import transaction

logger = logging.getLogger("core")

MAX_ATTEMPTS = 5
BLOCK_DURATION = 30 * 60

def apiestab(estab_id:str) -> dict:
    api_url = "http://apis.bbts.com.br:8000/psft/estabelecimentos/v2"
    headers = {
        'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJEUFloUDNYQ0VEekk4VVcwSWU2SmJVMDU2Ykg3TU1aWSJ9.IqqVjIx9u5wVfCfP5a6SXwUCmsf5oQNnjmlO_bXVKCE'
    }
    response = requests.get(api_url, headers=headers)
    if response.status_code != 200:
        return {}

    data = response.json()
    return JsonResponse({'dept_id': data})

import os
import logging
import requests
from django.http import JsonResponse
from django.views.decorators.http import require_GET

PSFT_FUNC_URL = os.getenv("PSFT_FUNC_URL", "http://apis.bbts.com.br:8000/psft/funcionarios/v3")
PSFT_TOKEN    = os.getenv("PSFT_TOKEN", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJEUFloUDNYQ0VEekk4VVcwSWU2SmJVMDU2Ykg3TU1aWSJ9.IqqVjIx9u5wVfCfP5a6SXwUCmsf5oQNnjmlO_bXVKCE")
TIMEOUT       = 120
PAGE          = 3
PAGE_SIZE     = 50

def _headers(post: bool = False):
    h = {"Accept": "application/json"}
    if post:
        h["Content-Type"] = "application/json"
    if PSFT_TOKEN:
        h["Authorization"] = f"Bearer {PSFT_TOKEN}"
    return h

def _extrair(payload: dict):
    # tenta várias chaves possíveis
    dados = (
        payload.get("lsFuncionarios")
        or payload.get("funcionarios")
        or payload.get("data")
        or []
    )
    # tenta descobrir a página retornada
    cur_page = None
    try:
        ip = payload.get("inPaginacao") or {}
        cur_page = ip.get("nrPaginaAtual")
        if cur_page is None:
            cur_page = payload.get("nrPaginaAtual") or payload.get("page")
        if cur_page is not None:
            cur_page = int(cur_page)
    except Exception:
        cur_page = None
    return dados, cur_page

# views.py
import os, logging, requests
from django.http import JsonResponse
from django.views.decorators.http import require_GET

PAGE_TARGET = 3          # queremos a página 3
PAGE_SIZE   = 50
TIMEOUT     = 120

def _pick_url():
    return (
        os.getenv("PSFT_FUNCIONARIO_URL")
        or os.getenv("PSFT_FUNC_URL")
        or "http://apis.bbts.com.br:8000/psft/funcionarios/v3"
    )

def _pick_token():
    return os.getenv("PSFT_API_TOKEN") or os.getenv("PSFT_TOKEN") or ""

def _headers():
    h = {"Accept": "application/json"}
    tok = _pick_token()
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h

def _extract(payload: dict):
    lista = payload.get("lsFuncionarios") or payload.get("data") or []
    ip    = payload.get("inPaginacao") or {}
    cur   = ip.get("nrPaginaAtual")
    try:
        cur = int(cur) if cur is not None else None
    except Exception:
        cur = None
    return lista, cur, ip

@require_GET
def funcionarios_pagina3(request):
    URL = _pick_url()
    debugs = []
    last_err = None

    # Estratégias com página 3 (base-1)
    attempts = [
        ("GET_brackets", {"inPaginacao[nrPaginaAtual]": PAGE_TARGET, "inPaginacao[nrTamanhoPagina]": PAGE_SIZE}),
        ("GET_dotted",   {"inPaginacao.nrPaginaAtual": PAGE_TARGET,  "inPaginacao.nrTamanhoPagina": PAGE_SIZE}),
        ("GET_flat",     {"nrPaginaAtual": PAGE_TARGET,              "nrTamanhoPagina": PAGE_SIZE}),
    ]

    # Se falhar, tenta base-0 (terceira página => 2)
    attempts_base0 = [
        ("GET_brackets_base0", {"inPaginacao[nrPaginaAtual]": PAGE_TARGET - 1, "inPaginacao[nrTamanhoPagina]": PAGE_SIZE}),
        ("GET_dotted_base0",   {"inPaginacao.nrPaginaAtual": PAGE_TARGET - 1,  "inPaginacao.nrTamanhoPagina": PAGE_SIZE}),
        ("GET_flat_base0",     {"nrPaginaAtual": PAGE_TARGET - 1,              "nrTamanhoPagina": PAGE_SIZE}),
    ]

    for label, params in attempts + attempts_base0:
        try:
            resp = requests.get(URL, params=params, headers=_headers(), timeout=TIMEOUT)
            info = {"estrategia": label, "status": resp.status_code, "url": getattr(resp, "url", URL)}
            debugs.append(info)

            resp.raise_for_status()
            payload = resp.json()

            lista, cur_page, ip = _extract(payload)

            # Log útil no container
            logging.warning("PSFT • Funcionários • solicitado=%s, retornado=%s via %s",
                            PAGE_TARGET, cur_page, label)

            if cur_page == PAGE_TARGET:
                return JsonResponse(lista, safe=False)

        except requests.exceptions.Timeout:
            last_err = {"tipo": "timeout", "estrategia": label}
        except requests.exceptions.RequestException as e:
            last_err = {"tipo": "http", "estrategia": label, "detalhe": str(e)}
        except ValueError:
            last_err = {"tipo": "json_invalido", "estrategia": label}
        except Exception as e:
            last_err = {"tipo": "erro_desconhecido", "estrategia": label, "detalhe": str(e)}

    # Nada bateu nrPaginaAtual == 3
    return JsonResponse(
        {
            "ok": False,
            "erro": "A API não retornou nrPaginaAtual == 3 em nenhuma estratégia.",
            "debug": debugs,
            "dicas": [
                "Use notação de colchetes no GET: inPaginacao[nrPaginaAtual]=3&inPaginacao[nrTamanhoPagina]=50.",
                "Se a paginação for base-0, peça 2 para obter a terceira página.",
                "Gateways/proxies costumam ignorar chaves com ponto — prefira colchetes.",
                "Confirme se há filtros obrigatórios (ex.: tpSituacao), sem os quais a API ‘reseta’ a paginação.",
            ],
            "ultimo_erro": last_err,
        },
        status=502,
    )







@require_GET
@only_administrador
def secure_pdf_view(request, attachment_id):
    user_profile = request.session.get('user_profile')
    if user_profile not in ['Administrador']:
        return render(request, 'main/administrador/acesso_negado.html', status=403)

    attachment = get_object_or_404(Attachment, att_id=attachment_id)
    file_path = attachment.att_file.path

    if not os.path.exists(file_path):
        raise Http404("Arquivo não encontrado")

    response = FileResponse(open(file_path, 'rb'), content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="{os.path.basename(file_path)}"'
    response['X-Content-Type-Options'] = 'nosniff'
    response['X-Frame-Options'] = 'DENY'
    response['Content-Security-Policy'] = "default-src 'none';"
    return response

@require_GET
def attachment_units_by_center(request):
    center_name = request.GET.get('center')
    if not center_name:
        return JsonResponse({"error": "Centro não informado"}, status=400)
    try:
        est = Establishment.objects.get(est_center=center_name)
        num_docs = NumDocsEstab.objects.filter(ndest_fk_establishment=est)
        units = list(num_docs.values('ndest_units', 'ndest_cnpj', 'ndest_nire', 'ndest_reg_city', 'ndest_reg_state'))
        return JsonResponse({'units': units})
    except Establishment.DoesNotExist:
        return JsonResponse({'units': []})

@only_administrador
def attachment_conference(request):
    attachments = Attachment.objects.filter(att_situation="Em Análise")
    
    document    = (request.GET.get('document') or '').strip()
    region      = (request.GET.get('region') or '').strip()
    state       = (request.GET.get('state') or '').strip()
    center      = (request.GET.get('center') or '').strip()
    data_expire = (request.GET.get('data_expire') or '').strip() 

    if document and document != "1":
        attachments = attachments.filter(att_doc=document)
    if region and region != "1":
        attachments = attachments.filter(att_region=region)
    if state and state != "1":
        attachments = attachments.filter(att_state=state)
    if center and center != "1":
        attachments = attachments.filter(att_center=center)
    if data_expire:
        attachments = attachments.filter(att_data_expire=data_expire)
        
    attachments = attachments.order_by('-att_data_inserted', 'att_center', 'att_doc')

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
            results.append({
                'att_id'         : a.att_id,
                'att_doc'        : a.att_doc,
                'att_region'     : a.att_region,
                'att_state'      : a.att_state,
                'att_center'     : a.att_center,
                'att_data_expire': a.att_data_expire.strftime('%d/%m/%Y') if a.att_data_expire else '',
                'att_file'       : getattr(a.att_file, 'url', ''), 
                'data_inserted'  : fmt_dt(a.att_data_inserted),
                'attached_by'    : a.att_attached_by or '',
            })

        return JsonResponse({
            'results'      : results,
            'count'        : paginator.count,
            'start_index'  : page_obj.start_index(),
            'end_index'    : page_obj.end_index(),
            'num_pages'    : paginator.num_pages,
            'current_page' : page_obj.number,
        })

    context = {
        'page_obj'        : page_obj,     
        'document_h_all'  : Document.objects.all(),
        'establishment_h_all': Establishment.objects.all(),
    }
    return render(request, 'main/administrador/attachment_conference.html', context)


def _get_user_profile(user):
    if hasattr(user, 'u_profile') and user.u_profile:
        return user.u_profile
    if user.is_superuser or user.groups.filter(name='Administrador').exists():
        return 'Administrador'
    return user.groups.values_list('name', flat=True).first() or '-'


@only_administrador
@require_http_methods(["POST"])
def attachment_validation(request, id: int):
    if getattr(request.user, 'u_status', 'Inativo') != 'Ativo':
        return JsonResponse(
            {'success': False, 'message': 'Usuário inativo.'},
            status=403
        )
    try:
        with transaction.atomic():
            attachment = Attachment.objects.select_for_update().get(att_id=id)

            if attachment.att_situation != "Em Análise":
                return JsonResponse(
                    {
                        'success': False,
                        'message': f"Não é possível validar: status atual é '{attachment.att_situation}'."
                    },
                    status=409 
                )

            attachment.att_situation = "Regular"
            attachment.att_data_conference = timezone.now()
            attachment.att_checked_by = request.user.get_username()
            attachment.save(update_fields=["att_situation", "att_data_conference", "att_checked_by"])
            est = (Establishment.objects
                   .filter(est_center=attachment.att_center)
                   .values('est_region', 'est_city', 'est_state')
                   .first()) or {}
            region = est.get('est_region') or "-"
            city   = est.get('est_city')   or "-"
            state  = est.get('est_state')  or "-"
            try:
                Audit.objects.create(
                    aud_login=request.user.get_username(),
                    aud_profile=_get_user_profile(request.user),
                    aud_action="Validação",
                    aud_obj_modified="Anexo",
                    aud_description=f"{attachment.att_doc} • {attachment.att_center}"
                )
            except Exception:
                pass
        return JsonResponse(
            {'success': True, 'message': 'Documento validado com sucesso!', 'status': attachment.att_situation},
            status=200
        )
    except Attachment.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Anexo não encontrado.'}, status=404)
    except Exception:
        return JsonResponse({'success': False, 'message': 'Erro ao validar o documento.'}, status=500)

def _parse_date_from_input(texto: str):
    if not texto:
        raise ValueError("vazio")
    try:
        dd, mm, yyyy = texto.strip().split("/")
        tz = timezone.get_current_timezone()
        return timezone.datetime(int(yyyy), int(mm), int(dd), tzinfo=tz).date()
    except Exception:
        raise ValueError("formato")

def _admin_identity_for_audit(request):
    u = request.user
    login = u.get_username() or (u.email or "")
    if u.is_superuser or u.groups.filter(name="Administrador").exists():
        profile = "Administrador"
    elif u.groups.filter(name="Auditor").exists():
        profile = "Auditor"
    elif u.groups.filter(name="Gerente Regional").exists():
        profile = "Gerente Regional"
    elif u.groups.filter(name="Usuário").exists():
        profile = "Usuário"
    else:
        profile = "Sem Acesso"
    return login, profile

@only_administrador
@require_http_methods(["GET", "POST"])
def user_access(request):
    User = get_user_model()
    today = timezone.localdate()
    dj_sem_acesso = (
        User.objects.filter(groups__name="Sem Acesso")
        .order_by("first_name", "last_name", "username")
        .only("id", "username", "email", "first_name", "last_name", "is_active")
    )

    if request.method == "GET":
        return render(request, "main/administrador/user_access.html", {
            "dj_sem_acesso": dj_sem_acesso,
            "today": today,
        })

    profile_post  = (request.POST.get("profile") or "").strip()          
    status_post   = (request.POST.get("status") or "").strip()            
    time_out_post = (request.POST.get("time_out") or "").strip()          
    auth_user_id  = (request.POST.get("auth_user_id") or "").strip()      

    if not auth_user_id:
        messages.error(request, "Selecione um usuário.")
        return render(request, "main/administrador/user_access.html", {
            "dj_sem_acesso": dj_sem_acesso, "today": today,
        })

    if status_post not in {"Ativo", "Inativo"}:
        messages.error(request, "Status inválido.")
        return render(request, "main/administrador/user_access.html", {
            "dj_sem_acesso": dj_sem_acesso, "today": today,
        })

    try:
        new_group = Group.objects.get(name=profile_post)
    except Group.DoesNotExist:
        messages.error(request, "Perfil inválido (grupo não encontrado).")
        return render(request, "main/administrador/user_access.html", {
            "dj_sem_acesso": dj_sem_acesso, "today": today,
        })

    try:
        time_out_date = _parse_date_from_input(time_out_post)
    except ValueError:
        messages.error(request, "Data de saída inválida. Use o formato DD/MM/AAAA.")
        return render(request, "main/administrador/user_access.html", {
            "dj_sem_acesso": dj_sem_acesso, "today": today,
        })

    if time_out_date < today:
        messages.error(request, "A data de saída não pode ser anterior a hoje.")
        return render(request, "main/administrador/user_access.html", {
            "dj_sem_acesso": dj_sem_acesso, "today": today,
        })

    try:
        target = User.objects.get(pk=int(auth_user_id))
    except (ValueError, User.DoesNotExist):
        messages.error(request, "Usuário inválido.")
        return render(request, "main/administrador/user_access.html", {
            "dj_sem_acesso": dj_sem_acesso, "today": today,
        })

    with transaction.atomic():
        target.groups.set([new_group]) 
        target.is_active = (status_post == "Ativo")

        if hasattr(target, "u_status"):
            target.u_status = status_post
        if hasattr(target, "u_time_in"):
            target.u_time_in = today
        if hasattr(target, "u_time_out"):
            target.u_time_out = time_out_date

        target.save()
        admin_login, admin_profile = _admin_identity_for_audit(request)
        desc = (
            f"Login({target.get_username() or target.email}) • "
            f"Perfil({new_group.name}) • "
            f"Status({status_post}) • "
            f"Data Saída({time_out_date.strftime('%d/%m/%Y')}"
        )
        Audit.objects.create(
            aud_login=admin_login,
            aud_profile=admin_profile,
            aud_action="Liberação de Acesso",
            aud_obj_modified="Usuário (auth)",
            aud_description=desc,
        )

    messages.success(
        request,
        f"Acesso liberado para {target.get_full_name() or target.username} ({target.username})."
    )
    return redirect('user_list')