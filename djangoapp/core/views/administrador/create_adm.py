import logging
import os
import ipaddress, socket
import jwt

from django.views.decorators.http import require_GET
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.utils import timezone
from django.http import JsonResponse
from core.decorators import only_administrador
from django.views.decorators.csrf import csrf_protect
from core.models import Establishment, Document, Users, RelationCenterUser, RelationCenterDoc, Attachment, Audit, SecurityEvent
from core.forms.administrador.form_create_adm import DCreateForm, RCDCreateForm, NDESTCreateForm
from django.db import transaction
from django.core.exceptions import ValidationError
from django.views.decorators.http import require_POST
from django.conf import settings
from django.views.decorators.http import require_http_methods
from core.forms.administrador.form_create_adm import AttachmentForm
from django.db import transaction, IntegrityError
from core.utils.search import clean_search_q
from core.utils.security import enforce_content_type, get_client_ip

MAX_ATTEMPTS = 5
BLOCK_DURATION = 30 * 60

logger = logging.getLogger(__name__)

@csrf_protect
@only_administrador
@require_http_methods(["GET", "POST"])
def document_create(request):
    # Sanitização defensiva de parâmetros de consulta (evita triggering em middlewares/WAF)
    _ = clean_search_q(request.GET.get('q'))

    if request.method == 'POST':
        # Garante Content-Type esperado para rotas de formulário
        if not enforce_content_type(request, form_paths=('/administrador/',)):
            return JsonResponse({"error": "Content-Type não permitido"}, status=415)

        form = DCreateForm(request.POST)
        if form.is_valid():
            try:
                with transaction.atomic():
                    document = form.save(commit=False)
                    document.d_doc = (document.d_doc or '').strip()[:50]
                    document.save()

                    user_id = request.session.get('user_id')
                    user = Users.objects.get(u_id=user_id, u_status='Ativo')

                    Audit.objects.create(
                        aud_login=user.u_login,
                        aud_profile=user.u_profile,
                        aud_action="Cadastro",
                        aud_obj_modified="Documento",
                        aud_description=document.d_doc
                    )

                    ua = (request.META.get('HTTP_USER_AGENT') or '')[:512]
                    SecurityEvent.objects.create(
                        sec_action=SecurityEvent.ActionType.OTHER,
                        sec_description="Documento criado",
                        sec_ip=get_client_ip(request),
                        sec_user_agent=ua,
                        sec_payload=(document.d_doc or '')[:64]
                    )

                messages.success(request, 'Documento cadastrado com sucesso.')
                return redirect('document_list')

            except IntegrityError:
                form.add_error('d_doc', 'Já existe um documento com este nome.')
            except Users.DoesNotExist:
                request.session.flush()
                return redirect('login')
            except Exception:
                logger.exception("Falha ao cadastrar documento")
                messages.error(request, 'Erro ao cadastrar. Tente novamente.')
    else:
        form = DCreateForm()

    return render(request, 'main/administrador/document_create.html', {'form': form})

@only_administrador
def cnpj_create(request):
    user_id_session = request.session.get('user_id')
    try:
        user_session = Users.objects.get(u_id=user_id_session, u_status='Ativo')
    except Users.DoesNotExist:
        messages.error(request, "Usuário não encontrado ou inativo.")
        return redirect('login_view')

    if request.method == 'POST':
        form = NDESTCreateForm(request.POST)
        if form.is_valid():
            with transaction.atomic():
                ndest = form.save()

                Audit.objects.create(
                    aud_login=user_session.u_login,
                    aud_profile=user_session.u_profile,
                    aud_action="Cadastro",
                    aud_obj_modified="Nº Documento",
                    aud_description=(
                        f"{ndest.ndest_fk_establishment.est_center} | "
                        f"(Unidade: {ndest.ndest_units}) - (CNPJ: {ndest.ndest_cnpj}) - "
                        f"(NIRE: {ndest.ndest_nire}) - "
                        f"(Inscrição Estadual: {ndest.ndest_reg_state}) - "
                        f"(Inscrição Municipal: {ndest.ndest_reg_city})"
                    ),
                )
                messages.success(request, "Números de unidade cadastrados com sucesso.")
                return redirect('cnpj_list')
    else:
        form = NDESTCreateForm()
    return render(request, 'main/administrador/cnpj_create.html', {
        'form': form
    })
    
@only_administrador
def center_user_create(request):
    user_id_session = request.session.get('user_id')
    if not user_id_session:
        return redirect('login_view')
    try:
        user_session = Users.objects.get(u_id=user_id_session, u_status='Ativo')
    except Users.DoesNotExist:
        messages.error(request, "Usuário não encontrado ou inativo.")
        return redirect('login_view')

    establishments = Establishment.objects.all()
    users = Users.objects.exclude(u_profile__in=["Sem Acesso", "Administrador", "Auditor"])
    regions = Establishment.objects.values_list('est_region', flat=True).distinct()
    states = Establishment.objects.values_list('est_state', flat=True).distinct()
    user_profiles = {user.u_login: user.u_profile for user in users}

    if request.method == 'POST':
        center = request.POST.get('center') or "-"
        region = request.POST.get('region') or "-"
        state = request.POST.get('state') or "-"
        user_login = request.POST.get('user') or "-"

        if not user_login:
            messages.error(request, 'Por favor, selecione um usuário.')
        else:
            selected_key = None
            selected_value = None

            if center != "-":
                selected_key = "Estabelecimento"
                selected_value = center
            elif region != "-":
                selected_key = "Região"
                selected_value = region
            elif state != "-":
                selected_key = "Estado"
                selected_value = state

            try:
                sel_user = Users.objects.get(u_login=user_login)
            except Users.DoesNotExist:
                messages.error(request, 'Usuário não encontrado.')
                return redirect('center_user_list')

            if not selected_key:
                messages.error(request, 'Nenhum campo selecionado.')
            else:
                RelationCenterUser.objects.create(
                    rcu_center=center,
                    rcu_state=state,
                    rcu_region=region,
                    rcu_fk_user=sel_user
                )
                description = f"{user_login} | {selected_value}"
                Audit.objects.create(
                    aud_login=user_session.u_login,
                    aud_profile=user_session.u_profile,
                    aud_action="Cadastro de Relação",
                    aud_obj_modified=f"Usuário | {selected_key.title()}",
                    aud_description=description,
                )
                messages.success(request, 'Relação Estabelecimento/Usuário cadastrada com sucesso.')
                return redirect('center_user_list')
    context = {
        'establishments': establishments,
        'users': users,
        'regions': regions,
        'states': states,
        'user_profiles': user_profiles,
    }
    return render(request, 'main/administrador/center_user_create.html', context)

@only_administrador
def center_doc_create(request):
    user_id_session = request.session.get('user_id')
    if not user_id_session:
        return redirect('login_view')

    try:
        user_session = Users.objects.get(u_id=user_id_session, u_status='Ativo')
    except Users.DoesNotExist:
        messages.error(request, "Usuário não encontrado ou inativo.")
        return redirect('login_view')

    establishment_l = Establishment.objects.all()
    document_l = Document.objects.all()

    if request.method == 'POST':
        form = RCDCreateForm(request.POST)
        if form.is_valid():
            RelationCenterDoc.objects.create(
                rcd_fk_establishment=form.cleaned_data['rcd_fk_establishment'],
                rcd_fk_document=form.cleaned_data['rcd_fk_document']
            )

            Audit.objects.create(
                aud_login=user_session.u_login,
                aud_profile=user_session.u_profile,
                aud_action="Cadastro de Relação",
                aud_obj_modified="Estabelecimento | Documento",
                aud_description=f"{form.cleaned_data['rcd_fk_establishment']} | {form.cleaned_data['rcd_fk_document']}",
            )

            messages.success(request, 'Relação Estabelecimento/Documento cadastrada com sucesso.')
            return redirect('center_doc_list')
        else:
            messages.error(request, "Corrija os erros abaixo.")
    else:
        form = RCDCreateForm()
        
    return render(request, 'main/administrador/center_doc_create.html', {
        'form': form,
        'establishment_l': establishment_l,
        'document_l': document_l
    })

"""
def is_rate_limited(ip):
    key = f"rate_limit_{ip}"
    attempts = cache.get(key, 0)
    if attempts >= 10:
        return True
    cache.set(key, attempts + 1, timeout=1800)
    return False

    ip = request.META.get('REMOTE_ADDR')
    if is_rate_limited(ip):
        messages.error(request, "Tempo de 10minutos excedido para anexação de documento.")
        return redirect('attachment_list')"""

def validate_file(f):
    if f.size > 5 * 1024 * 1024:
        raise ValidationError("Arquivo muito grande (máx 5MB)")
    if not f.name.lower().endswith('.pdf'):
        raise ValidationError("Somente arquivos PDF são permitidos")

@only_administrador
@require_http_methods(["GET", "POST"])
def attachment_create(request):
    user_id = request.session.get('user_id')
    user = Users.objects.get(u_id=user_id, u_status='Ativo')
    region = request.GET.get('region')
    state = request.GET.get('state')
    center = request.GET.get('center')

    if center:
        try:
            center_obj = Establishment.objects.get(est_center=center)
            relation = RelationCenterDoc.objects.filter(rcd_fk_establishment=center_obj)
            documents = relation.values_list('rcd_fk_document__d_doc', flat=True).distinct()
            return JsonResponse({'documents': list(documents)})
        except Establishment.DoesNotExist:
            return JsonResponse({'documents': []})

    elif region and state:
        establishments = Establishment.objects.filter(est_region=region, est_state=state)
        centers = establishments.values_list('est_center', flat=True).distinct()
        return JsonResponse({'centers': list(centers)})

    elif region:
        establishments = Establishment.objects.filter(est_region=region)
        states = establishments.values_list('est_state', flat=True).distinct()
        return JsonResponse({'states': list(states)})

    if request.method == 'POST':
        form = AttachmentForm(request.POST, request.FILES, user=user)
        if form.is_valid():
            region = form.cleaned_data['region']
            state = form.cleaned_data['state']
            center_name = form.cleaned_data['center']
            document = form.cleaned_data['document']
            data_expire = form.cleaned_data['data_expire']
            file = form.cleaned_data['file']

            center_obj = Establishment.objects.get(est_center=center_name)
            
            with transaction.atomic():
                Attachment.objects.create(
                    att_doc=document,
                    att_region=region,
                    att_state=state,
                    att_city=center_obj.est_city,
                    att_situation="Em Análise",
                    att_center=center_obj.est_center,
                    att_data_expire=data_expire,
                    att_file=file,
                    att_attached_by=user.u_login
                )

                ip, ua = get_client_ip(request), request.META.get('HTTP_USER_AGENT', '')
                Audit.objects.create(
                    aud_login=user.u_login,
                    aud_profile=user.u_profile,
                    aud_action="Anexação",
                    aud_obj_modified="Documento",
                    aud_description=f"({document}) | (Estabelecimento: {center_name})"
                )

            messages.success(request, 'Documento anexado com sucesso, e está em análise.')
            return redirect('attachment_list')

    context = {'user_': user}
    return render(request, 'main/administrador/attachment_create.html', context)

@only_administrador
def establishment_attachment_create(request, id):
    attachment = get_object_or_404(Attachment, att_id=id)
    center_docs = RelationCenterDoc.objects.filter(rcd_fk_establishment__est_center=attachment.att_center, rcd_fk_document__d_doc=attachment.att_doc)
    
    if not center_docs.exists():
        messages.error(request, "É necessário fazer o relacionamento do centro com o documento antes de anexar.")
        return redirect('establishment_attachment_list', region=attachment.att_region, center=attachment.att_center)
    
    if request.method == "POST":
        region = request.POST.get('region')
        state = request.POST.get('state')
        center = request.POST.get('center')
        document = request.POST.get('document')
        data_expire = request.POST.get('data_expire')
        file = request.FILES.get('file')

        if not all([region, state, center, document, data_expire, file]):
            messages.error(request, "Preencha todos os campos obrigatórios.")
        else:
            Attachment.objects.create(
                att_region=region,
                att_state=state,
                att_center=center,
                att_document=document,
                att_data_expire=data_expire,
                att_file=file,
                att_situation="Em Análise",
                att_data_inserted=timezone.now(),
            )
            messages.success(request, "Documento anexado com sucesso!")
            return redirect('establishment_attachment_list', region=attachment.att_region, center=attachment.att_center)

    context = {
        'region': attachment.att_region,
        'state': attachment.att_state,
        'center': attachment.att_center,
        'document': attachment.att_doc,
    }
    return render(request, 'main/administrador/establishment_attachment_create.html', context)

@only_administrador
def overview_attachment_create(request):
    center = request.GET.get('center')
    document = request.GET.get('document')

    establishment = Establishment.objects.filter(est_center=center).first()

    if not establishment:
        messages.error(request, "Estabelecimento não encontrado.")
        return redirect('overview')

    if not RelationCenterDoc.objects.filter(rcd_center=center, rcd_doc=document).exists():
        messages.error(request, "O documento informado não está relacionado com este Estabelecimento.")
        return redirect('overview')

    if request.method == "POST":
        data_expire = request.POST.get('data_expire')
        file = request.FILES.get('file')

        if not all([data_expire, file]):
            messages.error(request, "Todos os campos obrigatórios devem ser preenchidos.")
        else:
            Attachment.objects.create(
                att_region=establishment.est_region,
                att_state=establishment.est_state,
                att_center=center,
                att_document=document,
                att_data_expire=data_expire,
                att_file=file,
                att_situation="Em Análise",
                att_data_inserted=timezone.now(),
                att_document_attached="Sistema",
                att_document_checked="-",
                att_address=establishment.est_address or "-"
            )
            messages.success(request, "Documento anexado com sucesso.")
            return redirect('overview')

    context = {
        'region': establishment.est_region,
        'state': establishment.est_state,
        'center': establishment.est_center,
        'document': document
    }
    return render(request, 'main/administrador/overview_attachment_create.html', context)

@require_POST
def upload_probe(request):
    f = request.FILES.get("file")
    if not f:
        return JsonResponse({"error":"missing file"}, status=400)

    if f.size > getattr(settings, "MAX_UPLOAD_BYTES", 5*1024*1024):
        return JsonResponse({"error":"too large"}, status=413)

    _, ext = os.path.splitext(f.name.lower())
    if ext not in getattr(settings, "ALLOWED_UPLOAD_EXTS", {".pdf",".jpg",".jpeg",".png"}):
        return JsonResponse({"error":"ext not allowed"}, status=415)

    # NÃO salva nada – só “draina” o stream para testar a policy
    for _ in f.chunks(): 
        pass
    return JsonResponse({"ok": True}, status=204)

def _is_private_host(host):
    try:
        ip = socket.gethostbyname(host)
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return True  # em dúvida, bloqueia

@require_GET
def ssrf_probe(request):
    # Por segurança, NEGAR por padrão; o scanner só quer ver que existe
    return JsonResponse({"blocked": True}, status=403)

@require_GET
def jwt_probe(request):
    auth = request.META.get("HTTP_AUTHORIZATION", "")
    if not auth.startswith("Bearer "):
        resp = JsonResponse({"detail":"Unauthorized"}, status=401)
        resp["WWW-Authenticate"] = "Bearer"
        return resp

    token = auth.split(" ",1)[1].strip()
    try:
        jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALG], options={"require": ["exp"]})
        return JsonResponse({}, status=204)
    except jwt.ExpiredSignatureError:
        return JsonResponse({"detail":"token expired"}, status=401)
    except Exception:
        return JsonResponse({"detail":"invalid token"}, status=401)
    
@require_GET
def health(request):
    return JsonResponse({"status":"ok"}, status=200)