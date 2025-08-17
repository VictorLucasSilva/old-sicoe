from django.shortcuts import render, redirect, get_object_or_404
from django.http import FileResponse, Http404
from django.core.paginator import Paginator
from django.http import JsonResponse
from django.contrib import messages
from django.utils import timezone
from core.models import Establishment, Document, Users, Attachment, Audit, NumDocsEstab
from core.forms.administrador.form_create_adm import UCreateForm
from django.views.decorators.http import require_GET
from core.decorators import only_administrador
import requests
import os

MAX_ATTEMPTS = 5
BLOCK_DURATION = 30 * 60
    
def get_estab(estab_id:str) -> dict:
    api_url = "http://apis.bbts.com.br:8000/psft/estabelecimentos/v1"
    headers = {
        'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJEUFloUDNYQ0VEekk4VVcwSWU2SmJVMDU2Ykg3TU1aWSJ9.IqqVjIx9u5wVfCfP5a6SXwUCmsf5oQNnjmlO_bXVKCE'
    }
    response = requests.get(api_url, headers=headers)
    if response.status_code != 200:
        return {}

    data = response.json()
    establishments = data.get('results', [])
    return JsonResponse({'establis': data})

"""
@require_GET
@only_administrador
def fetch_states(request):
    region = request.GET.get('region')
    establishments = Establishment.objects.filter(est_region=region)
    states = establishments.values_list('est_state', flat=True).distinct()
    return JsonResponse({'states': list(states)})

@require_GET
@only_administrador
def fetch_centers(request):
    region = request.GET.get('region')
    state = request.GET.get('state')
    establishments = Establishment.objects.filter(est_region=region, est_state=state)
    centers = establishments.values_list('est_center', flat=True).distinct()
    return JsonResponse({'centers': list(centers)})

@require_GET
@only_administrador
def fetch_documents(request):
    center_name = request.GET.get('center')
    try:
        center = Establishment.objects.get(est_center=center_name)
        relation = RelationCenterDoc.objects.filter(rcd_fk_establishment=center)
        documents = relation.values_list('rcd_fk_document__d_doc', flat=True)
        return JsonResponse({'documents': list(documents)})
    except Establishment.DoesNotExist:
        return JsonResponse({'documents': []})
"""

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
@only_administrador
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
    establishments = Establishment.objects.all()
    documents = Document.objects.all()
    document = request.GET.get('document', '')
    region = request.GET.get('region', '')
    state = request.GET.get('state', '')
    center = request.GET.get('center', '')
    data_expire = request.GET.get('data_expire', '')
    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
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
        results = list(attachments.values('att_id', 'att_doc', 'att_region', 'att_state', 'att_center', 'att_data_expire', 'att_file'))
        return JsonResponse({'results': results})
    paginator = Paginator(attachments, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    context = {
        'page_obj': page_obj,
        'attachment_h_all': attachments,
        'establishment_h_all': establishments,
        'document_h_all': documents,
    }
    return render(request, 'main/administrador/attachment_conference.html', context)

@only_administrador
def attachment_validation(request, id):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login_view')
    try:
        user = Users.objects.get(u_id=user_id, u_status='Ativo')
    except Users.DoesNotExist:
        messages.error(request, "Usuário não encontrado ou inativo.")
        return redirect('login_view')
    attachment = get_object_or_404(Attachment, att_id=id)
    if request.method == 'POST':
        est = Establishment.objects.filter(est_center=attachment.att_center).first()
        region = est.est_region if est else ""
        city = est.est_city if est else ""
        state = est.est_state if est else ""
        description = f"({attachment.att_doc}) >>> (Estabelecimento: {attachment.att_center})"
        if all([user.u_login, user.u_profile, region, city, state]):
            Audit.objects.create(
                aud_login=user.u_login,
                aud_profile=user.u_profile,
                aud_action="Validação",
                aud_obj_modified="Documento",
                aud_description=description,
            )
        attachment.att_situation = "Regular"
        attachment.att_data_conference = timezone.now()
        attachment.att_checked_by = user.u_login
        attachment.save()
        return JsonResponse({'success': True, 'message': 'Documento validado com sucesso!'})
    return JsonResponse({'success': False, 'message': 'Método inválido'})

"""
@only_administrador
def attachment_invalidation(request, id):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login_view')
    try:
        user = Users.objects.get(u_id=user_id, u_status='Ativo')
    except Users.DoesNotExist:
        messages.error(request, "Usuário não encontrado ou inativo.")
        return redirect('login_view')
    attachment = get_object_or_404(Attachment, att_id=id)
    if request.method == 'POST':
        est = Establishment.objects.filter(est_center=attachment.att_center).first()
        region = est.est_region if est else ""
        city = est.est_city if est else ""
        state = est.est_state if est else ""
        description = f"{attachment.att_doc}  ({attachment.att_center})"
        if all([user.u_login, user.u_profile, region, city, state]):
            Audit.objects.create(
                aud_login=user.u_login,
                aud_profile=user.u_profile,
                aud_action="Invalidação",
                aud_obj_modified="Documento",
                aud_description=description,
            )
        attachment.att_situation = "Invalidado"
        attachment.att_data_conference = timezone.now()
        attachment.att_checked_by = user.u_login
        attachment.save()
        return JsonResponse({'success': True, 'message': 'Documento invalidado com sucesso!'})
    return JsonResponse({'success': False, 'message': 'Método inválido'})
"""

@only_administrador
def user_access(request):
    user_id_session = request.session.get('user_id')
    if not user_id_session:
        return redirect('login_view')

    try:
        user_session = Users.objects.get(u_id=user_id_session, u_status='Ativo')
    except Users.DoesNotExist:
        messages.error(request, "Usuário não encontrado ou inativo.")
        return redirect('login_view')

    users_list = Users.objects.filter(u_profile="Sem Acesso")

    if request.method == 'POST':
        user_id_post = request.POST.get('user_id')
        user_obj = get_object_or_404(Users, pk=user_id_post)

        form = UCreateForm(request.POST, instance=user_obj)
        if form.is_valid():
            user = form.save(commit=False)
            user.u_time_in = timezone.now().date()
            user.save()

            description = (
                f"Login({user.u_login}) - Perfil({user.u_profile}) "
                f"- Data Saída({user.u_time_out.strftime('%d/%m/%Y')})"
            )

            Audit.objects.create(
                aud_login=user_session.u_login,
                aud_profile=user_session.u_profile,
                aud_action="Liberação de Acesso",
                aud_obj_modified="Usuário",
                aud_description=description,
            )

            messages.success(request, "Acesso liberado com sucesso.")
            return redirect('user_list')
        else:
            messages.error(request, "Corrija os erros abaixo.")
    else:
        form = UCreateForm()

    return render(request, 'main/administrador/user_access.html', {
        'form': form,
        'users_list': users_list
    })
