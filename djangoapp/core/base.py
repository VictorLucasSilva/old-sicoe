import logging
import os

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.http import FileResponse, Http404
from django.contrib.auth.decorators import login_required
from core.models import Attachment, Audit

logger = logging.getLogger(__name__)

MAX_ATTEMPTS = 3           
BLOCK_DURATION = 60        

def get_redirect_url_by_group(request):
    
    user = request.user
    if not user.is_authenticated:
        return 'login'

    group_to_url = {
        'Administrador':      'attachment_list',           
        'Auditor':            'attachment_list_audit',
        'Gerente Regional':   'attachment_list_manager',
        'Usuário':            'attachment_list_user',
    }

    for group_name, url_name in group_to_url.items():
        if user.groups.filter(name=group_name).exists():
            return url_name

    if user.groups.filter(name='Sem Acesso').exists():
        messages.warning(request, "Enviar email para: app-sicoe@bbts.com.br, solicitando acesso. (Com motivo e estabelecimento desejado)")
        return 'login'

    Audit.objects.create(
        aud_login=request.user.get_username(),
        aud_profile=profile,
        aud_action="Acesso",
        aud_obj_modified="Entrada",
        aud_description=f"{request.user.get_username()} Entrou no sistema."
    )
    
    groups = list(request.user.groups.values_list('name', flat=True))
    if request.user.is_superuser or 'Administrador' in groups:
        profile = 'Administrador'
    else:
        profile = ', '.join(groups) or '-'

    messages.warning(request, "Seu usuário não possui perfil configurado.")
    return 'login'

def login_view(request):
    return render(request, "others/login.html")

@login_required
def post_login_redirect(request):
    return redirect(get_redirect_url_by_group(request))

def request_access(request):
    return render(request, "others/solicitar_acesso.html")

def secure_pdf_view(request, attachment_id):
    user_profile = request.session.get('user_profile')
    if user_profile not in ['Usuário', 'Administrador', 'Auditor', 'Gerente Regional']:
        return render(request, 'others/acesso_negado.html', status=403)

    attachment = get_object_or_404(Attachment, att_id=attachment_id)
    file_attr = getattr(attachment, 'att_file', None) or getattr(attachment, 'file', None)
    if not file_attr:
        raise Http404("Arquivo não encontrado")
    file_path = getattr(file_attr, 'path', None)
    if not (file_path and os.path.exists(file_path)):
        raise Http404("Arquivo não encontrado")

    return FileResponse(open(file_path, 'rb'), content_type='application/pdf')
