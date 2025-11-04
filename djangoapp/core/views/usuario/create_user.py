import logging
from django.utils.text import slugify
from django.views.decorators.http import require_http_methods
from django.shortcuts import render, redirect
from django.contrib import messages
from django.utils import timezone
from django.views.decorators.csrf import csrf_protect

from core.decorators import only_usuario
from core.models import (
    Establishment, User,
    RelationCenterDoc, Attachment, Audit
)
from core.forms.administrador.form_create_adm import OverAttachmentForm

logger = logging.getLogger(__name__)
try:
    from core.utils import enforce_content_type
except Exception:
    def enforce_content_type(request, form_paths=(), allow_multipart=True):
        ct = (request.META.get('CONTENT_TYPE') or '')
        ok = ('application/x-www-form-urlencoded' in ct) or ('multipart/form-data' in ct)
        return ok


def _safe_pdf_name(document: str, center: str, original: str) -> str:
    base = f"{slugify(document) or 'doc'}-{slugify(center) or 'center'}"
    ts = timezone.now().strftime('%Y%m%d%H%M%S')
    return f"{base}-{ts}.pdf"


def _profile_from_groups(user: User) -> str:
    if user.is_superuser or user.groups.filter(name="Administrador").exists():
        return "Administrador"
    if user.groups.filter(name="Auditor").exists():
        return "Auditor"
    if user.groups.filter(name="Gerente Regional").exists():
        return "Gerente Regional"
    if user.groups.filter(name="Usuário").exists():
        return "Usuário"
    return "Sem Acesso"


@csrf_protect
@require_http_methods(["GET", "POST"])
@only_usuario
def overview_attachment_create(request, document, center):
    related = RelationCenterDoc.objects.filter(
        rcd_fk_establishment__est_center=center,
        rcd_fk_document__d_doc=document
    ).exists()
    if not related:
        messages.error(request, "O documento informado não está relacionado com este Estabelecimento.")
        return redirect('home_user')

    establishment = Establishment.objects.filter(est_center=center).first()
    if not establishment:
        messages.error(request, "Estabelecimento não encontrado.")
        return redirect('home_user')

    if request.method == "POST":
        if not enforce_content_type(request, form_paths=('/usuario/',), allow_multipart=True):
            messages.error(request, "Content-Type não permitido para envio de formulário.")
            return redirect(request.path)

        form = OverAttachmentForm(request.POST, request.FILES, user=getattr(request, "user", None))
        if not form.is_valid():
            for field, errs in form.errors.items():
                for err in errs:
                    messages.error(request, f"{field}: {err}")

            context = {
                'region': establishment.est_region,
                'state': establishment.est_state,
                'center': center,
                'document': document,
                'initial_data': {
                    'region': establishment.est_region,
                    'state':  establishment.est_state,
                    'center': center,
                    'document': document,
                }
            }
            return render(request, 'main/usuario/overview_attachment_create.html', context)

        data_expire = form.cleaned_data['data_expire']
        up_file = form.cleaned_data['file']
        up_file.name = _safe_pdf_name(document, center, up_file.name)
        current = request.user 
        attached_by = current.get_username() or (current.email or "Sistema")
        profile_txt = _profile_from_groups(current)

        try:
            att = Attachment.objects.create(
                att_data_expire = data_expire,
                att_attached_by = attached_by,
                att_file        = up_file,
                att_region      = establishment.est_region or "-",
                att_state       = establishment.est_state,
                att_city        = establishment.est_city,
                att_doc         = document,
                att_center      = center,
            )
        except Exception as e:
            logger.exception("Falha ao salvar Attachment")
            messages.error(request, f"Falha ao salvar o anexo: {e}")
            return redirect(request.path)

        try:
            Audit.objects.create(
                aud_login       = attached_by,
                aud_profile     = profile_txt,
                aud_action      = "Cadastro",
                aud_obj_modified= "Attachment",
                aud_description = f"{document} • {center} • expira {data_expire.strftime('%d/%m/%Y')}",
            )
        except Exception:
            logger.warning("Falha ao salvar audit do cadastro de anexo", exc_info=True)

        messages.success(request, "Documento anexado com sucesso.")
        return redirect('home_user')
    
    context = {
        'region': establishment.est_region,
        'state': establishment.est_state,
        'center': center,
        'document': document,
        'initial_data': {
            'region': establishment.est_region,
            'state':  establishment.est_state,
            'center': center,
            'document': document,
        }
    }
    return render(request, 'main/usuario/overview_attachment_create.html', context)
