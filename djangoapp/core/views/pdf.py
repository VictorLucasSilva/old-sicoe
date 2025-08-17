from pathlib import Path
from django.conf import settings
from django.http import FileResponse, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.views.decorators.http import require_GET
from django.urls import reverse
from core.decorators import only_administrador

from core.models import Attachment, SecurityEvent
from core.utils.security import build_signed_pdf_params, verify_signed_pdf_params, get_client_ip

@require_GET
@only_administrador
def download_pdf(request, attachment_id: int):
    """
    Reforços:
    - Assinatura pode ser vinculada a UA/IP (flags em settings)
    - Headers de segurança e cache defensivos
    """
    if settings.ENFORCE_SIGNED_PDF_URLS:
        exp = request.GET.get('exp'); sig = request.GET.get('sig')
        user_id = request.session.get('user_id')
        ua = request.META.get('HTTP_USER_AGENT', '') or ''
        ip = get_client_ip(request)
        if not (exp and sig and user_id and verify_signed_pdf_params(attachment_id, user_id, exp, sig, ua=ua, ip=ip)):
            return render(request, 'others/acesso_negado.html', status=403)

    att = get_object_or_404(Attachment, att_id=attachment_id)
    abspath = Path(att.att_file.path).resolve()
    mediaroot = Path(settings.MEDIA_ROOT).resolve()
    if not str(abspath).startswith(str(mediaroot)):
        return render(request, 'others/acesso_negado.html', status=403)

    disp = 'attachment' if request.GET.get('dl') == '1' else 'inline'
    resp = FileResponse(open(abspath, 'rb'), content_type='application/pdf')
    resp['Content-Disposition'] = f'{disp}; filename="{abspath.name}"'
    resp['X-Content-Type-Options'] = 'nosniff'
    resp['X-Frame-Options'] = 'DENY'
    resp['Referrer-Policy'] = 'no-referrer'
    resp['Cache-Control'] = 'private, max-age=60, must-revalidate'
    resp['Cross-Origin-Resource-Policy'] = 'same-origin'

    SecurityEvent.objects.create(
        sec_action=SecurityEvent.ActionType.PDF_ACCESS,
        sec_description=f"PDF {disp}",
        sec_ip=get_client_ip(request),
        sec_user_agent=(request.META.get('HTTP_USER_AGENT') or '')[:256],
        sec_payload=f"att_id={attachment_id}"
    )
    return resp

@require_GET
@only_administrador
def api_signed_pdf_links(request, attachment_id: int):
    if request.headers.get('X-Requested-With') != 'XMLHttpRequest':
        return JsonResponse({'error': 'forbidden'}, status=403)
    user_id = request.session.get('user_id')
    ua = request.META.get('HTTP_USER_AGENT', '') or ''
    ip = get_client_ip(request)
    params = build_signed_pdf_params(attachment_id, user_id, ua=ua, ip=ip)
    base = reverse('download_pdf', args=[attachment_id])
    return JsonResponse({
        'view_url': f"{base}?exp={params['exp']}&sig={params['sig']}",
        'download_url': f"{base}?exp={params['exp']}&sig={params['sig']}&dl=1",
    })
