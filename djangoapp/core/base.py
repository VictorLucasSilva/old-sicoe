from __future__ import annotations
import time
import hmac
import hashlib
from datetime import timedelta

from django.conf import settings
from django.contrib import messages
from django.db import transaction
from django.shortcuts import render, redirect
from django.utils import timezone
from django.views.decorators.csrf import csrf_protect
from django.core.cache import cache
from django.utils.html import escape
from django.http import HttpResponseForbidden, FileResponse, Http404

from core.models import Users, LoginAttempt, SecurityEvent, Attachment
from core.forms.others.form_login import CustomLoginForm  # caminho correto
from core.utils.security import (
    get_client_ip,
    waf_detect_login,
    verify_signed_pdf_params,
    build_signed_pdf_params,
)
from core.middleware import hash_session  # compat (legado)

FAKE_PASSWORD = "this-is-not-the-real-password-and-has-a-decent-length"

def _strong_fingerprint(session_key: str, user_agent: str) -> str:
    salt = getattr(settings, "SECRET_KEY", "salt")
    base = f"{session_key}|{user_agent}|{salt}"
    return hashlib.sha256(base.encode()).hexdigest()

def get_redirect_url(profile: str) -> str:
    mapping = {
        'Administrador': 'attachment_list',
        'Auditor': 'audit_list',
        'Gerente Regional': 'establishment_list',
        'Usuário': 'home',
        'Sem Acesso': 'home',
    }
    return mapping.get(str(profile), 'home')

@csrf_protect
def login_view(request):
    ip_address = get_client_ip(request)
    user_agent = request.META.get('HTTP_USER_AGENT', '') or ''
    cache_key = f"login_attempts_{ip_address}"
    attempts_data = cache.get(cache_key, {'count': 0, 'blocked_until': None})

    if attempts_data.get('blocked_until') and timezone.now() < attempts_data['blocked_until']:
        messages.error(request, "Muitas tentativas. Tente novamente em alguns minutos.")
        return render(request, 'others/login.html', {'form': CustomLoginForm()})

    if request.method == 'POST':
        form = CustomLoginForm(request.POST)
        if form.is_valid():
            login_input = form.cleaned_data['login'][:100]
            password_input = form.cleaned_data['password'][:100]
            user_agent_clean = (user_agent or '')[:200]

            if waf_detect_login(login_input) or waf_detect_login(password_input):
                try:
                    SecurityEvent.objects.create(
                        sec_action=SecurityEvent.ActionType.WAF_BLOCK,
                        sec_description="Tentativa de login bloqueada pelo WAF - Entrada suspeita detectada",
                        sec_ip=ip_address,
                        sec_user_agent=user_agent_clean,
                        sec_payload=f"login={escape(login_input)}"
                    )
                except Exception:
                    pass
                messages.error(request, "Entrada inválida detectada.")
                return render(request, 'others/login.html', {'form': form}, status=403)

            start_time = time.time()

            user = Users.objects.filter(u_login=login_input, u_status='Ativo').first()

            if user:
                password_ok = hmac.compare_digest(user.u_password, password_input)
            else:
                password_ok = hmac.compare_digest(FAKE_PASSWORD, password_input)

            elapsed = time.time() - start_time
            if elapsed < 0.5:
                time.sleep(0.5 - elapsed)

            was_successful = bool(user and password_ok)

            try:
                with transaction.atomic():
                    LoginAttempt.objects.create(
                        login=login_input,
                        ip_address=ip_address,
                        user_agent=user_agent_clean,
                        timestamp=timezone.localtime(timezone.now()),
                        was_successful=was_successful
                    )
            except Exception:
                pass

            if was_successful:
                request.session.flush()
                try:
                    request.session.cycle_key()
                except Exception:
                    pass

                request.session.update({
                    'user_id': user.u_id,
                    'user_name': user.u_name,
                    'user_profile': user.u_profile,
                    'ip_address': ip_address,
                    'user_agent': user_agent_clean,
                    'user_status': user.u_status,
                })

                try:
                    request.session.save()
                except Exception:
                    pass

                legacy_fp = hash_session(ip_address, user_agent_clean)
                session_key = request.session.session_key or ''
                strong_fp = _strong_fingerprint(session_key, user_agent_clean)

                request.session['session_fingerprint'] = strong_fp
                request.session['session_key_at_login'] = session_key
                request.session['last_rotation'] = time.time()

                cache.delete(cache_key)

                try:
                    with transaction.atomic():
                        SecurityEvent.objects.create(
                            sec_action=SecurityEvent.ActionType.LOGIN,
                            sec_description=f"Usuário {user.u_login} logou com sucesso",
                            sec_ip=ip_address,
                            sec_user_agent=user_agent_clean
                        )
                except Exception:
                    pass

                messages.success(request, f"Bem-vindo(a) {user.u_name}!")
                return redirect(get_redirect_url(user.u_profile))

            attempts_data['count'] = int(attempts_data.get('count', 0)) + 1
            if attempts_data['count'] >= 5:
                attempts_data['blocked_until'] = timezone.now() + timedelta(minutes=1)
            cache.set(cache_key, attempts_data, timeout=1800)

            messages.error(request, "Login ou senha inválidos.")
        else:
            messages.error(request, "Verifique os campos do formulário.")
    else:
        form = CustomLoginForm()

    return render(request, 'others/login.html', {'form': form})

def logout_view(request):
    ip_address = get_client_ip(request)
    user_agent = request.META.get('HTTP_USER_AGENT', '') or ''
    user_login = request.session.get('user_name') or request.session.get('user_id')

    try:
        with transaction.atomic():
            SecurityEvent.objects.create(
                sec_action=SecurityEvent.ActionType.LOGOUT,
                sec_description=f"Logout do usuário {user_login}",
                sec_ip=ip_address,
                sec_user_agent=user_agent
            )
    except Exception:
        pass

    request.session.flush()
    messages.success(request, "Sessão encerrada.")
    return redirect('login')

@csrf_protect
def secure_pdf_view(request, attachment_id: int):
    enforce = bool(int(getattr(settings, "ENFORCE_SIGNED_PDF_URLS", 1)))
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')

    try:
        attachment = Attachment.objects.get(att_id=attachment_id)
    except Attachment.DoesNotExist:
        raise Http404("Arquivo não encontrado")

    exp = request.GET.get("exp")
    sig = request.GET.get("sig")

    if enforce:
        if not (exp and sig and verify_signed_pdf_params(attachment_id, user_id, exp, sig)):
            ip = get_client_ip(request)
            ua = request.META.get('HTTP_USER_AGENT', '') or ''
            try:
                SecurityEvent.objects.create(
                    sec_action=SecurityEvent.ActionType.WAF_BLOCK,
                    sec_description="Acesso PDF sem assinatura válida",
                    sec_ip=ip,
                    sec_user_agent=ua,
                    sec_payload=f"att_id={attachment_id}"
                )
            except Exception:
                pass
            return HttpResponseForbidden("Assinatura inválida ou expirada.")
    else:
        signed = build_signed_pdf_params(attachment_id, user_id, ttl_seconds=60)
        messages.info(request, "Gerada URL assinada temporária.")
        return redirect(f"{request.path}?exp={signed['exp']}&sig={signed['sig']}")

    f = attachment.att_file
    if not f or not f.name:
        raise Http404("Arquivo não encontrado")

    return FileResponse(f.open('rb'), content_type='application/pdf')
