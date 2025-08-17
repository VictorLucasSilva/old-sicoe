# core/utils/redirects.py
from django.shortcuts import redirect
from django.utils.http import url_has_allowed_host_and_scheme

def safe_redirect(request, to, default="/"):
    if to and url_has_allowed_host_and_scheme(to, allowed_hosts={request.get_host()}, require_https=request.is_secure()):
        return redirect(to)
    return redirect(default)
