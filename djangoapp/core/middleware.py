import logging
from django.conf import settings
from django.shortcuts import redirect, render
from django.contrib.auth import logout
from django.utils.deprecation import MiddlewareMixin
from core.utils import get_client_ip, session_fingerprint

logger = logging.getLogger(__name__)

PUBLIC_EXACT = {
    "/", "/login", "/login/", "/logout/", "/favicon.ico", "/robots.txt",
    "/health", "/ping", "/api/health/db", "/solicitar-acesso", "/post-login/",
}

ROUTE_ROLES = {
    "administrador/anexos": {"Administrador"},
    "auditor/anexos": {"Auditor"},
    "gerente-regional/anexos": {"Gerente Regional"},
    "usuario/anexos": {"Usuário"},
}

PDF_ALLOWED = {"Administrador", "Auditor", "Gerente Regional", "Usuário",}

def _is_authenticated(request) -> bool:
    if getattr(request, "user", None) and request.user.is_authenticated:
        return True
    return bool(request.session.get("user_id"))

def _has_role(request, required: str) -> bool:
    if getattr(request, "user", None) and request.user.is_authenticated:
        try:
            if request.user.groups.filter(name=required).exists():
                return True
        except Exception:
            pass

    profile = (request.session.get("user_profile") or "").strip()
    return profile == required

def _some_role(request, allowed: set) -> bool:
    return any(_has_role(request, r) for r in allowed)

class AuthRequiredMiddleware(MiddlewareMixin):

    def process_request(self, request):
        path = request.path or "/"

        if settings.STATIC_URL and path.startswith(settings.STATIC_URL):
            return None
        if path.startswith("/oauth2/"):
            return None

        if path in PUBLIC_EXACT:
            return None

        if settings.MEDIA_URL and path.startswith(settings.MEDIA_URL):
            if not _is_authenticated(request):
                return redirect("login")

            if path.lower().endswith(".pdf"):
                if not _some_role(request, PDF_ALLOWED):
                    logger.warning("Acesso negado a PDF por perfil/grupo: %s", request.session.get("user_profile"))
                    return render(request, "others/acesso_negado.html", status=403)
            return None

        if not _is_authenticated(request):
            try:
                request.session.flush()
            except Exception:
                pass
            return redirect("login")

        try:
            ip = get_client_ip(request)
            ua = request.META.get("HTTP_USER_AGENT", "")
            fp_now = session_fingerprint(ip, ua, settings.SECRET_KEY)
            fp_saved = request.session.get("fp")

            if not fp_saved:
                request.session["fp"] = fp_now
            elif fp_saved != fp_now:
                logger.warning("Sessão inválida: fingerprint alterado (%s -> %s)", fp_saved[:8], fp_now[:8])
                try:
                    logout(request) 
                except Exception:
                    pass
                try:
                    request.session.flush()
                except Exception:
                    pass
                return redirect("login")
        except Exception as e:
            logger.error("Erro ao validar fingerprint da sessão: %s", e)
            return redirect("login")

        for prefix, allowed in ROUTE_ROLES.items():
            if path.startswith(f"/{prefix}"):
                if not _some_role(request, allowed):
                    logger.warning("Acesso negado por perfil/grupo: path=%s allowed=%s", path, allowed)
                    return render(request, "others/acesso_negado.html", status=403)
                break

        return None

class RouteAclMiddleware(MiddlewareMixin):
    ALLOW_SUPERUSER_BYPASS = False

    GROUPS_BY_URL = {
        'attachment_list_audit': {'Auditor'},
        'home_audit': {'Auditor'},
        'audit_list_audit': {'Auditor'},
        'email_list_audit': {'Auditor'},
        'attachment_history_all_audit': {'Auditor'},
        'attachment_history_audit': {'Auditor'},

        'attachment_list_manager': {'Gerente Regional'},
        'home_manager': {'Gerente Regional'},
        'attachment_history_manager': {'Gerente Regional'},
        'overview_attachment_create_manager': {'Gerente Regional'},

        'attachment_list_user': {'Usuário'},
        'home_user': {'Usuário'},
        'attachment_history_user': {'Usuário'},
        'overview_attachment_create_user': {'Usuário'},

        'establishment_list': {'Administrador'},
        'attachment_list': {'Administrador'},
        'overview': {'Administrador'},
        'document_list': {'Administrador'},
        'center_user_list': {'Administrador'},
        'center_doc_list': {'Administrador'},
        'user_list': {'Administrador'},
        'audit_list': {'Administrador'},
        'apiestab': {'Administrador'},
        'cnpj_list': {'Administrador'},
        'attachment_units_by_center': {'Administrador', 'Auditor', 'Gerente Regional', 'Usuário'},
        'attachment_conference': {'Administrador'},
        'attachment_history_all': {'Administrador'},
        'email_list': {'Administrador'},
        'user_access': {'Administrador'},
        'attachment_create': {'Administrador'},
        'document_create': {'Administrador'},
        'cnpj_create': {'Administrador'},
        'overview_attachment_create': {'Administrador'},
        'center_doc_create': {'Administrador'},
        'center_user_create': {'Administrador'},
        'center_user_create_user': {'Administrador'},
        'center_user_create_ids': {'Administrador'},
        'user_edit': {'Administrador'},
        'cnpj_update': {'Administrador'},
        'document_delete': {'Administrador'},
        'document_update': {'Administrador'},
        'center_doc_update': {'Administrador'},
        'conference_invalidation': {'Administrador'},
        'conference_data_expire': {'Administrador'},
        'center_user_update': {'Administrador'},
        'establishment_update': {'Administrador'},
        'num_docs_delete': {'Administrador'},
        'center_user_delete': {'Administrador'},
        'center_doc_delete': {'Administrador'},
        'attachment_invalidation': {'Administrador'},
        'attachment_validation': {'Administrador'},
        'attachment_history': {'Administrador'},
        'home': {'Administrador'},
    }

    PERMS_BY_URL = {
        'attachment_list_audit': {'core.view_attachment'},
        'attachment_list_audit': {'core.view_numdocsestab'},
        'attachment_history_all_audit': {'core.view_attachment'},
        'attachment_history_audit': {'core.view_attachment'},
        'audit_list_audit': {'core.view_audit'},
        'email_list_audit': {'core.view_email'},
        'home_audit': {'core.view_attachment'},
        'attachment_history_all_audit': {'core.view_numdocsestab'},
        'attachment_history_audit': {'core.view_numdocsestab'},

        'attachment_list_manager': {'core.view_attachment'},
        'attachment_list_manager': {'core.view_numdocsestab'},
        'attachment_history_manager': {'core.view_attachment'},
        'attachment_history_manager': {'core.view_numdocsestab'},
        'home_manager': {'core.view_attachment'},
        'overview_attachment_create_manager': {'core.add_attachment'},

        'attachment_list_user': {'core.view_attachment'},
        'attachment_list_user': {'core.view_numdocsestab'},
        'attachment_history_user': {'core.view_attachment'},
        'home_user': {'core.view_attachment'},
        'overview_attachment_create_user': {'core.add_attachment'},
        'attachment_history_user': {'core.view_numdocsestab'},

        'establishment_list': {'core.view_establishment'},
        'attachment_list': {'core.view_attachment'},
        'overview': {'core.view_attachment'},
        'document_list': {'core.view_document'},
        'center_user_list': {'core.view_relationcenteruser'},
        'center_doc_list': {'core.view_relationcenterdoc'},
        'user_list': {'core.view_user'},
        'audit_list': {'core.view_audit'},
        'apiestab': {'core.view_establishment'},
        'cnpj_list': {'core.view_numdocsestab'},
        'attachment_units_by_center': {'core.view_attachment'},
        'attachment_conference': {'core.change_attachment'},
        'attachment_history_all': {'core.view_attachment'},
        'email_list': {'core.view_email'},
        'user_access': {'core.change_user'},

        'attachment_create': {'core.add_attachment'},
        'document_create': {'core.add_document'},
        'cnpj_create': {'core.add_numdocsestab'},
        'overview_attachment_create': {'core.add_attachment'},
        'center_doc_create': {'core.add_relationcenterdoc'},
        'center_user_create': {'core.add_relationcenteruser'},
        'center_user_create_user': {'core.add_relationcenteruser'},
        'center_user_create_ids': {'core.add_relationcenteruser'},

        'user_edit': {'core.change_user'},
        'cnpj_update': {'core.change_numdocsestab'},
        'document_update': {'core.change_document'},
        'center_doc_update': {'core.change_relationcenterdoc'},
        'conference_invalidation': {'core.change_attachment'},
        'conference_data_expire': {'core.change_attachment'},
        'center_user_update': {'core.change_relationcenteruser'},
        'establishment_update': {'core.change_establishment'},
        'attachment_validation': {'core.change_attachment'},
        'attachment_invalidation': {'core.change_attachment'},

        'document_delete': {'core.delete_document'},
        'num_docs_delete': {'core.delete_numdocsestab'},
        'center_user_delete': {'core.delete_relationcenteruser'},
        'center_doc_delete': {'core.delete_relationcenterdoc'},

        'attachment_history': {'core.view_attachment'},
        'home': {'core.view_attachment'},
    }

    def process_view(self, request, view_func, view_args, view_kwargs):
        u = getattr(request, "user", None)
        if not u or not u.is_authenticated:
            return None

        match = getattr(request, 'resolver_match', None)
        if not match:
            return None

        if self.ALLOW_SUPERUSER_BYPASS and u.is_superuser:
            return None

        url_name = match.url_name or ""

        required_groups = self.GROUPS_BY_URL.get(url_name)
        if required_groups:
            if not u.groups.filter(name__in=required_groups).exists():
                logger.warning("ACL: grupo negado url_name=%s required=%s", url_name, required_groups)
                return render(request, "others/acesso_negado.html", status=403)

        needed_perms = self.PERMS_BY_URL.get(url_name)
        if needed_perms:
            if not u.has_perms(list(needed_perms)):
                logger.warning("ACL: perm negada url_name=%s perms=%s", url_name, needed_perms)
                return render(request, "others/acesso_negado.html", status=403)

        return None