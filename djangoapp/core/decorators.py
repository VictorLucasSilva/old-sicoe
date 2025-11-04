from functools import wraps
import logging
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout as auth_logout
from django.shortcuts import redirect

logger = logging.getLogger(__name__)

def _deny_and_logout(request, reason: str):
    try:
        vname = getattr(getattr(request, "resolver_match", None), "view_name", "?")
    except Exception:
        vname = "?"
    logger.warning("ACL DENY: user=%s reason=%s view=%s path=%s",
                   getattr(getattr(request, "user", None), "username", "?"),
                   reason, vname, getattr(request, "path", "?"))
    try:
        auth_logout(request)
        request.session.flush()
    except Exception:
        pass
    return redirect("login")

def group_and_perm_required(*, groups=None, perms=None, any_perm=False, superuser_bypass=False):

    required_groups = set(groups or [])
    required_perms  = list(perms or [])

    def decorator(view_func):
        @wraps(view_func)
        @login_required
        def _wrapped(request, *args, **kwargs):
            u = request.user

            if superuser_bypass and u.is_superuser:
                return view_func(request, *args, **kwargs)

            if required_groups:
                user_groups = set(u.groups.values_list('name', flat=True))
                if user_groups != required_groups:
                    return _deny_and_logout(
                        request,
                        f"required_groups={sorted(required_groups)} user_groups={sorted(user_groups)}"
                    )

            if required_perms:
                ok_perm = any(u.has_perm(p) for p in required_perms) if any_perm else u.has_perms(required_perms)
                if not ok_perm:
                    return _deny_and_logout(request, f"missing-perms:{required_perms}")

            return view_func(request, *args, **kwargs)
        return _wrapped
    return decorator

only_administrador    = group_and_perm_required(groups={'Administrador'})
only_auditor          = group_and_perm_required(groups={'Auditor'})
only_gerente_regional = group_and_perm_required(groups={'Gerente Regional'})
only_usuario          = group_and_perm_required(groups={'Usuário'})
