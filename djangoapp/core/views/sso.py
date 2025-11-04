import json, base64, os, secrets, requests
from urllib.parse import urlencode
from django.conf import settings
from django.contrib import auth
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.http import HttpResponseBadRequest
from django.shortcuts import redirect
from core.models import PsFuncionario
from jwt import decode as jwt_decode, algorithms

TENANT = settings.AUTH_ADFS["TENANT_ID"]
CLIENT_ID = settings.AUTH_ADFS["CLIENT_ID"]
CLIENT_SECRET = settings.AUTH_ADFS["CLIENT_SECRET"]
REDIRECT_PATH = "/oauth2/callback"
PUBLIC_REDIRECT_URI = getattr(settings, "PUBLIC_REDIRECT_URI")
REDIRECT_URI = f"{PUBLIC_REDIRECT_URI}{REDIRECT_PATH}"
AUTHZ_URL = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/authorize"
TOKEN_URL = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"
WELL_KNOWN = f"https://login.microsoftonline.com/{TENANT}/v2.0/.well-known/openid-configuration"

def _b64d(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

def _name_from_claims(claims):
    first = (claims.get("given_name") or "").strip()
    last  = (claims.get("family_name") or "").strip()
    if first or last:
        return first, last
    full = (claims.get("name") or "").strip()
    if full:
        parts = full.split()
        if len(parts) == 1:
            return parts[0], ""
        return parts[0], " ".join(parts[1:])
    return "", ""

def _normalize_username(raw: str) -> str:
    s = (raw or "").strip().lower()
    return s.split("@", 1)[0]  

def login_start(request):
    state = secrets.token_urlsafe(24)
    request.session["oidc_state"] = state
    qs = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": "openid email profile",
        "response_mode": "query",
        "state": state,
    }
    return redirect(f"{AUTHZ_URL}?{urlencode(qs)}")

def callback(request):
    if "error" in request.GET:
        return HttpResponseBadRequest(
            f"OIDC error: {request.GET.get('error_description') or request.GET.get('error')}"
        )

    code  = request.GET.get("code")
    state = request.GET.get("state")
    if not code or not state or state != request.session.get("oidc_state"):
        return HttpResponseBadRequest("state inválido ou ausente.")

    tok = requests.post(
        TOKEN_URL,
        data={
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "grant_type": "authorization_code",
            "scope": "openid profile email",
            "code": code,
            "redirect_uri": REDIRECT_URI,
        },
        timeout=15,
    ).json()

    idt = tok.get("id_token")
    if not idt:
        return HttpResponseBadRequest("Sem id_token na resposta: " + json.dumps(tok)[:300])

    h, p, _ = idt.split(".")
    hdr = json.loads(_b64d(h))
    claims = json.loads(_b64d(p))

    oidc = requests.get(WELL_KNOWN, timeout=10).json()
    jwks = requests.get(oidc["jwks_uri"], timeout=10).json()
    key = next((k for k in jwks.get("keys", []) if k.get("kid") == hdr.get("kid")), None)
    if not key:
        return HttpResponseBadRequest("kid do id_token não encontrado no JWKS.")

    pub = algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
    try:
        jwt_decode(
            idt,
            key=pub,
            algorithms=["RS256"],
            audience=CLIENT_ID,
            issuer=claims.get("iss"),
            options={"require": ["iss", "aud", "exp"], "verify_at_hash": False},
        )
    except Exception as e:
        return HttpResponseBadRequest(f"Falha validando id_token: {e}")

    raw_username = (
        claims.get("preferred_username")
        or claims.get("upn")
        or claims.get("email")
    )
    if not raw_username:
        return HttpResponseBadRequest("Nenhum claim de login encontrado (preferred_username/upn/email).")

    username = _normalize_username(raw_username)
    email_claim = (claims.get("email") or raw_username).strip().lower()
    email = email_claim if "@" in email_claim else ""

    first_name, last_name = _name_from_claims(claims)
    User = get_user_model()

    user = User.objects.filter(username=username).first()
    empl_id = (
        PsFuncionario.objects
        .filter(func_nm_email__iexact=email)
        .values_list("func_matricula", flat=True)
        .first()
    )

    if user is None:
        legacy = User.objects.filter(username__iexact=raw_username.strip()).first()
        if legacy:
            if not User.objects.filter(username=username).exists():
                legacy.username = username
                legacy.save(update_fields=["username"])
                user = legacy
            else:
                base = username
                i = 2
                candidate = f"{base}{i}"
                while User.objects.filter(username=candidate).exists():
                    i += 1
                    candidate = f"{base}{i}"
                legacy.username = candidate
                legacy.save(update_fields=["username"])
                user = legacy

    if user is None:
        user = User.objects.create(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
            u_status="Ativo",
            u_num_employee=empl_id or None,
            is_active=True,
            is_staff=False,
        )
        user.set_unusable_password()
        user.save(update_fields=["password"])

    fields_to_update = []
    if user.email != email:
        user.email = email
        fields_to_update.append("email")
    if user.first_name != first_name:
        user.first_name = first_name
        fields_to_update.append("first_name")
    if user.last_name != last_name:
        user.last_name = last_name
        fields_to_update.append("last_name")
    if not user.is_active:
        user.is_active = True
        fields_to_update.append("is_active")

    try:
        
        emp_num = getattr(user, "u_num_employee", None)

        funcao = None
        if emp_num is not None:
            funcao = (
                PsFuncionario.objects
                .filter(func_matricula=emp_num)
                .values_list("func_nm_funcao", flat=True)
                .first()
            )
            empl_id = (
                PsFuncionario.objects
                .filter(func_nm_email__iexact=user.email)
                .values_list("func_matricula", flat=True)
                .first()
            )
            
            USUARIO = ["GERENTE DE DIVISAO","AUXILIAR DE OPERACOES","PRESTADOR DE SERVICO","GERENTE DE CENTRO II","GERENTE EXECUTIVO","CONSELHEIRO","GERENTE DE GRUPO II",
                       "ASSESSOR JUNIOR","GERENTE EXECUTIVO_","CONSULTOR","ANALISTA DE OPERACOES","GERENTE DE PROJETOS I",
                       "ASSESSOR SENIOR","ESTAGIARIO","JOVEM APRENDIZ","TECNICO","GERENTE DE CENTRO I","ASSESSOR PLENO",
                       "GERENTE_EXECUTIVO","ASSESSOR EXECUTIVO PRESIDENCIA","GERENTE DE PROJETOS II","TECNICO DE OPERACOES",
                       "R11_X_R12","ANALISTA ADMINISTRATIVO","DIRETOR","ANALISTA ESPECIALISTA","GERENTE DE CENTRO DE TIC I",
                       "ANALISTA","GERENTE DE GRUPO DE TIC","GERENTE","TECNICO ADMINISTRATIVO","ASSESSOR MASTER","CONSELHEIRO FISCAL","GERENTE DE DIVISAO_",
                       "MENOR APRENDIZ"]
            
        if user.groups.count() == 0:
            if empl_id in (107344, 109789, 108086, 105475):
                grupo = Group.objects.get(name="Administrador")
                user.groups.add(grupo)
            elif funcao and funcao.upper() in ("COMITE DE AUDITORIA", "CONSELHEIRO DE ADMINISTRACAO", "PRESIDENTE"):
                grupo = Group.objects.get(name="Auditor")
                user.groups.add(grupo)
            elif funcao and funcao.upper() in ("SUPERINTENDENTE", "GERENTE REGIONAL DE OPERACOES"):
                grupo = Group.objects.get(name="Gerente Regional")
                user.groups.add(grupo)
            elif funcao and funcao.upper() in USUARIO:
                grupo = Group.objects.get(name="Usuário")
                user.groups.add(grupo)
            else:
                grupo_default = Group.objects.get(name="Sem Acesso")
                user.groups.add(grupo_default)
    except Group.DoesNotExist:
        pass

    is_staff_now = user.groups.filter(name="Administrador").exists()
    if user.is_staff != is_staff_now:
        user.is_staff = is_staff_now
        fields_to_update.append("is_staff")

    if fields_to_update:
        user.save(update_fields=fields_to_update)

    user.backend = "django.contrib.auth.backends.ModelBackend"
    auth.login(request, user)

    gp = set(user.groups.values_list("name", flat=True))
    if   "Administrador"     in gp: request.session["user_profile"] = "Administrador"
    elif "Auditor"           in gp: request.session["user_profile"] = "Auditor"
    elif "Gerente Regional"  in gp: request.session["user_profile"] = "Gerente Regional"
    elif "Usuário"           in gp: request.session["user_profile"] = "Usuário"
    else:                          request.session["user_profile"] = "Sem Acesso"

    return redirect("post_login")

def logout(request):
    auth.logout(request)
    return redirect("login")
