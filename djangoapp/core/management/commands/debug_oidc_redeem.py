# core/management/commands/debug_oidc_redeem.py
import json, base64, requests, sys
from django.core.management.base import BaseCommand, CommandError
from django.conf import settings
from jwt import decode as jwt_decode, algorithms
from urllib.parse import urljoin

def b64d(s):
    s += '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

class Command(BaseCommand):
    help = "Troca um authorization code por tokens, imprime header/claims do id_token e valida assinatura usando JWKS"

    def add_arguments(self, parser):
        parser.add_argument("--code", required=True, help="authorization_code recém-gerado")
        parser.add_argument("--redirect-uri", default="http://localhost:8000/oauth2/callback")

    def handle(self, *args, **opts):
        auth = getattr(settings, "AUTH_ADFS", {})
        tenant = auth.get("TENANT_ID")
        client_id = auth.get("CLIENT_ID")
        client_secret = auth.get("CLIENT_SECRET")
        redirect_uri = opts["redirect_uri"]
        code = opts["code"]

        if not all([tenant, client_id, client_secret]):
            raise CommandError("Faltam TENANT_ID/CLIENT_ID/CLIENT_SECRET em AUTH_ADFS")

        token_endpoint = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
        r = requests.post(token_endpoint, data={
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "authorization_code",
            "scope": "openid profile email",
            "code": code,
            "redirect_uri": redirect_uri,
        })
        try:
            tok = r.json()
        except Exception:
            raise CommandError(f"Resposta não-JSON do token endpoint: {r.status_code} {r.text[:200]}")

        if "id_token" not in tok:
            self.stdout.write(self.style.ERROR("Sem id_token. Resposta:"))
            self.stdout.write(json.dumps(tok, indent=2))
            sys.exit(1)

        idt = tok["id_token"]
        h, p, _ = idt.split(".")
        hdr = json.loads(b64d(h))
        clm = json.loads(b64d(p))
        self.stdout.write(f"Header.alg: {hdr.get('alg')}")
        self.stdout.write(f"Header.kid: {hdr.get('kid')}")
        self.stdout.write(f"Claims.iss: {clm.get('iss')}")
        self.stdout.write(f"Claims.aud: {clm.get('aud')}")

        # baixa OIDC config e JWKS
        oidc = requests.get(
            f"https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration",
            timeout=10,
        ).json()
        jwks_uri = oidc["jwks_uri"]
        jwks = requests.get(jwks_uri, timeout=10).json()

        # acha a chave pelo kid
        key = None
        for k in jwks.get("keys", []):
            if k.get("kid") == hdr.get("kid"):
                key = k
                break

        if not key:
            raise CommandError("kid do id_token NÃO encontrado no JWKS atual.")

        pub = algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
        # valida assinatura/claims
        try:
            decoded = jwt_decode(
                idt,
                key=pub,
                algorithms=["RS256"],
                audience=client_id,
                issuer=clm.get("iss"),
                options={"require": ["iss", "aud", "exp"], "verify_at_hash": False},
            )
            self.stdout.write(self.style.SUCCESS("Assinatura e claims válidas."))
        except Exception as e:
            raise CommandError(f"Falha ao validar JWT com JWKS: {e}")
