from django.core.management.base import BaseCommand
from django.conf import settings

REQUIRED = ["TENANT_ID","CLIENT_ID","CLIENT_SECRET","AUDIENCE","RELYING_PARTY_ID"]

class Command(BaseCommand):
    help = "Verifica configuração do OIDC/Entra ID (variáveis e flags críticas)"

    def handle(self, *args, **kwargs):
        ok = True
        auth = getattr(settings, "AUTH_ADFS", {})
        self.stdout.write("=== AUTH_ADFS ===")
        for k in REQUIRED:
            v = auth.get(k)
            mark = "OK" if v else "FALTANDO"
            if not v: ok = False
            self.stdout.write(f"{k:18s}: {mark}")

        self.stdout.write(f"VERSION              : {auth.get('VERSION')}")
        self.stdout.write(f"USERNAME_CLAIM       : {auth.get('USERNAME_CLAIM')}")
        self.stdout.write(f"GROUPS_CLAIM         : {auth.get('GROUPS_CLAIM')}")
        self.stdout.write(f"MIRROR_GROUPS        : {auth.get('MIRROR_GROUPS')}")
        self.stdout.write(f"CREATE_NEW_USERS     : {auth.get('CREATE_NEW_USERS')}")
        self.stdout.write("")
        self.stdout.write("=== REDE/PROXY ===")
        self.stdout.write(f"SECURE_PROXY_SSL_HEADER: {getattr(settings,'SECURE_PROXY_SSL_HEADER',None)}")
        self.stdout.write(f"USE_X_FORWARDED_HOST   : {getattr(settings,'USE_X_FORWARDED_HOST',None)}")

        self.stdout.write("")
        if ok:
            self.stdout.write(self.style.SUCCESS("Configuração básica OK."))
            self.stdout.write("Lembre-se de cadastrar a Redirect URI: https://SEU-DOMINIO/oauth2/callback")
        else:
            self.stdout.write(self.style.ERROR("Faltam variáveis essenciais no AUTH_ADFS."))
