from django.core.management.base import BaseCommand
from django.conf import settings
import requests
import json

class Command(BaseCommand):
    help = "Mostra openid-configuration e os kids do JWKS do Entra ID"

    def handle(self, *args, **kwargs):
        auth = getattr(settings, "AUTH_ADFS", {})
        tenant = auth.get("TENANT_ID")
        version = auth.get("VERSION", "v2.0")
        if not tenant:
            self.stderr.write("AUTH_ADFS.TENANT_ID ausente")
            return

        well_known = f"https://login.microsoftonline.com/{tenant}/{version}/.well-known/openid-configuration"
        self.stdout.write(f"openid-configuration: {well_known}")
        r = requests.get(well_known, timeout=10)
        r.raise_for_status()
        cfg = r.json()
        jwks_uri = cfg.get("jwks_uri")
        self.stdout.write(f"jwks_uri: {jwks_uri}")
        r2 = requests.get(jwks_uri, timeout=10)
        r2.raise_for_status()
        jwks = r2.json()
        kids = [k.get("kid") for k in jwks.get("keys", [])]
        self.stdout.write("kids no JWKS:")
        for k in kids:
            self.stdout.write(f"  - {k}")
