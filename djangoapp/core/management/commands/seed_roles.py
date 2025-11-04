from django.core.management.base import BaseCommand
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType

GROUPS = ["Administrador","Auditor","Gerente Regional","Usuário","Sem Acesso"]

PERMISSIONS_BY_GROUP = {
    "Administrador":      ["add_attachment", "change_attachment", "delete_attachment", "view_attachment"],
    "Auditor":            ["view_attachment"],
    "Gerente Regional":   ["view_attachment", "add_attachment"],
    "Usuário":            ["view_attachment", "add_attachment"],
}

class Command(BaseCommand):
    help = "Cria grupos e permissões padrão"

    def handle(self, *args, **kwargs):
        for name in GROUPS:
            Group.objects.get_or_create(name=name)
            self.stdout.write(self.style.SUCCESS(f"Grupo OK: {name}"))

        try:
            from core.models import Attachment
            ct = ContentType.objects.get_for_model(Attachment)
            for gname, codenames in PERMISSIONS_BY_GROUP.items():
                group = Group.objects.get(name=gname)
                for code in codenames:
                    perm = Permission.objects.get(content_type=ct, codename=code)
                    group.permissions.add(perm)
                self.stdout.write(self.style.SUCCESS(f"Permissões aplicadas: {gname}"))
        except Exception as e:
            self.stdout.write(self.style.WARNING(f"Aviso permissões: {e}"))

        self.stdout.write(self.style.SUCCESS("Seed concluído."))
