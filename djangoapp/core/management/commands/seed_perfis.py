# core/management/commands/seed_perfis.py
from django.core.management.base import BaseCommand
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType

GROUPS = ["Administrador", "Auditor", "Gerente Regional", "Usuário", "Sem Acesso"]

# Permissões focadas no modelo Attachment (como no seu projeto)
PERMISSIONS_BY_GROUP = {
    "Administrador":     ["add_attachment", "change_attachment", "delete_attachment", "view_attachment"],
    "Auditor":           ["view_attachment"],
    "Gerente Regional":  ["view_attachment", "add_attachment"],
    "Usuário":           ["view_attachment", "add_attachment"],
    "Sem Acesso":        [],
}

class Command(BaseCommand):
    help = "Cria/atualiza grupos (perfis) e aplica permissões padrão sobre Attachment."

    def handle(self, *args, **kwargs):
        # cria grupos
        for name in GROUPS:
            Group.objects.get_or_create(name=name)
            self.stdout.write(self.style.SUCCESS(f"Grupo OK: {name}"))

        # tenta obter ContentType do modelo Attachment
        try:
            from core.models import Attachment
            ct = ContentType.objects.get_for_model(Attachment)
        except Exception as e:
            self.stdout.write(self.style.ERROR(
                f"Não foi possível obter ContentType de Attachment. Migrações aplicadas? Erro: {e}"
            ))
            return

        # aplica permissões de Attachment por grupo (idempotente)
        for gname, codenames in PERMISSIONS_BY_GROUP.items():
            group = Group.objects.get(name=gname)

            # remove quaisquer perms de Attachment do grupo e reatribui as desejadas
            current = Permission.objects.filter(group=group, content_type=ct)
            group.permissions.remove(*current)

            for code in codenames:
                try:
                    perm = Permission.objects.get(content_type=ct, codename=code)
                    group.permissions.add(perm)
                except Permission.DoesNotExist:
                    self.stdout.write(self.style.WARNING(f"Permissão ausente: {code} (Attachment)"))

            self.stdout.write(self.style.SUCCESS(f"Permissões aplicadas ao grupo: {gname}"))

        self.stdout.write(self.style.SUCCESS("Perfis/Permissões concluído."))
