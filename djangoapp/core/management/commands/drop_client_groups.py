from django.core.management.base import BaseCommand
from django.contrib.auth.models import Group

GROUPS_TO_REMOVE = ["bbts", "ext", "bb"]

class Command(BaseCommand):
    help = "Remove grupos específicos (bbts, ext, bb) do auth_group."

    def handle(self, *args, **kwargs):
        for name in GROUPS_TO_REMOVE:
            qs = Group.objects.filter(name=name)
            if qs.exists():
                g = qs.first()
                users = g.user_set.count()
                g.delete()  # remove também os vínculos M2M
                self.stdout.write(self.style.SUCCESS(
                    f"Grupo '{name}' removido (vínculos anteriores: {users} usuário(s))."
                ))
            else:
                self.stdout.write(self.style.WARNING(f"Grupo '{name}' não existe; nada a fazer."))
        self.stdout.write(self.style.SUCCESS("Concluído."))
