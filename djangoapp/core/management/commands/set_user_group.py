from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group

class Command(BaseCommand):
    help = "Define (substitui) o grupo do usuário"

    def add_arguments(self, parser):
        parser.add_argument("--username", required=True)
        parser.add_argument("--group", required=True)

    def handle(self, *args, **opts):
        User = get_user_model()
        try:
            user = User.objects.get(username=opts["username"])
            group = Group.objects.get(name=opts["group"])
        except User.DoesNotExist:
            raise CommandError("Usuário não encontrado")
        except Group.DoesNotExist:
            raise CommandError("Grupo não encontrado")

        user.groups.set([group])
        self.stdout.write(self.style.SUCCESS(f"{user.username} agora está em {group.name}"))
