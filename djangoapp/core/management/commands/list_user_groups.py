from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth import get_user_model

class Command(BaseCommand):
    help = "Lista grupos do usuário"

    def add_arguments(self, parser):
        parser.add_argument("--username", required=True)

    def handle(self, *args, **opts):
        User = get_user_model()
        try:
            user = User.objects.get(username=opts["username"])
        except User.DoesNotExist:
            raise CommandError("Usuário não encontrado")
        groups = ", ".join(user.groups.values_list("name", flat=True)) or "(sem grupos)"
        self.stdout.write(self.style.SUCCESS(f"{user.username}: {groups}"))
