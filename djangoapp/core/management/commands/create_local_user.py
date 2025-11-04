from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group

class Command(BaseCommand):
    help = "Cria um usuário local e adiciona a um grupo"

    def add_arguments(self, parser):
        parser.add_argument("--username", required=True)
        parser.add_argument("--password", required=True)
        parser.add_argument("--email", default="")
        parser.add_argument("--group", default="Sem Acesso")

    def handle(self, *args, **opts):
        User = get_user_model()
        if User.objects.filter(username=opts["username"]).exists():
            raise CommandError("Username já existe")
        user = User.objects.create_user(username=opts["username"], email=opts["email"], password=opts["password"], is_active=True)
        try:
            group = Group.objects.get(name=opts["group"])
            user.groups.add(group)
        except Group.DoesNotExist:
            pass
        self.stdout.write(self.style.SUCCESS(f"Usuário criado: {user.username} (grupo: {opts['group']})"))
