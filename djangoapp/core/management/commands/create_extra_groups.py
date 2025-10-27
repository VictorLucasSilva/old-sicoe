from django.core.management.base import BaseCommand
from django.contrib.auth.models import Group

EXTRA_GROUPS = ["bbts", "ext", "bb"]

class Command(BaseCommand):
    help = "Cria (se não existirem) os grupos: bbts, ext, bb"

    def handle(self, *args, **options):
        for name in EXTRA_GROUPS:
            obj, created = Group.objects.get_or_create(name=name)
            if created:
                self.stdout.write(self.style.SUCCESS(f"Grupo criado: {name}"))
            else:
                self.stdout.write(self.style.WARNING(f"Grupo já existia: {name}"))
        self.stdout.write(self.style.SUCCESS("Concluído."))
