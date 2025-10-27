from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.db.models.signals import post_save
from django.dispatch import receiver
from core.models import PsFuncionario

User = get_user_model()

@receiver(post_save, sender=User)
def add_default_group(sender, instance, created, **kwargs):
    if created:
        try:
            user = instance

            if not created:
                return

            emp_num = getattr(user, "u_num_employee", None)

            funcao = None
            if emp_num is not None:
                funcao = (
                    PsFuncionario.objects
                    .filter(func_matricula=emp_num)
                    .values_list("func_nm_funcao", flat=True)
                    .first()
                )
                
            empl_id = (
                PsFuncionario.objects
                .filter(func_nm_email__iexact=user.email)
                .values_list("func_matricula", flat=True)
                .first()
            )
            
            USUARIO = ["GERENTE DE DIVISAO","AUXILIAR DE OPERACOES","PRESTADOR DE SERVICO","GERENTE DE CENTRO II","GERENTE EXECUTIVO","CONSELHEIRO","GERENTE DE GRUPO II",
                       "ASSESSOR JUNIOR","GERENTE EXECUTIVO_","CONSULTOR","ANALISTA DE OPERACOES","GERENTE DE PROJETOS I",
                       "ASSESSOR SENIOR","ESTAGIARIO","JOVEM APRENDIZ","TECNICO","GERENTE DE CENTRO I","ASSESSOR PLENO",
                       "GERENTE_EXECUTIVO","ASSESSOR EXECUTIVO PRESIDENCIA","GERENTE DE PROJETOS II","TECNICO DE OPERACOES",
                       "R11_X_R12","ANALISTA ADMINISTRATIVO","DIRETOR","ANALISTA ESPECIALISTA","GERENTE DE CENTRO DE TIC I",
                       "ANALISTA","GERENTE DE GRUPO DE TIC","GERENTE","TECNICO ADMINISTRATIVO","ASSESSOR MASTER","CONSELHEIRO FISCAL","GERENTE DE DIVISAO_",
                       "MENOR APRENDIZ"]
            
            if empl_id in (107344, 109789, 108086, 105475):
                grupo = Group.objects.get(name="Administrador")
                user.groups.add(grupo)
            elif funcao and funcao.upper() in ("COMITE DE AUDITORIA", "CONSELHEIRO DE ADMINISTRACAO", "PRESIDENTE"):
                grupo = Group.objects.get(name="Auditor")
                user.groups.add(grupo)
            elif funcao and funcao.upper() in ("SUPERINTENDENTE", "GERENTE REGIONAL DE OPERACOES"):
                grupo = Group.objects.get(name="Gerente Regional")
                user.groups.add(grupo)
            elif funcao and funcao.upper() in USUARIO:
                grupo = Group.objects.get(name="Usuário")
                user.groups.add(grupo)
            else:
                grupo_default = Group.objects.get(name="Sem Acesso")
                user.groups.add(grupo_default)
        except Group.DoesNotExist:
            pass
