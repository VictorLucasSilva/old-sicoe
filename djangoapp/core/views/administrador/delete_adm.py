from django.shortcuts import redirect, get_object_or_404
from core.models import Document, User, RelationCenterUser, RelationCenterDoc, Audit, NumDocsEstab
from core.decorators import only_administrador
from django.views.decorators.http import require_http_methods
from django.db import transaction
from django.contrib import messages

MAX_ATTEMPTS = 5
BLOCK_DURATION = 30 * 60

def _get_profile(u: User) -> str:
    for g in ("Administrador", "Auditor", "Gerente Regional", "Usuário", "Sem Acesso"):
        if u.groups.filter(name=g).exists():
            return g

@only_administrador
def num_docs_estab_delete(request, id):
    try:
        if request.method == "POST": 
            with transaction.atomic():
                number_doc = get_object_or_404(NumDocsEstab, ndest_id=id)
            
                center = str(number_doc.ndest_fk_establishment.est_center)
                unit = str(number_doc.ndest_units)
                cnpj = str(number_doc.ndest_cnpj)
                nire = str(number_doc.ndest_nire)
                reg_city = str(number_doc.ndest_reg_city)
                reg_state = str(number_doc.ndest_reg_state)
                number_doc.delete()
                
                Audit.objects.create(
                    aud_login=request.user.username,
                    aud_profile=_get_profile(request.user),
                    aud_action="Deleção",
                    aud_obj_modified="Unidade",
                    aud_description=f"{center} • Unidade: {unit} | CNPJ: {cnpj} | NIRE: {nire} | Inscrição Estadual: {reg_state} | Inscrição Municipal: {reg_city}",
                )
                
                messages.success(request, 'Unidade deletada com sucesso.')
                return redirect('cnpj_list')
            
        messages.success(request, 'Método não permitido.')
        return redirect('cnpj_list')
        
    except Exception as e:
        messages.error(request, f'Ocorreu um erro: {str(e)}')
        return redirect('cnpj_list')
    
@only_administrador
def document_delete(request, id):
    try:
        if request.method == "POST":
            with transaction.atomic():
                document = get_object_or_404(Document, d_id=id)

                if RelationCenterDoc.objects.filter(rcd_fk_document=document).exists():
                    messages.error(request, 'Há relações de estabelecimentos com esse documento.')
                    return redirect('document_list')
                
                doc_name = str(document.d_doc)
                document.delete()

                Audit.objects.create(
                    aud_login=request.user.username,
                    aud_profile=_get_profile(request.user),
                    aud_action="Deleção",
                    aud_obj_modified="Documento",
                    aud_description=f"{doc_name}",
                )

                messages.success(request, 'Documento deletado com sucesso.')
                return redirect('document_list')
        
        messages.success(request, 'Método não permitido.')
        return redirect('document_list')

    except Exception as e:
        messages.error(request, f'Ocorreu um erro: {str(e)}')
        return redirect('document_list')

@only_administrador
@require_http_methods(["POST"])
def center_user_delete(request, id):
    try:
        with transaction.atomic():
            rcu = get_object_or_404(RelationCenterUser, rcu_id=id)
            if (rcu.rcu_center and rcu.rcu_center != "-"):
                label, value = "Estabelecimento", rcu.rcu_center

            actor = request.user
            actor_login = getattr(actor, "u_login", None) or actor.username

            rcu.rcu_active = False
            rcu.save()

            Audit.objects.create(
                aud_login=actor_login,
                aud_profile=_get_profile(request.user),
                aud_action="Deleção",
                aud_obj_modified=f"Vinculo Usuário",
                aud_description=f"{rcu.rcu_fk_user.username} • {value}",
            )

            messages.success(request, "Relação deletada com sucesso.")
            return redirect("center_user_list")

    except Exception as e:
        messages.error(request, f"Ocorreu um erro ao deletar: {e}")
        return redirect("center_user_list")

@only_administrador
def center_doc_delete(request, id):
    try:  
        if request.method == "POST":
            with transaction.atomic():
                center_doc = get_object_or_404(RelationCenterDoc, rcd_id=id)
                
                doc = str(center_doc.rcd_fk_document.d_doc)
                center = str(center_doc.rcd_fk_establishment.est_center)
                center_doc.delete()

                Audit.objects.create(
                    aud_login=request.user.username,
                    aud_profile=_get_profile(request.user),
                    aud_action="Deleção",
                    aud_obj_modified="Vinculo Documento",
                    aud_description=f"{center} • {doc}",
                )
                messages.success(request, 'Relação deletada com sucesso.')
                return redirect('center_doc_list')
            
        messages.success(request, 'Relação deletada com sucesso.')
        return redirect('center_doc_list')

    except Exception as e:
        messages.error(request, f'Ocorreu um erro: {str(e)}')
        return redirect('center_doc_list')
