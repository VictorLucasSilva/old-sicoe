import logging
from django.shortcuts import redirect, get_object_or_404
from core.models import Document, Users, RelationCenterUser, SecurityEvent, RelationCenterDoc, Audit, NumDocsEstab
from core.decorators import only_administrador
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_protect
from core.utils.security import enforce_content_type, get_client_ip
from django.http import JsonResponse
from django.db import transaction
from django.contrib import messages

MAX_ATTEMPTS = 5
BLOCK_DURATION = 30 * 60

logger = logging.getLogger(__name__)

@only_administrador
def num_docs_estab_delete(request, id):
    try:
        if request.method == "POST": 
            with transaction.atomic():
                number_doc = get_object_or_404(NumDocsEstab, ndest_id=id)
                user_id = request.session.get('user_id')
                user = Users.objects.get(u_id=user_id, u_status='Ativo')
                
                center = str(number_doc.ndest_fk_establishment.est_center)
                unit = str(number_doc.ndest_units)
                cnpj = str(number_doc.ndest_cnpj)
                nire = str(number_doc.ndest_nire)
                reg_city = str(number_doc.ndest_reg_city)
                reg_state = str(number_doc.ndest_reg_state)
                number_doc.delete()
                
                Audit.objects.create(
                    aud_login=user.u_login,
                    aud_profile=user.u_profile,
                    aud_action="Deleção",
                    aud_obj_modified="Nº Documento",
                    aud_description=f"{center} >>> (Unidade: {unit}) - (CNPJ: {cnpj}) - (NIRE: {nire}) - (Inscrição Estadual: {reg_state}) - (Inscrição Municipal: {reg_city})",
                )
                
                messages.success(request, 'Unidade deletada com sucesso.')
                return redirect('cnpj_list')
            
        messages.success(request, 'Método não permitido.')
        return redirect('cnpj_list')
        
    except Exception as e:
        messages.error(request, f'Ocorreu um erro: {str(e)}')
        return redirect('cnpj_list')
    
@csrf_protect
@only_administrador
@require_POST
def document_delete(request, id: int):
    # Apenas POST + CSRF + Content-Type válido nesta rota
    if not enforce_content_type(request, form_paths=('/administrador/',)):
        return JsonResponse({"error": "Content-Type não permitido"}, status=415)

    try:
        with transaction.atomic():
            document = get_object_or_404(Document, d_id=id)

            # Bloqueia deleção se houver relacionamento — evita inconsistência/IDOR lateral
            if RelationCenterDoc.objects.filter(rcd_fk_document=document).exists():
                messages.error(request, 'Há relações de estabelecimentos com esse documento.')
                return redirect('document_list')

            doc_name = str(document.d_doc)

            user = Users.objects.get(
                u_id=request.session.get('user_id'),
                u_status='Ativo'
            )

            document.delete()

            Audit.objects.create(
                aud_login=user.u_login,
                aud_profile=user.u_profile,
                aud_action="Deleção",
                aud_obj_modified="Documento",
                aud_description=doc_name,
            )

            SecurityEvent.objects.create(
                sec_action=SecurityEvent.ActionType.OTHER,
                sec_description="Documento excluído",
                sec_ip=get_client_ip(request),
                sec_user_agent=(request.META.get('HTTP_USER_AGENT') or '')[:256],
                sec_payload=f"doc_name={doc_name[:64]}"
            )

        messages.success(request, 'Documento deletado com sucesso.')
        return redirect('document_list')

    except Users.DoesNotExist:
        request.session.flush()
        return redirect('login')
    except Exception:
        logger.exception("Falha ao excluir documento")
        messages.error(request, 'Erro ao excluir. Tente novamente.')
        return redirect('document_list')

@only_administrador
def center_user_delete(request, id):
    try:
        if request.method == "POST":
            with transaction.atomic():
                center_user = get_object_or_404(RelationCenterUser, rcu_id=id)
                user_id_session = request.session.get('user_id')
                user = Users.objects.get(u_id=user_id_session, u_status='Ativo')
                    
                selected_key = None
                selected_value = None

                if center_user.rcu_center != "-":
                    selected_key = "Estabelecimento"
                    selected_value = center_user.rcu_center
                elif center_user.rcu_region != "-":
                    selected_key = "Região"
                    selected_value = center_user.rcu_region
                elif center_user.rcu_state != "-":
                    selected_key = "Estado"
                    selected_value = center_user.rcu_state
                description = f"{user.u_login} | {selected_value}"

                center_user.delete()
                
                Audit.objects.create(
                    aud_login=user.u_login,
                    aud_profile=user.u_profile,
                    aud_action="Exclusão de Relação",
                    aud_obj_modified=f"Usuário | {selected_key.title()}",
                    aud_description=description,
                )
                
                messages.success(request, 'Relação deletada com sucesso.')
                return redirect('center_user_list')
            
        messages.success(request, 'Método não permitido.')
        return redirect('center_user_list')
    
    except Exception as e:
        messages.error(request, f'Ocorreu um erro ao deletar: {str(e)}')
        return redirect('center_user_list')

@only_administrador
def center_doc_delete(request, id):
    try:  
        if request.method == "POST":
            with transaction.atomic():
                center_doc = get_object_or_404(RelationCenterDoc, rcd_id=id)
                user_id_session = request.session.get('user_id')
                user = Users.objects.get(u_id=user_id_session, u_status='Ativo')
                
                doc = str(center_doc.rcd_fk_document.d_doc)
                center = str(center_doc.rcd_fk_establishment.est_center)
                center_doc.delete()

                Audit.objects.create(
                    aud_login=user.u_login,
                    aud_profile=user.u_profile,
                    aud_action="Exclusão de Relação",
                    aud_obj_modified="Estabelecimento | Documento",
                    aud_description=f"{center} | {doc}",
                )
                messages.success(request, 'Relação deletada com sucesso.')
                return redirect('center_doc_list')
            
        messages.success(request, 'Relação deletada com sucesso.')
        return redirect('center_doc_list')

    except Exception as e:
        messages.error(request, f'Ocorreu um erro: {str(e)}')
        return redirect('center_doc_list')
