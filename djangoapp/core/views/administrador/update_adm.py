import logging

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from core.models import Establishment, Users, Audit, Document, Attachment, SecurityEvent, RelationCenterDoc, NumDocsEstab, RelationCenterUser
from core.decorators import only_administrador
from django.utils import timezone
from core.forms.administrador.form_update_adm import EstUpdateForm,  DUpdateForm, RCDUpdateForm, CNPJUpdateForm, UUpdateForm, INVUpdateForm, EXPUpdateForm
from django.views.decorators.http import require_http_methods
from django.db import transaction, IntegrityError
from core.utils.search import clean_search_q
from django.views.decorators.csrf import csrf_protect
from core.utils import enforce_content_type, get_client_ip
from django.http import JsonResponse

MAX_ATTEMPTS = 5
BLOCK_DURATION = 30 * 60

logger = logging.getLogger(__name__)

@only_administrador
def establishment_update(request, id):
    est = get_object_or_404(Establishment, est_id=id)
    est_old_manage = est.est_manage
    est_old_property = est.est_property

    if request.method == 'POST':
        form = EstUpdateForm(request.POST, instance=est)
        if form.is_valid():
            try:
                with transaction.atomic():
                    form.save()

                    user_id = request.session.get('user_id')
                    user = Users.objects.get(u_id=user_id, u_status='Ativo')

                    Audit.objects.create(
                        aud_login=user.u_login,
                        aud_profile=user.u_profile,
                        aud_action="Alteração",
                        aud_obj_modified="Estabelecimento",
                        aud_description=(
                            f"({est.est_center}) "
                            f"Área Gestora: {est_old_manage} >> {est.est_manage}, "
                            f"Propriedade: {est_old_property} >> {est.est_property}"
                        ),
                    )
                    messages.success(request, 'Estabelecimento atualizado com sucesso.')
                    return redirect('establishment_list')
            except Exception as e:
                messages.error(request, f'Ocorreu um erro ao atualizar: {str(e)}')
    else:
        form = EstUpdateForm(instance=est)

    return render(request, 'main/administrador/establishment_update.html', {
        'form': form,
        'establishment': est
    })

@csrf_protect
@only_administrador
@require_http_methods(["GET", "POST"])
def document_update(request, id: int):
    _ = clean_search_q(request.GET.get('q'))
    document = get_object_or_404(Document, d_id=id)
    old_name = document.d_doc

    if request.method == 'POST':
        if not enforce_content_type(request, form_paths=('/administrador/',)):
            return JsonResponse({"error": "Content-Type não permitido"}, status=415)

        form = DUpdateForm(request.POST, instance=document)
        if form.is_valid():
            try:
                with transaction.atomic():
                    updated = form.save(commit=False)
                    updated.d_doc = (updated.d_doc or '').strip()[:50]
                    updated.save()

                    Attachment.objects.filter(att_doc=old_name).update(att_doc=updated.d_doc)

                    user = Users.objects.get(
                        u_id=request.session.get('user_id'),
                        u_status='Ativo'
                    )

                    Audit.objects.create(
                        aud_login=user.u_login,
                        aud_profile=user.u_profile,
                        aud_action="Alteração",
                        aud_obj_modified="Documento",
                        aud_description=f"({old_name}) >> ({updated.d_doc})",
                    )

                    SecurityEvent.objects.create(
                        sec_action=SecurityEvent.ActionType.OTHER,
                        sec_description="Documento alterado",
                        sec_ip=get_client_ip(request),
                        sec_user_agent=(request.META.get('HTTP_USER_AGENT') or '')[:256],
                        sec_payload=f"doc_id={updated.d_id}"
                    )

                messages.success(request, 'Nome de documento atualizado com sucesso.')
                return redirect('document_list')

            except Users.DoesNotExist:
                request.session.flush()
                return redirect('login')
            except IntegrityError:
                form.add_error('d_doc', 'Já existe um documento com este nome.')
            except Exception:
                logger.exception("Falha ao atualizar documento")
                messages.error(request, 'Erro ao atualizar. Tente novamente.')
    else:
        form = DUpdateForm(instance=document)

    return render(request, 'main/administrador/document_update.html', {
        'form': form,
        'doc_l': document
    })
    
@only_administrador
def center_doc_update(request, id):
    try:
        center_doc = get_object_or_404(RelationCenterDoc, rcd_id=id)
        form = RCDUpdateForm(instance=center_doc)

        if request.method == 'POST':
            form = RCDUpdateForm(request.POST, instance=center_doc)
            if form.is_valid():
                try:
                    with transaction.atomic():
                        form.save()
                        messages.success(request, 'Relação atualizada com sucesso.')
                        return redirect('center_doc_list')
                except Exception as e:
                    messages.error(request, f'Ocorreu um erro ao atualizar: {str(e)}')

        return render(request, 'main/administrador/center_doc_update.html', {
            'form': form,
            'rcd_l': center_doc
        })

    except RelationCenterDoc.DoesNotExist:
        messages.error(request, 'Registro não encontrado.')
        return redirect('center_doc_list')
    except Exception as e:
        messages.error(request, f'Ocorreu um erro: {str(e)}')
        return redirect('center_doc_list')
    
@only_administrador
def cnpj_update(request, id):
    ndest = get_object_or_404(NumDocsEstab, ndest_id=id)
    establishments = Establishment.objects.all()
    if request.method == 'POST':
        form = CNPJUpdateForm(request.POST, instance=ndest)
        if form.is_valid():
            try:
                with transaction.atomic():
                    updated_ndest = form.save(commit=False)
                    desc_list = []

                    if updated_ndest.ndest_cnpj != ndest.ndest_cnpj:
                        desc_list.append(f'CNPJ: {ndest.ndest_cnpj} → {updated_ndest.ndest_cnpj}')
                    if updated_ndest.ndest_nire != ndest.ndest_nire:
                        desc_list.append(f'NIRE: {ndest.ndest_nire} → {updated_ndest.ndest_nire}')
                    if updated_ndest.ndest_reg_state != ndest.ndest_reg_state:
                        desc_list.append(f'IE: {ndest.ndest_reg_state} → {updated_ndest.ndest_reg_state}')
                    if updated_ndest.ndest_reg_city != ndest.ndest_reg_city:
                        desc_list.append(f'IM: {ndest.ndest_reg_city} → {updated_ndest.ndest_reg_city}')

                    if desc_list:
                        user_id = request.session.get('user_id')
                        user = Users.objects.get(u_id=user_id, u_status='Ativo')
                        Audit.objects.create(
                            aud_login=user.u_login,
                            aud_profile=user.u_profile,
                            aud_action="Alteração",
                            aud_obj_modified="Estabelecimento/CNPJ",
                            aud_description=f"{ndest.ndest_fk_establishment.est_center} - " + "; ".join(desc_list)
                        )

                    updated_ndest.save()
                    messages.success(request, 'Numeros de unidade atualizados com sucesso.')
                    return redirect('cnpj_list')
            except Exception as e:
                messages.error(request, f'Erro ao atualizar: {e}')
                return redirect('cnpj_list')
    else:
        form = CNPJUpdateForm(instance=ndest)

    return render(request, 'main/administrador/cnpj_update.html', {
        'form': form,
        'cnpj_l': ndest,
        'establishments': establishments
    })
    
@only_administrador
def conference_invalidation(request, id):
    attachment = get_object_or_404(Attachment, att_id=id)
    
    if request.method == 'POST':
        form = INVUpdateForm(request.POST, instance=attachment)
        if form.is_valid():
            try:
                with transaction.atomic():
                    form.save()
                    
                    user_id_session = request.session.get('user_id')
                    user = Users.objects.get(u_id=user_id_session)

                    attachment.att_situation = "Invalidado"
                    attachment.att_checked_by = user.u_login
                    attachment.att_data_conference = timezone.now()
                    attachment.save()

                    Audit.objects.create(
                        aud_login=user.u_login,
                        aud_profile=user.u_profile,
                        aud_action="Invalidação",
                        aud_obj_modified="Anexos",
                        aud_description=f"({attachment.att_doc}) >>> (Estabelecimento: {attachment.att_center}) - (Justificativa: {attachment.att_just})",
                    )
                messages.success(request, 'Anexo invalidado com sucesso!')
                return redirect('attachment_conference')
            
            except Exception as e:
                messages.error(request, f'Ocorreu um erro ao atualizar: {str(e)}')
    else:
        form = INVUpdateForm(instance=attachment)

    return render(request, 'main/administrador/conference_invalidation.html', {
        'form': form,
        'attachment_l': attachment,
    })

"""
    except Document.DoesNotExist:
        messages.error(request, 'Documento não encontrado.')
        return redirect('attachment_conference')

    except Exception as e:
        messages.error(request, f'Ocorreu um erro: {str(e)}')
        return redirect('attachment_conference')"""

"""  
@only_administrador
def conference_data_expire(request, id):
    try:
        if request.method == 'POST':
            attachment = get_object_or_404(Attachment, att_id=id)
            just = request.GET.get('just')
            try:
                with transaction.atomic():
                    
                    attachment.att_fk_attaux.attaux_just=just
                    attachment.save()
                    
                    user_id_session = request.session.get('user_id')
                    user = Users.objects.get(u_id=user_id_session)
                    Audit.objects.create(
                        aud_login=user.u_login,
                        aud_profile=user.u_profile,
                        aud_action="Invalidação",
                        aud_obj_modified="Anexos",
                        aud_description=f"(Justificativa : {attachment.att_fk_attaux.attaux_just})",
                    )
                        
                    messages.success(request, 'Documento atualizado com sucesso.')
                    return redirect('attachment_conference')
                
            except Exception as e:
                messages.error(request, f'Ocorreu um erro ao atualizar: {str(e)}')
                return redirect('attachment_conference')
        else:
            messages.error(request, f'Ocorreu um erro na atualização')
            
        return render(request, 'main/administrador/conference_invalidation.html', {
            'attachament_l':attachment,  
        })

    except Document.DoesNotExist:
        messages.error(request, 'Documento não encontrado.')
        return redirect('attachment_conference')

    except Exception as e:
        messages.error(request, f'Ocorreu um erro: {str(e)}')
        return redirect('attachment_conference')
"""

@only_administrador
def conference_data_expire(request, id):
    attachment = get_object_or_404(Attachment, att_id=id)
    
    if request.method == 'POST':
        form = EXPUpdateForm(request.POST, instance=attachment)
        if form.is_valid():
            try:
                with transaction.atomic():
                    form.save()
                    
                    user_id_session = request.session.get('user_id')
                    user = Users.objects.get(u_id=user_id_session)

                    Audit.objects.create(
                        aud_login=user.u_login,
                        aud_profile=user.u_profile,
                        aud_action="Invalidação",
                        aud_obj_modified="Anexos",
                        aud_description=f"(Justificativa: {attachment.att_just})",
                    )

                messages.success(request, 'Data de Vencimento atualizado com sucesso!')
                return redirect('attachment_conference')
            except Exception as e:
                messages.error(request, f'Ocorreu um erro ao atualizar: {str(e)}')
    else:
        form = EXPUpdateForm(instance=attachment)

    return render(request, 'main/administrador/conference_data_expire.html', {
        'form': form,
        'attachment_l': attachment,
    })

@only_administrador
def user_edit(request, id):
    user_obj = get_object_or_404(Users, u_id=id)
    form = UUpdateForm(request.POST or None, instance=user_obj)

    if request.method == 'POST':
        if form.is_valid():
            try:
                with transaction.atomic():
                    form.save()
                    session_user_id = request.session.get('user_id')
                    session_user = Users.objects.get(u_id=session_user_id, u_status='Ativo')
                    Audit.objects.create(
                        aud_login=session_user.u_login,
                        aud_profile=session_user.u_profile,
                        aud_action="Alteração",
                        aud_obj_modified="Usuário",
                        aud_description=f"({user_obj.u_login}) - Perfil: {user_obj.u_profile} - Status: {user_obj.u_status}",
                    )
                    messages.success(request, 'Usuário atualizado com sucesso.')
                    return redirect('user_list')
            except Exception as e:
                messages.error(request, f'Erro ao salvar: {str(e)}')

    return render(request, 'main/administrador/user_edit.html', {
        'form': form,
        'user_obj': user_obj
    })

@only_administrador
def center_user_update(request, id):
    try:
        center_user = get_object_or_404(RelationCenterUser, rcu_id=id)
        users = Users.objects.exclude(u_profile="Sem Acesso")
        user_id_session = request.session.get('user_id')
        user = Users.objects.get(u_id=user_id_session, u_status='Ativo')

        est = Establishment.objects.all()
        regions = Establishment.objects.values_list('est_region', flat=True).distinct()
        states = Establishment.objects.values_list('est_state', flat=True).distinct()

        if request.method == 'POST':
            center = request.POST.get('center', '')
            region = request.POST.get('region', '')
            state = request.POST.get('state', '')
            user_req = request.POST.get('user', '')

            if not user_req:
                messages.error(request, 'Por favor, selecione um usuário.')
            elif sum(bool(x) for x in [center, region, state]) != 1:
                messages.error(request, 'Selecione apenas Estabelecimento ou Região ou Estado.')
            else:
                center_user.rcu_fk_user = Users.objects.get(u_login=user_req)
                tipo = ""
                local = ""

                if center:
                    center_user.rcu_center = center
                    center_user.rcu_region = "-"
                    center_user.rcu_state = "-"
                    tipo = "Estabelecimento"
                    local = center
                elif region:
                    center_user.rcu_center = "-"
                    center_user.rcu_region = region
                    center_user.rcu_state = "-"
                    tipo = "Região"
                    local = region
                elif state:
                    center_user.rcu_center = "-"
                    center_user.rcu_region = "-"
                    center_user.rcu_state = state
                    tipo = "Estado"
                    local = state

                center_user.save()

                description = f"( {local} ) - ( {user_req} )"
                Audit.objects.create(
                    aud_login=user.u_login,
                    aud_profile=user.u_profile,
                    aud_action="Alteração de Relação",
                    aud_obj_modified=f"{tipo}/Usuário",
                    aud_description=description,
                )
                messages.success(request, "Relação atualizada com sucesso!")
                return redirect('center_user_list')

        context = {
            'center_user': center_user,
            'establishments': est,
            'users': users,
            'regions': regions,
            'states': states,
        }
        return render(request, 'main/administrador/center_user_update.html', context)

    except Exception as e:
        messages.error(request, f'Ocorreu um erro: {str(e)}')
        return redirect('center_user_list')
