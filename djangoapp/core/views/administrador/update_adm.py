import logging
import re

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from core.models import Establishment, User, Audit, Document, Attachment, RelationCenterDoc, NumDocsEstab, RelationCenterUser
from core.decorators import only_administrador
from django.utils import timezone
from django.contrib.auth.models import Group
from core.forms.administrador.form_update_adm import EstUpdateForm, DUpdateForm, RCDUpdateForm, CNPJUpdateForm, UUpdateForm, INVUpdateForm, EXPUpdateForm
from django.views.decorators.http import require_http_methods
from django.db import transaction, IntegrityError
from django.views.decorators.csrf import csrf_protect


MAX_ATTEMPTS = 5
BLOCK_DURATION = 30 * 60

logger = logging.getLogger(__name__)

def _get_profile(u: User) -> str:
    for g in ("Administrador", "Auditor", "Gerente Regional", "Usuário", "Sem Acesso"):
        if u.groups.filter(name=g).exists():
            return g

SIGLAS_GESTORAS = [
    "DIAGE","DIAPA","DIATI","DICIT","DICOA","DICOC","DICOF","DICOI","DICOM","DICON","DICOP","DICOR",
    "DICOS","DIDAP","DIDES","DIEMP","DIENG","DIFIN","DIFIT","DIGES","DIGOV","DIJUC","DIJUN","DIJUS",
    "DIJUT","DILIC","DIMAC","DIMAG","DIMUC","DINEL","DIOGE","DIPAR","DIPAV","DIPLI","DIPRA","DIPRO",
    "DIREL","DIREM","DIRIS","DISEC","DISEF","DISEI","DISEN","DISOP","DISUP","DITIC","DITOP","DITRI",
]

@only_administrador
def establishment_update(request, id):
    est = get_object_or_404(Establishment, est_id=id)
    est_old_manage = est.est_manage
    est_old_property = est.est_property
    gestora_options = sorted(set(SIGLAS_GESTORAS))

    if request.method == 'POST':
        form = EstUpdateForm(request.POST, instance=est)
        if form.is_valid():
            try:
                with transaction.atomic():
                    form.save()

                    Audit.objects.create(
                        aud_login=request.user.username,
                        aud_profile=_get_profile(request.user),
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
            messages.error(request, 'Verifique os campos destacados e tente novamente.')
    else:
        form = EstUpdateForm(instance=est)

    return render(request, 'main/administrador/establishment_update.html', {
        'form': form,
        'establishment': est,
        'gestora_options': gestora_options,
    })

@csrf_protect
@only_administrador
@require_http_methods(["GET", "POST"])
def document_update(request, id):
    document = get_object_or_404(Document, d_id=id)
    old_name = document.d_doc

    if request.method == 'POST':
        form = DUpdateForm(request.POST, instance=document)
        if form.is_valid():
            try:
                with transaction.atomic():
                    updated = form.save() 
                    Attachment.objects.filter(att_doc=old_name).update(att_doc=updated.d_doc)

                    Audit.objects.create(
                        aud_login=request.user.username,
                        aud_profile=_get_profile(request.user),
                        aud_action="Alteração",
                        aud_obj_modified="Documento",
                        aud_description=f"({old_name}) >> ({updated.d_doc})",
                    )
                    messages.success(request, 'Nome de documento atualizado com sucesso.')
                    return redirect('document_list')

            except IntegrityError:
                form.add_error('d_doc', 'Já existe um documento com este nome.')
    else:
        form = DUpdateForm(instance=document)

    return render(request, 'main/administrador/document_update.html', {
        'form': form,
        'doc_l': document,
    })
    
@only_administrador
@require_http_methods(["GET", "POST"])
def center_doc_update(request, id):
    center_doc = get_object_or_404(
        RelationCenterDoc.objects.select_related("rcd_fk_document", "rcd_fk_establishment"),
        rcd_id=id,
    )

    if request.method == "POST":
        form = RCDUpdateForm(request.POST, instance=center_doc)
        if form.is_valid():
            with transaction.atomic():
                updated = form.save()

                Audit.objects.create(
                    aud_login=request.user.username,
                    aud_profile=_get_profile(request.user),
                    aud_action="Alteração",
                    aud_obj_modified="Estabelecimento/Documento",
                    aud_description=(
                        f"({updated.rcd_fk_establishment.est_center}) / ({updated.rcd_fk_document.d_doc})"
                    ),
                )
                
                messages.success(request, "Relação atualizada com sucesso.")
                return redirect("center_doc_list")
    else:
        form = RCDUpdateForm(instance=center_doc)

    return render(
        request,
        "main/administrador/center_doc_update.html",
        {"form": form, "rcd_l": center_doc},
    )
    
def _fmt_cnpj(c: str) -> str:
    d = re.sub(r"\D", "", c or "")
    if len(d) == 14:
        return f"{d[0:2]}.{d[2:5]}.{d[5:8]}/{d[8:12]}-{d[12:14]}"
    return c or "-"

@only_administrador
@require_http_methods(["GET", "POST"])
def cnpj_update(request, id):
    ndest = get_object_or_404(
        NumDocsEstab.objects.select_related("ndest_fk_establishment"),
        ndest_id=id
    )
    establishments = Establishment.objects.all()

    if request.method == "POST":
        form = CNPJUpdateForm(request.POST, instance=ndest, require_establishment=False)
        if form.is_valid():
            old = {
                "cnpj": ndest.ndest_cnpj or "-",
                "nire": ndest.ndest_nire or "-",
                "ie":   ndest.ndest_reg_state or "-",
                "im":   ndest.ndest_reg_city or "-",
            }
            try:
                with transaction.atomic():
                    saved = form.save()

                    Audit.objects.create(
                        aud_login=request.user.username,
                        aud_profile=_get_profile(request.user),
                        aud_action="Alteração",
                        aud_obj_modified="Estabelecimento/CNPJ",
                        aud_description=(
                            f"{ndest.ndest_fk_establishment.est_center} | "
                            f"(Unidade: {ndest.ndest_units}) - (CNPJ: {ndest.ndest_cnpj}) - "
                            f"(NIRE: {ndest.ndest_nire}) - "
                            f"(Inscrição Estadual: {ndest.ndest_reg_state}) - "
                            f"(Inscrição Municipal: {ndest.ndest_reg_city})"
                        ),
                    )
                    messages.success(request, "Números da unidade atualizados com sucesso.")
                    return redirect("cnpj_list")

            except IntegrityError as e:
                messages.warning(request, f"Erro de integridade ao atualizar: {e}")
            except Exception as e:
                logger.exception("Erro ao atualizar unidade (cnpj_update)")
                messages.warning(request, f"Erro ao atualizar: {e}")
        else:
            messages.warning(request, f"Corrija os campos: {form.errors.as_text()}")
    else:
        form = CNPJUpdateForm(instance=ndest, require_establishment=False)

    return render(
        request,
        "main/administrador/cnpj_update.html",
        {"form": form, "cnpj_l": ndest, "establishments": establishments},
    )

@only_administrador              
@require_http_methods(["GET", "POST"])   
def attachment_invalidation(request, id):
    try:
        if request.method == 'GET':
            attachment = get_object_or_404(Attachment, att_id=id)
            form = INVUpdateForm(instance=attachment)
            return render(request, 'main/administrador/attachment_invalidation.html', {
                'form': form,
                'attachment_l': attachment,
            })

        with transaction.atomic():
            attachment = Attachment.objects.select_for_update().get(att_id=id)
            form = INVUpdateForm(request.POST, instance=attachment)

            if (attachment.att_situation or '').strip().lower() != 'regular':
                messages.error(request, 'Somente anexos REGULARES podem ser invalidados.')
                return redirect('attachment_list')

            if not form.is_valid():
                return render(request, 'main/administrador/attachment_invalidation.html', {
                    'form': form,
                    'attachment_l': attachment,
                })

            form.save()  

            attachment.att_situation = "Invalidado"
            attachment.att_data_conference = timezone.now()
            attachment.save(update_fields=["att_situation", "att_checked_by", "att_data_conference", "att_just"])

            Audit.objects.create(
                aud_login=request.user.username,
                aud_profile=_get_profile(request.user),
                aud_action="Invalidação",
                aud_obj_modified="Anexos",
                aud_description=f"(doc={attachment.att_doc}) (estab={attachment.att_center}) (justificativa={attachment.att_just or '-'})",
            )

            messages.success(request, 'Anexo invalidado com sucesso!')
            return redirect('attachment_list')
    except Exception as e:
        messages.error(request, f'Ocorreu um erro ao atualizar: {str(e)}')
                
@only_administrador
def conference_invalidation(request, id):
    attachment = get_object_or_404(Attachment, att_id=id)
    
    if request.method == 'POST':
        form = INVUpdateForm(request.POST, instance=attachment)
        if form.is_valid():
            try:
                with transaction.atomic():
                    form.save()

                    attachment.att_situation = "Invalidado"
                    attachment.att_checked_by = request.user.get_username()
                    attachment.att_data_conference = timezone.now()
                    attachment.save()

                    Audit.objects.create(
                        aud_login=request.user.get_username(),
                        aud_profile=_get_profile(request.user),
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

@only_administrador
def conference_data_expire(request, id):
    attachment = get_object_or_404(Attachment, att_id=id)
    
    if request.method == 'POST':
        form = EXPUpdateForm(request.POST, instance=attachment)
        if form.is_valid():
            try:
                with transaction.atomic():
                    attachment = form.save()

                    data_br = (
                        attachment.att_data_expire.strftime('%d/%m/%Y')
                        if attachment.att_data_expire else '-'
                    )

                    Audit.objects.create(
                        aud_login=request.user.username,
                        aud_profile=_get_profile(request.user),
                        aud_action="Alteração",
                        aud_obj_modified="Anexos",
                        aud_description=f"(Data: {data_br})",
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

ALLOWED_PROFILE_GROUPS = ["Administrador", "Auditor", "Gerente Regional", "Usuário"]


def _fmt(d):
    if not d:
        return "-"
    try:
        return d.strftime("%d/%m/%Y")
    except Exception:
        return str(d)


def _first_allowed_perfil_in(group_names):
    for name in ALLOWED_PROFILE_GROUPS:
        if name in group_names:
            return name
    return ""

@only_administrador
@require_http_methods(["GET", "POST"])
def user_edit(request, id):
    if request.method == "GET":
        user_obj = get_object_or_404(User, id=id)
        form = UUpdateForm(instance=user_obj)
        allowed_qs = Group.objects.filter(name__in=ALLOWED_PROFILE_GROUPS).order_by("name")
        allowed_names = [g.name for g in allowed_qs]
        user_group_names = set(user_obj.groups.values_list("name", flat=True))
        current_perfil = _first_allowed_perfil_in(user_group_names)

        return render(
            request,
            "main/administrador/user_edit.html",
            {
                "form": form,
                "user_obj": user_obj,
                "today": timezone.localdate(),
                "perfil_choices": allowed_names,
                "selected_perfil": current_perfil or "Usuário", 
            },
        )

    try:
        with transaction.atomic():
            user_locked = User.objects.select_for_update().get(pk=id)
            before_status = user_locked.u_status
            before_out = user_locked.u_time_out
            before_groups = set(user_locked.groups.values_list("name", flat=True))
            before_perfil = _first_allowed_perfil_in(before_groups)

            form = UUpdateForm(request.POST, instance=user_locked)
            perfil_post = (request.POST.get("perfil") or "").strip()

            allowed_qs = Group.objects.filter(name__in=ALLOWED_PROFILE_GROUPS)
            allowed_names = set(allowed_qs.values_list("name", flat=True))
            if perfil_post and perfil_post not in allowed_names:
                messages.error(request, "Perfil inválido.")
                return render(
                    request,
                    "main/administrador/user_edit.html",
                    {
                        "form": form,
                        "user_obj": user_locked,
                        "today": timezone.localdate(),
                        "perfil_choices": sorted(list(allowed_names)),
                        "selected_perfil": perfil_post or "Usuário",
                    },
                )

            if not form.is_valid():
                messages.error(request, "Corrija os erros do formulário e tente novamente.")
                return render(
                    request,
                    "main/administrador/user_edit.html",
                    {
                        "form": form,
                        "user_obj": user_locked,
                        "today": timezone.localdate(),
                        "perfil_choices": sorted(list(allowed_names)),
                        "selected_perfil": perfil_post or _first_allowed_perfil_in(before_groups) or "Usuário",
                    },
                )

            obj = form.save(commit=False)
            obj.save()
            form.save_m2m()  
            if perfil_post:
                target_group = Group.objects.get(name=perfil_post)
                through = User.groups.through  
                allowed_ids = list(allowed_qs.values_list("id", flat=True))
                has_target = through.objects.filter(user_id=obj.pk, group_id=target_group.id).exists()
                if not has_target:
                    row = (
                        through.objects
                        .select_for_update()
                        .filter(user_id=obj.pk, group_id__in=allowed_ids)
                        .exclude(group_id=target_group.id)
                        .order_by("pk")
                        .first()
                    )
                    if row:
                        through.objects.filter(pk=row.pk).update(group_id=target_group.id)
                    else:
                        pass

            after_groups = set(User.objects.get(pk=obj.pk).groups.values_list("name", flat=True))
            after_perfil = _first_allowed_perfil_in(after_groups) or (perfil_post or "-")

            changes = [
                f"Status: {before_status} → {obj.u_status}",
                f"Data Saída: {_fmt(before_out)} → {_fmt(obj.u_time_out)}",
            ]
            if before_perfil != after_perfil:
                changes.append(f"Perfil: {before_perfil or '-'} → {after_perfil or '-'}")

            if before_groups != after_groups:
                added = after_groups - before_groups
                removed = before_groups - after_groups
                if added:
                    changes.append("Grupos adicionados: " + ", ".join(sorted(added)))
                if removed:
                    changes.append("Grupos removidos: " + ", ".join(sorted(removed)))

            Audit.objects.create(
                aud_login=getattr(request.user, "username", "-"),
                aud_profile=", ".join(request.user.groups.values_list("name", flat=True)) or "-",
                aud_action="Alteração",
                aud_obj_modified="Usuário",
                aud_description=f"({obj.username}) - " + " | ".join(changes),
            )

        messages.success(request, "Usuário atualizado com sucesso.")
        return redirect("user_list")

    except Exception as e:
        messages.error(request, f"Erro ao salvar: {e}")
        return redirect("user_list")

@only_administrador
@require_http_methods(["GET", "POST"])
def center_user_update(request, id):
    rcu = get_object_or_404(RelationCenterUser, rcu_id=id)
    target_user = rcu.rcu_fk_user

    establishments_qs = Establishment.objects.order_by("est_center")
    regions_qs = (
        Establishment.objects.values_list("est_region", flat=True)
        .exclude(est_region__isnull=True).exclude(est_region__in=["", "-"])
        .distinct().order_by("est_region")
    )
    states_qs = (
        Establishment.objects.values_list("est_state", flat=True)
        .exclude(est_state__isnull=True).exclude(est_state__in=["", "-"])
        .distinct().order_by("est_state")
    )

    if request.method == "POST":
        eid = (request.POST.get("rcu_fk_estab") or "").strip()
        if not eid:
            messages.error(request, "Selecione um Estabelecimento.")
            return redirect("center_user_update", id=rcu.rcu_id)

        try:
            eid = int(eid)
        except ValueError:
            messages.error(request, "Estabelecimento inválido.")
            return redirect("center_user_update", id=rcu.rcu_id)

        est = Establishment.objects.filter(pk=eid).first()
        if not est:
            messages.error(request, "Estabelecimento não encontrado.")
            return redirect("center_user_update", id=rcu.rcu_id)

        try:
            with transaction.atomic():
                existing = (
                    RelationCenterUser.objects
                    .select_for_update()
                    .filter(rcu_fk_user_id=target_user.pk, rcu_fk_estab_id=eid)
                    .exclude(pk=rcu.pk)
                    .first()
                )

                if existing:
                    if not existing.rcu_active:
                        existing.rcu_active = True
                        existing.rcu_center = est.est_center or "-"
                        existing.rcu_region = est.est_region or "-"
                        existing.rcu_state  = est.est_state  or "-"
                        existing.save(update_fields=["rcu_active", "rcu_center", "rcu_region", "rcu_state"])
                        
                        rcu.delete()

                        try:
                            Audit.objects.create(
                                aud_login=request.user.username,
                                aud_profile=(request.user.groups.first().name if request.user.groups.exists() else "-"),
                                aud_action="Reativação de Relação",
                                aud_obj_modified="Estabelecimento/Usuário",
                                aud_description=f"( {est.est_center} ) - ( {target_user.username} )",
                            )
                        except Exception:
                            pass

                        messages.success(request, "Relação reativada com sucesso!")
                        return redirect("center_user_list")
                    else:
                        messages.warning(request, "Já existe uma relação ativa para este colaborador e estabelecimento.")
                        return redirect("center_user_list")

                rcu.rcu_fk_estab_id = eid
                rcu.rcu_center = est.est_center or "-"
                rcu.rcu_region = est.est_region or "-"
                rcu.rcu_state  = est.est_state  or "-"
                rcu.rcu_active = True 
                rcu.save(update_fields=["rcu_fk_estab", "rcu_center", "rcu_region", "rcu_state", "rcu_active"])

                try:
                    Audit.objects.create(
                        aud_login=request.user.username,
                        aud_profile=(request.user.groups.first().name if request.user.groups.exists() else "-"),
                        aud_action="Alteração de Relação",
                        aud_obj_modified="Estabelecimento/Usuário",
                        aud_description=f"( {est.est_center} ) - ( {target_user.username} )",
                    )
                except Exception:
                    pass

                messages.success(request, "Relação atualizada e reativada com sucesso!")
                return redirect("center_user_list")

        except Exception as e:
            logger.exception("Erro ao atualizar relação Estabelecimento/Usuário")
            messages.error(request, f"Erro ao salvar: {e}")
            return redirect("center_user_update", id=rcu.rcu_id)

    context = {
        "center_user": rcu,
        "target_user": target_user,
        "target_profile": (target_user.groups.first().name if target_user.groups.exists() else "-"),
        "allowed_type": "center",           
        "establishments": establishments_qs, 
        "regions": regions_qs,
        "states": states_qs,
    }
    return render(request, "main/administrador/center_user_update.html", context)