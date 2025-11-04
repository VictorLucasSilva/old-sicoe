import logging
import os
import jwt
import re

from django.views.decorators.http import require_GET
from django.shortcuts import render, redirect
from django.contrib import messages
from django.http import JsonResponse
from core.decorators import only_administrador
from core.models import Establishment, Document, User, RelationCenterUser, RelationCenterDoc, Attachment, Audit
from core.forms.administrador.form_create_adm import DCreateForm, RCDCreateForm, NDESTCreateForm, OverAttachmentForm, RCUCreateForm
from django.db import transaction
from django.db.models import OuterRef, Subquery, F
from django.core.exceptions import ValidationError
from django.views.decorators.http import require_POST
from django.conf import settings
from django.db.models.functions import Lower
from django.views.decorators.http import require_http_methods
from core.forms.administrador.form_create_adm import AttachmentForm, RCUCreateForm, DCreateForm, NDESTCreateForm, RCDCreateForm, OverAttachmentForm 
from django.db import transaction, IntegrityError
from django.core.exceptions import MultipleObjectsReturned

MAX_ATTEMPTS = 5
BLOCK_DURATION = 30 * 60

logger = logging.getLogger(__name__)

@only_administrador
@require_http_methods(["GET", "POST"])
def document_create(request):
    if request.method == 'POST':
        form = DCreateForm(request.POST)
        if form.is_valid():
            try:
                with transaction.atomic():
                    document = form.save()
                    groups = list(request.user.groups.values_list('name', flat=True))
                    if request.user.is_superuser or 'Administrador' in groups:
                        profile = 'Administrador'
                    else:
                        profile = ', '.join(groups) or '-'

                    Audit.objects.create(
                        aud_login=request.user.get_username(),
                        aud_profile=profile,
                        aud_action="Cadastro",
                        aud_obj_modified="Documento",
                        aud_description=document.d_doc
                    )
                messages.success(request, 'Documento cadastrado com sucesso.')
                return redirect('document_list')
            except IntegrityError:
                form.add_error('d_doc', 'Já existe um documento com este nome.')
            except Exception:
                logger.exception("Falha ao cadastrar documento")
                messages.warning(request, 'Erro ao cadastrar. Tente novamente.')
    else:
        form = DCreateForm()
    return render(request, 'main/administrador/document_create.html', {'form': form})

@only_administrador
def cnpj_create(request):
    user = request.user
    if request.method == "POST":
        form = NDESTCreateForm(request.POST)
        if form.is_valid():
            try:
                with transaction.atomic():
                    ndest = form.save()
                    group = user.groups.first().name if user.groups.exists() else "Sem Acesso"
                    Audit.objects.create(
                        aud_login=user.username,          
                        aud_profile=group,
                        aud_action="Cadastro",
                        aud_obj_modified="Unidade",
                        aud_description=(
                            f"{ndest.ndest_fk_establishment.est_center} • "
                            f" Unidade: {ndest.ndest_units} | (CNPJ: {ndest.ndest_cnpj} | "
                            f" NIRE: {ndest.ndest_nire} | "
                            f" Inscrição Estadual: {ndest.ndest_reg_state} | "
                            f" Inscrição Municipal: {ndest.ndest_reg_city}"
                        ),
                    )
                    messages.success(request, "Unidade cadastrada com sucesso.")
                    return redirect("cnpj_list")
            except IntegrityError:
                messages.warning(request, "Registro duplicado ou conflito de integridade.")
            except Exception:
                logger.exception("Falha ao cadastrar número de documento/estabelecimento.")
                messages.warning(request, "Erro ao cadastrar. Tente novamente.")
    else:
        form = NDESTCreateForm()
    return render(request, "main/administrador/cnpj_create.html", {"form": form})

@only_administrador
@require_http_methods(["GET", "POST"])
def center_user_create(request):
    users_qs = (
        User.objects.filter(
            is_active=True, u_status="Ativo",
            groups__name__in=["Usuário", "Gerente Regional"]
        ).distinct().order_by("username")
    )
    centers_qs = Establishment.objects.order_by("est_center")

    # Pré-seleção só no GET (UI)
    selected_user = None
    if request.method == "GET":
        uid_from_req = request.GET.get("user")
        if uid_from_req:
            selected_user = users_qs.filter(id=uid_from_req).first()

    if request.method == "POST":
        # 1) Ache a instância existente para evitar o erro de unicidade do ModelForm
        u_id = request.POST.get("rcu_fk_user")
        e_id = request.POST.get("rcu_fk_estab")

        existing_rcu = None
        if u_id and e_id:
            try:
                existing_rcu = RelationCenterUser.objects.get(
                    rcu_fk_user_id=u_id,
                    rcu_fk_estab_id=e_id,
                )
            except RelationCenterUser.DoesNotExist:
                existing_rcu = None
            except MultipleObjectsReturned:
                # Se houver dados antigos duplicados, pega o último
                existing_rcu = (
                    RelationCenterUser.objects
                    .filter(rcu_fk_user_id=u_id, rcu_fk_estab_id=e_id)
                    .order_by("-rcu_id").first()
                )

        # 2) No POST, NÃO passe selected_user (para não filtrar o queryset!)
        form = RCUCreateForm(
            request.POST,
            users_qs=users_qs,
            centers_qs=centers_qs,
            instance=existing_rcu,   # <<<<<< aqui é o pulo do gato
        )

        if not form.is_valid():
            for fld, errs in form.errors.items():
                for e in errs:
                    messages.error(request, f"{fld}: {e}")
            return render(request, "main/administrador/center_user_create.html", {"form": form})

        u_obj   = form.cleaned_data["rcu_fk_user"]
        est_obj = form.cleaned_data["rcu_fk_estab"]

        admin_profile = (
            "Administrador"
            if (request.user.is_superuser or request.user.groups.filter(name="Administrador").exists())
            else ", ".join(request.user.groups.values_list("name", flat=True)) or "-"
        )

        try:
            with transaction.atomic():
                # Reativar se já existe inativo
                updated = (
                    RelationCenterUser.objects
                    .select_for_update()
                    .filter(rcu_fk_user=u_obj, rcu_fk_estab=est_obj, rcu_active=False)
                    .update(
                        rcu_active=True,
                        rcu_center=est_obj.est_center or "-",
                        rcu_state=est_obj.est_state or "-",
                        rcu_region=est_obj.est_region or "-",
                    )
                )
                if updated >= 1:
                    Audit.objects.create(
                        aud_login=request.user.get_username(),
                        aud_profile=admin_profile,
                        aud_action="Reativação de Relação",
                        aud_obj_modified="Usuário | Estabelecimento",
                        aud_description=f"{u_obj.get_username()} | {est_obj.est_center}",
                    )
                    messages.success(request, "Relação reativada com sucesso.")
                    return redirect("center_user_list")

                # Criar se não existe nada
                rcu, created = RelationCenterUser.objects.get_or_create(
                    rcu_fk_user=u_obj,
                    rcu_fk_estab=est_obj,
                    defaults={
                        "rcu_active": True,
                        "rcu_center": est_obj.est_center or "-",
                        "rcu_state": est_obj.est_state or "-",
                        "rcu_region": est_obj.est_region or "-",
                    },
                )
                if created:
                    Audit.objects.create(
                        aud_login=request.user.get_username(),
                        aud_profile=admin_profile,
                        aud_action="Cadastro",
                        aud_obj_modified="Vinculo Usuário",
                        aud_description=f"{u_obj.get_username()} • {est_obj.est_center}",
                    )
                    messages.success(request, "Relação criada com sucesso.")
                    return redirect("center_user_list")

                # Já existia e está ATIVO
                if rcu.rcu_active:
                    messages.warning(request, "Já existe uma relação ativa para este colaborador e estabelecimento.")
                    return redirect("center_user_list")

                # Caso extremo: existia mas não caiu no update acima; force ativar
                rcu.rcu_active = True
                rcu.rcu_center = est_obj.est_center or "-"
                rcu.rcu_state  = est_obj.est_state or "-"
                rcu.rcu_region = est_obj.est_region or "-"
                rcu.save(update_fields=["rcu_active", "rcu_center", "rcu_state", "rcu_region"])
                Audit.objects.create(
                    aud_login=request.user.get_username(),
                    aud_profile=admin_profile,
                    aud_action="Reativação de Relação",
                    aud_obj_modified="Usuário | Estabelecimento",
                    aud_description=f"{u_obj.get_username()} | {est_obj.est_center}",
                )
                messages.success(request, "Relação reativada com sucesso.")
                return redirect("center_user_list")

        except Exception:
            logger.exception("Falha ao salvar relação Estabelecimento/Usuário")
            messages.error(request, "Erro ao salvar. Tente novamente.")
            return render(request, "main/administrador/center_user_create.html", {"form": form})

    # GET permanece igual (pode passar selected_user para esconder ATIVOS no combo)
    initial = {}
    if selected_user:
        initial["rcu_fk_user"] = selected_user.id
    form = RCUCreateForm(
        users_qs=users_qs,
        centers_qs=centers_qs,
        selected_user=selected_user,
        initial=initial or None,
    )
    return render(request, "main/administrador/center_user_create.html", {"form": form})

@only_administrador
@require_http_methods(["GET", "POST"])
def center_doc_create(request):
    # Bloqueia usuário inativo
    if getattr(request.user, 'u_status', 'Inativo') != 'Ativo':
        messages.error(request, "Seu usuário está inativo.")
        return redirect('login_view')

    # ---------- AJAX: retorna listas filtradas com base em doc e/ou center ----------
    if request.method == "GET" and request.headers.get('x-requested-with') == 'XMLHttpRequest':
        doc_id    = request.GET.get("doc") or None
        center_id = request.GET.get("center") or None

        centers_qs = Establishment.objects.order_by(Lower('est_center'), 'est_center')
        docs_qs    = Document.objects.order_by(Lower('d_doc'), 'd_doc')

        # Se veio doc, remove centros já relacionados a esse doc
        if doc_id:
            centers_qs = centers_qs.exclude(
                pk__in=RelationCenterDoc.objects
                    .filter(rcd_fk_document_id=doc_id)
                    .values_list('rcd_fk_establishment_id', flat=True)
            )

        # Se veio center, remove docs já relacionados a esse center
        if center_id:
            docs_qs = docs_qs.exclude(
                pk__in=RelationCenterDoc.objects
                    .filter(rcd_fk_establishment_id=center_id)
                    .values_list('rcd_fk_document_id', flat=True)
            )

        return JsonResponse({
            "establishments": [
                {"est_id": e.pk, "est_center": e.est_center or ""}
                for e in centers_qs
            ],
            "documents": [
                {"doc_id": d.pk, "d_doc": d.d_doc}
                for d in docs_qs
            ],
        })
    # -------------------------------------------------------------------------------

    establishment_l = Establishment.objects.order_by(Lower('est_center'), 'est_center')
    document_l      = Document.objects.order_by(Lower('d_doc'), 'd_doc')

    if request.method == 'POST':
        form = RCDCreateForm(request.POST)
        if form.is_valid():
            est = form.cleaned_data['rcd_fk_establishment']
            doc = form.cleaned_data['rcd_fk_document']

            # Defesa extra contra duplicidade
            if RelationCenterDoc.objects.filter(
                rcd_fk_establishment=est, rcd_fk_document=doc
            ).exists():
                messages.warning(request, 'Esta relação já existe.')
                return redirect('center_doc_list')

            try:
                with transaction.atomic():
                    RelationCenterDoc.objects.create(
                        rcd_fk_establishment=est,
                        rcd_fk_document=doc
                    )

                    admin_profile = (
                        'Administrador' if (
                            request.user.is_superuser or
                            request.user.groups.filter(name='Administrador').exists()
                        )
                        else ', '.join(request.user.groups.values_list('name', flat=True)) or '-'
                    )

                    Audit.objects.create(
                        aud_login=request.user.get_username(),
                        aud_profile=admin_profile,
                        aud_action="Cadastro",
                        aud_obj_modified="Vinculo Documento",
                        aud_description=f"{est} • {doc}",
                    )

                messages.success(request, 'Relação Estabelecimento/Documento cadastrada com sucesso.')
                return redirect('center_doc_list')
            except Exception:
                logger.exception("Falha ao cadastrar relação Estabelecimento/Documento")
                messages.error(request, 'Erro ao cadastrar. Tente novamente.')
        else:
            messages.error(request, "Corrija os erros abaixo.")
    else:
        form = RCDCreateForm()

    return render(
        request,
        'main/administrador/center_doc_create.html',
        {
            'form': form,
            'establishment_l': establishment_l,
            'document_l': document_l,
        }
    ) 
    
def validate_file(f):
    if f.size > 5 * 1024 * 1024:
        raise ValidationError("Arquivo muito grande (máx 5MB)")
    if not f.name.lower().endswith('.pdf'):
        raise ValidationError("Somente arquivos PDF são permitidos")

@only_administrador
@require_http_methods(["GET", "POST"])
def attachment_create(request):
    if getattr(request.user, 'u_status', 'Inativo') != 'Ativo':
        messages.error(request, "Seu usuário está inativo.")
        return redirect('login')

    region = request.GET.get('region')
    state  = request.GET.get('state')
    center = request.GET.get('center')

    if region and not state and not center:
        states = (Establishment.objects
                  .filter(est_region=region)
                  .exclude(est_state__isnull=True)
                  .values_list('est_state', flat=True)
                  .distinct()
                  .order_by('est_state'))
        return JsonResponse({'states': list(states)})

    if region and state and not center:
        centers = (Establishment.objects
                   .filter(est_region=region, est_state=state)
                   .exclude(est_center__isnull=True)
                   .values_list('est_center', flat=True)
                   .distinct()
                   .order_by(Lower('est_center'), 'est_center'))
        return JsonResponse({'centers': list(centers)})

    if center:
        try:
            center_obj = Establishment.objects.get(est_center=center)
        except Establishment.DoesNotExist:
            return JsonResponse({'documents': []})

        docs_qs = (RelationCenterDoc.objects
                   .filter(rcd_fk_establishment=center_obj)
                   .values_list('rcd_fk_document__d_doc', flat=True)
                   .distinct())

        base_att = Attachment.objects.filter(att_center=center_obj.est_center, att_doc__in=docs_qs)
        latest_dt_sub = (Attachment.objects
                         .filter(att_center=center_obj.est_center, att_doc=OuterRef('att_doc'))
                         .order_by('-att_data_inserted')
                         .values('att_data_inserted')[:1])
        latest_rows = base_att.annotate(_latest_dt=Subquery(latest_dt_sub)).filter(att_data_inserted=F('_latest_dt'))

        blocked_docs = set(latest_rows
                           .filter(att_situation__in=['Regular', 'Em Análise'])
                           .values_list('att_doc', flat=True))

        documents_filtered = sorted([d for d in docs_qs if d not in blocked_docs], key=str.casefold)
        return JsonResponse({'documents': documents_filtered})

    if request.method == 'POST':
        form = AttachmentForm(request.POST, request.FILES, user=request.user)
        if form.is_valid():
            region      = form.cleaned_data['region']
            state       = form.cleaned_data['state']
            center_name = form.cleaned_data['center']
            document    = form.cleaned_data['document']
            data_expire = form.cleaned_data['data_expire']
            file        = form.cleaned_data['file']

            try:
                center_obj = Establishment.objects.get(
                    est_center=center_name, est_region=region, est_state=state
                )
            except Establishment.DoesNotExist:
                messages.error(request, "Estabelecimento inválido.")
                return redirect('attachment_create')

            last_for_doc = (Attachment.objects
                            .filter(att_center=center_obj.est_center, att_doc=document)
                            .order_by('-att_data_inserted')
                            .first())
            if last_for_doc and last_for_doc.att_situation in ('Regular', 'Em Análise'):
                messages.error(
                    request,
                    f"Já existe um anexo de '{document}' com status "
                    f"'{last_for_doc.att_situation}' para o estabelecimento '{center_name}'."
                )
                return redirect('attachment_create')

            try:
                with transaction.atomic():
                    Attachment.objects.create(
                        att_doc=document,
                        att_region=region,
                        att_state=state,
                        att_city=center_obj.est_city,
                        att_situation="Em Análise",
                        att_center=center_obj.est_center,
                        att_data_expire=data_expire,
                        att_file=file,
                        att_attached_by=request.user.get_username(),
                    )

                    admin_profile = (
                        'Administrador'
                        if (request.user.is_superuser or request.user.groups.filter(name='Administrador').exists())
                        else ', '.join(request.user.groups.values_list('name', flat=True)) or '-'
                    )
                    Audit.objects.create(
                        aud_login=request.user.get_username(),
                        aud_profile=admin_profile,
                        aud_action="Cadastro",
                        aud_obj_modified="Anexo",
                        aud_description=f"{center_name} • {document} • {data_expire.strftime('%d/%m/%Y')}"
                    )

                messages.success(request, 'Documento anexado com sucesso, e está em análise.')
                return redirect('attachment_list')

            except Exception:
                logger.exception("Falha ao anexar documento")
                messages.error(request, 'Erro ao anexar. Tente novamente.')
    else:
        form = AttachmentForm(user=request.user)

    return render(
        request,
        'main/administrador/attachment_create.html',
        {'form': form, 'user_': request.user} 
    )

try:
    from core.utils import enforce_content_type
except Exception:
    def enforce_content_type(request, form_paths=(), allow_multipart=True):
        ct = (request.META.get('CONTENT_TYPE') or '')
        ok = ('application/x-www-form-urlencoded' in ct) or ('multipart/form-data' in ct)
        return ok

SAFE_NAME_RE = re.compile(r'[^A-Za-z0-9\-\._]+', re.UNICODE)

def _safe_pdf_name(document: str, center: str, original: str) -> str:
    base = f"{center}__{document}__{original}".strip()
    base = SAFE_NAME_RE.sub('_', base)
    if not base.lower().endswith('.pdf'):
        base += '.pdf'
    return base[:150]

@only_administrador
@require_http_methods(["GET", "POST"])
def overview_attachment_create(request, document, center):
    establishment = Establishment.objects.filter(est_center=center).first()
    if not establishment:
        messages.error(request, "Estabelecimento não encontrado.")
        return redirect('overview')

    doc_permitido = RelationCenterDoc.objects.filter(
        rcd_fk_establishment=establishment,
        rcd_fk_document__d_doc=document
    ).exists()
    if not doc_permitido:
        messages.error(request, "Documento não é permitido para este estabelecimento.")
        return redirect('overview')

    if request.method == "POST":
        if not enforce_content_type(request, form_paths=('/administrador/',), allow_multipart=True):
            messages.error(request, "Content-Type não permitido para envio de formulário.")
            return redirect(request.path)

        form = OverAttachmentForm(request.POST, request.FILES, user=request.user)
        if not form.is_valid():
            for field, errs in form.errors.items():
                for err in errs:
                    messages.error(request, f"{field}: {err}")

            context = {
                'region': establishment.est_region,
                'state': establishment.est_state,
                'center': center,
                'document': document,
                'initial_data': {
                    'region': establishment.est_region,
                    'state':  establishment.est_state,
                    'center': center,
                    'document': document,
                }
            }
            return render(request, 'main/administrador/overview_attachment_create.html', context)

        data_expire = form.cleaned_data['data_expire']
        up_file     = form.cleaned_data['file']

        last_for_doc = (Attachment.objects
                        .filter(att_center=center, att_doc=document)
                        .order_by('-att_data_inserted')
                        .first())
        if last_for_doc and last_for_doc.att_situation in ('Regular', 'Em Análise'):
            messages.error(
                request,
                f"Já existe um anexo de '{document}' com status "
                f"'{last_for_doc.att_situation}' para o estabelecimento '{center}'."
            )
            return redirect('overview')

        up_file.name = _safe_pdf_name(document, center, up_file.name or 'arquivo.pdf')
        attached_by = request.user.get_username() or getattr(request.user, 'email', '') or "Sistema"

        try:
            with transaction.atomic():
                Attachment.objects.create(
                    att_data_expire = data_expire,
                    att_attached_by = attached_by,
                    att_file        = up_file,
                    att_region      = establishment.est_region or "-",
                    att_state       = establishment.est_state,
                    att_city        = establishment.est_city,
                    att_doc         = document,
                    att_center      = center,
                )

                admin_profile = (
                    'Administrador'
                    if (request.user.is_superuser or request.user.groups.filter(name='Administrador').exists())
                    else ', '.join(request.user.groups.values_list('name', flat=True)) or '-'
                )

                Audit.objects.create(
                    aud_login      = attached_by,
                    aud_profile    = admin_profile,
                    aud_action     = "Cadastro",
                    aud_obj_modified = "Anexo",
                    aud_description  = f"{center} • {document} • {data_expire.strftime('%d/%m/%Y')}",
                )
            messages.success(request, "Documento anexado com sucesso.")
            return redirect('overview')
        except Exception:
            logger.exception("Falha ao salvar o anexo")
            messages.error(request, "Erro ao salvar o anexo. Tente novamente.")
            return redirect(request.path)
    context = {
        'region': establishment.est_region,
        'state': establishment.est_state,
        'center': center,
        'document': document,
        'initial_data': {
            'region': establishment.est_region,
            'state':  establishment.est_state,
            'center': center,
            'document': document,
        }
    }
    return render(request, 'main/administrador/overview_attachment_create.html', context)

@require_POST
def upload_probe(request):
    f = request.FILES.get("file")
    if not f:
        return JsonResponse({"error":"missing file"}, status=400)

    if f.size > getattr(settings, "MAX_UPLOAD_BYTES", 5*1024*1024):
        return JsonResponse({"error":"too large"}, status=413)

    _, ext = os.path.splitext(f.name.lower())
    if ext not in getattr(settings, "ALLOWED_UPLOAD_EXTS", {".pdf",".jpg",".jpeg",".png"}):
        return JsonResponse({"error":"ext not allowed"}, status=415)

    for _ in f.chunks(): 
        pass
    return JsonResponse({"ok": True}, status=204)

@require_GET
def ssrf_probe(request):
    return JsonResponse({"blocked": True}, status=403)

@require_GET
def jwt_probe(request):
    auth = request.META.get("HTTP_AUTHORIZATION", "")
    if not auth.startswith("Bearer "):
        resp = JsonResponse({"detail":"Unauthorized"}, status=401)
        resp["WWW-Authenticate"] = "Bearer"
        return resp

    token = auth.split(" ",1)[1].strip()
    try:
        jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALG], options={"require": ["exp"]})
        return JsonResponse({}, status=204)
    except jwt.ExpiredSignatureError:
        return JsonResponse({"detail":"token expired"}, status=401)
    except Exception:
        return JsonResponse({"detail":"invalid token"}, status=401)
    
@require_GET
def health(request):
    return JsonResponse({"status":"ok"}, status=200)