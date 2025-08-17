from .models import Attachment, RelationCenterUser, Users, Establishment, Email, EstAux, Document
from celery import shared_task
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.db.models import Max, Q
from django.conf import settings
from datetime import timedelta
from django.utils import timezone
from django.db import transaction
from django.utils.dateformat import format as dj_format
from collections import defaultdict
import requests
import logging

logger = logging.getLogger('core')

@shared_task 
def update_status_attachment():
    try:
        with transaction.atomic():
            attachments = Attachment.objects.all()
            atualizados = 0
            for att in attachments:
                if timezone.now().date() > att.att_data_expire:
                    if att.att_situation != "Vencido" and not att.att_situation == "Em Análise" and not att.att_situation == "Invalidado" :
                        att.att_situation = "Vencido"
                        att.save(update_fields=['att_situation'])
                        atualizados += 1
                elif (timezone.now().date() > (att.att_data_expire - timedelta(days=60))) and (timezone.now().date() < att.att_data_expire):
                    if att.att_situation != "A Vencer" and not att.att_situation == "Em Análise" and not att.att_situation == "Invalidado" :
                        att.att_situation = "A Vencer"
                        att.save(update_fields=['att_situation'])
                        atualizados += 1
                elif timezone.now().date() < (att.att_data_expire - timedelta(days=60)):
                    if att.att_situation != "Regular" and not att.att_situation == "Em Análise" and not att.att_situation == "Invalidado" :
                        att.att_situation = "Regular"
                        att.save(update_fields=['att_situation'])
                        atualizados += 1
            logger.info(f'Atualização concluída.')
            return f'Atualização concluída.'
    except Exception as e:
        logger.error(f'Falha ao atualizar. Erro: {str(e)}')
        return f'Falha ao atualizar. Erro: {str(e)}'

@shared_task
def establishment_list():
    try:
        api_url = "http://apis.bbts.com.br:8000/psft/estabelecimentos/v1"
        headers = {
            'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJEUFloUDNYQ0VEekk4VVcwSWU2SmJVMDU2Ykg3TU1aWSJ9.IqqVjIx9u5wVfCfP5a6SXwUCmsf5oQNnjmlO_bXVKCE'
        }
        response = requests.get(api_url, headers=headers, timeout=60)
        response.raise_for_status()
        data = response.json()
        establishments = data.get('establishment', [])

        with transaction.atomic():
            for item in establishments:
                if isinstance(item, dict):
                    id = int(item.get('estab_id', ''))
                    center = str(item.get('estab_name', '')).strip()
                    addresstype = str(item.get('addresstype', '')).strip()
                    streetaddress = str(item.get('streetaddress', '')).strip()
                    neighborhood = str(item.get('neighborhood', '')).strip()
                    num = str(item.get('num', '')).strip()
                    complement = str(item.get('complement', '')).strip()
                    city = str(item.get('city', '')).strip()
                    state = str(item.get('uf', '')).strip()
                    postal_code = str(item.get('postal_code', '')).strip()
                    address = f'{addresstype} {streetaddress} {num} {complement} {neighborhood}, {city}, {state} - {postal_code}'
                    est_all = Establishment.objects.all()
                    
                    if not est_all.filter(est_id=id).exists():
                        Establishment.objects.create(
                            est_id=id,
                            est_state=state,
                            est_city=city,
                            est_region='',
                            est_center=center,
                            est_address=address,
                            est_manage='-',
                            est_property='-'
                        
                        )

                    est_filtered = Establishment.objects.filter(est_id=id).first()
                    att = Attachment.objects.filter(att_center=est_filtered.est_center).exists()

                    est = est_all.filter(est_id=id).first()
                    if not est.est_region:
                        uf_region = EstAux.objects.filter(estaux_uf=est.est_state).first()
                        est.est_region=uf_region.estaux_region
                        est.save()

                    Establishment.objects.update_or_create(
                        est_id=id,
                        defaults={
                            'est_region': est.est_region,
                            'est_state': state,
                            'est_city': city,
                            'est_center': center,
                            'est_address': address,
                            'est_manage': est.est_manage,
                            'est_property': est.est_property,
                        }
                    )
                    
                    attup = Attachment.objects.filter(att_center=est_filtered.est_center)
                    if not att:
                        attup.update(
                            att_center=center
                        )
                else:
                    print(f"Item inválido (não é dicionário): {item}")
            return f'Atualização concluída.'
    except requests.exceptions.RequestException as e:
        return f'Falha ao atualizar: {str(e)}'

logger = logging.getLogger('core')

"""
logger = logging.getLogger(__name__)
def get_latest_attachments():
    base = Attachment.objects.values('att_doc', 'att_center').annotate(
        latest_date=Max('att_data_inserted')
    )
    query = Q()
    for item in base:
        query |= Q(
            att_doc=item['att_doc'],
            att_center=item['att_center'],
            att_data_inserted=item['latest_date'],
            att_situation__in=["Vencido", "Invalidado", "A Vencer"]
        )
    return Attachment.objects.filter(query).order_by('att_center', '-att_data_inserted')

def get_users_mapped():
    users = Users.objects.all()
    return {u.u_login.strip().lower(): u for u in users}

def get_user_relations(region=None, state=None, center=None, users_dict=None, profile=None):
    filters = Q()
    if region:
        filters |= Q(rcu_region=region)
    if state:
        filters |= Q(rcu_state=state)
    if center:
        filters |= Q(rcu_center=center)

    result = []
    for rel in RelationCenterUser.objects.filter(filters):
        login = rel.rcu_fk_user.u_login.strip().lower()
        user = users_dict.get(login)
        if user and (not profile or user.u_profile == profile):
            result.append({
                "name": user.u_name,
                "login": user.u_login,
                "email": user.u_email or "",
                "profile": user.u_profile
            })
    return result

def get_documents_by_center(region, state, center, attachments):
    docs = set()
    if region != '-' and state == '-' and center == '-':
        filter_ = Q(rcu_region=region)
    elif region == '-' and state != '-' and center == '-':
        filter_ = Q(rcu_state=state)
    elif region == '-' and state == '-' and center != '-':
        filter_ = Q(rcu_center=center)
    else:
        return []

    related = RelationCenterUser.objects.filter(filter_).distinct()
    attachment_filter = Q()
    for r in related:
        if r.rcu_region:
            attachment_filter |= Q(att_region=r.rcu_region)
        if r.rcu_state:
            attachment_filter |= Q(att_state=r.rcu_state)
        if r.rcu_center:
            attachment_filter |= Q(att_center=r.rcu_center)

    matched_attachments = attachments.filter(attachment_filter).distinct()
    for a in matched_attachments:
        docs.add(a.att_doc)

    return list(docs)

@shared_task(bind=True, max_retries=1, default_retry_delay=60)
def send_emails_to_users(self):
    with transaction.atomic():
        attachments = get_latest_attachments()
        send_attachments = attachments
        centers = Establishment.objects.filter(est_center__in=attachments.values_list('att_center', flat=True).distinct())
        users_dict = get_users_mapped()
        user_relations = RelationCenterUser.objects.all()

        for attach in attachments.order_by('-att_data_inserted'):
            center_name = attach.att_center
            est = Establishment.objects.filter(est_center=center_name).first()
            if not est:
                continue

            query = Q(rcu_center=center_name)
            center_user = RelationCenterUser.objects.filter(query)

            for u in center_user:
                list_doc = []
                list_rse = []

                if u.rcu_center == '-' and u.rcu_state == '-':
                    list_rse.append(u.rcu_region)
                    list_doc = get_documents_by_center(region=u.rcu_region, state=None, center=None, attachments=send_attachments)

                elif u.rcu_region == '-' and u.rcu_state == '-':
                    list_rse.append(u.rcu_center)
                    list_doc = get_documents_by_center(region=None, state=None, center=u.rcu_center, attachments=send_attachments)

                elif u.rcu_region == '-' and u.rcu_center == '-':
                    list_rse.append(u.rcu_state)
                    list_doc = get_documents_by_center(region=None, state=u.rcu_state, center=None, attachments=send_attachments)

                if not list_doc:
                    continue

                subject = "Documentos Pendentes - Painel de Estabelecimento"
                from_email = settings.EMAIL_HOST_USER
                context = {
                    'center': ", ".join(list_rse),
                    'first_name': u.rcu_fk_user.u_name,
                    'address_url': "www.pde.com.br",
                    'document': ", ".join(list_doc),
                }

                text_content = render_to_string('others/notification.txt', context)
                msg = EmailMultiAlternatives(subject, text_content, from_email, [u.rcu_fk_user.u_email])
                msg.send()

                Email.objects.create(
                    em_email=u.rcu_fk_user.u_email,
                    em_subject=subject,
                    em_doc=", ".join(list_doc)[:50],
                    em_center=", ".join(list_rse)[:50],
                    em_login=u.rcu_fk_user.u_login
                )

                logger.info(f"[DEBUG] Email enviado para: {u.rcu_fk_user.u_email} com assunto '{subject}'")

"""

@shared_task(bind=True, max_retries=1, default_retry_delay=60)
def send_emails_to_users(self):
    with transaction.atomic():  
        latest = Attachment.objects.values('att_doc', 'att_center').annotate(
            latest_date=Max('att_data_inserted')
        )
        query = Q()
        for item in latest:
            query |= Q(
                att_doc=item['att_doc'],
                att_center=item['att_center'],
                att_data_inserted=item['latest_date'],
                att_situation__in=["Vencido", "Invalidado", "A Vencer"]
            )
            
        latest_attachments = Attachment.objects.filter(query).order_by('att_center', '-att_data_inserted')
        
        send_attachments = Attachment.objects.filter(query).order_by('att_center', '-att_data_inserted')
        centers_names = latest_attachments.values_list('att_center', flat=True).distinct()
        centers = Establishment.objects.filter(est_center__in=centers_names)

        center_status = {}
        for center in centers:
            center_name = center.est_center
            center_status[center_name] = "warning"

        region_centers = {}
        for center in centers:
            reg = center.est_region.upper()
            name = center.est_center
            region_centers.setdefault(reg, []).append({
                "name": name,
                "status": center_status.get(name, "secondary")
            })

        users = Users.objects.all()
        users_dict = {u.u_login.strip().lower(): u for u in users}
        relation_users = RelationCenterUser.objects.all()

        centers_data = {}
        for center in centers:
            center_name = center.est_center
            manage = center.est_manage
            region = center.est_region

            grouped = {}
            for attach in latest_attachments.filter(att_center=center_name).order_by('att_doc', '-att_data_inserted'):
                doc = attach.att_doc
                if doc not in grouped:
                    grouped[doc] = {
                        "document": doc,
                        "data_inserted": dj_format(attach.att_data_inserted, 'd/m/Y H:i')
                    }
            invalidado_info = list(grouped.values())

            user_list = []
            for rel in relation_users.filter(rcu_region=region):
                login = rel.rcu_fk_user.u_login.strip().lower()
                user_obj = users_dict.get(login)
                if user_obj and user_obj.u_profile == "Gerente Regional":
                    user_list.append({
                        "name": user_obj.u_name,
                        "login": user_obj.u_login,
                        "email": user_obj.u_email or "",
                        "profile": user_obj.u_profile
                    })

            for rel in relation_users.filter(rcu_state=center.est_state):
                login = rel.rcu_fk_user.u_login.strip().lower()
                user_obj = users_dict.get(login)
                if user_obj and user_obj.u_profile == "Gerente Regional":
                    user_list.append({
                        "name": user_obj.u_name,
                        "login": user_obj.u_login,
                        "email": user_obj.u_email or "",
                        "profile": user_obj.u_profile
                    })

            for rel in relation_users.filter(rcu_center=center_name):
                login = rel.rcu_fk_user.u_login.strip().lower()
                user_obj = users_dict.get(login)
                if user_obj and user_obj.u_profile == "Usuário":
                    user_list.append({
                        "name": user_obj.u_name,
                        "login": user_obj.u_login,
                        "email": user_obj.u_email or "",
                        "profile": user_obj.u_profile
                    })

            centers_data[center_name] = {
                "invalidado": invalidado_info,
                "users": user_list,
                "manage": manage,
                "region": region
            }

        invalid_by_document = defaultdict(list)
        seen = set()
        for attach in latest_attachments.order_by('-att_data_inserted'):
            key = (attach.att_doc, attach.att_center)
            if key not in seen:
                seen.add(key)
                invalid_by_document[attach.att_doc].append({
                    "center": attach.att_center,
                    "data_inserted": dj_format(attach.att_data_inserted, 'd/m/Y H:i')
                })

            center_name = attach.att_center
            est = Establishment.objects.filter(est_center=center_name)
            query = Q()
            for item in est:
                query |= Q(
                    rcu_center=item.est_center,
                )
                
        center_user = RelationCenterUser.objects.filter(query)

        for u in center_user:
            list_doc = []
            list_rse = []
            if u.rcu_center == '-' and u.rcu_state == '-':
                list_rse.append(u.rcu_region)
                
                query_doc = Q()
                query_rcu_est = Q()
                query_att = Q()
                for item in send_attachments:
                    query_rcu_est |= Q(rcu_region=item.att_region)
                    rcu_est = RelationCenterUser.objects.filter(query_rcu_est).distinct()
                    for item in rcu_est:
                        query_att |= Q(att_region=item.rcu_region)
                        att = latest_attachments.filter(query_att).distinct()
                        for item in att:
                            query_doc |= Q(d_doc=item.att_doc)
                            doc = Document.objects.filter(query_doc).distinct()
                            for d in doc:
                                list_doc.append(d.d_doc)     
            elif u.rcu_region == '-' and u.rcu_state == '-':
                list_rse.append(u.rcu_center)
                
                query_doc = Q()
                query_rcu_est = Q()
                query_att = Q()
                for item in send_attachments:
                    query_rcu_est |= Q(rcu_center=item.att_center)
                    rcu_est = RelationCenterUser.objects.filter(query_rcu_est).distinct()
                    for item in rcu_est:
                        query_att |= Q(att_center=item.rcu_center)
                        att = latest_attachments.filter(query_att).distinct()
                        for item in att:
                            query_doc |= Q(d_doc=item.att_doc)
                            doc = Document.objects.filter(query_doc).distinct()
                            for d in doc:
                                list_doc.append(d.d_doc)
            elif u.rcu_region == '-' and u.rcu_center == '-':
                list_rse.append(u.rcu_state)
                
                query_doc = Q()
                query_rcu_est = Q()
                query_att = Q()
                
                query_rcu_est |= Q(rcu_state=item.att_state)
                rcu_est = send_attachments.filter(query_rcu_est).distinct()
                for item in send_attachments:
                    query_rcu_est |= Q(rcu_state=item.att_state)
                    rcu_est = RelationCenterUser.objects.filter(query_rcu_est).distinct()
                    for item in rcu_est:
                        query_att |= Q(att_state=item.rcu_state)
                        att = latest_attachments.filter(query_att).distinct()
                        for item in att:
                            query_doc |= Q(d_doc=item.att_doc)
                            doc = Document.objects.filter(query_doc).distinct()
                            for d in doc:
                                list_doc.append(d.d_doc)
                        
            subject = f"Documentos Pendentes - Painel de Estabelecimento"
            from_email = settings.EMAIL_HOST_USER
            doc=", ".join(list_doc)
            center=", ".join(list_rse)
            
            context = {
                'center': center,
                'first_name': u.rcu_fk_user.u_name,
                'address_url': "wwww.pde.com.br",
                'document' : doc,
            }
            
            text_content = render_to_string('others/notification.txt', context)
            # html_content = render_to_string('others/notification.html', context)

            msg = EmailMultiAlternatives(subject, text_content, from_email, [u.rcu_fk_user.u_email])
            # msg.attach_alternative(html_content, "text/html")
            msg.send()
            
            Email.objects.create(
                em_email=u.rcu_fk_user.u_email,
                em_subject=subject,
                em_doc=", ".join(list_doc)[:50],
                em_center=", ".join(list_rse)[:50],
                em_login=u.rcu_fk_user.u_login
            )

            list_doc.clear()
            list_rse.clear()
            logger.info(f"[DEBUG] Email enviado para: {u.rcu_fk_user.u_email} com assunto '{subject}'")

            
@shared_task
def update_status_user():
    try:
        with transaction.atomic():
            user = Users.objects.all()
            
            for u in user:
                if timezone.now().date() > u.u_time_out:
                    if u.u_status != "Inativo":
                        u.u_status = "Inativo"
                        u.save()
                elif timezone.now().date() < u.u_time_out:
                    if u.u_status != "Ativo":
                        u.u_status = "Ativo"
                        u.save()            
                    
            logger.info(f'Atualização concluída.')
            return f'Atualização concluída.'
        
    except Exception as e:
        logger.error(f'Falha ao atualizar. Erro: {str(e)}')
        return f'Falha ao atualizar. Erro: {str(e)}' 
                    
                    