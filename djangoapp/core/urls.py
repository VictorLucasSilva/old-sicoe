# project/urls.py
from django.urls import path

from core.views.administrador import (
    create_adm,
    delete_adm,
    others_adm,
    read_adm,
    update_adm,
)

from core.views.pdf import api_signed_pdf_links, download_pdf
from core.base import login_view, logout_view

urlpatterns = [
    path('', login_view, name='login'),
    path('login', login_view, name='login'),
    path('logout/', logout_view, name='logout'),

    path('administrador/estabelecimento', read_adm.establishment_list, name='establishment_list'),
    path('administrador/anexos', read_adm.attachment_list, name='attachment_list'),
    path('administrador/visaogeral', read_adm.overview, name='overview'),
    path('administrador/documento', read_adm.document_list, name='document_list'),
    path('administrador/estabelecimento-usuario', read_adm.center_user_list, name='center_user_list'),
    path('administrador/estabelecimento-documento', read_adm.center_doc_list, name='center_doc_list'),
    path('administrador/send_mail', read_adm.email_list, name='email_list'),
    path('administrador/cnpj', read_adm.number_doc_list, name='cnpj_list'),
    path('administrador/usuario', read_adm.user_list, name='user_list'),
    path('administrador/auditoria', read_adm.audit_list, name='audit_list'),

    path('attachment-units-by-center/', others_adm.attachment_units_by_center, name='attachment_units_by_center'),
    path('administrador/attachment/conference/', others_adm.attachment_conference, name='attachment_conference'),
    path('administrador/attachment/busca-geral/', read_adm.attachment_history_all, name='attachment_history_all'),
    path('administrador/email', read_adm.email_list, name='email_list'),
    path('administrador/liberar_acesso/', others_adm.user_access, name='user_access'),

    path('administrador/anexo/cadastrar/', create_adm.attachment_create, name='attachment_create'),
    path('administrador/documento/cadastrar', create_adm.document_create, name='document_create'),
    path('administrador/cnpj/cadastrar', create_adm.cnpj_create, name='cnpj_create'),
    path('administrador/anexo/cadastrar/', create_adm.overview_attachment_create, name='overview_attachment_create'),
    path('administrador/estabelecimento-documento/cadastrar', create_adm.center_doc_create, name='center_doc_create'),
    path('administrador/estabelecimento-usuario/cadastrar', create_adm.center_user_create, name='center_user_create'),

    path('administrador/usuario/<int:id>/editar/', update_adm.user_edit, name='user_edit'),
    path('administrador/cnpj/<int:id>/editar/', update_adm.cnpj_update, name='cnpj_update'),
    path('administrador/documento/<int:id>/excluir/', delete_adm.document_delete, name='document_delete'),
    path('administrador/documento/<int:id>/editar/', update_adm.document_update, name='document_update'),
    path('administrador/establishment/<int:id>/anexar/', create_adm.establishment_attachment_create, name='establishment_attachment_create'),
    path('administrador/estabelecimento-documento/<int:id>/editar/', update_adm.center_doc_update, name='center_doc_update'),
    path('administrador/documento/invalidacao/<int:id>/', update_adm.conference_invalidation, name='conference_invalidation'),
    path('administrador/documento/vencimento/<int:id>/', update_adm.conference_data_expire, name='conference_data_expire'),
    path('administrador/estabelecimento-usuario/<int:id>/editar/', update_adm.center_user_update, name='center_user_update'),
    path('administrador/estabelecimento/<int:id>/editar/', update_adm.establishment_update, name='establishment_update'),
    path('administrador/cnpj/<int:id>/excluir/', delete_adm.num_docs_estab_delete, name='num_docs_delete'),
    path('administrador/estabelecimento-usuario/<int:id>/excluir/', delete_adm.center_user_delete, name='center_user_delete'),
    path('administrador/estabelecimento-documento/<int:id>/excluir/', delete_adm.center_doc_delete, name='center_doc_delete'),

    path('administrador/security/', read_adm.security_list, name='security_list'),
    path('administrador/attachment/<str:region>/<str:center>/documentos/', read_adm.establishment_attachment_list, name='establishment_attachment_list'),
    path('administrador/attachment/<str:document>/<str:region>/<str:center>/busca-2-filtros/', read_adm.attachment_history, name='attachment_history'),

    path('administrador/home', read_adm.overview, name='home'),

    path('administrador/attachment/validation/<int:id>/', others_adm.attachment_validation, name='attachment_validation'),

    path("api/health", create_adm.health, name="health"),
    path("api/_probe/jwt", create_adm.jwt_probe, name="pt_jwt_probe"),
    path("api/_probe/upload", create_adm.upload_probe, name="pt_upload_probe"),
    path("api/_probe/ssrf", create_adm.ssrf_probe, name="pt_ssrf_probe"),
    path('download-pdf/<int:attachment_id>/', download_pdf, name='download_pdf'),
    path('api/attachments/<int:attachment_id>/signed-links', api_signed_pdf_links, name='api_signed_pdf_links'),
]
