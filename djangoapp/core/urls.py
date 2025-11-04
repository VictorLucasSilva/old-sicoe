from django.urls import path
from core.views.administrador import(create_adm,delete_adm,others_adm,read_adm,update_adm, teste)
from core.views.usuario import(create_user, read_user)
from core.views.gerente import(create_manager, read_manager)
from core.views.auditor import(read_aud)

from core.base import (
    login_view,secure_pdf_view, post_login_redirect, request_access
)

from core.views.sso import (
    login_start, logout, callback
)

urlpatterns = [

    path('', login_view, name='login'),

    path("oauth2/login",    login_start, name="oidc_login"),
    path("oauth2/callback", callback,    name="oidc_callback"),
    path("oauth2/logout",   logout,      name="oidc_logout"),

    path("post-login/", post_login_redirect, name="post_login"),
    path("solicitar-acesso", request_access, name="request_access"),

    path('teste', teste.relatorio_estabelecimentos, name="teste"),
    #path("email/enviar-simples/", teste.enviar_email_simples, name="enviar_email_simples"),

    path('usuario/anexos', read_user.attachment_list, name='attachment_list_user'), 
    path('usuario/home', read_user.overview, name='home_user'), 
    path('usuario/attachment/<str:document>/<str:region>/<str:center>/busca-2-filtros/', read_user.attachment_history, name='attachment_history_user'),
    path('usuario/anexo/cadastrar/<str:document>/<str:center>/', create_user.overview_attachment_create, name='overview_attachment_create_user'),
    
    path('gerente-regional/anexos', read_manager.attachment_list, name='attachment_list_manager'), 
    path('gerente-regional/home', read_manager.overview, name='home_manager'), 
    path('gerente-regional/attachment/<str:document>/<str:region>/<str:center>/busca-2-filtros/', read_manager.attachment_history, name='attachment_history_manager'), 
    path('gerente-regional/anexo/cadastrar/<str:document>/<str:center>/', create_manager.overview_attachment_create, name='overview_attachment_create_manager'),
    
    path('auditor/anexos', read_aud.attachment_list, name='attachment_list_audit'),
    path('auditor/home', read_aud.overview, name='home_audit'), 
    path('auditor/auditoria', read_aud.audit_list, name='audit_list_audit'), 
    path('auditor/email', read_aud.email_list, name='email_list_audit'),
    path('auditor/attachment/busca-geral/', read_aud.attachment_history_all, name='attachment_history_all_audit'),
    path('auditor/attachment/<str:document>/<str:region>/<str:center>/busca-2-filtros/', read_aud.attachment_history, name='attachment_history_audit'), 
    
    path('administrador/estabelecimento', read_adm.establishment_list, name='establishment_list'), 
    path('administrador/anexos', read_adm.attachment_list, name='attachment_list'),
    path("administrador/psft/funcionarios/pagina3", others_adm.funcionarios_pagina3, name="funcionarios_pagina3"), 
    path('administrador/visaogeral', read_adm.overview, name='overview'), 
    path('administrador/documento', read_adm.document_list, name='document_list'),
    path('administrador/estabelecimento-usuario', read_adm.center_user_list, name='center_user_list'), 
    path('administrador/estabelecimento-documento', read_adm.center_doc_list, name='center_doc_list'),
    path('administrador/usuario', read_adm.user_list, name='user_list'), 
    path('administrador/auditoria', read_adm.audit_list, name='audit_list'), 
    path("administrador/apiestab", others_adm.apiestab, name="apiestab"),
    path('administrador/cnpj', read_adm.number_doc_list, name='cnpj_list'),
    path('attachment-units-by-center/', others_adm.attachment_units_by_center, name='attachment_units_by_center'),
    path('administrador/attachment/conference/', others_adm.attachment_conference, name='attachment_conference'),
    path('administrador/attachment/busca-geral/', read_adm.attachment_history_all, name='attachment_history_all'),
    path('administrador/email', read_adm.email_list, name='email_list'),
    path('administrador/liberar_acesso/', others_adm.user_access, name='user_access'),
    path('administrador/anexo/cadastrar/', create_adm.attachment_create, name='attachment_create'),
    path('administrador/documento/cadastrar', create_adm.document_create, name='document_create'),
    path('administrador/cnpj/cadastrar', create_adm.cnpj_create, name='cnpj_create'),
    path('administrador/anexo/cadastrar/<str:document>/<str:center>/', create_adm.overview_attachment_create, name='overview_attachment_create'),
    path('administrador/estabelecimento-documento/cadastrar', create_adm.center_doc_create, name='center_doc_create'), 
    path('administrador/estabelecimento-usuario/cadastrar', create_adm.center_user_create, name='center_user_create'),
    path('administrador/usuario/<int:id>/editar/', update_adm.user_edit, name='user_edit'),
    path('administrador/cnpj/<int:id>/editar/', update_adm.cnpj_update, name='cnpj_update'),
    path('administrador/documento/<int:id>/excluir/', delete_adm.document_delete, name='document_delete'),
    path('administrador/documento/<int:id>/editar/', update_adm.document_update, name='document_update'),
    path('administrador/estabelecimento-documento/<int:id>/editar/', update_adm.center_doc_update, name='center_doc_update'),
    path('administrador/documento/invalidacao/<int:id>/', update_adm.conference_invalidation, name='conference_invalidation'),
    path('administrador/documento/vencimento/<int:id>/', update_adm.conference_data_expire, name='conference_data_expire'),
    path('administrador/estabelecimento-usuario/<int:id>/editar/', update_adm.center_user_update, name='center_user_update'),
    path('administrador/estabelecimento/<int:id>/editar/', update_adm.establishment_update, name='establishment_update'), 
    path('administrador/cnpj/<int:id>/excluir/', delete_adm.num_docs_estab_delete, name='num_docs_delete'),
    path('administrador/estabelecimento-usuario/<int:id>/excluir/', delete_adm.center_user_delete, name='center_user_delete'),
    path('administrador/estabelecimento-documento/<int:id>/excluir/', delete_adm.center_doc_delete, name='center_doc_delete'),
    path('administrador/anexos/invalidacao/<int:id>/', update_adm.attachment_invalidation, name='attachment_invalidation'),
    path('administrador/attachment/validation/<int:id>/', others_adm.attachment_validation, name='attachment_validation'),
    path('administrador/attachment/<str:document>/<str:region>/<str:center>/busca-2-filtros/', read_adm.attachment_history, name='attachment_history'),
    
    path('administrador/home', read_adm.overview, name='home'),
    path('download-pdf/<int:attachment_id>/', secure_pdf_view, name='secure_pdf'),
]
