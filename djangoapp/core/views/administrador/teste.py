
"""
import requests 
import pandas as pd  
import os 
import time  

url = "http://apis.bbts.com.br:8000/psft/funcionarios/v3"
token = os.getenv("PSFT_API_TOKEN", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJEUFloUDNYQ0VEekk4VVcwSWU2SmJVMDU2Ykg3TU1aWSJ9.IqqVjIx9u5wVfCfP5a6SXwUCmsf5oQNnjmlO_bXVKCE")
headers = {
    "Authorization": f"Bearer {token}",
    "Accept": "application/json",
}

def apiestab(url):
    if not token:
        raise RuntimeError("PSFT_API_TOKEN não definido no ambiente.")

    lista_dados_todas_paginas = []  
    page = 1                        
    page_size = 50                  

    while True:
        resp = requests.get(
            url,
            headers=headers,
            params={"nrPaginaAtual": page, "nrTamanhoPagina": page_size},
            timeout=80,
        )
        resp.raise_for_status()
        data = resp.json()

        funcionarios = data.get("lsFuncionarios", [])
        lista_dados_todas_paginas.extend(funcionarios)

        pag = data.get("inPaginacao", {}) or {}
        nr_atual = pag.get("nrPaginaAtual", page)
        nr_total = pag.get("nrTotalPaginas", nr_atual)

        if nr_atual <= 3: 
            break

        page += 1
        time.sleep(1) 

    return lista_dados_todas_paginas

lista_dados_todas_paginas = apiestab(url)
df = pd.DataFrame(lista_dados_todas_paginas)
df.to_excel("fTransactions.xlsx", index=False, engine="openpyxl")

try:
    df.to_parquet("fTransactions.parquet")
except Exception as e:
    print(f"Parquet não salvo (dependência ausente?): {e}")

"""

import logging
from django.http import JsonResponse, HttpResponseBadRequest
from django.views.decorators.http import require_GET
from core.db.databricks import sql_query, DatabricksConfigError

logger = logging.getLogger("core")

@require_GET
def relatorio_estabelecimentos(request):
    try:
        limite = int(request.GET.get("limit", "50000"))
    except ValueError:
        return HttpResponseBadRequest("limit inválido (use inteiro)")

    if limite <= 0 or limite > 50001:
        return HttpResponseBadRequest("limit inválido (1..10000)")

    sql = '''
        SELECT *
        FROM `colaborativo_gesap`.`refined`.`rst_sicoe_relacionamento`
        LIMIT ?
    '''

    try:
        dados = sql_query(sql, params=[limite], as_dict=True)
    except DatabricksConfigError as e:
        return JsonResponse({"error": str(e)}, status=500)
    except Exception as e:
        logger.exception("Erro consultando Databricks")
        return JsonResponse({"error": "Falha ao consultar Databricks"}, status=502)

    return JsonResponse(
        {"count": len(dados), "results": dados},
        json_dumps_params={"ensure_ascii": False, "default": str},
        safe=False,
    )

"""
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.http import require_GET
from django.core.mail import EmailMultiAlternatives

@require_GET
def enviar_email_simples(request):

    subject = "Teste de e-mail simples"
    from_email = getattr(settings, "DEFAULT_FROM_EMAIL", "app-sicoe@bbts.com.br")
    to = ["micael.vasconcelos@bbts.com.br"]

    text_content = (
        "Olá,\n\nEste é um teste simples de envio com EmailMultiAlternatives.\n"
        "Se você recebeu, o SMTP está funcionando. 👍"
    )
    
    html_content = '''
        <p>o email ta truvando fih kkkk,</p>
    '''

    msg = EmailMultiAlternatives(
        subject=subject,
        body=text_content,
        from_email=from_email,
        to=to,
    )
    
    msg.attach_alternative(html_content, "text/html")
    msg.extra_headers = {"X-App": "app-sicoe"}

    enviados = msg.send(fail_silently=False)

    return JsonResponse({
        "ok": bool(enviados),
        "message": f"E-mail enviado para {to[0]} a partir de {from_email}" if enviados else "Falha no envio"
    })
"""

"""
import secrets

secret_key = secrets.token_hex(32)

print(f"SECRET_KEY gerada: {secret_key}")
"""