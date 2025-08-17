import threading
_local = threading.local()

def set_csp_nonce(nonce: str):
    _local.csp_nonce = nonce

def get_csp_nonce() -> str:
    return getattr(_local, 'csp_nonce', '')

def csp_nonce(request):
    return {'csp_nonce': get_csp_nonce()}
