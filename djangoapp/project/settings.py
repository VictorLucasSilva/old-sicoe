# project/settings.py
from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR.parent / 'data' / 'web'
LOG_DIR = BASE_DIR / 'core' / 'logs'
LOG_DIR.mkdir(parents=True, exist_ok=True)

SECRET_KEY = os.getenv('SECRET_KEY', 'change-me')
DEBUG = bool(int(os.getenv('DEBUG', 0)))

_default_hosts = ['localhost', '127.0.0.1', '[::1]'] if DEBUG else []
ALLOWED_HOSTS = [h.strip() for h in os.getenv('ALLOWED_HOSTS', '').split(',') if h.strip()] or _default_hosts

_default_csrf = []
if DEBUG:
    _default_csrf = [
        'http://localhost:8000', 'https://localhost:8000',
        'http://127.0.0.1:8000', 'https://127.0.0.1:8000',
    ]
CSRF_TRUSTED_ORIGINS = [o.strip() for o in os.getenv('CSRF_TRUSTED_ORIGINS', '').split(',') if o.strip()] or _default_csrf

INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'corsheaders',
    'core',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'core.middleware.QueryStringSizeMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'core.middleware.AuthRequiredMiddleware',
    'core.middleware.LoginLoopGuardMiddleware',
    'core.middleware.CSPMiddleware',
    'core.middleware_security_headers.SecurityHeadersMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'project.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'core.context_processors.csp_nonce',
            ],
        },
    },
]

WSGI_APPLICATION = 'project.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': os.getenv('DB_ENGINE'),
        'NAME': os.getenv('POSTGRES_DB'),
        'USER': os.getenv('POSTGRES_USER'),
        'PASSWORD': os.getenv('POSTGRES_PASSWORD'),
        'HOST': os.getenv('POSTGRES_HOST'),
        'PORT': os.getenv('POSTGRES_PORT'),
        'OPTIONS': {
            'connect_timeout': int(os.getenv('DB_CONNECT_TIMEOUT', '5') or 5),
        },
    }
}

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "unique-login-attempts"
    }
}
"""
# Produção (opcional) — habilite Redis:
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": os.getenv("REDIS_URL", "redis://redis:6379/0"),
        "TIMEOUT": 300,
    }
}
"""

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

LANGUAGE_CODE = 'pt-br'
TIME_ZONE = 'America/Sao_Paulo'
USE_I18N = True
USE_TZ = True

STATIC_URL = '/static/'
STATIC_ROOT = DATA_DIR / 'static'
MEDIA_URL = '/media/'
MEDIA_ROOT = DATA_DIR / 'media'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

#Rode local com USE_HTTPS=0. Em produção, USE_HTTPS=1 atrás de TLS
USE_HTTPS = bool(int(os.getenv('USE_HTTPS', '0')))
SESSION_COOKIE_SECURE = USE_HTTPS
CSRF_COOKIE_SECURE = USE_HTTPS
SECURE_SSL_REDIRECT = USE_HTTPS and not DEBUG


# ---------- CORS ----------
CORS_ALLOWED_ORIGINS = [o.strip() for o in os.getenv('CORS_ALLOWED_ORIGINS', 'http://localhost:8000').split(',') if o.strip()]
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
CORS_ALLOW_HEADERS = ["Authorization", "Content-Type", "X-CSRFToken", "X-Requested-With"]

# ---------- JSON/FORM enforcement ----------
JSON_ONLY_PATHS = tuple([p.strip() for p in os.getenv('JSON_ONLY_PATHS', '/api/').split(',') if p.strip()])
FORM_ONLY_PATHS = tuple([p.strip() for p in os.getenv('FORM_ONLY_PATHS', '/login,/administrador/').split(',') if p.strip()])

# ---------- Assinatura de PDF ----------
SIGNED_URL_BIND_UA = bool(int(os.getenv('SIGNED_URL_BIND_UA', '1')))
SIGNED_URL_BIND_IP = bool(int(os.getenv('SIGNED_URL_BIND_IP', '0')))
SIGNED_URL_CLOCK_SKEW = int(os.getenv('SIGNED_URL_CLOCK_SKEW', '15'))
ENFORCE_SIGNED_PDF_URLS = bool(int(os.getenv('ENFORCE_SIGNED_PDF_URLS', 1)))
SIGNED_URL_TTL_SECONDS = int(os.getenv('SIGNED_URL_TTL_SECONDS', 60))

# ---------- SSRF ----------
SSRF_HOST_ALLOWLIST = [h.strip() for h in os.getenv('SSRF_HOST_ALLOWLIST', '').split(',') if h.strip()]
SSRF_BAD_PORTS = [int(p) for p in os.getenv('SSRF_BAD_PORTS', '21,25,110,143,1900,2049,3306,5432,6379,11211').split(',') if p.strip()]

# ---------- Headers de segurança globais ----------
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SECURE_REFERRER_POLICY = "strict-origin"
SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"
SECURE_CROSS_ORIGIN_EMBEDDER_POLICY = "require-corp"
SECURE_CROSS_ORIGIN_RESOURCE_POLICY = "same-origin"

SESSION_COOKIE_NAME = os.getenv('SESSION_COOKIE_NAME', 'app_session')
CSRF_COOKIE_NAME = os.getenv('CSRF_COOKIE_NAME', 'app_csrf')
#SESSION_COOKIE_SECURE = not DEBUG
#CSRF_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
CSRF_COOKIE_SAMESITE = 'Strict'
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_SAVE_EVERY_REQUEST = True
SESSION_SERIALIZER = 'django.contrib.sessions.serializers.JSONSerializer'

SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
#SECURE_SSL_REDIRECT = (bool(int(os.getenv('SECURE_SSL_REDIRECT', 0))) and not DEBUG)
SECURE_HSTS_SECONDS = 31536000 if not DEBUG else 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = not DEBUG
SECURE_HSTS_PRELOAD = not DEBUG

PT_UPLOAD_ENDPOINT = "/api/_probe/upload"
MAX_UPLOAD_BYTES = 5 * 1024 * 1024 
ALLOWED_UPLOAD_EXTS = {".pdf"}
PT_SSRF_ENDPOINTS = ["/api/_probe/ssrf"]
SSRF_ALLOW_HOSTS = []
PT_JWT_PROBE_ENDPOINT = "/api/_probe/jwt"
JWT_SECRET = os.environ.get("JWT_SECRET", "dev-only-change-me")
JWT_ALG = "HS256"

DATA_UPLOAD_MAX_MEMORY_SIZE = int(os.getenv('DATA_UPLOAD_MAX_MEMORY_SIZE', 2 * 1024 * 1024))
FILE_UPLOAD_MAX_MEMORY_SIZE = int(os.getenv('FILE_UPLOAD_MAX_MEMORY_SIZE', 2 * 1024 * 1024))
DATA_UPLOAD_MAX_NUMBER_FIELDS = int(os.getenv('DATA_UPLOAD_MAX_NUMBER_FIELDS', 1000))
FILE_UPLOAD_PERMISSIONS = 0o640

WAF_AJAX_MODE = os.getenv('WAF_AJAX_MODE', 'lenient').strip().lower()
WAF_NUMERIC_FIELDS = [s.strip() for s in os.getenv('WAF_NUMERIC_FIELDS', 'page,id,offset,limit,u_id,user_id,est_id,d_id,estaux_id,ndest_id,establishment_id,document_id,attachment_id,rcu_id,att_id,rcd_id,aud_id,em_id,sec_id').split(',') if s.strip()]
WAF_SAFE_FIELDS = [s.strip() for s in os.getenv('WAF_SAFE_FIELDS', 'q,search,term,name,d_doc').split(',') if s.strip()]

TRUSTED_PROXIES = [s.strip() for s in os.getenv('TRUSTED_PROXIES', '').split(',') if s.strip()]

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'padrao': {'format': '[{asctime}] {levelname} ({name}:{lineno}) - {message}', 'style': '{'},
        'json':   {'format': '{{"t":"{asctime}","lvl":"{levelname}","log":"{name}","ln":{lineno},"msg":"{message}"}}', 'style': '{'},
    },
    'handlers': {
        'arquivo_seguro': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': str(LOG_DIR / 'seguranca.log'),
            'formatter': 'padrao',
            'maxBytes': 10 * 1024 * 1024,
            'backupCount': 5,
            'encoding': 'utf-8',
        },
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'padrao' if not DEBUG else 'json',
        },
    },
    'loggers': {
        'django': {'handlers': ['arquivo_seguro', 'console'], 'level': 'INFO', 'propagate': True},
        'core':   {'handlers': ['arquivo_seguro', 'console'], 'level': 'INFO', 'propagate': False},
    },
}

if not DEBUG and SECRET_KEY == 'change-me':
    raise RuntimeError("SECRET_KEY obrigatória.")

CELERY_BROKER_URL = os.getenv('CELERY_BROKER_URL') or os.getenv('REDIS_URL')
CELERY_RESULT_BACKEND = os.getenv('CELERY_RESULT_BACKEND') or CELERY_BROKER_URL
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = 'America/Sao_Paulo'

EMAIL_BACKEND = os.getenv('EMAIL_BACKEND', 'django.core.mail.backends.console.EmailBackend')
EMAIL_HOST_USER = os.getenv('EMAIL_HOST_USER', 'no-reply@hostdominio.com')
