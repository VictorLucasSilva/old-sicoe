import logging
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR.parent / "data" / "web"

SECRET_KEY = os.getenv("SECRET_KEY", "change-me")
DEBUG = bool(int(os.getenv("DEBUG")))

def env_str(name, default=""):
    v = os.getenv(name)
    return v if v is not None else default

AUTH_USER_MODEL = "core.User"

ALLOWED_HOSTS = [
    h.strip() for h in os.getenv("ALLOWED_HOSTS", "").split(",") if h.strip()
]

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "core",
    "django_apscheduler",
    "scheduler_app",
    "django_auth_adfs",
]
PUBLIC_REDIRECT_URI = env_str("PUBLIC_REDIRECT_URI", None) 
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "core.middleware.RouteAclMiddleware",
    "core.middleware.AuthRequiredMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "project.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "project.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": os.getenv("DB_ENGINE"),
        "NAME": os.getenv("POSTGRES_DB"),
        "USER": os.getenv("POSTGRES_USER"),
        "PASSWORD": os.getenv("POSTGRES_PASSWORD"),
        "HOST": os.getenv("POSTGRES_HOST"),
        "PORT": os.getenv("POSTGRES_PORT"),
    }
}

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "unique-login-attempts",
    }
}

LANGUAGE_CODE = "pt-br"
TIME_ZONE = "America/Sao_Paulo"   
USE_I18N = True
USE_TZ = True                    

STATIC_URL = "/static/"
STATIC_ROOT = DATA_DIR / "static"

MEDIA_URL = "/media/"
MEDIA_ROOT = DATA_DIR / "media"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

SESSION_COOKIE_AGE = 1800
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

SECURE_PROXY_SSL_HEADER = None
USE_X_FORWARDED_HOST = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
SECURE_SSL_REDIRECT = False
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_HSTS_SECONDS = 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = False
SECURE_HSTS_PRELOAD = False
X_FRAME_OPTIONS = "DENY"

SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE    = "Lax"
CSRF_COOKIE_HTTPONLY    = True

CSRF_FAILURE_VIEW = "django.views.csrf.csrf_failure"

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "padrao": {
            "format": "[{asctime}] {levelname} ({name}:{lineno}) - {message}",
            "style": "{",
        },
    },
    "handlers": {
        "arquivo_seguro": {
            "level": "INFO",
            "class": "logging.handlers.RotatingFileHandler",
            "filename": os.path.join(BASE_DIR, "core", "logs", "seguranca.log"),
            "formatter": "padrao",
            "maxBytes": 10 * 1024 * 1024, 
            "backupCount": 5,
        },
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "padrao",
            "level": "INFO",
        },
    },
    "loggers": {
        "django": {
            "handlers": ["arquivo_seguro", "console"],
            "level": "INFO",
            "propagate": True,
        },
        "core": {
            "handlers": ["arquivo_seguro", "console"],
            "level": "INFO",
            "propagate": False,
        },
    },
}

LOGGING["loggers"]["django_auth_adfs"] = {"handlers": ["console"], "level": "DEBUG"}

APSCHEDULER_DATETIME_FORMAT = "d/m/Y H:i:s"

SCHEDULER_CONFIG = {
    "executors": {
        "default": {"class": "apscheduler.executors.pool:ThreadPoolExecutor", "max_workers": 20},
        "processpool": {"class": "apscheduler.executors.pool:ProcessPoolExecutor", "max_workers": 4},
    },
    "job_defaults": {
        "coalesce": True,         
        "max_instances": 100,        
        "misfire_grace_time": 300, 
    },
}

SCHEDULER_LOG_EMAIL_BODY = bool(int(os.getenv("SCHEDULER_LOG_EMAIL_BODY", "1" if DEBUG else "0")))

PDE_ADDRESS_URL = os.getenv("PDE_ADDRESS_URL", "https://www.pde.com.br")

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "django_auth_adfs.backend.AdfsAuthCodeBackend", 
]

LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "/post-login/"
LOGOUT_REDIRECT_URL = "login"

PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
    "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
]

AUTH_ADFS = {
    "TENANT_ID":        os.getenv("AZURE_TENANT_ID"),
    "CLIENT_ID":        os.getenv("AZURE_CLIENT_ID"),
    "CLIENT_SECRET":    os.getenv("AZURE_CLIENT_SECRET"),
    "AUDIENCE":         os.getenv("AZURE_CLIENT_ID"),
    "RELYING_PARTY_ID": os.getenv("AZURE_CLIENT_ID"),
    "VERSION": "v2.0",
    "SCOPES": ["openid", "email", "profile"], 
    "CLAIM_MAPPING": {
        "first_name": "given_name",
        "last_name":  "family_name",
        "email":      "upn",        
    },
    "USERNAME_CLAIM": "upn",       
    "GROUPS_CLAIM": None,
    "MIRROR_GROUPS": False,
    "CREATE_NEW_USERS": True,
}

def env_bool(name: str, default: str = "0") -> bool:
    return os.getenv(name, default).lower() in ("1", "true", "yes", "on")

EMAIL_BACKEND = os.getenv("EMAIL_BACKEND")
EMAIL_HOST = os.getenv("EMAIL_HOST") 
EMAIL_PORT = int(os.getenv("EMAIL_PORT"))  
EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD")
EMAIL_TIMEOUT = int(os.getenv("EMAIL_TIMEOUT")) 
DEFAULT_FROM_EMAIL = os.getenv("DEFAULT_FROM_EMAIL")

DATABRICKS = {
    "HOST": os.getenv("DATABRICKS_HOST", "").rstrip("/"),
    "TOKEN": os.getenv("DATABRICKS_TOKEN", ""),
    "HTTP_PATH": os.getenv("DATABRICKS_HTTP_PATH", ""),
    "TIMEOUT": int(os.getenv("DATABRICKS_TIMEOUT", "30")),
}
