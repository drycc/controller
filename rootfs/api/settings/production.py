"""
Django settings for the Drycc project.
"""
import sys
import uuid
import os.path
import tempfile
import dj_database_url


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, 'apps_extra'))

# drycc controller app version.
VERSION = os.environ.get('VERSION', uuid.uuid1().hex[:8])

# A boolean that turns on/off debug mode.
# https://docs.djangoproject.com/en/1.11/ref/settings/#debug
DEBUG = os.environ.get('DRYCC_DEBUG', 'false').lower() == "true"

# If set to True, Django's normal exception handling of view functions
# will be suppressed, and exceptions will propagate upwards
# https://docs.djangoproject.com/en/1.11/ref/settings/#debug-propagate-exceptions
DEBUG_PROPAGATE_EXCEPTIONS = False

# Silence two security messages around SSL as router takes care of them
# https://docs.djangoproject.com/en/1.11/ref/checks/#security
SILENCED_SYSTEM_CHECKS = [
    'security.W004',
    'security.W008',
    'security.W012',
    'security.W016',
]

CONN_MAX_AGE = 60 * 3

# SECURITY: change this to allowed fqdn's to prevent host poisioning attacks
# https://docs.djangoproject.com/en/1.11/ref/settings/#allowed-hosts
ALLOWED_HOSTS = ['*']

# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# In a Windows environment this must be set to your system time zone.
TIME_ZONE = os.environ.get('TZ', 'UTC')

# Language code for this installation. All choices can be found here:
# http://www.i18nguy.com/unicode/language-identifiers.html
LANGUAGE_CODE = 'en-us'

# If you set this to False, Django will make some optimizations so as not
# to load the internationalization machinery.
# https://docs.djangoproject.com/en/1.11/ref/settings/#use-i18n
USE_I18N = False

# If you set this to False, Django will not format dates, numbers and
# calendars according to the current locale.
USE_L10N = True

# If you set this to False, Django will not use timezone-aware datetimes.
USE_TZ = True

# Manage templates
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            # insert your TEMPLATE_DIRS here
        ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                "django.contrib.auth.context_processors.auth",
                "django.template.context_processors.debug",
                "django.template.context_processors.i18n",
                "django.template.context_processors.media",
                "django.template.context_processors.request",
                "django.template.context_processors.tz",
                "django.contrib.messages.context_processors.messages"
            ],
        },
    },
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'api.middleware.APIVersionMiddleware',
]

ROOT_URLCONF = 'drycc.urls'

# Python dotted path to the WSGI application used by Django's runserver.
WSGI_APPLICATION = 'api.wsgi.application'

INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.humanize',
    'django.contrib.messages',
    'django.contrib.sessions',
    # Third-party apps
    'corsheaders',
    'guardian',
    'gunicorn',
    'rest_framework',
    'rest_framework.authtoken',
    'social_django',
    # Drycc apps
    'api'
)

AUTH_USER_MODEL = "api.User"
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

AUTHENTICATION_BACKENDS = (
    "django.contrib.auth.backends.ModelBackend",
    "guardian.backends.ObjectPermissionBackend",
)
GUARDIAN_GET_INIT_ANONYMOUS_USER = 'api.models.base.get_anonymous_user_instance'
ANONYMOUS_USER_NAME = os.environ.get('ANONYMOUS_USER_NAME', 'AnonymousUser')
LOGIN_URL = '/v2/auth/login/'

# Security settings
CORS_ORIGIN_ALLOW_ALL = True
CORS_ALLOW_HEADERS = (
    'content-type',
    'accept',
    'origin',
    'Authorization',
    'Host',
)

CORS_EXPOSE_HEADERS = (
    'DRYCC_API_VERSION',
    'DRYCC_PLATFORM_VERSION',
)

X_FRAME_OPTIONS = 'DENY'
CSRF_COOKIE_HTTPONLY = False
CSRF_COOKIE_SAMESITE = None
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() == "true"
CSRF_COOKIE_SECURE = os.environ.get('CSRF_COOKIE_SECURE', 'false').lower() == "true"


# Honor HTTPS from a trusted proxy
# see https://docs.djangoproject.com/en/1.11/ref/settings/#secure-proxy-ssl-header
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# standard datetime format used for logging, model timestamps, etc.
DRYCC_DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

REST_FRAMEWORK = {
    'DATETIME_FORMAT': DRYCC_DATETIME_FORMAT,
    'DEFAULT_MODEL_SERIALIZER_CLASS': 'rest_framework.serializers.ModelSerializer',
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'api.authentication.DryccAuthentication',
    ),
    'DEFAULT_RENDERER_CLASSES': (
        'rest_framework.renderers.JSONRenderer',
    ),
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.LimitOffsetPagination',
    'PAGE_SIZE': 100,
    'TEST_REQUEST_DEFAULT_FORMAT': 'json',
    'EXCEPTION_HANDLER': 'api.exceptions.custom_exception_handler'
}

# URLs that end with slashes are ugly
APPEND_SLASH = False

# See http://docs.djangoproject.com/en/dev/topics/logging for
# more details on how to customize your logging configuration.
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'root': {'level': 'DEBUG' if DEBUG else 'WARN'},
    'formatters': {
        'verbose': {
            'format': '%(levelname)s %(asctime)s %(module)s %(process)d %(thread)d %(message)s'
        },
        'simple': {
            'format': '%(levelname)s %(message)s'
        },
    },
    'filters': {
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse'
        },
        'require_debug_true': {
            '()': 'django.utils.log.RequireDebugTrue'
        }
    },
    'handlers': {
        'null': {
            'level': 'DEBUG',
            'class': 'logging.NullHandler',
        },
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'simple'
        }
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'filters': ['require_debug_true'],
            'propagate': True,
        },
        'django.db.backends': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'filters': ['require_debug_true'],
            'propagate': False,
        },
        'django.request': {
            'handlers': ['console'],
            'level': 'WARNING',
            'filters': ['require_debug_true'],
            'propagate': True,
        },
        'api': {
            'handlers': ['console'],
            'propagate': True,
        },
        'registry': {
            'handlers': ['console'],
            'propagate': True,
        },
        'scheduler': {
            'handlers': ['console'],
            'propagate': True,
        },
    }
}
TEST_RUNNER = 'api.tests.SilentDjangoTestSuiteRunner'

# default drycc settings
LOG_LINES = 100
TEMPDIR = tempfile.mkdtemp(prefix='drycc')

# names which apps cannot reserve for routing
DRYCC_RESERVED_NAMES = os.environ.get('RESERVED_NAMES', '').replace(' ', '').split(',')
DRYCC_RESERVED_NAMES.append("canary")

# the k8s namespace in which the controller and workflow were installed.
WORKFLOW_NAMESPACE = os.environ.get('WORKFLOW_NAMESPACE', 'drycc')

# kubernetes cluster domain
KUBERNETES_CLUSTER_DOMAIN = os.environ.get("KUBERNETES_CLUSTER_DOMAIN", "cluster.local")
# default scheduler settings
SCHEDULER_MODULE = 'scheduler'
SCHEDULER_URL = "https://{}:{}".format(
    # accessing the k8s api server by IP address rather than hostname avoids
    # intermittent DNS errors
    os.environ.get(
        'KUBERNETES_SERVICE_HOST',
        'kubernetes.default.svc.{}'.format(KUBERNETES_CLUSTER_DOMAIN)
    ),
    os.environ.get('KUBERNETES_SERVICE_PORT', '443')
)

K8S_API_VERIFY_TLS = os.environ.get('K8S_API_VERIFY_TLS', 'true').lower() == "true"
# drycc prometheus url
DRYCC_PROMETHEUS_URL = os.environ.get('DRYCC_PROMETHEUS_URL', '')

# security keys and auth tokens
random_secret = 'CHANGEME_sapm$s%upvsw5l_zuy_&29rkywd^78ff(qi*#@&*^'
SECRET_KEY = os.environ.get('DRYCC_SECRET_KEY', random_secret)
BUILDER_KEY = os.environ.get('DRYCC_BUILDER_KEY', random_secret)

# Drycc admission mutate key
MUTATE_KEY_PATH = os.environ.get('DRYCC_MUTATE_KEY_PATH', '/etc/controller/mutate/cert/key')
if os.path.exists(MUTATE_KEY_PATH):
    with open(MUTATE_KEY_PATH) as f:
        MUTATE_KEY = f.read()
else:
    MUTATE_KEY = None

# gateway class name
GATEWAY_CLASS = os.environ.get('DRYCC_GATEWAY_CLASS', '')

IMAGE_PULL_POLICY = os.environ.get('IMAGE_PULL_POLICY', "IfNotPresent")

# True, true, yes, y and more evaluate to True
# False, false, no, n and more evaluate to False
# see the above for all available options
#
# If a user deploys one build with a Procfile but then forgets to in the next one
# then let that go through without scaling the missing process types down
#
# If the user has a Procfile in both deploys then processes are scaled up / down as per usual
#
# By default the process types are scaled down unless this setting is turned on
DRYCC_DEPLOY_PROCFILE_MISSING_REMOVE = os.environ.get(
    'DRYCC_DEPLOY_PROCFILE_MISSING_REMOVE', 'true').lower() == "true"

# True, true, yes, y and more evaluate to True
# False, false, no, n and more evaluate to False
# see the above for all available options
#
# If a previous deploy had a Procfile but then the following deploy has no Procfile then it will
# result in a 406 - Not Acceptable
# Has priority over DRYCC_DEPLOY_PROCFILE_MISSING_REMOVE
DRYCC_DEPLOY_REJECT_IF_PROCFILE_MISSING = os.environ.get(
    'DRYCC_DEPLOY_REJECT_IF_PROCFILE_MISSING', 'false').lower() == "true"

# Define a global default on how many pods to bring up and then
# take down sequentially during a deploy
# Defaults to None, the default is to deploy to as many nodes as
# the application has been instructed to run on
# Can also be overwritten on per app basis if desired
DRYCC_DEPLOY_BATCHES = int(os.environ.get('DRYCC_DEPLOY_BATCHES', 0))

# For old style deploys (RCs) defines how long each batch
# (as defined by DRYCC_DEPLOY_BATCHES) can take before giving up
# For Kubernetes Deployments it is part of the global timeout
# where it roughly goes BATCHES * TIMEOUT = global timeout
DRYCC_DEPLOY_TIMEOUT = int(os.environ.get('DRYCC_DEPLOY_TIMEOUT', 120))

try:
    DRYCC_DEPLOY_HOOK_URLS = os.environ['DRYCC_DEPLOY_HOOK_URLS'].split(',')
except KeyError:
    DRYCC_DEPLOY_HOOK_URLS = []

DRYCC_DEPLOY_HOOK_SECRET_KEY = os.environ.get('DRYCC_DEPLOY_HOOK_SECRET_KEY', None)

DRYCC_APP_STORAGE_CLASS = os.environ.get('DRYCC_APP_STORAGE_CLASS', "")

DRYCC_APP_RUNTIME_CLASS = os.environ.get('DRYCC_APP_RUNTIME_CLASS', "")

DRYCC_APP_DNS_POLICY = os.environ.get('DRYCC_APP_DNS_POLICY', "")

DRYCC_APP_POD_EXEC_TIMEOUT = int(os.environ.get('DRYCC_APP_POD_EXEC_TIMEOUT', "3600"))

DRYCC_DEFAULT_CONFIG_TAGS = os.environ.get('DRYCC_DEFAULT_CONFIG_TAGS', '')

KUBERNETES_DEPLOYMENTS_REVISION_HISTORY_LIMIT = os.environ.get(
    'KUBERNETES_DEPLOYMENTS_REVISION_HISTORY_LIMIT', None)

# How long k8s waits for a pod to finish work after a SIGTERM before sending SIGKILL
KUBERNETES_POD_TERMINATION_GRACE_PERIOD_SECONDS = int(os.environ.get(
    'KUBERNETES_POD_TERMINATION_GRACE_PERIOD_SECONDS', 30))
# Minimum Stroage Volume limit, units are represented in Gigabytes(G)
KUBERNETES_LIMITS_MIN_VOLUME = int(os.environ.get('KUBERNETES_LIMITS_MIN_VOLUME', 1))
# Max Stroage Volume limit, units are represented in Gigabytes(G)
KUBERNETES_LIMITS_MAX_VOLUME = int(os.environ.get('KUBERNETES_LIMITS_MAX_VOLUME', 1024 * 16))

KUBERNETES_JOB_MAX_TTL_SECONDS_AFTER_FINISHED = int(os.environ.get(
    'KUBERNETES_JOB_MAX_TTL_SECONDS_AFTER_FINISHED', '7200'
))

# registry settings
REGISTRY_LOCATION = os.environ.get('DRYCC_REGISTRY_LOCATION', 'on-cluster')
REGISTRY_SECRET_PREFIX = os.environ.get('DRYCC_REGISTRY_SECRET_PREFIX', 'private-registry')

# logger settings
LOGGER_HOST = os.environ.get('DRYCC_LOGGER_SERVICE_HOST', '127.0.0.1')
LOGGER_PORT = os.environ.get('DRYCC_LOGGER_SERVICE_PORT_HTTP', 80)

DRYCC_DATABASE_URL = os.environ.get('DRYCC_DATABASE_URL', 'postgres://postgres:@:5432/drycc')
DATABASES = {
    'default': dj_database_url.config(default=DRYCC_DATABASE_URL)
}

# database replica setting
DRYCC_DATABASE_REPLICA_URL = os.environ.get('DRYCC_DATABASE_REPLICA_URL', None)
if DRYCC_DATABASE_REPLICA_URL is not None:
    DATABASES["replica"] = dj_database_url.config(default=DRYCC_DATABASE_REPLICA_URL)

# database monitor setting
DRYCC_DATABASE_MONITOR_URL = os.environ.get('DRYCC_DATABASE_MONITOR_URL', None)
if DRYCC_DATABASE_MONITOR_URL is not None:
    DATABASES["monitor"] = dj_database_url.config(default=DRYCC_DATABASE_MONITOR_URL)

# database routers
DATABASE_ROUTERS = ['api.routers.DefaultReplicaRouter', ]

APP_URL_REGEX = '[a-z0-9-]+'

# Oauth settings

DRYCC_PASSPORT_URL = os.environ.get('DRYCC_PASSPORT_URL', 'https://127.0.0.1:8000')

LOGIN_REDIRECT_URL = os.environ.get(
    'LOGIN_REDIRECT_URL',
    f'{DRYCC_PASSPORT_URL}/user/login/done/',
)

SOCIAL_AUTH_DRYCC_KEY = os.environ.get(
    "DRYCC_PASSPORT_KEY",
    os.environ.get("SOCIAL_AUTH_DRYCC_KEY"),
)

SOCIAL_AUTH_DRYCC_SECRET = os.environ.get(
    'DRYCC_PASSPORT_SECRET',
    os.environ.get("SOCIAL_AUTH_DRYCC_SECRET"),
)

SOCIAL_AUTH_DRYCC_AUTHORIZATION_URL = os.environ.get(
    'SOCIAL_AUTH_DRYCC_AUTHORIZATION_URL',
    f'{DRYCC_PASSPORT_URL}/oauth/authorize/',
)
SOCIAL_AUTH_DRYCC_ACCESS_TOKEN_URL = os.environ.get(
    'SOCIAL_AUTH_DRYCC_ACCESS_TOKEN_URL',
    f'{DRYCC_PASSPORT_URL}/oauth/token/'
)
SOCIAL_AUTH_DRYCC_ACCESS_API_URL = os.environ.get(
    'SOCIAL_AUTH_DRYCC_ACCESS_API_URL',
    f'{DRYCC_PASSPORT_URL}'
)
SOCIAL_AUTH_DRYCC_USERINFO_URL = os.environ.get(
    'SOCIAL_AUTH_DRYCC_USERINFO_URL',
    f'{DRYCC_PASSPORT_URL}/oauth/userinfo/'
)
SOCIAL_AUTH_DRYCC_JWKS_URI = os.environ.get(
    'SOCIAL_AUTH_DRYCC_JWKS_URI',
    f'{DRYCC_PASSPORT_URL}/oauth/.well-known/jwks.json'
)
SOCIAL_AUTH_DRYCC_OIDC_ENDPOINT = os.environ.get(
    'SOCIAL_AUTH_DRYCC_OIDC_ENDPOINT',
    f'{DRYCC_PASSPORT_URL}/oauth'
)

SOCIAL_AUTH_JSONFIELD_ENABLED = True
SOCIAL_AUTH_PIPELINE = (
    'social_core.pipeline.social_auth.social_details',
    'social_core.pipeline.social_auth.social_uid',
    'social_core.pipeline.social_auth.social_user',
    'social_core.pipeline.user.get_username',
    'social_core.pipeline.social_auth.associate_by_email',
    'api.pipeline.update_or_create',
    'social_core.pipeline.social_auth.associate_user',
    'social_core.pipeline.social_auth.load_extra_data',
    'social_core.pipeline.user.user_details',
)
AUTHENTICATION_BACKENDS = ("api.backend.DryccOIDC", ) + AUTHENTICATION_BACKENDS
OAUTH_CACHE_USER_TIME = int(os.environ.get('OAUTH_CACHE_USER_TIME', 30 * 60))

# Redis Configuration
DRYCC_REDIS_ADDRS = os.environ.get('DRYCC_REDIS_ADDRS', '127.0.0.1:6379').split(",")
DRYCC_REDIS_PASSWORD = os.environ.get('DRYCC_REDIS_PASSWORD', '')

# Cache Configuration
CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": [
            'redis://:{}@{}'.format(
                DRYCC_REDIS_PASSWORD, DRYCC_REDIS_ADDR) for DRYCC_REDIS_ADDR in DRYCC_REDIS_ADDRS
        ],
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.ShardClient",
        }
    }
}

# Workflow-manager Configuration Options
WORKFLOW_MANAGER_URL = os.environ.get('WORKFLOW_MANAGER_URL', None)
WORKFLOW_MANAGER_ACCESS_KEY = os.environ.get('WORKFLOW_MANAGER_ACCESS_KEY', None)
WORKFLOW_MANAGER_SECRET_KEY = os.environ.get('WORKFLOW_MANAGER_SECRET_KEY', None)
