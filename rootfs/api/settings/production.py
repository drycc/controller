"""
Django settings for the Drycc project.
"""
from distutils.util import strtobool
import os.path
import tempfile
import ldap
import json

from django_auth_ldap.config import LDAPSearch, GroupOfNamesType

# A boolean that turns on/off debug mode.
# https://docs.djangoproject.com/en/1.11/ref/settings/#debug
DEBUG = bool(os.environ.get('DRYCC_DEBUG', False))

# If set to True, Django's normal exception handling of view functions
# will be suppressed, and exceptions will propagate upwards
# https://docs.djangoproject.com/en/1.11/ref/settings/#debug-propagate-exceptions
DEBUG_PROPAGATE_EXCEPTIONS = False

# Silence two security messages around SSL as router takes care of them
# https://docs.djangoproject.com/en/1.11/ref/checks/#security
SILENCED_SYSTEM_CHECKS = [
    'security.W004',
    'security.W008'
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
    'jsonfield',
    'rest_framework',
    'rest_framework.authtoken',
    # Drycc apps
    'api'
)

AUTHENTICATION_BACKENDS = (
    "django.contrib.auth.backends.ModelBackend",
    "guardian.backends.ObjectPermissionBackend",
)

ANONYMOUS_USER_ID = -1
LOGIN_URL = '/v2/auth/login/'
LOGIN_REDIRECT_URL = '/'

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
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True

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
        'rest_framework.authentication.TokenAuthentication',
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

# the k8s namespace in which the controller and workflow were installed.
WORKFLOW_NAMESPACE = os.environ.get('WORKFLOW_NAMESPACE', 'drycc')

# default scheduler settings
SCHEDULER_MODULE = 'scheduler'
SCHEDULER_URL = "https://{}:{}".format(
    # accessing the k8s api server by IP address rather than hostname avoids
    # intermittent DNS errors
    os.environ.get(
        'KUBERNETES_SERVICE_HOST',
        'kubernetes.default.svc.{}'.format(os.environ.get(
            "KUBERNETES_CLUSTER_DOMAIN", "cluster.local"
        ))
    ),
    os.environ.get('KUBERNETES_SERVICE_PORT', '443')
)

K8S_API_VERIFY_TLS = bool(strtobool(os.environ.get('K8S_API_VERIFY_TLS', 'true')))

# security keys and auth tokens
random_secret = 'CHANGEME_sapm$s%upvsw5l_zuy_&29rkywd^78ff(qi*#@&*^'
SECRET_KEY = os.environ.get('DRYCC_SECRET_KEY', random_secret)
BUILDER_KEY = os.environ.get('DRYCC_BUILDER_KEY', random_secret)

# experimental native ingress
INGRESS_CLASS = os.environ.get('DRYCC_INGRESS_CLASS', '')

PLATFORM_DOMAIN = os.environ.get('DRYCC_PLATFORM_DOMAIN', 'local.drycc.cc')

# k8s image policies
if os.path.exists('/etc/slugrunner/images.json'):
    with open('/etc/slugrunner/images.json') as fb:
        SLUGRUNNER_IMAGES = json.load(fb)
else:
    SLUGRUNNER_IMAGES = [
        {
            "name": 'heroku-18',
            "image": 'drycc/slugrunner:canary.heroku-18',
        },
        {
            "name": 'heroku-20',
            "image": 'drycc/slugrunner:canary.heroku-20',
        },
    ]
IMAGE_PULL_POLICY = os.environ.get('IMAGE_PULL_POLICY', "IfNotPresent")  # noqa

# True, true, yes, y and more evaluate to True
# False, false, no, n and more evaluate to False
# https://docs.python.org/3/distutils/apiref.html?highlight=distutils.util#distutils.util.strtobool
# see the above for all available options
#
# If a user deploys one build with a Procfile but then forgets to in the next one
# then let that go through without scaling the missing process types down
#
# If the user has a Procfile in both deploys then processes are scaled up / down as per usual
#
# By default the process types are scaled down unless this setting is turned on
DRYCC_DEPLOY_PROCFILE_MISSING_REMOVE = bool(strtobool(os.environ.get('DRYCC_DEPLOY_PROCFILE_MISSING_REMOVE', 'true')))  # noqa

# True, true, yes, y and more evaluate to True
# False, false, no, n and more evaluate to False
# https://docs.python.org/3/distutils/apiref.html?highlight=distutils.util#distutils.util.strtobool
# see the above for all available options
#
# If a previous deploy had a Procfile but then the following deploy has no Procfile then it will
# result in a 406 - Not Acceptable
# Has priority over DRYCC_DEPLOY_PROCFILE_MISSING_REMOVE
DRYCC_DEPLOY_REJECT_IF_PROCFILE_MISSING = bool(strtobool(os.environ.get('DRYCC_DEPLOY_REJECT_IF_PROCFILE_MISSING', 'false')))  # noqa

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

KUBERNETES_DEPLOYMENTS_REVISION_HISTORY_LIMIT = os.environ.get('KUBERNETES_DEPLOYMENTS_REVISION_HISTORY_LIMIT', None)  # noqa

DRYCC_DEFAULT_CONFIG_TAGS = os.environ.get('DRYCC_DEFAULT_CONFIG_TAGS', '')

# How long k8s waits for a pod to finish work after a SIGTERM before sending SIGKILL
KUBERNETES_POD_TERMINATION_GRACE_PERIOD_SECONDS = int(os.environ.get('KUBERNETES_POD_TERMINATION_GRACE_PERIOD_SECONDS', 30))  # noqa

# CPU request ratio
KUBERNETES_REQUEST_CPU_RATIO = int(os.environ.get('KUBERNETES_REQUEST_CPU_RATIO', '10'))
# Memory request ratio
KUBERNETES_REQUEST_MEMORY_RATIO = int(os.environ.get('KUBERNETES_REQUEST_MEMORY_RATIO', '2'))
# Minimum limits cpu, units are represented in the millicpu of CPUs
KUBERNETES_LIMITS_MIN_CPU = int(os.environ.get('KUBERNETES_LIMITS_MIN_CPU', '9'))
# Minimum limits memory, units are represented in Megabytes(M)
KUBERNETES_LIMITS_MIN_MEMORY = int(os.environ.get('KUBERNETES_LIMITS_MIN_MEMORY', '63'))
# Maximum limits cpu, units are represented in the millicpu of CPUs
KUBERNETES_LIMITS_MAX_CPU = int(os.environ.get('KUBERNETES_LIMITS_MAX_CPU', '32000'))
# Maximum limits memory, units are represented in Megabytes(M)
KUBERNETES_LIMITS_MAX_MEMORY = int(os.environ.get('KUBERNETES_LIMITS_MAX_MEMORY', '131072'))
# Default CPU limit, units are represented in the millicpu of CPUs
KUBERNETES_LIMITS_DEFAULT_CPU = (KUBERNETES_LIMITS_MIN_CPU + 1) * KUBERNETES_REQUEST_CPU_RATIO
# Default Memory limit, units are represented in Megabytes(M)
KUBERNETES_LIMITS_DEFAULT_MEMORY = (KUBERNETES_LIMITS_MIN_MEMORY + 1) * KUBERNETES_REQUEST_MEMORY_RATIO  # noqa

# Default pod spec for application.
KUBERNETES_POD_DEFAULT_RESOURCES = os.environ.get(
    'KUBERNETES_POD_DEFAULT_RESOURCES',
    json.dumps({
        "requests": {
            "ephemeral-storage": "1Gi",
        },
        "limits": {
            "ephemeral-storage": "2Gi",
        }
    })
)
# Default quota spec for application namespace
KUBERNETES_NAMESPACE_DEFAULT_QUOTA_SPEC = os.environ.get(
    'KUBERNETES_NAMESPACE_DEFAULT_QUOTA_SPEC', ''
)
# Default limit range spec for application namespace
KUBERNETES_NAMESPACE_DEFAULT_LIMIT_RANGES_SPEC = os.environ.get(
    'KUBERNETES_NAMESPACE_DEFAULT_LIMIT_RANGES_SPEC',
    json.dumps({
        "limits": [
            {
                "default": {
                    "cpu": "%sm" % KUBERNETES_LIMITS_DEFAULT_CPU,
                    "memory": "%sMi" % KUBERNETES_LIMITS_DEFAULT_MEMORY
                },
                "defaultRequest": {
                    "cpu": "%sm" % (KUBERNETES_LIMITS_MIN_CPU + 1),
                    "memory": "%sMi" % (KUBERNETES_LIMITS_MIN_MEMORY + 1)
                },
                "max": {
                    "cpu": "%sm" % KUBERNETES_LIMITS_MAX_CPU,
                    "memory": "%sMi" % KUBERNETES_LIMITS_MAX_MEMORY
                },
                "min": {
                    "cpu": "%sm" % KUBERNETES_LIMITS_MIN_CPU,
                    "memory": "%sMi" % KUBERNETES_LIMITS_MIN_MEMORY
                },
                "type": "Container"
            },
            {
                "max": {
                    "storage": "100Gi"
                },
                "min": {
                    "storage": "100Mi"
                },
                "type": "PersistentVolumeClaim"
            }
        ]
    })
)

# registry settings
REGISTRY_HOST = os.environ.get('DRYCC_REGISTRY_PROXY_HOST', '127.0.0.1')
REGISTRY_PORT = os.environ.get('DRYCC_REGISTRY_PROXY_PORT', 5000)
REGISTRY_URL = '{}:{}'.format(REGISTRY_HOST, REGISTRY_PORT)
REGISTRY_LOCATION = os.environ.get('DRYCC_REGISTRY_LOCATION', 'on-cluster')
REGISTRY_SECRET_PREFIX = os.environ.get('DRYCC_REGISTRY_SECRET_PREFIX', 'private-registry')

# logger settings
LOGGER_HOST = os.environ.get('DRYCC_LOGGER_SERVICE_HOST', '127.0.0.1')
LOGGER_PORT = os.environ.get('DRYCC_LOGGER_SERVICE_PORT_HTTP', 80)

# router information
ROUTER_HOST = os.environ.get('DRYCC_ROUTER_SERVICE_HOST', '127.0.0.1')
ROUTER_PORT = os.environ.get('DRYCC_ROUTER_SERVICE_PORT', 80)

# minio information
MINIO_HOST = os.environ.get('DRYCC_MINIO_SERVICE_HOST', '127.0.0.1')
MINIO_PORT = os.environ.get('DRYCC_MINIO_SERVICE_PORT', 80)
APP_STORAGE = os.environ.get('APP_STORAGE')

# check if we can register users with `drycc register`
REGISTRATION_MODE = os.environ.get('REGISTRATION_MODE', 'enabled')

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ.get(
            'DRYCC_DATABASE_NAME', os.environ.get('DRYCC_DATABASE_USER', 'drycc')),
        'USER': os.environ.get('DRYCC_DATABASE_USER', ''),
        'PASSWORD': os.environ.get('DRYCC_DATABASE_PASSWORD', ''),
        'HOST': os.environ.get('DRYCC_DATABASE_SERVICE_HOST', ''),
        'PORT': os.environ.get('DRYCC_DATABASE_SERVICE_PORT', 5432),
        # https://docs.djangoproject.com/en/1.11/ref/databases/#persistent-connections
        'CONN_MAX_AGE': 600,
    }
}

APP_URL_REGEX = '[a-z0-9-]+'

# LDAP settings taken from environment variables.
LDAP_ENDPOINT = os.environ.get('LDAP_ENDPOINT', '')
LDAP_BIND_DN = os.environ.get('LDAP_BIND_DN', '')
LDAP_BIND_PASSWORD = os.environ.get('LDAP_BIND_PASSWORD', '')
LDAP_USER_BASEDN = os.environ.get('LDAP_USER_BASEDN', '')
LDAP_USER_FILTER = os.environ.get('LDAP_USER_FILTER', 'username')
LDAP_GROUP_BASEDN = os.environ.get('LDAP_GROUP_BASEDN', '')
LDAP_GROUP_FILTER = os.environ.get('LDAP_GROUP_FILTER', '')
LDAP_ACTIVE_GROUP = os.environ.get('LDAP_ACTIVE_GROUP', '')
LDAP_STAFF_GROUP = os.environ.get('LDAP_STAFF_GROUP', '')
LDAP_SUPERUSER_GROUP = os.environ.get('LDAP_SUPERUSER_GROUP', '')

# Django LDAP backend configuration.
# See https://pythonhosted.org/django-auth-ldap/reference.html
# for variables' details.
# In order to debug LDAP configuration it is possible to enable
# verbose logging from auth-ldap plugin:
# https://pythonhosted.org/django-auth-ldap/logging.html

if LDAP_ENDPOINT:
    AUTHENTICATION_BACKENDS = ("django_auth_ldap.backend.LDAPBackend",) + AUTHENTICATION_BACKENDS
    AUTH_LDAP_SERVER_URI = LDAP_ENDPOINT
    AUTH_LDAP_BIND_DN = LDAP_BIND_DN
    AUTH_LDAP_BIND_PASSWORD = LDAP_BIND_PASSWORD
    AUTH_LDAP_USER_SEARCH = LDAPSearch(
        base_dn=LDAP_USER_BASEDN,
        scope=ldap.SCOPE_SUBTREE,
        filterstr="%s" % LDAP_USER_FILTER
    )
    AUTH_LDAP_GROUP_SEARCH = LDAPSearch(
        base_dn=LDAP_GROUP_BASEDN,
        scope=ldap.SCOPE_SUBTREE,
        filterstr="%s" % LDAP_GROUP_FILTER
    )
    AUTH_LDAP_USER_FLAGS_BY_GROUP = {
        'is_active': LDAP_ACTIVE_GROUP,
        'is_staff': LDAP_STAFF_GROUP,
        'is_superuser': LDAP_SUPERUSER_GROUP,
    }
    AUTH_LDAP_GROUP_TYPE = GroupOfNamesType()
    AUTH_LDAP_USER_ATTR_MAP = {
        "first_name": "givenName",
        "last_name": "sn",
        "email": "mail",
        "username": LDAP_USER_FILTER,
    }
    AUTH_LDAP_GLOBAL_OPTIONS = {
        ldap.OPT_X_TLS_REQUIRE_CERT: False,
        ldap.OPT_REFERRALS: False
    }
    AUTH_LDAP_ALWAYS_UPDATE_USER = True
    AUTH_LDAP_MIRROR_GROUPS = True
    AUTH_LDAP_FIND_GROUP_PERMS = True
    AUTH_LDAP_CACHE_GROUPS = False

# Redis Configuration
DRYCC_REDIS_ADDRS = os.environ.get('DRYCC_REDIS_ADDRS', '127.0.0.1:6379').split(",")
DRYCC_REDIS_PASSWORD = os.environ.get('DRYCC_REDIS_PASSWORD', '')

# Cache Configuration
CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": ['redis://:{}@{}'.format(DRYCC_REDIS_PASSWORD, DRYCC_REDIS_ADDR) \
                     for DRYCC_REDIS_ADDR in DRYCC_REDIS_ADDRS],  # noqa
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.ShardClient",
        }
    }
}

# Celery Configuration Options
CELERY_TIMEZONE = "Asia/Shanghai"
CELERY_ENABLE_UTC = True
CELERY_TASK_SERIALIZER = 'pickle'
CELERY_ACCEPT_CONTENT = frozenset([
    'application/data',
    'application/text',
    'application/json',
    'application/x-python-serialize',
])
CELERY_TASK_TRACK_STARTED = True
CELERY_TASK_TIME_LIMIT = 30 * 60
CELERYD_MAX_TASKS_PER_CHILD = 200
CELERY_TASK_RESULT_EXPIRES = 24 * 60 * 60
CELERY_BROKER_URL ='redis://:{}@{}'.format(DRYCC_REDIS_PASSWORD, DRYCC_REDIS_ADDRS[0])  # noqa
CELERY_RESULT_BACKEND = 'redis://:{}@{}'.format(DRYCC_REDIS_PASSWORD, DRYCC_REDIS_ADDRS[0])  # noqa
CELERY_CACHE_BACKEND = 'django-cache'
CELERY_DEFAULT_QUEUE = 'priority.middle'

# Influxdb Configuration Options
INFLUXDB_URL = os.environ.get('DRYCC_INFLUXDB_URL', 'http://localhost:8086')
INFLUXDB_BUCKET = os.environ.get('DRYCC_INFLUXDB_BUCKET', 'drycc')
INFLUXDB_ORG = os.environ.get('DRYCC_INFLUXDB_ORG', 'root')
INFLUXDB_TOKEN = os.environ.get('DRYCC_INFLUXDB_TOKEN', 'root')


# Workflow-manager Configuration Options
WORKFLOW_MANAGER_URL = os.environ.get('DRYCC_WORKFLOW_MANAGER_URL', None)
WORKFLOW_MANAGER_TOKEN = os.environ.get('DRYCC_WORKFLOW_MANAGER_TOKEN', None)
