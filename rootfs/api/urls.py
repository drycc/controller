"""
URL routing patterns for the Drycc REST API.
"""
from django.conf import settings
from django.conf.urls import include, url
from rest_framework.routers import DefaultRouter
from social_core.utils import setting_name
from api import views


router = DefaultRouter(trailing_slash=False)
extra = getattr(settings, setting_name('TRAILING_SLASH'), True) and '/' or ''

# Add the generated REST URLs and login/logout endpoint
app_urlpatterns = [
    url(r'^', include(router.urls)),
    url(r'^login/(?P<backend>[^/]+){0}$'.format(extra), views.auth,
        name='begin'),
    url(r'^complete/(?P<backend>[^/]+){0}$'.format(extra), views.complete,
        name='complete'),
    url('', include('social_django.urls', namespace='social')),
    url(r'auth/login/?$', views.AuthLoginView.as_view({"post": "login"})),
    url(r'auth/token/(?P<key>[-_\w]+)/?$', views.AuthTokenView.as_view({"get": "token"})),
    # application release components
    url(r"^apps/(?P<id>{})/config/?$".format(settings.APP_URL_REGEX),
        views.ConfigViewSet.as_view({'get': 'retrieve', 'post': 'create'})),
    url(r"^apps/(?P<id>{})/builds/(?P<uuid>[-_\w]+)/?$".format(settings.APP_URL_REGEX),
        views.BuildViewSet.as_view({'get': 'retrieve'})),
    url(r"^apps/(?P<id>{})/builds/?$".format(settings.APP_URL_REGEX),
        views.BuildViewSet.as_view({'get': 'list', 'post': 'create'})),
    url(r"^apps/(?P<id>{})/releases/v(?P<version>[0-9]+)/?$".format(settings.APP_URL_REGEX),
        views.ReleaseViewSet.as_view({'get': 'retrieve'})),
    url(r"^apps/(?P<id>{})/releases/rollback/?$".format(settings.APP_URL_REGEX),
        views.ReleaseViewSet.as_view({'post': 'rollback'})),
    url(r"^apps/(?P<id>{})/releases/?$".format(settings.APP_URL_REGEX),
        views.ReleaseViewSet.as_view({'get': 'list'})),
    # restart pods
    url(r"^apps/(?P<id>{})/pods/restart/?$".format(settings.APP_URL_REGEX),
        views.PodViewSet.as_view({'post': 'restart'})),
    url(r"^apps/(?P<id>{})/pods/(?P<type>[-_\w.]+)/restart/?$".format(settings.APP_URL_REGEX),
        views.PodViewSet.as_view({'post': 'restart'})),
    url(r"^apps/(?P<id>{})/pods/(?P<type>[-_\w]+)/(?P<name>[-_\w]+)/restart/?$".format(
        settings.APP_URL_REGEX),
        views.PodViewSet.as_view({'post': 'restart'})),
    # list pods
    url(r"^apps/(?P<id>{})/pods/(?P<type>[-_\w]+)/(?P<name>[-_\w]+)/?$".format(
        settings.APP_URL_REGEX),
        views.PodViewSet.as_view({'get': 'list'})),
    url(r"^apps/(?P<id>{})/pods/(?P<type>[-_\w.]+)/?$".format(settings.APP_URL_REGEX),
        views.PodViewSet.as_view({'get': 'list'})),
    url(r"^apps/(?P<id>{})/pods/?$".format(settings.APP_URL_REGEX),
        views.PodViewSet.as_view({'get': 'list'})),
    # application domains
    url(r"^apps/(?P<id>{})/domains/(?P<domain>\**\.?[-\._\w]+)/?$".format(settings.APP_URL_REGEX),
        views.DomainViewSet.as_view({'delete': 'destroy'})),
    url(r"^apps/(?P<id>{})/domains/?$".format(settings.APP_URL_REGEX),
        views.DomainViewSet.as_view({'post': 'create', 'get': 'list'})),
    # application services
    url(r"^apps/(?P<id>{})/services/?$".format(settings.APP_URL_REGEX),
        views.ServiceViewSet.as_view({'post': 'create_or_update',
                                     'get': 'list', 'delete': 'delete'})),
    # application actions
    url(r"^apps/(?P<id>{})/scale/?$".format(settings.APP_URL_REGEX),
        views.AppViewSet.as_view({'post': 'scale'})),
    url(r"^apps/(?P<id>{})/logs/?$".format(settings.APP_URL_REGEX),
        views.AppViewSet.as_view({'get': 'logs'})),
    url(r"^apps/(?P<id>{})/run/?$".format(settings.APP_URL_REGEX),
        views.AppViewSet.as_view({'post': 'run'})),
    # application settings
    url(r"^apps/(?P<id>{})/settings/?$".format(settings.APP_URL_REGEX),
        views.AppSettingsViewSet.as_view({'get': 'retrieve', 'post': 'create'})),
    # application ip allowlist
    url(r"^apps/(?P<id>{})/allowlist/?$".format(settings.APP_URL_REGEX),
        views.AllowlistViewSet.as_view({'post': 'create', 'get': 'list', 'delete': 'delete'})),
    # application TLS settings
    url(r"^apps/(?P<id>{})/tls/?$".format(settings.APP_URL_REGEX),
        views.TLSViewSet.as_view({'get': 'retrieve', 'post': 'create'})),
    # apps sharing
    url(r"^apps/(?P<id>{})/perms/(?P<username>[-_\w]+)/?$".format(settings.APP_URL_REGEX),
        views.AppPermsViewSet.as_view({'delete': 'destroy'})),
    url(r"^apps/(?P<id>{})/perms/?$".format(settings.APP_URL_REGEX),
        views.AppPermsViewSet.as_view({'get': 'list', 'post': 'create'})),
    # application volumes
    url(r"^apps/(?P<id>{})/volumes/?$".format(settings.APP_URL_REGEX),
        views.AppVolumesViewSet.as_view({'get': 'list', 'post': 'create'})),
    url(r"^apps/(?P<id>{})/volumes/(?P<name>[-_\w]+)/?$".format(settings.APP_URL_REGEX),
        views.AppVolumesViewSet.as_view({'delete': 'destroy'})),
    url(r"^apps/(?P<id>{})/volumes/(?P<name>[-_\w]+)/path/?$".format(settings.APP_URL_REGEX),
        views.AppVolumeMountPathViewSet.as_view({'patch': 'path'})),
    # application resources
    url(r"^apps/(?P<id>{})/resources/?$".format(settings.APP_URL_REGEX),
        views.AppResourcesViewSet.as_view({'get': 'list', 'post': 'create'})),
    url(r"^apps/(?P<id>{})/resources/(?P<name>[-_\w]+)/?$".format(settings.APP_URL_REGEX),
        views.AppSingleResourceViewSet.as_view({
            'get': 'retrieve',
            'delete': 'destroy',
            'put': 'update'
        })),
    url(r"^apps/(?P<id>{})/resources/(?P<name>[-_\w]+)/binding/?$".format(settings.APP_URL_REGEX),
        views.AppResourceBindingViewSet.as_view({'patch': 'binding'})),
    # apps base endpoint
    url(r"^apps/(?P<id>{})/?$".format(settings.APP_URL_REGEX),
        views.AppViewSet.as_view({'get': 'retrieve', 'post': 'update', 'delete': 'destroy'})),
    url(r'^apps/?$',
        views.AppViewSet.as_view({'get': 'list', 'post': 'create'})),
    # key
    url(r'^keys/(?P<id>.+)/?$',
        views.KeyViewSet.as_view({'get': 'retrieve', 'delete': 'destroy'})),
    url(r'^keys/?$',
        views.KeyViewSet.as_view({'get': 'list', 'post': 'create'})),
    # hooks
    url(r'^hooks/keys/(?P<id>{})/(?P<username>[-_\w]+)?$'.format(settings.APP_URL_REGEX),
        views.KeyHookViewSet.as_view({'get': 'users'})),
    url(r'^hooks/keys/(?P<id>{})/?$'.format(settings.APP_URL_REGEX),
        views.KeyHookViewSet.as_view({'get': 'app'})),
    url(r'^hooks/key/(?P<fingerprint>.+)/?$',
        views.KeyHookViewSet.as_view({'get': 'public_key'})),
    url(r'^hooks/build/?$',
        views.BuildHookViewSet.as_view({'post': 'create'})),
    url(r'^hooks/config/?$',
        views.ConfigHookViewSet.as_view({'post': 'create'})),
    # authn / authz
    url(r'^auth/whoami/?$',
        views.UserManagementViewSet.as_view({'get': 'list'})),
    # admin sharing
    url(r'^admin/perms/(?P<username>[\w.@+-]+)/?$',
        views.AdminPermsViewSet.as_view({'delete': 'destroy'})),
    url(r'^admin/perms/?$',
        views.AdminPermsViewSet.as_view({'get': 'list', 'post': 'create'})),
    # certificates
    url(r'^certs/(?P<name>[-_*.\w]+)/domain/(?P<domain>\**\.?[-\._\w]+)?$',
        views.CertificateViewSet.as_view({'delete': 'detach', 'post': 'attach'})),
    url(r'^certs/(?P<name>[-_*.\w]+)/?$',
        views.CertificateViewSet.as_view({
            'get': 'retrieve',
            'delete': 'destroy'
        })),
    url(r'^certs/?$',
        views.CertificateViewSet.as_view({'get': 'list', 'post': 'create'})),
    # users
    url(r'^users/?$',
        views.UserView.as_view({'get': 'list'})),
    url(r'^users/(?P<username>[\w.@+-]+)/enable/?$',
        views.UserView.as_view({'patch': 'enable'})),
    url(r'^users/(?P<username>[\w.@+-]+)/disable/?$',
        views.UserView.as_view({'patch': 'disable'})),
    url(r'^apps/(?P<id>{})/metrics/(?P<type>[a-z0-9]+(\-[a-z0-9]+)*)/status/?$'.format(
        settings.APP_URL_REGEX),
        views.MetricView.as_view({'get': 'status'})),
    url(r'^manager/(?P<type>[\w.@+-]+)s/(?P<id>{})/block/?$'.format(settings.APP_URL_REGEX),
        views.WorkflowManagerViewset.as_view({'post': 'block'})),
    url(r'^manager/(?P<type>[\w.@+-]+)s/(?P<id>{})/unblock/?$'.format(settings.APP_URL_REGEX),
        views.WorkflowManagerViewset.as_view({'delete': 'unblock'})),
]

webhook_urlpatterns = [
    url(
        r'^webhooks/scale/(?P<token>.+)/?$',
        views.AdmissionWebhookViewSet.as_view({'post': 'scale'})
    ),
]

# If there is a mutating admission webhook configuration, use webhook url
if settings.DRYCC_ADMISSION_WEBHOOK_TOKEN:
    urlpatterns = webhook_urlpatterns
else:
    urlpatterns = app_urlpatterns
