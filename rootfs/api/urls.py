"""
URL routing patterns for the Drycc REST API.
"""
from django.conf import settings
from django.urls import include, re_path
from rest_framework.routers import DefaultRouter
from social_core.utils import setting_name
from api import views


class OptionalSlashRouter(DefaultRouter):
    """Router that accepts both trailing-slash and no-trailing-slash URLs."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.trailing_slash = '/?'


router = OptionalSlashRouter()
router.register(r'workspaces', views.WorkspaceViewSet, basename='workspace')
router.register(r'apps', views.AppViewSet, basename='app')
router.register(r'keys', views.KeyViewSet, basename='key')
router.register(r'tokens', views.TokenViewSet, basename='token')
router.register(r'limits/specs', views.LimitSpecViewSet, basename='limitspec')
router.register(r'limits/plans', views.LimitPlanViewSet, basename='limitplan')

extra = getattr(settings, setting_name('TRAILING_SLASH'), True) and '/' or ''

# Add the generated REST URLs and login/logout endpoint
app_urlpatterns = [
    re_path(r'^', include(router.urls)),
    re_path(r'auth/login/?$', views.AuthLoginView.as_view({"post": "login"})),
    re_path(r'auth/token/?$', views.AuthTokenView.as_view({"post": "token"})),
    re_path(r'auth/token/(?P<key>[-_\w]+)/?$', views.AuthTokenView.as_view({"get": "token"})),
    # Workspace sub-resources (members, invitations)
    re_path(r'^workspaces/(?P<id>[-_\w]+)/members/?$',
            views.WorkspaceMemberViewSet.as_view({'get': 'list'}),
            name='workspace_member_list'),
    re_path(r'^workspaces/(?P<id>[-_\w]+)/members/(?P<user>[-_\w]+)/?$',
            views.WorkspaceMemberViewSet.as_view(
                {'get': 'retrieve', 'patch': 'partial_update', 'delete': 'destroy'}),
            name='workspace_member_detail'),
    re_path(r'^workspaces/(?P<id>[-_\w]+)/invitations/?$',
            views.WorkspaceInvitationViewSet.as_view({'get': 'list', 'post': 'create'}),
            name='workspace_invitation_list'),
    re_path(r'^workspaces/(?P<id>[-_\w]+)/invitations/(?P<uid>[-_\w]+)/?$',
            views.WorkspaceInvitationViewSet.as_view({'get': 'retrieve', 'delete': 'destroy'}),
            name='workspace_invitation_detail'),
    # application release components
    re_path(
        r"^apps/(?P<id>{})/build/?$".format(settings.APP_URL_REGEX),
        views.BuildViewSet.as_view({'get': 'retrieve', 'post': 'create'})),
    re_path(
        r"^apps/(?P<id>{})/config/?$".format(settings.APP_URL_REGEX),
        views.ConfigViewSet.as_view({'get': 'retrieve', 'post': 'create', 'delete': 'destroy'})),
    re_path(
        r"^apps/(?P<id>{})/releases/v(?P<version>[0-9]+)/?$".format(settings.APP_URL_REGEX),
        views.ReleaseViewSet.as_view({'get': 'retrieve'})),
    re_path(
        r"^apps/(?P<id>{})/releases/deploy/?$".format(settings.APP_URL_REGEX),
        views.ReleaseViewSet.as_view({'post': 'deploy'})),
    re_path(
        r"^apps/(?P<id>{})/releases/rollback/?$".format(settings.APP_URL_REGEX),
        views.ReleaseViewSet.as_view({'post': 'rollback'})),
    re_path(
        r"^apps/(?P<id>{})/releases/?$".format(settings.APP_URL_REGEX),
        views.ReleaseViewSet.as_view({'get': 'list'})),
    # list/delete pods
    re_path(
        r"^apps/(?P<id>{})/pods/?$".format(settings.APP_URL_REGEX),
        views.PodViewSet.as_view({'get': 'list', 'delete': 'destroy'})),
    # describe pod
    re_path(
        r"^apps/(?P<id>{})/pods/(?P<name>{})/describe/?$".format(
            settings.APP_URL_REGEX, settings.NAME_REGEX),
        views.PodViewSet.as_view({'get': 'describe'})),
    # restart deployment/ptype's pods
    re_path(
        r"^apps/(?P<id>{})/ptypes/restart/?$".format(settings.APP_URL_REGEX),
        views.PtypeViewSet.as_view({'post': 'restart'})),
    # clean old k8s resource
    re_path(
        r"^apps/(?P<id>{})/ptypes/clean/?$".format(settings.APP_URL_REGEX),
        views.PtypeViewSet.as_view({'post': 'clean'})),
    # scale ptype replcas
    re_path(
        r"^apps/(?P<id>{})/ptypes/scale/?$".format(settings.APP_URL_REGEX),
        views.PtypeViewSet.as_view({'post': 'scale'})),
    # list ptypes
    re_path(
        r"^apps/(?P<id>{})/ptypes/?$".format(settings.APP_URL_REGEX),
        views.PtypeViewSet.as_view({'get': 'list'})),
    # describe ptypes
    re_path(
        r"^apps/(?P<id>{})/ptypes/(?P<name>{})/describe/?$".format(
            settings.APP_URL_REGEX, settings.NAME_REGEX),
        views.PtypeViewSet.as_view({'get': 'describe'})),
    # list events
    re_path(
        r"^apps/(?P<id>{})/events/?$".format(settings.APP_URL_REGEX),
        views.EventViewSet.as_view({'get': 'list'})),
    # application domains
    re_path(
        r"^apps/(?P<id>{})/domains/(?P<domain>{})/?$".format(
            settings.APP_URL_REGEX, settings.DOMAIN_URL_REGEX),
        views.DomainViewSet.as_view({'delete': 'destroy'})),
    re_path(
        r"^apps/(?P<id>{})/domains/?$".format(settings.APP_URL_REGEX),
        views.DomainViewSet.as_view({'post': 'create', 'get': 'list'})),
    # application services
    re_path(
        r"^apps/(?P<id>{})/services/?$".format(settings.APP_URL_REGEX),
        views.ServiceViewSet.as_view({'post': 'upsert',
                                     'get': 'list', 'delete': 'destroy'})),
    # application settings
    re_path(
        r"^apps/(?P<id>{})/settings/?$".format(settings.APP_URL_REGEX),
        views.AppSettingsViewSet.as_view({'get': 'retrieve', 'post': 'create'})),
    # application TLS settings
    re_path(
        r"^apps/(?P<id>{})/tls/?$".format(settings.APP_URL_REGEX),
        views.TLSViewSet.as_view({'get': 'retrieve', 'post': 'create'})),
    # application volumes
    re_path(
        r"^apps/(?P<id>{})/volumes/?$".format(settings.APP_URL_REGEX),
        views.AppVolumesViewSet.as_view({'get': 'list', 'post': 'create'})),
    re_path(
        r"^apps/(?P<id>{})/volumes/(?P<name>{})/?$".format(
            settings.APP_URL_REGEX, settings.NAME_REGEX),
        views.AppVolumesViewSet.as_view(
            {'get': 'retrieve', 'patch': 'expand', 'delete': 'destroy'})),
    re_path(
        r"^apps/(?P<id>{})/volumes/(?P<name>{})/path/?$".format(
            settings.APP_URL_REGEX, settings.NAME_REGEX),
        views.AppVolumesViewSet.as_view({'patch': 'path'})),
    # certificates
    re_path(
        r'^apps/(?P<id>{})/certs/(?P<name>{})/domain/(?P<domain>{})?/?$'.format(
            settings.APP_URL_REGEX, settings.NAME_REGEX, settings.DOMAIN_URL_REGEX),
        views.CertificateViewSet.as_view({'delete': 'detach', 'post': 'attach'})),
    re_path(
        r'^apps/(?P<id>{})/certs/(?P<name>{})/?$'.format(
            settings.APP_URL_REGEX, settings.NAME_REGEX),
        views.CertificateViewSet.as_view({'get': 'retrieve', 'delete': 'destroy'})),
    re_path(
        r'^apps/(?P<id>{})/certs/?$'.format(settings.APP_URL_REGEX),
        views.CertificateViewSet.as_view({'get': 'list', 'post': 'create'})),
    # application addons (upsert via PUT, list under an app)
    re_path(
        r'^apps/(?P<id>{})/addons/?$'.format(settings.APP_URL_REGEX),
        views.AddonInstanceViewSet.as_view({'get': 'list'})),
    re_path(
        r'^apps/(?P<id>{})/addons/(?P<name>[a-z0-9]([a-z0-9-]*[a-z0-9])?)/?$'.format(
            settings.APP_URL_REGEX),
        views.AddonInstanceViewSet.as_view(
            {'get': 'retrieve', 'put': 'upsert', 'delete': 'destroy'})),
    # addon classes (catalog, read-only)
    re_path(
        r'^addon-classes/?$',
        views.AddonClassViewSet.as_view({'get': 'list'})),
    re_path(
        r'^addon-classes/(?P<name>[a-z0-9]([a-z0-9-]*[a-z0-9])?)/?$',
        views.AddonClassViewSet.as_view({'get': 'retrieve'})),
    # hooks
    re_path(
        r'^hooks/keys/(?P<id>{})/(?P<username>[\w.@+-]+)/?$'.format(settings.APP_URL_REGEX),
        views.KeyHookViewSet.as_view({'get': 'users'})),
    re_path(
        r'^hooks/keys/(?P<id>{})/?$'.format(settings.APP_URL_REGEX),
        views.KeyHookViewSet.as_view({'get': 'app'})),
    re_path(
        r'^hooks/key/(?P<fingerprint>.+)/?$',
        views.KeyHookViewSet.as_view({'get': 'public_key'})),
    re_path(
        r'^hooks/build/?$',
        views.BuildHookViewSet.as_view({'post': 'create'})),
    re_path(
        r'^hooks/config/?$',
        views.ConfigHookViewSet.as_view({'post': 'create'})),
    re_path(
        r'^alerts/?$',
        views.AlertsHookViewSet.as_view({'post': 'create'})),
    # authn / authz
    re_path(
        r'^auth/whoami/?$',
        views.UserManagementViewSet.as_view({'get': 'whoami'})),
    # gateways
    re_path(
        r"^apps/(?P<id>{})/gateways/?$".format(settings.APP_URL_REGEX),
        views.GatewayViewSet.as_view({'get': 'list'})),
    re_path(
        r"^apps/(?P<id>{})/gateways/(?P<name>{})/?$".format(
            settings.APP_URL_REGEX, settings.NAME_REGEX),
        views.GatewayViewSet.as_view(
            {'get': 'retrieve', 'put': 'upsert', 'delete': 'destroy'})),
    # routes
    re_path(
        r"^apps/(?P<id>{})/routes/?$".format(settings.APP_URL_REGEX),
        views.RouteViewSet.as_view({'get': 'list'})),
    re_path(
        r"^apps/(?P<id>{})/routes/(?P<name>{})/?$".format(
            settings.APP_URL_REGEX, settings.NAME_REGEX),
        views.RouteViewSet.as_view(
            {'get': 'retrieve', 'put': 'upsert', 'delete': 'destroy'})),
    re_path(
        r'^apps/(?P<id>{})/metrics/?$'.format(settings.APP_URL_REGEX),
        views.MetricView.as_view({'get': 'metric'})),
    re_path(
        r'^apps/(?P<id>{})/metrics/(?P<ptype>[a-z0-9]+(\-[a-z0-9]+)*)/status/?$'.format(
            settings.APP_URL_REGEX),
        views.MetricView.as_view({'get': 'status'})),
    # quickwit
    re_path(
        r'^quickwit/(?P<workspace>[-\w]+)/(?P<path>.+)/?$', views.QuickwitProxyView.as_view()),
    # prometheus
    re_path(
        r'^prometheus/(?P<workspace>[-\w]+)/(?P<path>.+)/?$',
        views.PrometheusProxyView.as_view()),
]

metric_urlpatterns = [
    re_path(r'^metrics/?$', views.MetricsProxyView.as_view()),
]

mutate_urlpatterns = [
    re_path(
        r'^mutate/(?P<key>.+)/?$',
        views.AdmissionWebhookViewSet.as_view({'post': 'handle'})
    ),
]

# social login is placed at the end of the URL match
social_urlpatterns = [
    re_path(r'^login/(?P<backend>[^/]+){0}$'.format(extra), views.auth, name='begin'),
    re_path(r'^complete/(?P<backend>[^/]+){0}$'.format(extra), views.complete, name='complete'),
    re_path('', include('social_django.urls', namespace='social')),
]

if settings.RUNNER == 'metric':
    urlpatterns = metric_urlpatterns
elif settings.RUNNER == 'mutate':
    urlpatterns = mutate_urlpatterns
else:
    urlpatterns = app_urlpatterns + social_urlpatterns
