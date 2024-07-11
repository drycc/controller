"""
RESTful view classes for presenting Drycc API objects.
"""
import re
import uuid
import logging
import json
import requests
from django.db.models import Q
from django.core.cache import cache
from django.http import Http404, HttpResponse
from django.conf import settings
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404, redirect
from guardian.shortcuts import assign_perm, get_objects_for_user, \
    get_users_with_perms, remove_perm
from django.views.generic import View
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
from django.views.decorators.vary import vary_on_headers
from rest_framework import renderers, status, filters
from rest_framework.exceptions import PermissionDenied, NotFound
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet
from rest_framework.parsers import MultiPartParser

from api import monitor, models, permissions, serializers, viewsets, authentication
from api.tasks import scale_app, restart_app, mount_app, downstream_model_owner, \
    delete_pod, run_deploy
from api.exceptions import AlreadyExists, ServiceUnavailable, DryccException

from django.views.decorators.cache import never_cache
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.views.decorators.csrf import csrf_exempt
from django.http.response import FileResponse, StreamingHttpResponse
from social_django.utils import psa
from social_django.views import _do_login
from social_core.utils import setting_name
from api import admissions, utils, filer
from api.backend import OauthCacheManager
from api.apps_extra.social_core.actions import do_auth, do_complete

User = get_user_model()
logger = logging.getLogger(__name__)
oauth_cache_manager = OauthCacheManager()
NAMESPACE = getattr(settings, setting_name('URL_NAMESPACE'), None) or 'social'


class ReadinessCheckView(View):
    """
    Simple readiness check view to determine DB connection / query.
    """

    def get(self, request):
        try:
            import django.db
            with django.db.connection.cursor() as c:
                c.execute("SELECT 0")
        except django.db.Error as e:
            raise ServiceUnavailable("Database health check failed") from e

        return HttpResponse("OK")
    head = get


class LivenessCheckView(View):
    """
    Simple liveness check view to determine if the server
    is responding to HTTP requests.
    """

    def get(self, request):
        return HttpResponse("OK")
    head = get


@never_cache
@psa('{0}:complete'.format(NAMESPACE))
def auth(request, backend):
    return do_auth(request.backend, redirect_name=REDIRECT_FIELD_NAME)


@never_cache
@csrf_exempt
@psa('{0}:complete'.format(NAMESPACE))
def complete(request, backend, *args, **kwargs):
    """Authentication complete view"""
    return do_complete(request.backend, _do_login, user=None,
                       redirect_name=REDIRECT_FIELD_NAME, request=request,
                       *args, **kwargs)


class AuthLoginView(GenericViewSet):

    permission_classes = (AllowAny, )
    serializer_class = serializers.AuthSerializer

    def login(self, request, *args, **kwargs):
        key = uuid.uuid4().hex
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        username = serializer.validated_data.get('username')
        password = serializer.validated_data.get('password')
        if username and password:
            return self._create_interactive_response(username, password, key)
        return self._create_browser_response(key)

    def _create_browser_response(self, key):
        uri = self.request.build_absolute_uri()
        return redirect(f"{uri[0:uri.find(self.request.path)]}/v2/login/drycc/?key={key}")

    def _create_interactive_response(self, username, password, key):
        response = requests.post(
            settings.SOCIAL_AUTH_DRYCC_ACCESS_TOKEN_URL,
            data={
                'grant_type': 'password',
                'client_id': settings.SOCIAL_AUTH_DRYCC_KEY,
                'client_secret': settings.SOCIAL_AUTH_DRYCC_SECRET,
                'username': username,
                'password': password,
            },
        )
        if response.status_code != 200:
            raise DryccException(response.content)
        state = uuid.uuid4().hex
        oauth_cache_manager.set_state(key, state)
        oauth_cache_manager.set_token(state, response.json())
        return HttpResponse(json.dumps({"key": key}))


class AuthTokenView(GenericViewSet):

    permission_classes = (AllowAny, )

    def token(self, request, *args, **kwargs):
        oauth = oauth_cache_manager.get_token(self.kwargs['key'])
        if oauth:
            user = oauth_cache_manager.get_user(oauth['access_token'])
            alias = request.query_params.get('alias', '')
            token = models.base.Token(owner=user, alias=alias, oauth=oauth)
            token.save()
            return HttpResponse(json.dumps({"token": token.key, "username": user.username}))
        return HttpResponse(status=404)


class UserManagementViewSet(GenericViewSet):
    serializer_class = serializers.UserSerializer

    def get_queryset(self):
        return User.objects.filter(pk=self.request.user.pk)

    def get_object(self):
        return self.get_queryset()[0]

    def list(self, request, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(user, many=False)
        return Response(serializer.data)


class WorkflowManagerViewset(GenericViewSet):
    permission_classes = (permissions.IsWorkflowManager, )
    authentication_classes = (authentication.AnonymousAuthentication, )

    def block(self, request,  **kwargs):
        try:
            blocklist, _ = models.blocklist.Blocklist.objects.get_or_create(
                id=kwargs['id'],
                type=models.blocklist.Blocklist.get_type(kwargs["type"]),
                defaults={"remark": request.data.get("remark")}
            )
            for app in blocklist.related_apps:
                scale_app.delay(app, app.owner, {key: 0 for key in app.structure.keys()})
            return HttpResponse(status=201)
        except ValueError as e:
            logger.info(e)
            raise DryccException("Unsupported block type: %s" % kwargs["type"])

    def unblock(self, request,  **kwargs):
        try:
            models.blocklist.Blocklist.objects.filter(
                id=kwargs['id'],
                type=models.blocklist.Blocklist.get_type(kwargs["type"])
            ).delete()
            return HttpResponse(status=204)
        except ValueError as e:
            logger.info(e)
            raise DryccException("Unsupported block type: %s" % kwargs["type"])


class AdmissionWebhookViewSet(GenericViewSet):

    admission_classes = (
        admissions.JobsStatusHandler,
        admissions.DeploymentsScaleHandler,
        admissions.ServiceInstancesStatusHandler,
        admissions.ServicebindingsStatusHandler,
    )
    permission_classes = (AllowAny, )

    def handle(self, request,  **kwargs):
        key = kwargs['key']
        data = json.loads(request.body.decode("utf8"))["request"]
        if settings.MUTATE_KEY == key:
            allowed = True
            for admission_class in self.admission_classes:
                admission = admission_class()
                if admission.detect(data):
                    allowed = admission.handle(data)
                    break
        else:
            allowed = False
        return Response({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": {
                "uid": data["uid"],
                "allowed": allowed,
            }
        })


class TokenViewSet(viewsets.OwnerViewSet):

    serializer_class = serializers.TokenSerializer
    permission_classes = [IsAuthenticated, permissions.IsOwner]

    def get_queryset(self):
        return models.base.Token.objects.filter(owner=self.request.user)

    def destroy(self, *args, **kwargs):
        key = self.get_object().key
        response = super(TokenViewSet, self).destroy(self, *args, **kwargs)
        cache.delete(key)
        return response


class BaseDryccViewSet(viewsets.OwnerViewSet):
    """
    A generic ViewSet for objects related to Drycc.

    To use it, at minimum you'll need to provide the `serializer_class` attribute and
    the `model` attribute shortcut.
    """
    lookup_field = 'id'
    permission_classes = [IsAuthenticated, permissions.IsAppUser]
    renderer_classes = [renderers.JSONRenderer]


class AppResourceViewSet(BaseDryccViewSet):
    """A viewset for objects which are attached to an application."""

    def get_app(self):
        app = get_object_or_404(models.app.App, id=self.kwargs['id'])
        self.check_object_permissions(self.request, app)
        return app

    def get_queryset(self, **kwargs):
        app = self.get_app()
        return self.model.objects.filter(app=app)

    def get_object(self, **kwargs):
        return self.get_queryset(**kwargs).latest('created')

    def create(self, request, **kwargs):
        request.data['app'] = self.get_app()
        return super(AppResourceViewSet, self).create(request, **kwargs)


class ReleasableViewSet(AppResourceViewSet):
    """A viewset for application resources which affect the release cycle."""
    def get_object(self):
        """Retrieve the object based on the latest release's value"""
        return getattr(
            self.get_app().release_set.filter(failed=False).latest(),
            self.model.__name__.lower()
        )


class AppViewSet(BaseDryccViewSet):
    """A viewset for interacting with App objects."""
    model = models.app.App
    filter_backends = [filters.SearchFilter]
    search_fields = ['^id', ]
    serializer_class = serializers.AppSerializer

    def get_queryset(self, *args, **kwargs):
        return self.model.objects.all(*args, **kwargs)

    def list(self, request, *args, **kwargs):
        """
        HACK: Instead of filtering by the queryset, we limit the queryset to list only the apps
        which are owned by the user as well as any apps they have been given permission to
        interact with.
        """
        queryset = super(AppViewSet, self).get_queryset(**kwargs) | \
            get_objects_for_user(self.request.user, 'api.use_app')
        instance = self.filter_queryset(queryset)
        page = self.paginate_queryset(instance)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(instance, many=True)
        return Response(serializer.data)

    def run(self, request, **kwargs):
        app = self.get_object()
        command = request.data.get('command', '').split()
        timeout = int(request.data.get('timeout', 3600))
        expires = int(request.data.get('expires', 3600))
        if expires == 0 or expires > settings.KUBERNETES_JOB_MAX_TTL_SECONDS_AFTER_FINISHED:
            expires = settings.KUBERNETES_JOB_MAX_TTL_SECONDS_AFTER_FINISHED
        if not command:
            raise DryccException('command is a required field, or it can be defined in Procfile')
        volumes = request.data.get('volumes', None)
        if volumes:
            volumes = serializers.VolumeSerializer().validate_path(volumes)
        app.run(self.request.user, args=command,
                volumes=volumes, timeout=timeout, expires=expires)
        return Response(status=status.HTTP_204_NO_CONTENT)

    def update(self, request, **kwargs):
        app = self.get_object()
        old_owner = app.owner

        if request.data.get('owner'):
            if self.request.user != app.owner and not self.request.user.is_superuser:
                raise PermissionDenied()
            new_owner = get_object_or_404(User, username=request.data['owner'])
            # ensure all downstream objects that are owned by this user and are part of this app
            # is also updated
            downstream_model_owner.delay(app, old_owner, new_owner)
        return Response(status=status.HTTP_200_OK)


class BuildViewSet(ReleasableViewSet):
    """A viewset for interacting with Build objects."""
    model = models.build.Build
    serializer_class = serializers.BuildSerializer

    def post_save(self, build):
        build.create_release(self.request.user)
        super(BuildViewSet, self).post_save(build)


class LimitSpecViewSet(BaseDryccViewSet):
    """A viewset for interacting with Limit objects."""
    model = models.limit.LimitSpec
    serializer_class = serializers.LimitSpecSerializer

    def get_queryset(self, **kwargs):
        q = Q(disabled=False)
        keywords = self.request.query_params.get('keywords', '').strip()
        if keywords:
            q &= Q(
                keywords__contains=[keyword.lower() for keyword in re.split(r"\W+", keywords)])
        return self.model.objects.filter(q)


class LimitPlanViewSet(BaseDryccViewSet):
    """A viewset for interacting with Limit objects."""
    model = models.limit.LimitPlan
    serializer_class = serializers.LimitPlanSerializer

    def get_object(self):
        return get_object_or_404(self.model, id=self.kwargs["id"])

    def get_queryset(self, **kwargs):
        q = Q(disabled=False)
        spec_id = self.request.query_params.get('spec-id', '')
        if spec_id:
            q &= Q(spec_id=spec_id)
        cpu_match = re.search("^[0-9]+", self.request.query_params.get('cpu', ''))
        if cpu_match:
            q &= Q(cpu=cpu_match.group())
        memory_match = re.search("^[0-9]+", self.request.query_params.get('memory', ''))
        if memory_match:
            q &= Q(memory=memory_match.group())
        return self.model.objects.filter(q)


class ConfigViewSet(ReleasableViewSet):
    """A viewset for interacting with Config objects."""
    model = models.config.Config
    serializer_class = serializers.ConfigSerializer

    def post_save(self, config):
        latest_release = config.app.release_set.filter(failed=False).latest()
        if latest_release.build is not None and latest_release.state == "created":
            config.delete()
            raise DryccException('There is an executing pipeline, please wait')
        try:
            release = latest_release.new(
                self.request.user, config=config, build=latest_release.build)
            run_deploy.delay(release, config)
        except Exception as e:
            config.delete()
            if isinstance(e, AlreadyExists):
                raise
            raise DryccException(str(e)) from e


class PodViewSet(BaseDryccViewSet):
    model = models.app.App
    serializer_class = serializers.PodSerializer

    def list(self, *args, **kwargs):
        pods = self.get_object().list_pods(*args, **kwargs)
        data = self.get_serializer(pods, many=True).data
        # fake out pagination for now
        pagination = {'results': data, 'count': len(data)}
        return Response(pagination, status=status.HTTP_200_OK)

    def describe(self, *args, **kwargs):
        pod_name = kwargs["name"]
        data = self.get_object().describe_pod(pod_name)
        if len(data) == 0:
            raise DryccException("this process not found")
        # fake out pagination for now
        pagination = {'results': data, 'count': len(data)}
        return Response(pagination, status=status.HTTP_200_OK)

    def delete(self, request, **kwargs):
        pod_names = request.data.get("pod_ids")
        pod_names = pod_names.split(",")
        for pod_name in set(pod_names):
            delete_pod.delay(self.get_object(), **{"pod_name": pod_name})
        return Response(status=status.HTTP_200_OK)


class PtypesViewSet(BaseDryccViewSet):
    model = models.app.App
    serializer_class = serializers.PtypesSerializer

    def get_queryset(self, *args, **kwargs):
        return self.model.objects.all(*args, **kwargs)

    def list(self, *args, **kwargs):
        deploys = self.get_object().list_deployments(*args, **kwargs)
        data = self.get_serializer(deploys, many=True).data
        # fake out pagination for now
        pagination = {'results': data, 'count': len(data)}
        return Response(pagination, status=status.HTTP_200_OK)

    def describe(self, *args, **kwargs):
        deployment_name = kwargs["name"]
        data = self.get_object().describe_deployment(deployment_name)
        if len(data) == 0:
            raise DryccException("this ptype not found")
        # fake out pagination for now
        pagination = {'results': data, 'count': len(data)}
        return Response(pagination, status=status.HTTP_200_OK)

    def restart(self, request, *args, **kwargs):
        app = self.get_object()
        ptypes = []
        types = request.data.get("types", "").split(",")
        types = [ptype for ptype in set(types) if ptype != ""]
        if not types:
            # all ptypes need to restart
            ptypes = app.structure.keys()
        else:
            ptypes = [ptype for ptype in types if ptype in app.structure]
            invalid_ptypes = set(types) - set(ptypes)
            if len(invalid_ptypes) != 0:
                raise DryccException("process type {} is not included in procfile".
                                     format(','.join(invalid_ptypes)))
        for ptype in set(ptypes):
            restart_app.delay(app, **{"type": ptype})
        return Response(status=status.HTTP_204_NO_CONTENT)

    def scale(self, request, **kwargs):
        app = self.get_object()
        latest_release = app.release_set.filter(failed=False).latest()
        if latest_release.build is not None and latest_release.state == "created":
            raise DryccException('There is an executing pipeline, please wait')
        scale_app.delay(app, request.user, request.data)
        return Response(status=status.HTTP_204_NO_CONTENT)


class EventViewSet(AppResourceViewSet):
    model = models.app.App
    serializer_class = serializers.EventSerializer

    def list(self, request, **kwargs):
        ptype_name = request.query_params.get("ptype_name", None)
        pod_name = request.query_params.get("pod_name", None)
        if not any([ptype_name, pod_name]):
            data = []
        else:
            ref_kind, ref_name = ("Pod", pod_name) if pod_name else \
                ("Deployment", ptype_name)
            events = self.get_app().list_events(ref_kind, ref_name)
            data = self.get_serializer(events, many=True).data
        # fake out pagination for now
        pagination = {'results': data, 'count': len(data)}
        return Response(pagination, status=status.HTTP_200_OK)


class AppSettingsViewSet(AppResourceViewSet):
    model = models.appsettings.AppSettings
    serializer_class = serializers.AppSettingsSerializer


class DomainViewSet(AppResourceViewSet):
    """A viewset for interacting with Domain objects."""
    model = models.domain.Domain
    serializer_class = serializers.DomainSerializer

    def get_object(self, **kwargs):
        qs = self.get_queryset(**kwargs)
        domain = self.kwargs['domain']
        # support IDN domains, i.e. accept Unicode encoding too
        try:
            import idna
            if domain.startswith("*."):
                ace_domain = "*." + idna.encode(domain[2:]).decode("utf-8", "strict")
            else:
                ace_domain = idna.encode(domain).decode("utf-8", "strict")
        except:  # noqa
            ace_domain = domain
        return get_object_or_404(qs, domain=ace_domain)

    def destroy(self, request, **kwargs):
        domain = self.get_object()
        domain.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class ServiceViewSet(AppResourceViewSet):
    """A viewset for interacting with Service objects."""
    model = models.service.Service
    serializer_class = serializers.ServiceSerializer

    def list(self, *args, **kwargs):
        services = self.get_app().service_set.all()
        data = [obj.as_dict() for obj in services]
        return Response({"services": data}, status=status.HTTP_200_OK)

    def create_or_update(self, request, **kwargs):
        app = self.get_app()
        port = self.get_serializer().validate_port(request.data.get('port'))
        protocol = self.get_serializer().validate_protocol(request.data.get('protocol'))
        procfile_type = self.get_serializer().validate_procfile_type(request.data.get(
            'procfile_type'))
        target_port = self.get_serializer().validate_target_port(request.data.get('target_port'))
        service = app.service_set.filter(procfile_type=procfile_type).first()
        if service:
            for item in service.ports:
                if item["port"] == port:
                    return Response(status=status.HTTP_400_BAD_REQUEST, data={"detail": "port is occupied"})  # noqa
            http_status = status.HTTP_204_NO_CONTENT
        else:
            service = self.model(owner=app.owner, app=app, procfile_type=procfile_type)
            http_status = status.HTTP_201_CREATED
        service.add_port(port, protocol, target_port)
        service.save()
        return Response(status=http_status)

    def delete(self, request, **kwargs):
        port = self.get_serializer().validate_port(request.data.get('port'))
        protocol = self.get_serializer().validate_protocol(request.data.get('protocol'))
        procfile_type = self.get_serializer().validate_procfile_type(
            request.data.get('procfile_type'))
        service = get_object_or_404(self.get_queryset(**kwargs), procfile_type=procfile_type)
        removed = service.remove_port(port, protocol)
        if len(service.ports) == 0:
            service.delete()
        elif removed:
            service.save()
        return Response(status=status.HTTP_204_NO_CONTENT)


class CertificateViewSet(BaseDryccViewSet):
    """A viewset for interacting with Certificate objects."""
    model = models.certificate.Certificate
    serializer_class = serializers.CertificateSerializer

    def get_object(self, **kwargs):
        """Retrieve domain certificate by its name"""
        qs = self.get_queryset(**kwargs)
        return get_object_or_404(qs, name=self.kwargs['name'])

    def attach(self, request, *args, **kwargs):
        try:
            if "domain" not in kwargs and not request.data.get('domain'):
                raise DryccException("domain is a required field")
            elif request.data.get('domain'):
                kwargs['domain'] = request.data['domain']

            self.get_object().attach(*args, **kwargs)
        except Http404:
            raise

        return Response(status=status.HTTP_201_CREATED)

    def detach(self, request, *args, **kwargs):
        try:
            self.get_object().detach(*args, **kwargs)
        except Http404:
            raise

        return Response(status=status.HTTP_204_NO_CONTENT)


class KeyViewSet(BaseDryccViewSet):
    """A viewset for interacting with Key objects."""
    model = models.key.Key
    permission_classes = [IsAuthenticated, permissions.IsOwner]
    serializer_class = serializers.KeySerializer


class ReleaseViewSet(AppResourceViewSet):
    """A viewset for interacting with Release objects."""
    model = models.release.Release
    serializer_class = serializers.ReleaseSerializer

    def get_object(self, **kwargs):
        """Get release by version always"""
        qs = self.get_queryset(**kwargs)
        return get_object_or_404(qs, version=self.kwargs['version'])

    def rollback(self, request, **kwargs):
        """
        Create a new release as a copy of the state of the compiled slug and config vars of a
        previous release.
        """
        latest_release = self.get_app().release_set.filter(failed=False).latest()
        new_release = latest_release.rollback(request.user, request.data.get('version', None))
        response = {'version': new_release.version}
        return Response(response, status=status.HTTP_201_CREATED)


class TLSViewSet(AppResourceViewSet):
    model = models.tls.TLS
    serializer_class = serializers.TLSSerializer

    def events(self, request, **kwargs):
        results = self.get_object().events()
        return Response({'results': results, 'count': len(results)})


class BaseHookViewSet(BaseDryccViewSet):
    permission_classes = [permissions.HasBuilderAuth]


class KeyHookViewSet(BaseHookViewSet):
    """API hook to create new :class:`~api.models.Push`"""
    model = models.key.Key
    serializer_class = serializers.KeySerializer

    def public_key(self, request, *args, **kwargs):
        fingerprint = kwargs['fingerprint'].strip()
        key = get_object_or_404(models.key.Key, fingerprint=fingerprint)

        queryset = models.app.App.objects.all() | \
            get_objects_for_user(self.request.user, 'api.use_app')
        items = self.filter_queryset(queryset)

        apps = []
        for item in items:
            apps.append(item.id)

        data = {
            'username': key.owner.username,
            'apps': apps
        }

        return Response(data, status=status.HTTP_200_OK)

    def app(self, request, *args, **kwargs):
        app = get_object_or_404(models.app.App, id=kwargs['id'])

        perm_name = "api.use_app"
        usernames = [u.id for u in get_users_with_perms(app)
                     if u.has_perm(perm_name, app)]

        data = {}
        result = models.key.Key.objects \
                       .filter(owner__in=usernames) \
                       .values('owner__username', 'public', 'fingerprint') \
                       .order_by('created')
        for info in result:
            user = info['owner__username']
            if user not in data:
                data[user] = []

            data[user].append({
                'key': info['public'],
                'fingerprint': info['fingerprint']
            })

        return Response(data, status=status.HTTP_200_OK)

    def users(self, request, *args, **kwargs):
        app = get_object_or_404(models.app.App, id=kwargs['id'])
        request.user = get_object_or_404(User, username=kwargs['username'])
        # check the user is authorized for this app
        has_permission, message = permissions.has_app_permission(
            request.user, app, request.method)
        if not has_permission:
            raise PermissionDenied(message)

        data = {request.user.username: []}
        keys = models.key.Key.objects \
                     .filter(owner__username=kwargs['username']) \
                     .values('public', 'fingerprint') \
                     .order_by('created')
        if not keys:
            raise NotFound("No Keys match the given query.")

        for info in keys:
            data[request.user.username].append({
                'key': info['public'],
                'fingerprint': info['fingerprint']
            })

        return Response(data, status=status.HTTP_200_OK)


class BuildHookViewSet(BaseHookViewSet):
    """API hook to create new :class:`~api.models.build.Build`"""
    model = models.build.Build
    serializer_class = serializers.BuildSerializer

    def create(self, request, *args, **kwargs):
        app = get_object_or_404(models.app.App, id=request.data['receive_repo'])
        self.user = request.user = get_object_or_404(User, username=request.data['receive_user'])
        # check the user is authorized for this app
        has_permission, message = permissions.has_app_permission(self.user, app, request.method)
        if not has_permission:
            raise PermissionDenied(message)
        request.data['app'] = app
        request.data['owner'] = self.user
        super(BuildHookViewSet, self).create(request, *args, **kwargs)
        # return the application databag
        response = {
            'release': {
                'version': app.release_set.filter(failed=False).latest().version
            }
        }
        return Response(response, status=status.HTTP_200_OK)

    def post_save(self, build):
        build.create_release(self.user)


class ConfigHookViewSet(BaseHookViewSet):
    """API hook to grab latest :class:`~api.models.config.Config`"""
    model = models.config.Config
    serializer_class = serializers.ConfigSerializer

    def create(self, request, *args, **kwargs):
        app = get_object_or_404(models.app.App, id=request.data['receive_repo'])
        request.user = get_object_or_404(User, username=request.data['receive_user'])
        # check the user is authorized for this app
        has_permission, message = permissions.has_app_permission(
            request.user, app, request.method)
        if not has_permission:
            raise PermissionDenied(message)
        config = app.release_set.filter(failed=False).latest().config
        serializer = self.get_serializer(config)
        return Response(serializer.data, status=status.HTTP_200_OK)


class AppPermsViewSet(BaseDryccViewSet):
    """RESTful views for sharing apps with collaborators."""

    model = models.app.App  # models class
    perm = 'use_app'    # short name for permission

    def get_queryset(self):
        return self.model.objects.all()

    def list(self, request, **kwargs):
        app = self.get_object()
        perm_name = "api.{}".format(self.perm)
        usernames = [u.username for u in get_users_with_perms(app)
                     if u.has_perm(perm_name, app)]
        return Response({'users': usernames})

    def create(self, request, **kwargs):
        app = self.get_object()
        if not permissions.IsOwnerOrAdmin.has_object_permission(permissions.IsOwnerOrAdmin(),
                                                                request, self, app):
            raise PermissionDenied()

        user = get_object_or_404(User, username=request.data['username'])
        assign_perm(self.perm, user, app)
        app.log("User {} was granted access to {}".format(user, app))
        return Response(status=status.HTTP_201_CREATED)

    def destroy(self, request, **kwargs):
        app = get_object_or_404(models.app.App, id=self.kwargs['id'])
        user = get_object_or_404(User, username=kwargs['username'])

        perm_name = "api.{}".format(self.perm)
        if not user.has_perm(perm_name, app):
            raise PermissionDenied()

        if (user != request.user and
            not permissions.IsOwnerOrAdmin.has_object_permission(permissions.IsOwnerOrAdmin(),
                                                                 request, self, app)):
            raise PermissionDenied()
        remove_perm(self.perm, user, app)
        app.log("User {} was revoked access to {}".format(user, app))
        return Response(status=status.HTTP_204_NO_CONTENT)


class AppVolumesViewSet(ReleasableViewSet):
    """RESTful views for volumes apps with collaborators."""
    model = models.volume.Volume
    serializer_class = serializers.VolumeSerializer

    def get_object(self):
        return get_object_or_404(models.volume.Volume,
                                 app__id=self.kwargs['id'],
                                 name=self.kwargs['name'])

    def expand(self, request, **kwargs):
        volume = self.get_object()
        volume.expand(request.data['size'])
        serializer = self.get_serializer(volume, many=False)
        return Response(serializer.data)

    def destroy(self, request, **kwargs):
        volume = self.get_object()
        if volume.path != {}:
            raise DryccException("this volume is mounting")
        volume.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    def path(self, request, *args, **kwargs):
        path = request.data.get('path')
        if path is None:
            raise DryccException("path is a required field")
        else:
            path = serializers.VolumeSerializer().validate_path(path)
        volume = self.get_object()
        container_types = [_ for _ in path.keys()
                           if _ not in volume.app.procfile_types]
        if container_types:
            raise DryccException("process type {} is not included in procfile".
                                 format(','.join(container_types)))
        if set(path.items()).issubset(set(volume.path.items())):
            raise DryccException("mount path not changed")
        volume.check_path(path)

        app = self.get_app()
        mount_app.delay(app, self.request.user, volume, path)
        serializer = self.get_serializer(volume, many=False)
        return Response(serializer.data)


class AppFilerClientViewSet(BaseDryccViewSet):
    """RESTful views for volumes apps with collaborators."""
    model = models.volume.Volume
    parser_classes = [MultiPartParser]

    def get_client(self):
        volume = get_object_or_404(
            models.volume.Volume, app__id=self.kwargs['id'], name=self.kwargs['name'])
        return filer.FilerClient(volume.app.id, volume, volume.app.scheduler())

    def list(self, request, **kwargs):
        path = request.query_params.get('path', '')
        client = self.get_client()
        response = client.get(path, params={"action": "list"})
        if response.status_code != 200:
            raise DryccException(response.text.replace("\n", ""))
        results = response.json()
        # fake out pagination for now
        pagination = {'results': results, 'count': len(results)}
        return Response(data=pagination)

    def retrieve(self, request, **kwargs):
        path = self.kwargs.get('path', '')
        client = self.get_client()
        chunk_size = 1024 * 1024 * 2
        response = client.get(path, stream=True, params={"action": "get"})
        if response.status_code != 200:
            raise DryccException(response.text.replace("\n", ""))
        return FileResponse(
            status=response.status_code,
            headers=response.headers,
            streaming_content=utils.iter_to_aiter(response.iter_content(chunk_size=chunk_size)),
        )

    def create(self, request, **kwargs):
        path = request.data.get('path', '')
        client = self.get_client()
        response = client.post(path, files=request.FILES)
        return Response(data=response.content, status=response.status_code)

    def destroy(self, request, **kwargs):
        path = self.kwargs.get('path', '')
        client = self.get_client()
        response = client.delete(path)
        return Response(data=response.content, status=response.status_code)


class AppResourcesViewSet(AppResourceViewSet):
    """RESTful views for resources apps with collaborators."""
    model = models.resource.Resource
    serializer_class = serializers.ResourceSerializer

    def services(self, request, *args, **kwargs):
        results = self.model.services()
        # fake out pagination for now
        pagination = {'results': results, 'count': len(results)}
        return Response(data=cache.get_or_set(
            "resources:services", pagination
        ))

    def plans(self, request, *args, **kwargs):
        serviceclass_name = kwargs["id"]
        results = self.model.plans(serviceclass_name)
        # fake out pagination for now
        pagination = {'results': results, 'count': len(results)}
        return Response(data=cache.get_or_set(
            "resources:services:%s:plan" % serviceclass_name, pagination
        ))


class AppSingleResourceViewSet(AppResourceViewSet):
    """RESTful views for resource apps with collaborators."""
    model = models.resource.Resource
    serializer_class = serializers.ResourceSerializer

    def get_object(self):
        return get_object_or_404(models.resource.Resource,
                                 app__id=self.kwargs['id'],
                                 name=self.kwargs['name'])

    def retrieve(self, request, *args, **kwargs):
        resource = self.get_object()
        resource.retrieve(request)
        response =  super(AppSingleResourceViewSet, self).retrieve(request, *args, **kwargs)  # noqa
        response.data["message"] = resource.message
        return response

    def destroy(self, request, *args, **kwargs):
        resource = self.get_object()
        resource.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    def update(self, request, *args, **kwargs):
        resource = self.get_object()
        resource = serializers.ResourceSerializer(data=request.data,
                                                  instance=resource,
                                                  partial=True)
        if resource.is_valid():
            resource.save()
        return Response(resource.data)


class AppResourceBindingViewSet(AppResourceViewSet):
    model = models.resource.Resource
    serializer_class = serializers.ResourceSerializer

    def get_object(self):
        return get_object_or_404(models.resource.Resource,
                                 app__id=self.kwargs['id'],
                                 name=self.kwargs['name'])

    def binding(self, request, *args, **kwargs):
        resource = self.get_object()
        # {"bind_action":bind/unbind}
        bind_action = self.request.data.get('bind_action', '').lower()
        if bind_action == 'bind':
            resource.bind()
            serializer = self.get_serializer(resource, many=False)
            logger.info("resoruce bind response data: {}".format(serializer))
            return Response(serializer.data)
        elif bind_action == 'unbind':
            resource.unbind()
            serializer = self.get_serializer(resource, many=False)
            logger.info("resoruce unbind response data: {}".format(serializer))
            return Response(serializer.data)
        else:
            return Http404("unknown action")


class GatewayViewSet(AppResourceViewSet):
    """A viewset for interacting with Gateway objects."""
    model = models.gateway.Gateway
    filter_backends = [filters.SearchFilter]
    search_fields = ['^id', ]
    serializer_class = serializers.GatewaySerializer

    def create_or_update(self, request, *args, **kwargs):
        app = self.get_app()
        name = request.data['name']
        port = self.get_serializer().validate_port(request.data['port'])
        protocol = self.get_serializer().validate_protocol(request.data['protocol'])
        gateway = app.gateway_set.filter(name=name).first()
        if not gateway:
            gateway = self.model(app=app, owner=app.owner, name=name)
        added, msg = gateway.add(port, protocol)
        if not added:
            return Response(status=status.HTTP_400_BAD_REQUEST, data=msg)
        gateway.save()
        return Response(status=status.HTTP_201_CREATED)

    def delete(self, request, **kwargs):
        app = self.get_app()
        port = self.get_serializer().validate_port(request.data.get('port'))
        protocol = self.get_serializer().validate_protocol(request.data['protocol'])
        gateway = get_object_or_404(app.gateway_set, name=request.data.get("name"))
        ok, msg = gateway.remove(port, protocol)
        if not ok:
            return Response(status=status.HTTP_400_BAD_REQUEST, data=msg)
        if len(gateway.listeners) == 0:
            gateway.delete()
        else:
            gateway.save()
        return Response(status=status.HTTP_204_NO_CONTENT)


class RouteViewSet(AppResourceViewSet):
    """A viewset for interacting with Route objects."""
    model = models.gateway.Route
    filter_backends = [filters.SearchFilter]
    search_fields = ['^id', ]
    serializer_class = serializers.RouteSerializer

    def get(self, request, *args, **kwargs):
        app = self.get_app()
        route = get_object_or_404(app.route_set, name=kwargs['name'])
        return Response(route.rules, status=status.HTTP_200_OK)

    def set(self, request, *args, **kwargs):
        app = self.get_app()
        route = get_object_or_404(self.model, app=app, name=kwargs['name'])
        rules = request.data
        if isinstance(rules, str):
            rules = json.loads(rules)
        rules = self.get_serializer(route, many=False).validate_rules(rules)
        route.rules = rules
        ok, msg = route.check_rules()
        if not ok:
            return Response(status=status.HTTP_400_BAD_REQUEST, data=msg)
        route.save()
        return Response(status=status.HTTP_204_NO_CONTENT)

    def create(self, request, *args, **kwargs):
        app = self.get_app()
        port = self.get_serializer().validate_port(request.data.get('port'))
        app_settings = app.appsettings_set.latest()
        procfile_type = self.get_serializer().validate_procfile_type(
            request.data.get('procfile_type'))
        kind = self.get_serializer().validate_kind(request.data.get('kind'))
        name = request.data['name']
        route = app.route_set.filter(name=name).first()
        if route:
            return Response(status=status.HTTP_400_BAD_REQUEST, data={
                "detail": f"this route {name} already exists"})
        route = self.model(
            app=app,
            owner=app.owner,
            kind=kind,
            name=name,
            port=port,
            routable=app_settings.routable,
            procfile_type=procfile_type,
        )
        route.rules = route.default_rules
        if route.rules and not route.rules[0]["backendRefs"]:
            return Response(status=status.HTTP_400_BAD_REQUEST, data={
                "detail": "this route does not match services. please add service first."
            })
        route.save()
        return Response(status=status.HTTP_201_CREATED)

    def attach(self, request, *args, **kwargs):
        app = self.get_app()
        port = self.get_serializer().validate_port(request.data.get('port'))
        gateway_name = request.data['gateway']
        route = get_object_or_404(self.model, app=app, name=kwargs['name'])
        attached, msg = route.attach(gateway_name, port)
        if not attached:
            return Response(status=status.HTTP_400_BAD_REQUEST, data=msg)
        route.save()
        return Response(status=status.HTTP_204_NO_CONTENT)

    def detach(self, request, *args, **kwargs):
        app = self.get_app()
        port = self.get_serializer().validate_port(request.data.get('port'))
        gateway_name = request.data['gateway']
        route = get_object_or_404(self.model, app=app, name=kwargs['name'])
        detached, msg = route.detach(gateway_name, port)
        if not detached:
            return Response(status=status.HTTP_400_BAD_REQUEST, data=msg)
        route.save()
        return Response(status=status.HTTP_204_NO_CONTENT)

    def delete(self, request, *args, **kwargs):
        app = self.get_app()
        route = get_object_or_404(self.model, app=app, name=kwargs['name'])
        route.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class AdminPermsViewSet(BaseDryccViewSet):
    """RESTful views for sharing admin permissions with other users."""

    model = User
    serializer_class = serializers.AdminUserSerializer
    permission_classes = [permissions.IsAdmin]

    def get_queryset(self, **kwargs):
        self.check_object_permissions(self.request, self.request.user)
        return self.model.objects.filter(is_active=True, is_superuser=True)

    def create(self, request, **kwargs):
        user = get_object_or_404(self.model, username=request.data['username'])
        user.is_superuser = user.is_staff = True
        user.save(update_fields=['is_superuser', 'is_staff'])
        return Response(status=status.HTTP_201_CREATED)

    def destroy(self, request, **kwargs):
        user = get_object_or_404(self.model, username=kwargs['username'])
        user.is_superuser = user.is_staff = False
        user.save(update_fields=['is_superuser', 'is_staff'])
        return Response(status=status.HTTP_204_NO_CONTENT)


class UserView(BaseDryccViewSet):
    """A Viewset for interacting with User objects."""
    model = User
    serializer_class = serializers.UserSerializer
    permission_classes = [permissions.IsAdmin]

    def get_queryset(self):
        return self.model.objects.exclude(username='AnonymousUser')

    def enable(self, request, **kwargs):
        if request.user.username == kwargs['username']:
            return Response(status=status.HTTP_423_LOCKED)
        user = get_object_or_404(self.model, username=kwargs['username'])
        user.is_active = True
        user.save(update_fields=['is_active', ])
        return Response(status=status.HTTP_204_NO_CONTENT)

    def disable(self, request, **kwargs):
        if request.user.username == kwargs['username']:
            return Response(status=status.HTTP_423_LOCKED)
        user = get_object_or_404(self.model, username=kwargs['username'])
        user.is_active = False
        user.save(update_fields=['is_active', ])
        return Response(status=status.HTTP_204_NO_CONTENT)


class MetricView(BaseDryccViewSet):
    """Getting monitoring indicators from monitor database"""

    def _get_app(self):
        app = get_object_or_404(models.app.App, id=self.kwargs['id'])
        self.check_object_permissions(self.request, app)
        return app

    def _get_cpus(self, app_id, container_type, start, stop, every):
        avg_list, max_list = [], []
        for _, _, _, timestamp, max, avg in monitor.query_cpu_usage(
                app_id, container_type, start, stop, every):
            max_list.append((timestamp, max))
            avg_list.append((timestamp, avg))
        return {
            "max": max_list,
            "avg": avg_list,
        }

    def _get_memory(self, app_id, container_type, start, stop, every):
        max_list, avg_list = [], []
        for _, _, _, timestamp, max, avg in monitor.query_memory_usage(
                app_id, container_type, start, stop, every):
            max_list.append((timestamp, max))
            avg_list.append((timestamp, avg))
        return {
            "max": max_list,
            "avg": avg_list,
        }

    def _get_networks(self, app_id, container_type, start, stop, every):
        networks = []
        for _, _, timestamp, rx_bytes, tx_bytes in monitor.query_network_usage(
                app_id, container_type, start, stop, every):
            networks.append((timestamp, rx_bytes, tx_bytes))
        return networks

    @method_decorator(cache_page(settings.DRYCC_METRICS_EXPIRY))
    @method_decorator(vary_on_headers("Authorization"))
    def status(self, request, **kwargs):
        app_id = self._get_app().id
        data = serializers.MetricSerializer(data=self.request.query_params)
        if not data.is_valid():
            return Response(data.errors, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        start, stop, every = data.validated_data['start'], data.validated_data[
            'stop'], data.validated_data["every"]
        return Response({
            "id": app_id,
            "type": kwargs['type'],
            "count": monitor.query_container_count(app_id, kwargs['type'], start, stop),
            "status": {
                "cpus": self._get_cpus(
                    app_id, kwargs['type'], start, stop, every),
                "memory": self._get_memory(
                    app_id, kwargs['type'], start, stop, every),
                "networks": self._get_networks(
                    app_id, kwargs['type'], start, stop, every),
            }
        })

    @method_decorator(cache_page(settings.DRYCC_METRICS_EXPIRY))
    @method_decorator(vary_on_headers("Authorization"))
    def metric(self, request, **kwargs):
        app_id = self._get_app().id
        return StreamingHttpResponse(
            streaming_content=monitor.last_metrics(app_id)
        )
