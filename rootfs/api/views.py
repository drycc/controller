"""
RESTful view classes for presenting Drycc API objects.
"""
import re
import uuid
import logging
import json
import ssl
import time
import zlib
import random
import aiohttp
import requests
import warnings

from urllib.parse import urljoin
from django.db import transaction
from django.db.models import Q
from django.core.cache import cache
from django.http import Http404, HttpResponse
from django.conf import settings
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404, redirect
from guardian.shortcuts import assign_perm, get_objects_for_user, \
    get_users_with_perms, get_user_perms, remove_perm
from django.views.generic import View
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
from django.views.decorators.vary import vary_on_headers
from rest_framework import renderers, status, filters
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet
from rest_framework.exceptions import PermissionDenied

from api import monitor, models, permissions, serializers, viewsets, authentication, __version__
from api.tasks import scale_app, restart_app, mount_app, downstream_model_owner, \
    delete_pod
from api.exceptions import AlreadyExists, ServiceUnavailable, DryccException

from django.views.decorators.cache import never_cache
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.views.decorators.csrf import csrf_exempt
from django.http.response import FileResponse, JsonResponse, StreamingHttpResponse
from channels.db import database_sync_to_async
from social_django.utils import psa
from social_django.views import _do_login
from social_core.utils import setting_name
from api import admissions, utils, filer
from api.backend import OauthCacheManager
from api.apps_extra.social_core.actions import do_auth, do_complete
from api.files.parsers import FilerUploadParser

User = get_user_model()
logger = logging.getLogger(__name__)
is_loopback = re.compile(r'^(localhost|127\.0\.0\.1)(:\d+)?/').match
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
        if 'key' in self.kwargs:
            oauth = oauth_cache_manager.get_token(self.kwargs['key'])
        else:
            try:
                oauth = json.loads(request.body.decode("utf8"))
            except json.decoder.JSONDecodeError:
                return HttpResponse(status=400)
        if oauth and 'access_token' in oauth:
            user = oauth_cache_manager.get_user(oauth['access_token'])
            alias = request.query_params.get('alias', '')
            token = models.base.Token(owner=user, alias=alias, oauth=oauth)
            token.save()
            return HttpResponse(json.dumps(
                {"uuid": str(token.uuid), "token": token.key, "username": user.username}))
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
        if settings.CERT_KEY == key:
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
    permission_classes = [IsAuthenticated, permissions.IsObjectUser]
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
        version = self.request.query_params.get('version', '').lower().strip('v')
        if re.search("^[0-9]+$", version):
            release = get_object_or_404(
                models.release.Release, app=self.get_app(), version=int(version))
        else:
            release = models.release.Release.latest(self.get_app())
        return getattr(release, self.model.__name__.lower())


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
            get_objects_for_user(
                self.request.user, f'api.{models.app.VIEW_APP_PERMISSION.codename}')
        instance = self.filter_queryset(queryset)
        page = self.paginate_queryset(instance)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(instance, many=True)
        return Response(serializer.data)

    def run(self, request, **kwargs):
        app = self.get_object()
        ptype = request.data.get('ptype', 'run')
        command = request.data.get('command', '').split()
        timeout = int(request.data.get('timeout', 3600))
        expires = int(request.data.get('expires', 3600))
        if expires == 0 or expires > settings.KUBERNETES_JOB_MAX_TTL_SECONDS_AFTER_FINISHED:
            expires = settings.KUBERNETES_JOB_MAX_TTL_SECONDS_AFTER_FINISHED
        if not command:
            raise DryccException('command is a required field, or it can be defined in Procfile')
        release = models.release.Release.latest(app)
        if release is None or release.build is None:
            raise DryccException('no build available, please deploy a release')
        volumes = request.data.get('volumes', None)
        if volumes:
            volumes = serializers.VolumeSerializer().validate_path(volumes)
        app.run(self.request.user, release.get_deploy_image(ptype),
                command=release.get_deploy_command(ptype), args=command, volumes=volumes,
                timeout=timeout, expires=expires)
        return Response(status=status.HTTP_204_NO_CONTENT)

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)

    @transaction.atomic
    def update(self, request, **kwargs):
        app = self.get_object()
        old_owner = app.owner

        if request.data.get('owner'):
            if self.request.user != app.owner and not self.request.user.is_superuser:
                return Response(status=status.HTTP_403_FORBIDDEN)
            new_owner = get_object_or_404(User, username=request.data['owner'])
            # ensure all downstream objects that are owned by this user and are part of this app
            # is also updated
            downstream_model_owner.delay(app, old_owner, new_owner)
        return Response(status=status.HTTP_200_OK)

    @transaction.atomic
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)


class BuildViewSet(ReleasableViewSet):
    """A viewset for interacting with Build objects."""
    model = models.build.Build
    serializer_class = serializers.BuildSerializer

    def post_save(self, build):
        for ptype in build.ptypes:
            image = build.get_image(ptype)
            if is_loopback(image):
                raise DryccException("image must not use the loopback address")
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

    def delete(self, request, **kwargs):
        values_refs = self.get_serializer().validate_values_refs(request.data.get('values_refs'))
        if not values_refs or not values_refs.values():
            raise DryccException("ptype or groups is required")

        config = self.model(app=self.get_app(), owner=self.request.user, values_refs={})
        old_values_refs = config.previous().values_refs.copy()
        for ptype, groups in values_refs.items():
            for group in old_values_refs.get(ptype, []):
                if group not in groups:
                    if ptype not in config.values_refs:
                        config.values_refs[ptype] = [group]
                    elif group not in config.values_refs[ptype]:
                        config.values_refs[ptype].append(group)
        config.save(ignore_update_fields=["values_refs"])

        self.post_save(config)
        return Response(status=status.HTTP_200_OK)

    def post_save(self, config):
        latest_release = models.release.Release.latest(self.get_app())
        try:
            release = latest_release.new(
                self.request.user, config=config, build=latest_release.build)
            if release.build and config.app.appsettings_set.latest().autodeploy:
                release.deploy(release.ptypes, False)
        except BaseException as e:
            config.delete()
            if isinstance(e, AlreadyExists):
                raise
            raise DryccException(str(e)) from e


class PodViewSet(AppResourceViewSet):
    model = models.app.App
    serializer_class = serializers.PodSerializer

    def list(self, *args, **kwargs):
        pods = self.get_app().list_pods(*args, **kwargs)
        data = self.get_serializer(pods, many=True).data
        # fake out pagination for now
        pagination = {'results': data, 'count': len(data)}
        return Response(pagination, status=status.HTTP_200_OK)

    def describe(self, *args, **kwargs):
        pod_name = kwargs["name"]
        data = self.get_app().describe_pod(pod_name)
        if len(data) == 0:
            raise DryccException("this process not found")
        # fake out pagination for now
        pagination = {'results': data, 'count': len(data)}
        return Response(pagination, status=status.HTTP_200_OK)

    def delete(self, request, **kwargs):
        pod_names = request.data.get("pod_ids")
        pod_names = pod_names.split(",")
        for pod_name in set(pod_names):
            delete_pod.delay(self.get_app(), **{"pod_name": pod_name})
        return Response(status=status.HTTP_200_OK)


class PtypeViewSet(AppResourceViewSet):
    model = models.app.App
    serializer_class = serializers.PtypeSerializer

    def list(self, *args, **kwargs):
        deploys = self.get_app().list_deployments(*args, **kwargs)
        data = self.get_serializer(deploys, many=True).data
        # fake out pagination for now
        pagination = {'results': data, 'count': len(data)}
        return Response(pagination, status=status.HTTP_200_OK)

    def describe(self, *args, **kwargs):
        deployment_name = kwargs["name"]
        data = self.get_app().describe_deployment(deployment_name)
        if len(data) == 0:
            raise DryccException("this procfile type not found")
        # fake out pagination for now
        pagination = {'results': data, 'count': len(data)}
        return Response(pagination, status=status.HTTP_200_OK)

    def restart(self, request, *args, **kwargs):
        app = self.get_app()
        ptypes = set(
            [ptype for ptype in request.data.get("ptypes", "").split(",") if ptype])
        ptypes = app.check_ptypes(ptypes)
        for ptype in set(ptypes):
            restart_app.delay(app, **{"type": ptype})
        return Response(status=status.HTTP_204_NO_CONTENT)

    def clean(self, request, *args, **kwargs):
        app = self.get_app()
        ptypes = set(
            [ptype for ptype in request.data.get("ptypes", "").split(",") if ptype])
        if not ptypes:
            raise DryccException("ptypes is a required field")
        latest_ptypes = [k for k, v in app.structure.items() if v != 0]
        not_allow = [ptype for ptype in ptypes if ptype in latest_ptypes]
        if not_allow:
            raise DryccException(f'ptype {",".join(not_allow)} should not garbage.')
        app.clean(ptypes=ptypes)
        return Response(status=status.HTTP_204_NO_CONTENT)

    def scale(self, request, **kwargs):
        app = self.get_app()
        scale_app.delay(app, request.user, request.data)
        return Response(status=status.HTTP_204_NO_CONTENT)


class EventViewSet(AppResourceViewSet):
    model = models.app.App
    serializer_class = serializers.EventSerializer

    def list(self, request, **kwargs):
        ptype = request.query_params.get("ptype", None)
        pod_name = request.query_params.get("pod_name", None)
        if not any([ptype, pod_name]):
            data = []
        else:
            ref_kind, ref_name = ("Pod", pod_name) if pod_name else \
                ("Deployment", ptype)
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
        ptype = self.get_serializer().validate_ptype(request.data.get(
            'ptype'))
        target_port = self.get_serializer().validate_target_port(request.data.get('target_port'))
        service = app.service_set.filter(ptype=ptype).first()
        if service:
            for item in service.ports:
                if item["port"] == port:
                    return Response(status=status.HTTP_400_BAD_REQUEST, data={"detail": "port is occupied"})  # noqa
            http_status = status.HTTP_204_NO_CONTENT
        else:
            service = self.model(owner=app.owner, app=app, ptype=ptype)
            http_status = status.HTTP_201_CREATED
        service.add_port(port, protocol, target_port)
        service.save()
        return Response(status=http_status)

    def delete(self, request, **kwargs):
        port = self.get_serializer().validate_port(request.data.get('port'))
        protocol = self.get_serializer().validate_protocol(request.data.get('protocol'))
        ptype = self.get_serializer().validate_ptype(
            request.data.get('ptype'))
        service = get_object_or_404(self.get_queryset(**kwargs), ptype=ptype)
        removed = service.remove_port(port, protocol)
        if len(service.ports) == 0:
            service.delete()
        elif removed:
            service.save()
        return Response(status=status.HTTP_204_NO_CONTENT)


class CertificateViewSet(AppResourceViewSet):
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

    def get_queryset(self, **kwargs):
        ptypes = self.request.query_params.get('ptypes', '').strip()
        queryset = super(ReleaseViewSet, self).get_queryset(**kwargs)
        if ptypes:
            queryset = queryset.filter(Q(
                deployed_ptypes__contains=[
                    ptype.lower() for ptype in re.split(r"\W+", ptypes)]))
        return queryset

    def deploy(self, request, **kwargs):
        """Deploy the latest release"""
        latest_release = self.get_app().release_set.latest()

        force_deploy = request.data.get("force", False)
        ptypes = set(
            [ptype for ptype in request.data.get("ptypes", "").split(",") if ptype])
        if not ptypes:
            ptypes = latest_release.ptypes
        else:
            invalid_ptypes = ptypes.difference(
                latest_release.ptypes + [d["name"] for d in self.get_app().list_deployments()])
            if len(invalid_ptypes) != 0:
                raise DryccException(f"process type {','.join(invalid_ptypes)} is not exists")
        latest_release.deploy(ptypes, force_deploy)
        return Response(status=status.HTTP_204_NO_CONTENT)

    def rollback(self, request, **kwargs):
        """
        Create a new release as a copy of the state of the compiled slug and config vars of a
        previous release.
        """
        latest_release = models.release.Release.latest(self.get_app())
        ptypes = set(
            [ptype for ptype in request.data.get("ptypes", "").split(",") if ptype])
        ptypes = latest_release.app.check_ptypes(ptypes)
        new_release = latest_release.rollback(
            request.user, ptypes, request.data.get('version', None))
        response = {'version': new_release.version}
        return Response(response, status=status.HTTP_201_CREATED)


class TLSViewSet(AppResourceViewSet):
    model = models.tls.TLS
    serializer_class = serializers.TLSSerializer

    def events(self, request, **kwargs):
        results = self.get_object().events()
        return Response({'results': results, 'count': len(results)})


class BaseHookViewSet(BaseDryccViewSet):
    permission_classes = [permissions.IsServiceToken]


class KeyHookViewSet(BaseHookViewSet):
    """API hook to create new :class:`~api.models.Push`"""
    model = models.key.Key
    serializer_class = serializers.KeySerializer

    def public_key(self, request, *args, **kwargs):
        fingerprint = kwargs['fingerprint'].strip()
        key = get_object_or_404(models.key.Key, fingerprint=fingerprint)

        queryset = models.app.App.objects.all() | \
            get_objects_for_user(
                self.request.user, f'api.{models.app.VIEW_APP_PERMISSION.codename}')
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
        usernames = [u.id for u in get_users_with_perms(app)
                     if u.has_perm(f"api.{models.app.VIEW_APP_PERMISSION.codename}", app)]

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
        has_permission, message = permissions.has_app_permission(request.user, app, request.method)
        if not has_permission:
            return Response(message, status=status.HTTP_403_FORBIDDEN)

        data = {request.user.username: []}
        keys = models.key.Key.objects \
                     .filter(owner__username=kwargs['username']) \
                     .values('public', 'fingerprint') \
                     .order_by('created')
        if not keys:
            return Response("No Keys match the given query.", status=status.HTTP_404_NOT_FOUND)

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
            return Response(message, status=status.HTTP_403_FORBIDDEN)
        request.data['app'] = app
        request.data['owner'] = self.user
        super(BuildHookViewSet, self).create(request, *args, **kwargs)
        # return the application databag
        response = {
            'release': {
                'version': models.release.Release.latest(app).version
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
        has_permission, message = permissions.has_app_permission(request.user, app, request.method)
        if not has_permission:
            return Response(message, status=status.HTTP_403_FORBIDDEN)
        config = models.release.Release.latest(app).config
        serializer = self.get_serializer(config)
        return Response(serializer.data, status=status.HTTP_200_OK)


class AppPermViewSet(AppResourceViewSet):
    """RESTful views for sharing apps with collaborators."""

    def get_app(self, request):
        app = get_object_or_404(models.app.App, id=self.kwargs['id'])
        if not permissions.IsOwnerOrAdmin().has_object_permission(request, self, app):
            raise PermissionDenied()
        return app

    def list(self, request, **kwargs):
        app = self.get_app(request)
        results = [
            {
                "app": app.id,
                "username": user.username,
                "permissions": [
                    models.app.app_permission_registry.get(codename).shortname
                    for codename in get_user_perms(user, app)
                ],
            }
            for user in get_users_with_perms(app)
        ]
        # fake out pagination for now
        pagination = {'results': results, 'count': len(results)}
        return Response(data=pagination)

    def create(self, request, **kwargs):
        app = self.get_app(request)
        username = request.data.get('username')
        shortnames = set([perm for perm in request.data.get("permissions", "").split(",") if perm])
        all_shortnames = models.app.app_permission_registry.shortnames
        if not shortnames or not shortnames.issubset(all_shortnames):
            msg = "The permissions field is required and has a value range of: {}".format(
                ",".join(all_shortnames)
            )
            return Response(status=status.HTTP_400_BAD_REQUEST, data=msg)
        user = get_object_or_404(User, username=username)
        for shortname in shortnames:
            permission = models.app.app_permission_registry.get(shortname)
            if permission:
                assign_perm(permission.codename, user, app)
        app.log("User {} was granted access to {}".format(user, app))
        return Response(status=status.HTTP_201_CREATED)

    def update(self, request, **kwargs):
        app = self.get_app(request)
        user = get_object_or_404(User, username=kwargs['username'])
        shortnames = set([perm for perm in request.data.get("permissions", "").split(",") if perm])
        all_shortnames = models.app.app_permission_registry.shortnames
        if not shortnames or not shortnames.issubset(all_shortnames):
            msg = "The permissions field is required and has a value range of: {}".format(
                ",".join(all_shortnames)
            )
            return Response(status=status.HTTP_400_BAD_REQUEST, data=msg)
        for shortname in shortnames.symmetric_difference([
                models.app.app_permission_registry.get(codename).shortname
                for codename in get_user_perms(user, app)]):
            permission = models.app.app_permission_registry.get(shortname)
            if permission:
                if shortname in shortnames:
                    assign_perm(permission.codename, user, app)
                else:
                    remove_perm(permission.codename, user, app)
        app.log("User {} was revoked access to {}".format(user, app))
        return Response(status=status.HTTP_204_NO_CONTENT)

    def destroy(self, request, **kwargs):
        app = self.get_app(request)
        username = kwargs['username']
        user = get_object_or_404(User, username=username)
        for codename in get_user_perms(user, app):
            remove_perm(codename, user, app)
        app.log("User {} was revoked access to {}".format(user, app))
        return Response(status=status.HTTP_204_NO_CONTENT)


class AppVolumesViewSet(AppResourceViewSet):
    """RESTful views for volumes apps with collaborators."""
    model = models.volume.Volume
    serializer_class = serializers.VolumeSerializer

    def get_object(self):
        return get_object_or_404(models.volume.Volume,
                                 app__id=self.kwargs['id'],
                                 name=self.kwargs['name'])

    def expand(self, request, **kwargs):
        size, volume = request.data['size'], self.get_object()
        if volume.type == "csi":
            if utils.unit_to_bytes(request.data['size']) < utils.unit_to_bytes(volume.size):
                raise DryccException('Shrink volume is not supported.')
            volume.size = size
            volume.save()
            serializer = self.get_serializer(volume, many=False)
            return Response(serializer.data)
        raise DryccException(f'{volume.type} volume is not support expand.')

    def destroy(self, request, **kwargs):
        volume = self.get_object()
        app = self.get_app()
        is_subset = set(volume.path.keys()).issubset(set(app.ptypes))
        if volume.path != {} and is_subset:
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
        ptypes = [_ for _ in path.keys() if _ not in volume.app.ptypes]
        if ptypes:
            raise DryccException("process type {} is not included in procfile".
                                 format(','.join(ptypes)))
        if set(path.items()).issubset(set(volume.path.items())):
            raise DryccException("mount path not changed")
        volume.check_path(path)

        app = self.get_app()
        mount_app.delay(app, self.request.user, volume, path)
        serializer = self.get_serializer(volume, many=False)
        return Response(serializer.data)


class AppFilerClientViewSet(AppResourceViewSet):
    """RESTful views for volumes apps with collaborators."""
    model = models.volume.Volume
    parser_classes = [FilerUploadParser]

    def get_client(self):
        volume = get_object_or_404(
            models.volume.Volume, app=self.get_app(), name=self.kwargs['name'])
        return filer.FilerClient(volume.app.id, volume, volume.app.scheduler)

    def list(self, request, **kwargs):
        path = request.query_params.get('path', '')
        client = self.get_client()
        response = client.get(path, params={"action": "list"})
        if response.status_code == 200:
            results = response.json()
            # fake out pagination for now
            pagination = {'results': results, 'count': len(results)}
            return Response(data=pagination)
        return Response(status=response.status_code, data=response.text)

    def retrieve(self, request, **kwargs):
        path = self.kwargs.get('path', '')
        client = self.get_client()
        chunk_size = 1024 * 1024 * 2
        response = client.get(path, stream=True, params={"action": "get"})
        return FileResponse(
            status=response.status_code,
            headers=response.headers,
            streaming_content=utils.iter_to_aiter(response.iter_content(chunk_size=chunk_size)),
        )

    def create(self, request, **kwargs):
        client = self.get_client()
        file = request.data['file']
        response = client.post(file.filepath, files=request.FILES)
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
            return Response("unknown action", status=status.HTTP_404_NOT_FOUND)


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
        ok, msg = route.check_rules(rules)
        if not ok:
            return Response(status=status.HTTP_400_BAD_REQUEST, data=msg)
        route.rules = rules
        route.save()
        return Response(status=status.HTTP_204_NO_CONTENT)

    def attach(self, request, *args, **kwargs):
        app = self.get_app()
        port = serializers.validate_port(request.data.get('port'))
        gateway_name = request.data['gateway']
        route = get_object_or_404(self.model, app=app, name=kwargs['name'])
        attached, msg = route.attach(gateway_name, port)
        if not attached:
            return Response(status=status.HTTP_400_BAD_REQUEST, data=msg)
        route.save()
        return Response(status=status.HTTP_204_NO_CONTENT)

    def detach(self, request, *args, **kwargs):
        app = self.get_app()
        port = serializers.validate_port(request.data.get('port'))
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

    @method_decorator(cache_page(settings.DRYCC_METRICS_EXPIRY))
    @method_decorator(vary_on_headers("Authorization"))
    def metric(self, request, **kwargs):
        warnings.warn(
            'this interface will be removed in the next version.', PendingDeprecationWarning)
        app_id = self._get_app().id
        return StreamingHttpResponse(
            streaming_content=monitor.last_metrics(app_id)
        )


class MetricsProxyView(View):
    cache = {}
    match_meta = staticmethod(
        re.compile(r'^(?:# (?:HELP|TYPE) )([a-zA-Z_][a-zA-Z0-9_:.-]*)').match)
    match_data = staticmethod(
        re.compile(r'^([a-zA-Z_][a-zA-Z0-9_:]*)(?:\{([^}]*)\})?\s+(\S+)').match)
    default_cache_value = (-1, -1)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if settings.K8S_API_VERIFY_TLS:
            ssl_context = ssl.create_default_context(
                cafile='/var/run/secrets/kubernetes.io/serviceaccount/ca.crt')
        else:
            ssl_context = ssl.create_default_context()
        self.connector = aiohttp.TCPConnector(ssl_context=ssl_context)

    async def sample(self, name, labels_str, value):
        if not labels_str or name not in settings.DRYCC_METRICS_CONFIG:
            return None
        fields = set(settings.DRYCC_METRICS_CONFIG[name])
        labels = {}
        for pair in labels_str.strip(" {}").split(','):
            k, v = pair.split('=', 1)
            if k in fields:
                labels[k] = v.strip(' "')
        app_id = labels.get("namespace", None)
        if not app_id:
            return None
        account_id, timeout = self.cache.get(app_id, self.default_cache_value)
        if (account_id < 0 and timeout < 0) or time.time() > timeout:
            if app := await models.app.App.objects.filter(id=app_id).afirst():
                account_id = app.owner_id
            else:
                account_id = -1
            self.cache[app_id] = (account_id, time.time() + random.randint(600, 1200))
        if account_id < 0:
            return None
        project_id = zlib.crc32(app_id.encode("utf-8"))
        labels.update({'vm_account_id': account_id, 'vm_project_id': project_id})
        return "%s{%s} %s\n" % (name, ",".join([f'{k}="{v}"' for k, v in labels.items()]), value)

    async def get(self, request):
        params = dict(request.GET)
        if not set(["host", "port"]).issubset(params.keys()):
            return HttpResponse(
                "Error: Required parameter 'host' or 'port' is missing or empty", status=400)
        host, port = params.pop('host')[0], params.pop('port')[0]
        scheme, path = params.pop('scheme', ['http'])[0], params.pop('path', ['/metrics'])[0]
        url = urljoin(f"{scheme}://{host}:{port}", path)
        headers = {"Authorization": request.META.get("HTTP_AUTHORIZATION", "")}

        async def stream_response():
            async with aiohttp.ClientSession(connector=self.connector) as session:
                async with session.get(url, params=params, headers=headers) as resp:
                    async for line_bytes in resp.content:
                        line = line_bytes.decode('utf-8', errors='ignore').strip(' \n')
                        if line.startswith('#') and (match := self.match_meta(line)):
                            if match.group(1) in settings.DRYCC_METRICS_CONFIG:
                                yield f"{line}\n"
                            continue
                        match = self.match_data(line)
                        if not match:
                            continue
                        name, labels_str, value = match.groups()
                        sample = await self.sample(name, labels_str, value)
                        if not sample:
                            continue
                        yield sample
        content_type = f"text/plain; version={__version__}"
        return StreamingHttpResponse(stream_response(), content_type=content_type)


@method_decorator(csrf_exempt, name='dispatch')
class BaseUserProxyView(View):
    timeout = aiohttp.ClientTimeout(total=30, connect=10, sock_read=15)
    permission = permissions.IsServiceToken()
    authentication = authentication.DryccAuthentication()
    authentication.ignore_authentication_failed = True

    async def authenticate(self, request, username):
        """
        Authenticate the user based on the provided request and username.
        Returns the user ID on success; returns None and an error message on failure.
        """
        if self.permission.has_permission(request, None):
            if username != "drycc":
                return None, {'error': 'Access denied', "status_code": 403}
            return -1, None
        auth = await database_sync_to_async(self.authentication.authenticate)(request)
        if not auth or len(auth) != 2:
            return None, {'error': 'Unauthorized', "status_code": 401}
        if auth[0].username != username:
            return None, {'error': 'Access denied', "status_code": 403}
        return auth[0].id, None


@method_decorator(csrf_exempt, name='dispatch')
class QuickwitProxyView(BaseUserProxyView):
    index_url_match = re.compile(r"^indexes/?$").match
    search_url_match = re.compile(r"^(?P<index>[a-zA-Z*][\w.*-，]{0,})/search/?$").match
    msearch_url_match = re.compile(r"^_elastic/_msearch/?$").match
    field_caps_url_match = re.compile(
        r"_elastic/(?P<index>[a-zA-Z*][\w.*-，]{0,})/_field_caps/?$").match

    async def proxy(self, request, username, path):
        user_id, message = await self.authenticate(request, username)
        if user_id is None and message is not None:
            return JsonResponse(message, status=message["status_code"])
        kwargs = {"request": request, "username": username}
        if self.index_url_match(path):
            func, kwargs["index"] = self.index, request.GET.get("index_id_patterns", "*")
        elif match := self.search_url_match(path):
            func, kwargs["index"] = self.query, match.group("index")
        elif self.msearch_url_match(path):
            func = self.msearch
        elif match := self.field_caps_url_match(path):
            func, kwargs["index"] = self.field_caps, match.group("index")
        else:
            return JsonResponse({'error': 'Not Found'}, status=404)
        return await func(**kwargs)

    async def index(self, request, username, index):
        base_url = settings.QUICKWIT_SEARCHER_URL
        index = await self.get_app_indexes(username, index)
        url, params = urljoin(base_url, "/api/v1/indexes"), dict(request.GET)
        params["index_id_patterns"] = index
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params, timeout=self.timeout) as response:
                    data, status = await response.json(), response.status
        except aiohttp.ClientError as e:
            data, status = {'error': f'quickwit connection failed: {str(e)}'}, 502
        return JsonResponse(data, status=status, safe=False)

    async def query(self, request, username, index):
        base_url = settings.QUICKWIT_SEARCHER_URL
        index = await self.get_app_indexes(username, index)
        url, params = urljoin(base_url, f"/api/v1/{index}/search"), dict(request.GET)
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params, timeout=self.timeout) as response:
                    data, status = await response.json(), response.status
        except aiohttp.ClientError as e:
            data, status = {'error': f'quickwit connection failed: {str(e)}'}, 502
        return JsonResponse(data, status=status)

    async def msearch(self, request, username):
        base_url = settings.QUICKWIT_SEARCHER_URL
        json_lines = request.body.decode('utf-8').strip().split('\n')
        for i, json_line in enumerate(json_lines):
            if i % 2 == 0:
                request_header = json.loads(json_line)
                request_header['index'] = ",".join(
                    [await self.get_app_indexes(username, i) for i in request_header['index']]
                ).split(",")
                json_lines[i] = json.dumps(request_header)
        url, params = urljoin(
            base_url, "/api/v1/_elastic/_msearch"), dict(request.GET)
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url, data="\n".join(json_lines), params=params, timeout=self.timeout
                ) as response:
                    data, status = await response.json(), response.status
        except aiohttp.ClientError as e:
            data, status = {'error': f'quickwit connection failed: {str(e)}'}, 502
        return JsonResponse(data, status=status)

    async def field_caps(self, request, username, index):
        base_url = settings.QUICKWIT_SEARCHER_URL
        index = await self.get_app_indexes(username, index)
        url, params = urljoin(
            base_url, f"/api/v1/_elastic/{index}/_field_caps"), dict(request.GET)
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params, timeout=self.timeout) as response:
                    data, status = await response.json(), response.status
        except aiohttp.ClientError as e:
            data, status = {'error': f'quickwit connection failed: {str(e)}'}, 502
        return JsonResponse(data, status=status)

    async def get_app_indexes(self, username, index):
        if username == "drycc":
            return index
        if "," in index:
            match = re.compile("|".join([f"^{i}$" for i in index.split(",")])).match
        else:
            match = re.compile(index).match
        app_indexes, log_index_prefix = [], settings.QUICKWIT_LOG_INDEX_PREFIX
        if hasattr(self, "app_ids"):
            app_ids = self.app_ids
        else:
            app_ids = [
                app.id async for app in models.app.App.objects.filter(owner__username=username)]
            setattr(self, "app_ids", app_ids)
        for app_id in app_ids:
            app_index = f"{log_index_prefix}{app_id}"
            if match(app_index):
                app_indexes.append(app_index)
        return ",".join(app_indexes)

    get = post = proxy


@method_decorator(csrf_exempt, name='dispatch')
class PrometheusProxyView(BaseUserProxyView):
    async def proxy(self, request, username, path):
        user_id, message = await self.authenticate(request, username)
        if user_id is None and message is not None:
            return JsonResponse(message, status=message["status_code"])
        if username == "drycc":
            path = f"/select/0/prometheus/{path}"
        else:
            path = f"/select/{user_id}/prometheus/{path}"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    urljoin(settings.DRYCC_VICTORIAMETRICS_URL, path),
                    data=dict(request.GET) if request.method == "GET" else dict(request.POST),
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    timeout=self.timeout
                ) as response:
                    data, status = await response.json(), response.status
        except aiohttp.ClientError as e:
            data, status = {'error': f'victoriametrics connection failed: {str(e)}'}, 502
        return JsonResponse(data, status=status)

    get = post = proxy
