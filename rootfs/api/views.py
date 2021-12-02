"""
RESTful view classes for presenting Drycc API objects.
"""
import uuid
import logging
import json
from copy import deepcopy
from django.core.cache import cache
from django.http import Http404, HttpResponse
from django.conf import settings
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404, redirect
from guardian.shortcuts import assign_perm, get_objects_for_user, \
    get_users_with_perms, remove_perm
from django.views.generic import View
from rest_framework import renderers, status
from rest_framework.exceptions import PermissionDenied, NotFound
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet

from api import influxdb, models, permissions, serializers, viewsets
from api.tasks import scale_app, restart_app
from api.models import AlreadyExists, ServiceUnavailable, DryccException, \
    UnprocessableEntity

from django.views.decorators.cache import never_cache
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.views.decorators.csrf import csrf_exempt
from social_django.utils import psa
from social_django.views import _do_login
from social_core.utils import setting_name
from api.apps_extra.social_core.actions import do_auth, do_complete

logger = logging.getLogger(__name__)
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
    return do_complete(request.backend, _do_login, user=request.user,
                       redirect_name=REDIRECT_FIELD_NAME, request=request,
                       *args, **kwargs)


class AuthLoginView(GenericViewSet):

    permission_classes = (AllowAny, )

    def login(self, request, *args, **kwargs):
        def get_local_host(request):
            uri = request.build_absolute_uri()
            return uri[0:uri.find(request.path)]
        res = redirect(get_local_host(request) + "/v2/login/drycc/?key=" + uuid.uuid4().hex)
        return res


class AuthTokenView(GenericViewSet):

    permission_classes = (AllowAny, )

    def token(self, request, *args, **kwargs):
        state = cache.get("oidc_key_" + self.kwargs['key'], "")
        token = cache.get("oidc_state_" + state, {})
        if not token.get('token'):
            return HttpResponse(status=404)
        return HttpResponse(json.dumps(token))


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

    def block(self, request,  **kwargs):
        try:
            blocklist = models.Blocklist(
                id=kwargs['id'],
                type=models.Blocklist.get_type(kwargs["type"]),
                remark=request.data.get("remark")
            )
            apps = blocklist.related_apps
            [scale_app(app, app.owner, {key: 0 for key in app.structure.keys()}) for app in apps]
            blocklist.save()
        except ValueError as e:
            logger.info(e)
            raise DryccException("Unsupported block type: %s" % kwargs["type"])

    def unblock(self, request,  **kwargs):
        try:
            models.Blocklist.objects.filter(
                id=kwargs['id'],
                type=models.Blocklist.get_type(kwargs["type"])
            ).delete()
        except ValueError as e:
            logger.info(e)
            raise DryccException("Unsupported block type: %s" % kwargs["type"])


class AdmissionWebhookViewSet(GenericViewSet):

    permission_classes = (AllowAny, )

    def scale(self, request,  **kwargs):
        token = kwargs['token']
        data = json.loads(request.body.decode("utf8"))["request"]
        if settings.DRYCC_ADMISSION_WEBHOOK_TOKEN == token:
            allowed = True
            app_id = data["object"]["metadata"]["namespace"]
            app = models.App.objects.filter(id=app_id).first()
            replicas = data["object"]["spec"].get("replicas", 0)
            container_type = data["object"]["metadata"]["name"].replace(f"{app_id}-", "", 1)
            if app and app.structure.get(container_type) != replicas:  # sync replicas
                app.structure[container_type] = replicas
                super(models.App, app).save(update_fields=["structure", ])
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
        app = get_object_or_404(models.App, id=self.kwargs['id'])
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
        return getattr(self.get_app().release_set.filter(failed=False).latest(), self.model.__name__.lower())  # noqa


class AppViewSet(BaseDryccViewSet):
    """A viewset for interacting with App objects."""
    model = models.App
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

    def scale(self, request, **kwargs):
        scale_app.delay(self.get_object(), request.user, request.data)
        return Response(status=status.HTTP_204_NO_CONTENT)

    def logs(self, request, **kwargs):
        app = self.get_object()
        try:
            logs = app.logs(request.query_params.get('log_lines', str(settings.LOG_LINES)))
            return HttpResponse(logs, status=status.HTTP_200_OK, content_type='text/plain')
        except NotFound:
            return HttpResponse(status=status.HTTP_204_NO_CONTENT)
        except ServiceUnavailable:
            # TODO make 503
            return HttpResponse("Error accessing logs for {}".format(app.id),
                                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                content_type='text/plain')

    def run(self, request, **kwargs):
        app = self.get_object()
        if not request.data.get('command'):
            raise DryccException("command is a required field")
        volumes = request.data.get('volumes', None)
        if volumes:
            serializers.VolumeSerializer().validate_path(volumes)
        rc, output = app.run(self.request.user, request.data['command'], volumes)
        return Response({'exit_code': rc, 'output': str(output)})

    def update(self, request, **kwargs):
        app = self.get_object()
        old_owner = app.owner

        if request.data.get('owner'):
            if self.request.user != app.owner and not self.request.user.is_superuser:
                raise PermissionDenied()
            new_owner = get_object_or_404(User, username=request.data['owner'])
            app.owner = new_owner
            # ensure all downstream objects that are owned by this user and are part of this app
            # is also updated
            for downstream_model in [models.AppSettings, models.Build, models.Config,
                                     models.Domain, models.Release, models.TLS]:
                downstream_model.objects.filter(owner=old_owner, app=app).update(owner=new_owner)
        app.save()
        return Response(status=status.HTTP_200_OK)


class BuildViewSet(ReleasableViewSet):
    """A viewset for interacting with Build objects."""
    model = models.Build
    serializer_class = serializers.BuildSerializer

    def post_save(self, build):
        self.release = build.create(self.request.user)
        super(BuildViewSet, self).post_save(build)


class ConfigViewSet(ReleasableViewSet):
    """A viewset for interacting with Config objects."""
    model = models.Config
    serializer_class = serializers.ConfigSerializer

    def post_save(self, config):
        release = config.app.release_set.filter(failed=False).latest()
        latest_version = config.app.release_set.latest().version
        try:
            self.release = release.new(self.request.user, config=config, build=release.build)
            # It's possible to set config values before a build
            if self.release.build is not None:
                config.app.deploy(self.release)
        except Exception as e:
            if (not hasattr(self, 'release') and
                    config.app.release_set.latest().version == latest_version+1):
                self.release = config.app.release_set.latest()
            if hasattr(self, 'release'):
                self.release.failed = True
                self.release.summary = "{} deployed a config that failed".format(self.request.user)  # noqa
                # Get the exception that has occured
                self.release.exception = "error: {}".format(str(e))
                self.release.save()
            else:
                config.delete()
            if isinstance(e, AlreadyExists):
                raise
            raise DryccException(str(e)) from e


class PodViewSet(AppResourceViewSet):
    model = models.App
    serializer_class = serializers.PodSerializer

    def list(self, *args, **kwargs):
        pods = self.get_app().list_pods(*args, **kwargs)
        data = self.get_serializer(pods, many=True).data
        # fake out pagination for now
        pagination = {'results': data, 'count': len(data)}
        return Response(pagination, status=status.HTTP_200_OK)

    def restart(self, *args, **kwargs):
        if "name" in kwargs:  # a single pod uses sync
            pods = self.get_app().restart(**kwargs)
        else:  # multi pod uses async
            restart_app.delay(self.get_app(), **kwargs)
            pods = self.get_app().list_pods(**kwargs)
        data = self.get_serializer(pods, many=True).data
        # fake out pagination for now
        # pagination = {'results': data, 'count': len(data)}
        pagination = data
        return Response(pagination, status=status.HTTP_200_OK)


class AppSettingsViewSet(AppResourceViewSet):
    model = models.AppSettings
    serializer_class = serializers.AppSettingsSerializer


class AllowlistViewSet(AppResourceViewSet):
    model = models.AppSettings
    serializer_class = serializers.AppSettingsSerializer

    def list(self, *args, **kwargs):
        appSettings = self.get_app().appsettings_set.latest()
        data = {"addresses": appSettings.allowlist}
        return Response(data, status=status.HTTP_200_OK)

    def create(self, request, **kwargs):
        appSettings = self.get_app().appsettings_set.latest()
        addresses = self.get_serializer().validate_allowlist(request.data.get('addresses'))
        addresses = list(set(appSettings.allowlist) | set(addresses))
        new_appsettings = appSettings.new(self.request.user, allowlist=addresses)
        return Response({"addresses": new_appsettings.allowlist}, status=status.HTTP_201_CREATED)

    def delete(self, request, **kwargs):
        appSettings = self.get_app().appsettings_set.latest()
        addresses = self.get_serializer().validate_allowlist(request.data.get('addresses'))

        unfound_addresses = set(addresses) - set(appSettings.allowlist)
        if len(unfound_addresses) != 0:
            raise UnprocessableEntity('addresses {} does not exist in allowlist'.format(unfound_addresses))  # noqa
        addresses = list(set(appSettings.allowlist) - set(addresses))
        appSettings.new(self.request.user, allowlist=addresses)
        return Response(status=status.HTTP_204_NO_CONTENT)


class DomainViewSet(AppResourceViewSet):
    """A viewset for interacting with Domain objects."""
    model = models.Domain
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
        if "%s.%s" % (domain.app.id, settings.PLATFORM_DOMAIN) == domain.domain:
            return Response(status=status.HTTP_403_FORBIDDEN)
        domain.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class ServiceViewSet(AppResourceViewSet):
    """A viewset for interacting with Service objects."""
    model = models.Service
    serializer_class = serializers.ServiceSerializer

    def list(self, *args, **kwargs):
        services = self.get_app().service_set.all()
        data = [obj.as_dict() for obj in services]
        return Response({"services": data}, status=status.HTTP_200_OK)

    def create_or_update(self, request, **kwargs):
        pft = self.get_serializer().validate_procfile_type(request.data.get('procfile_type'))
        pp = self.get_serializer().validate_path_pattern(request.data.get('path_pattern'))
        app = self.get_app()
        svc = app.service_set.filter(procfile_type=pft).first()
        if svc:
            if svc.path_pattern == pp:
                return Response(status=status.HTTP_204_NO_CONTENT)
            else:
                svc.path_pattern = pp
                svc.save()
        else:
            svc = models.Service.objects.create(owner=app.owner, app=app,
                                                procfile_type=pft,
                                                path_pattern=pp)
        return Response(status=status.HTTP_201_CREATED)

    def delete(self, request, **kwargs):
        pft = self.get_serializer().validate_procfile_type(request.data.get('procfile_type'))
        qs = self.get_queryset(**kwargs)
        svc = get_object_or_404(qs, procfile_type=pft)
        svc.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class CertificateViewSet(BaseDryccViewSet):
    """A viewset for interacting with Certificate objects."""
    model = models.Certificate
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
    model = models.Key
    permission_classes = [IsAuthenticated, permissions.IsOwner]
    serializer_class = serializers.KeySerializer


class ReleaseViewSet(AppResourceViewSet):
    """A viewset for interacting with Release objects."""
    model = models.Release
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
        release = self.get_app().release_set.filter(failed=False).latest()
        new_release = release.rollback(request.user, request.data.get('version', None))
        response = {'version': new_release.version}
        return Response(response, status=status.HTTP_201_CREATED)


class TLSViewSet(AppResourceViewSet):
    model = models.TLS
    serializer_class = serializers.TLSSerializer


class BaseHookViewSet(BaseDryccViewSet):
    permission_classes = [permissions.HasBuilderAuth]


class KeyHookViewSet(BaseHookViewSet):
    """API hook to create new :class:`~api.models.Push`"""
    model = models.Key
    serializer_class = serializers.KeySerializer

    def public_key(self, request, *args, **kwargs):
        fingerprint = kwargs['fingerprint'].strip()
        key = get_object_or_404(models.Key, fingerprint=fingerprint)

        queryset = models.App.objects.all() | \
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
        app = get_object_or_404(models.App, id=kwargs['id'])

        perm_name = "api.use_app"
        usernames = [u.id for u in get_users_with_perms(app)
                     if u.has_perm(perm_name, app)]

        data = {}
        result = models.Key.objects \
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
        app = get_object_or_404(models.App, id=kwargs['id'])
        request.user = get_object_or_404(User, username=kwargs['username'])
        # check the user is authorized for this app
        has_permission, message = permissions.has_app_permission(request, app)
        if not has_permission:
            raise PermissionDenied(message)

        data = {request.user.username: []}
        keys = models.Key.objects \
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
    """API hook to create new :class:`~api.models.Build`"""
    model = models.Build
    serializer_class = serializers.BuildSerializer

    def create(self, request, *args, **kwargs):
        app = get_object_or_404(models.App, id=request.data['receive_repo'])
        self.user = request.user = get_object_or_404(User, username=request.data['receive_user'])
        # check the user is authorized for this app
        has_permission, message = permissions.has_app_permission(request, app)
        if not has_permission:
            raise PermissionDenied(message)
        request.data['app'] = app
        request.data['owner'] = self.user
        super(BuildHookViewSet, self).create(request, *args, **kwargs)
        # return the application databag
        response = {'release': {'version': app.release_set.filter(failed=False).latest().version}}
        return Response(response, status=status.HTTP_200_OK)

    def post_save(self, build):
        build.create(self.user)


class ConfigHookViewSet(BaseHookViewSet):
    """API hook to grab latest :class:`~api.models.Config`"""
    model = models.Config
    serializer_class = serializers.ConfigSerializer

    def create(self, request, *args, **kwargs):
        app = get_object_or_404(models.App, id=request.data['receive_repo'])
        request.user = get_object_or_404(User, username=request.data['receive_user'])
        # check the user is authorized for this app
        has_permission, message = permissions.has_app_permission(request, app)
        if not has_permission:
            raise PermissionDenied(message)
        config = app.release_set.filter(failed=False).latest().config
        serializer = self.get_serializer(config)
        return Response(serializer.data, status=status.HTTP_200_OK)


class AppPermsViewSet(BaseDryccViewSet):
    """RESTful views for sharing apps with collaborators."""

    model = models.App  # models class
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
        app = get_object_or_404(models.App, id=self.kwargs['id'])
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
    model = models.Volume
    serializer_class = serializers.VolumeSerializer

    def destroy(self, request, **kwargs):
        volume = get_object_or_404(models.Volume,
                                   app__id=self.kwargs['id'],
                                   name=self.kwargs['name'])
        volume.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class AppVolumeMountPathViewSet(ReleasableViewSet):
    serializer_class = serializers.VolumeSerializer

    def get_object(self):
        return get_object_or_404(models.Volume,
                                 app__id=self.kwargs['id'],
                                 name=self.kwargs['name'])

    def path(self, request, *args, **kwargs):
        new_path = request.data.get('path')
        if new_path is None:
            raise DryccException("path is a required field")
        obj = self.get_object()
        container_types = [_ for _ in new_path.keys()
                           if _ not in obj.app.types or
                           _ not in obj.app.structure.keys()]
        if container_types:
            raise DryccException("process type {} is not included in profile".
                                 format(','.join(container_types)))

        if set(new_path.items()).issubset(set(obj.path.items())):
            raise DryccException("mount path not changed")

        other_volumes = self.get_app().volume_set.exclude(name=obj.name)
        type_paths = {}  # {'type1':[path1,path2], tyep2:[path3,path4]}
        for _ in other_volumes:
            for k, v in _.path.items():
                if k not in type_paths:
                    type_paths[k] = [v]
                else:
                    type_paths[k].append(k)
        repeat_path = [v for k, v in new_path.items() if v in type_paths.get(k, [])]  # noqa
        if repeat_path:
            raise DryccException("path {} is used by another volume".
                                 format(','.join(repeat_path)))
        path = obj.path
        pre_path = deepcopy(path)
        # merge mount path
        # remove path keys if a null value is provided
        for key, value in new_path.items():
            if value is None:
                # error if unsetting non-existing key
                if key not in path:
                    raise UnprocessableEntity(
                        '{} does not exist under {}'.format(key, "volume"))  # noqa
                path.pop(key)
            else:
                path[key] = value
        obj.path = path  # after merge path
        obj.save()
        self.deploy(obj, pre_path)
        serializer = self.get_serializer(obj, many=False)
        return Response(serializer.data)

    def deploy(self, volume, pre_mount_path):
        app = self.get_app()
        latest_release = app.release_set.filter(failed=False).latest()
        latest_version = app.release_set.latest().version
        try:
            summary = "{user} changed volume mount for {volume}".\
                format(user=self.request.user, volume=volume.name)
            self.release = latest_release.new(
                self.request.user,
                config=latest_release.config,
                build=latest_release.build,
                summary=summary)
            # It's possible to mount volume before a build
            if self.release.build is not None:
                app.deploy(self.release)
        except Exception as e:
            if (not hasattr(self, 'release') and
                    app.release_set.latest().version == latest_version+1):
                self.release = app.release_set.latest()
            if hasattr(self, 'release'):
                self.release.failed = True
                self.release.summary = "{} deploy with a volume that failed".\
                    format(self.request.user)  # noqa
                # Get the exception that has occured
                self.release.exception = "error: {}".format(str(e))
                self.release.save()
            volume.path = pre_mount_path
            volume.save()
            if isinstance(e, AlreadyExists):
                raise
            raise DryccException(str(e)) from e


class AppResourcesViewSet(AppResourceViewSet):
    """RESTful views for resources apps with collaborators."""
    model = models.Resource
    serializer_class = serializers.ResourceSerializer


class AppSingleResourceViewSet(AppResourceViewSet):
    """RESTful views for resource apps with collaborators."""
    model = models.Resource
    serializer_class = serializers.ResourceSerializer

    def get_object(self):
        return get_object_or_404(models.Resource,
                                 app__id=self.kwargs['id'],
                                 name=self.kwargs['name'])

    def retrieve(self, request, *args, **kwargs):
        resource = self.get_object()
        resource.retrieve(request)
        return super(AppSingleResourceViewSet, self).retrieve(request, *args, **kwargs)  # noqa

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
    model = models.Resource
    serializer_class = serializers.ResourceSerializer

    def get_object(self):
        return get_object_or_404(models.Resource,
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
    """Getting monitoring indicators from influxdb"""

    def _get_app(self):
        app = get_object_or_404(models.App, id=self.kwargs['id'])
        self.check_object_permissions(self.request, app)
        return app

    def _get_cpus(self, app_id, container_type, start, stop, every):
        avg_total, max_total = [], []
        for record in influxdb.query_memory_usage(app_id, container_type, start, stop, every):
            if record["result"] == "mean":
                avg_total.append((record["_value"], record["timestamp"]))
            else:
                max_total.append((record["_value"], record["timestamp"]))
        return {
            "max_total": max_total,
            "avg_total": avg_total
        }

    def _get_memory(self, app_id, container_type, start, stop, every):
        max_total, avg_total = [], []
        for record in influxdb.query_memory_usage(app_id, container_type, start, stop, every):
            if record["result"] == "mean":
                avg_total.append((record["_value"], record["timestamp"]))
            else:
                max_total.append((record["_value"], record["timestamp"]))
        return {
            "max_total": max_total,
            "avg_total": avg_total
        }

    def _get_networks(self, app_id, container_type, start, stop, every):
        networks = []
        for record in influxdb.query_network_usage(app_id, container_type, start, stop, every):
            networks.append((record["rx_bytes"], record["tx_bytes"], record["timestamp"]))
        return networks

    def _get_container_count(self, app_id, container_type, start, stop):
        for record in influxdb.query_container_count([app_id, ], start, stop):
            if record["container_name"] == "%s-%s" % (app_id, container_type):
                return record["_value"]
        return 0

    def status(self, request, **kwargs):
        """
        {

            app_id: "django_t1",
            container_type: "web",
            container_count: 1
            cpus: {
                max_total: [(50000, 1611023853)],
                avg_total: [(50000, 1611023853)],
                timestamp: 1611023853
            },
            memory: {
                max_total: [(50000, 1611023853)],
                avg_total: [(50000, 1611023853)],
                timestamp: 1611023853
            },
            networks: [
                (10000, 50000, 1611023853)
            ],
        }
        """
        app_id, container_type = self._get_app().id, kwargs['container_type']

        data = serializers.MetricSerializer(data=self.request.query_params)
        if not data.is_valid():
            return Response(data.errors, status=422)
        start, stop, every = data.validated_data['start'], data.validated_data[
            'stop'], data.validated_data["every"]
        return Response({
            "app_id": app_id,
            "container_type": container_type,
            "container_count": self._get_container_count(
                app_id, container_type, start, stop),
            "cpu_usage_list": self._get_cpus(
                app_id, container_type, start, stop, every),
            "memory": self._get_memory(
                app_id, container_type, start, stop, every),
            "networks": self._get_networks(
                app_id, container_type, start, stop, every)
        })
