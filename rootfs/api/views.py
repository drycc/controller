"""
RESTful view classes for presenting Drycc API objects.
"""
import re
import uuid
import asyncio
import logging
import json
import ssl
import time
import random
import secrets
import aiohttp
import requests
import warnings
from collections import namedtuple

from urllib.parse import urljoin
from django.db import transaction, connection, Error
from django.db.models import Q
from django.core.cache import cache
from django.http import Http404, HttpResponse
from django.conf import settings
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404, redirect, render
from django.views.generic import View
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
from django.views.decorators.vary import vary_on_headers
from channels.db import database_sync_to_async
from rest_framework import status, filters
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet, ModelViewSet, ReadOnlyModelViewSet
from rest_framework.exceptions import ValidationError, PermissionDenied
from rest_framework.renderers import JSONRenderer, TemplateHTMLRenderer

from api import monitor, models, permissions, serializers, viewsets, authentication, __version__
from api.tasks import scale_app, delete_pod, restart_app, mount_app, dispatch_alert_message

from api.exceptions import AlreadyExists, ServiceUnavailable, DryccException

from django.views.decorators.cache import never_cache
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.views.decorators.csrf import csrf_exempt
from django.http.response import JsonResponse, StreamingHttpResponse
from social_django.utils import psa
from social_django.views import _do_login
from social_core.utils import setting_name
from api import admissions, utils
from api.apps_extra.social_core.backends import OauthCacheManager
from api.apps_extra.social_core.actions import do_auth, do_complete


User = get_user_model()
logger = logging.getLogger(__name__)
is_loopback = re.compile(r'^(localhost|127\.0\.0\.1)(:\d+)?/').match
oauth_cache_manager = OauthCacheManager()
NAMESPACE = getattr(settings, setting_name('URL_NAMESPACE'), None) or 'social'


class ReadinessCheckView(View):
    """Simple readiness check view to determine DB connection and Migrations."""
    migrations_completed = False

    def get(self, request):
        try:
            with connection.cursor() as c:
                c.execute("SELECT 0")
            if not ReadinessCheckView.migrations_completed:
                from django.db.migrations.executor import MigrationExecutor
                executor = MigrationExecutor(connection)
                targets = executor.loader.graph.leaf_nodes()
                if executor.migration_plan(targets):
                    raise ServiceUnavailable("Migrations are not yet applied")
                ReadinessCheckView.migrations_completed = True
        except Error as e:
            raise ServiceUnavailable(f"Database health check failed: {e}") from e
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
        # Get token endpoint from OIDC discovery
        token_url = oauth_cache_manager.drycc_oauth.access_token_url()
        client_id, client_secret = oauth_cache_manager.drycc_oauth.get_key_and_secret()
        response = requests.post(
            token_url,
            data={
                'grant_type': 'password',
                'client_id': client_id,
                'client_secret': client_secret,
                'username': username,
                'password': password,
            },
        )
        if response.status_code != 200:
            content_type = response.headers.get('Content-Type', '')
            if 'application/json' in content_type:
                try:
                    return JsonResponse(response.json(), status=response.status_code)
                except ValueError:
                    pass
            raise DryccException(response.text or "Authentication failed")
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

    def whoami(self, request, **kwargs):
        user = get_object_or_404(User, pk=self.request.user.pk)
        serializer = self.get_serializer(user, many=False)
        return Response(serializer.data)


class AdmissionWebhookViewSet(GenericViewSet):

    admission_classes = (
        admissions.JobsStatusHandler,
        admissions.DeploymentsScaleHandler,
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


class WorkspaceViewSet(ModelViewSet):
    """
    ViewSet for Workspace model.
    """
    lookup_field = 'id'
    lookup_value_regex = r'[-_\w]+'
    serializer_class = serializers.WorkspaceSerializer
    permission_classes = [IsAuthenticated]

    def _require_admin(self, workspace, message):
        if not workspace.has_member(self.request.user, role='admin'):
            raise PermissionDenied(message)

    def get_queryset(self):
        return models.workspace.Workspace.objects.filter(
            workspacemember__user=self.request.user
        ).distinct()

    def perform_create(self, serializer):
        workspace = serializer.save()
        models.workspace.WorkspaceMember.objects.create(
            user=self.request.user, workspace=workspace, role='admin'
        )

    def get_object(self):
        """Override to get workspace by id instead of pk"""
        return get_object_or_404(self.get_queryset(), id=self.kwargs['id'])

    def update(self, request, *args, **kwargs):
        """Only admins can update workspaces"""
        workspace = self.get_object()
        self._require_admin(workspace, "Only workspace admins can update workspaces")
        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        """Only admins can delete workspaces"""
        workspace = self.get_object()
        self._require_admin(workspace, "Only workspace admins can delete workspaces")
        if models.workspace.WorkspaceMember.objects.filter(workspace=workspace).count() > 1:
            raise PermissionDenied("Cannot delete workspace with more than one member")
        return super().destroy(request, *args, **kwargs)


class WorkspaceMemberViewSet(ModelViewSet):
    """
    ViewSet for WorkspaceMember model.
    """
    serializer_class = serializers.WorkspaceMemberSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        workspace = get_object_or_404(models.workspace.Workspace, id=self.kwargs['id'])
        # Check if user has access to this workspace
        if workspace.has_member(self.request.user):
            return models.workspace.WorkspaceMember.objects.filter(workspace=workspace)
        return models.workspace.WorkspaceMember.objects.none()

    def get_object(self):
        """Override to get member by username and workspace id"""
        workspace = get_object_or_404(models.workspace.Workspace, id=self.kwargs['id'])
        return get_object_or_404(
            models.workspace.WorkspaceMember,
            workspace=workspace, user__username=self.kwargs['user']
        )

    @staticmethod
    def _only_member_workspace(member):
        return models.workspace.WorkspaceMember.objects.filter(
            workspace=member.workspace
        ).count() == 1

    def update(self, request, *args, **kwargs):
        """Update a member. Admins can update any member (role and alerts).
        Non-admins can only update their own alerts field."""
        member = self.get_object()
        is_admin = member.workspace.has_member(request.user, role='admin')
        is_only_member = self._only_member_workspace(member)

        # Only member cannot modify role
        if is_only_member and 'role' in request.data:
            raise PermissionDenied("Cannot modify role: workspace only has one member")

        # Non-admin users restrictions
        if not is_admin:
            # Cannot update other members
            if request.user != member.user:
                raise PermissionDenied("Only workspace admins can update other members")
            # Cannot modify own role
            if 'role' in request.data:
                raise PermissionDenied("Cannot modify your own role")

        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        """Delete a member. Admins can delete any member.
        Non-admins can only delete themselves (leave workspace)."""
        member = self.get_object()
        is_admin = member.workspace.has_member(request.user, role='admin')
        is_only_member = self._only_member_workspace(member)

        # Only member cannot delete self
        if is_only_member and request.user == member.user:
            raise PermissionDenied("Cannot delete: workspace only has one member")

        # Non-admin can delete self
        if request.user == member.user:
            return super().destroy(request, *args, **kwargs)

        # Admin can delete any member
        if is_admin:
            return super().destroy(request, *args, **kwargs)

        # Other cases forbidden
        raise PermissionDenied("Only workspace admins can remove other members")


class WorkspaceInvitationViewSet(ModelViewSet):
    """
    ViewSet for WorkspaceInvitation model.
    """
    serializer_class = serializers.WorkspaceInvitationSerializer

    def get_permissions(self):
        """
        Allow anyone to accept an invitation.
        Only authenticated users can create or list invitations.
        """
        if self.action == 'retrieve':
            return [AllowAny()]
        return super().get_permissions()

    def get_renderers(self):
        if self.action == 'retrieve':
            return [JSONRenderer(), TemplateHTMLRenderer()]
        return super().get_renderers()

    def get_queryset(self):
        workspace = get_object_or_404(models.workspace.Workspace, id=self.kwargs['id'])
        if workspace.has_member(self.request.user):
            return models.workspace.WorkspaceInvitation.objects.filter(
                workspace=workspace, accepted=False)
        return models.workspace.WorkspaceInvitation.objects.none()

    def get_object(self):
        """Override to get invitation by uid and workspace id"""
        return get_object_or_404(
            models.workspace.WorkspaceInvitation,
            workspace=get_object_or_404(models.workspace.Workspace, id=self.kwargs['id']),
            token=self.kwargs['uid'],
            accepted=False,
        )

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.accept()
        user_exists = User.objects.filter(email=instance.email).exists()
        data = {
            'workspace_id': instance.workspace.id,
            'user_exists': user_exists,
            'register_url': settings.DRYCC_REGISTER_URL,
        }
        if isinstance(request.accepted_renderer, TemplateHTMLRenderer):
            return render(request, 'workspace/workspace_invitation_accept.html', data)
        return Response(data)

    def perform_create(self, serializer):
        workspace = get_object_or_404(models.workspace.Workspace, id=self.kwargs['id'])
        if not workspace.has_member(self.request.user, role='admin'):
            raise PermissionDenied("Only workspace admins can create invitations")
        email = serializer.validated_data['email']
        user = User.objects.filter(email=email).first()
        if user and workspace.has_member(user):
            raise ValidationError("User is already a member of the workspace")
        invitation = models.workspace.WorkspaceInvitation.objects.filter(
            email=email, workspace=workspace, accepted=False
        ).first()
        if not invitation:
            models.workspace.WorkspaceInvitation.objects.filter(
                email=email, workspace=workspace, accepted=True
            ).delete()
            invitation = serializer.save(
                token=secrets.token_hex(64), inviter=self.request.user, workspace=workspace)
        if settings.EMAIL_HOST:
            invitation.send_email(self.request)
        else:
            invitation.accept()

    def destroy(self, request, *args, **kwargs):
        """Only admins can revoke invitations"""
        invitation = self.get_object()
        if not invitation.workspace.has_member(request.user, role='admin'):
            raise PermissionDenied("Only workspace admins can revoke invitations")
        return super().destroy(request, *args, **kwargs)


class TokenViewSet(viewsets.OwnerViewSet):
    """
    A viewset for interacting with Token objects.
    """
    http_method_names = ['get', 'delete', 'head', 'options']
    lookup_value_regex = r'[-_\w]+'
    serializer_class = serializers.TokenSerializer

    def get_queryset(self):
        return models.base.Token.objects.filter(owner=self.request.user)

    def destroy(self, *args, **kwargs):
        key = self.get_object().key
        response = super().destroy(self, *args, **kwargs)
        cache.delete(key)
        return response


class AppFilterViewSet(viewsets.BaseAppViewSet):
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
        return super().create(request, **kwargs)


class ReleasableViewSet(AppFilterViewSet):
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


class AppViewSet(viewsets.BaseAppViewSet):
    """A viewset for interacting with App objects."""
    model = models.app.App
    lookup_value_regex = settings.APP_URL_REGEX
    filter_backends = [filters.SearchFilter]
    search_fields = ['^id', ]
    serializer_class = serializers.AppSerializer

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        workspace = request.query_params.get('workspace')
        if workspace:
            workspace_obj = get_object_or_404(models.workspace.Workspace, id=workspace)
            if not workspace_obj.has_member(request.user):
                raise PermissionDenied(f"You are not a member of workspace '{workspace_obj.id}'")
            queryset = queryset.filter(workspace=workspace_obj)
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
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

    def perform_create(self, serializer):
        workspace = serializer.validated_data['workspace']
        self.check_object_permissions(self.request, workspace)
        serializer.save()

    def update(self, request, *args, **kwargs):
        app = self.get_object()
        if not app.workspace.has_member(request.user, role='admin'):
            raise PermissionDenied("you must be an admin of the current workspace")
        workspace = request.data.get('workspace', '')
        if not workspace:
            raise ValidationError("workspace is required")
        app.workspace = get_object_or_404(models.workspace.Workspace, id=workspace)
        app.save()
        return Response(status=status.HTTP_204_NO_CONTENT)

    @transaction.atomic
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)


class BuildViewSet(ReleasableViewSet):
    """A viewset for interacting with Build objects."""
    model = models.build.Build
    serializer_class = serializers.BuildSerializer

    def perform_create(self, serializer):
        build = serializer.save()
        for ptype in build.ptypes:
            image = build.get_image(ptype)
            if is_loopback(image):
                raise DryccException("image must not use the loopback address")
        build.create_release(self.request.user)


class LimitSpecViewSet(ReadOnlyModelViewSet):
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


class LimitPlanViewSet(ReadOnlyModelViewSet):
    """A viewset for interacting with Limit objects."""
    lookup_field = 'id'
    lookup_value_regex = r'[-.\w]+'
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

    def create(self, request, **kwargs):
        if self.request.query_params.get('merge', 'true').lower() == 'true':
            return super().create(request, **kwargs)
        values = self.get_serializer().validate_values(request.data.get('values'))
        config = self.model(app=self.get_app(), values=values)
        old_config = config.previous()
        if old_config and old_config.values:
            replace_ptypes = {v['ptype'] for v in config.values if 'ptype' in v}
            replace_groups = {v['group'] for v in config.values if 'group' in v}
            config.merge_field("values", old_config, replace_ptypes, replace_groups)
        config.save(ignore_update_fields=["values"])
        self.post_save(config)
        data = self.get_serializer(config).data
        headers = self.get_success_headers(data)
        return Response(data, status=status.HTTP_201_CREATED, headers=headers)

    def perform_create(self, serializer):
        config = serializer.save()
        self.post_save(config)

    def destroy(self, request, **kwargs):
        values_refs = self.get_serializer().validate_values_refs(
            request.data.get('values_refs', {}))
        if not values_refs or not values_refs.values():
            raise DryccException("ptype or groups is required")

        config = self.model(app=self.get_app(), values_refs={})
        previous = config.previous()
        old_values_refs = previous.values_refs.copy() if previous else {}
        for ptype, old_groups in old_values_refs.items():
            groups_to_delete = values_refs.get(ptype, [])
            for group in old_groups:
                if group not in groups_to_delete:
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
            build = latest_release.build.merge(config) if latest_release.build else None
            release = latest_release.new(self.request.user, config=config, build=build)
            if release.build and config.app.appsettings_set.latest().autodeploy:
                release.deploy(release.ptypes, False)
        except BaseException as e:
            config.delete()
            if isinstance(e, AlreadyExists):
                raise
            raise DryccException(str(e)) from e


class PodViewSet(AppFilterViewSet):
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

    def destroy(self, request, **kwargs):
        pod_names = request.data.get("pod_ids")
        pod_names = pod_names.split(",")
        for pod_name in set(pod_names):
            delete_pod.delay(self.get_app(), **{"pod_name": pod_name})
        return Response(status=status.HTTP_200_OK)


class PtypeViewSet(AppFilterViewSet):
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


class EventViewSet(AppFilterViewSet):
    model = models.app.App
    serializer_class = serializers.EventSerializer

    def list(self, request, **kwargs):
        ptype = request.query_params.get("ptype", None)
        pod_name = request.query_params.get("pod_name", None)
        if not any([ptype, pod_name]):
            data = []
        else:
            ref_kind, ref_name = "Deployment", f"{self.get_app().id}-{ptype}"
            if pod_name:
                ref_kind, ref_name = "Pod", pod_name
            events = self.get_app().list_events(ref_kind, ref_name)
            data = self.get_serializer(events, many=True).data
        # fake out pagination for now
        pagination = {'results': data, 'count': len(data)}
        return Response(pagination, status=status.HTTP_200_OK)


class AppSettingsViewSet(AppFilterViewSet):
    model = models.appsettings.AppSettings
    serializer_class = serializers.AppSettingsSerializer


class DomainViewSet(AppFilterViewSet):
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


class ServiceViewSet(AppFilterViewSet):
    """A viewset for interacting with Service objects."""
    model = models.service.Service
    serializer_class = serializers.ServiceSerializer

    def list(self, *args, **kwargs):
        services = self.get_app().service_set.all()
        data = [obj.as_dict() for obj in services]
        return Response({"services": data}, status=status.HTTP_200_OK)

    def upsert(self, request, **kwargs):
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
            service = self.model(app=app, ptype=ptype)
            http_status = status.HTTP_201_CREATED
        service.add_port(port, protocol, target_port)
        service.save()
        return Response(status=http_status)

    def destroy(self, request, **kwargs):
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


class CertificateViewSet(AppFilterViewSet):
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


class KeyViewSet(viewsets.OwnerViewSet):
    """A viewset for interacting with Key objects."""
    http_method_names = ['get', 'post', 'delete', 'head', 'options']
    lookup_field = 'id'
    lookup_value_regex = r'.+'
    model = models.key.Key
    serializer_class = serializers.KeySerializer


class ReleaseViewSet(AppFilterViewSet):
    """A viewset for interacting with Release objects."""
    model = models.release.Release
    serializer_class = serializers.ReleaseSerializer

    def get_object(self, **kwargs):
        """Get release by version always"""
        qs = self.get_queryset(**kwargs)
        return get_object_or_404(qs, version=self.kwargs['version'])

    def get_queryset(self, **kwargs):
        ptypes = self.request.query_params.get('ptypes', '').strip()
        queryset = super().get_queryset(**kwargs)
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


class TLSViewSet(AppFilterViewSet):
    model = models.tls.TLS
    serializer_class = serializers.TLSSerializer

    def events(self, request, **kwargs):
        results = self.get_object().events()
        return Response({'results': results, 'count': len(results)})


class BaseServiceViewSet(viewsets.BaseAppViewSet):
    authentication_classes = (authentication.AnonymousAuthentication, )
    permission_classes = [permissions.HasOAuthScope]
    required_oauth_scopes = ['controller:hook']


class KeyHookViewSet(BaseServiceViewSet):
    """API hook to create new :class:`~api.models.Push`"""
    model = models.key.Key
    serializer_class = serializers.KeySerializer

    def public_key(self, request, *args, **kwargs):
        fingerprint = kwargs['fingerprint'].strip()
        key = get_object_or_404(models.key.Key, fingerprint=fingerprint)
        queryset = models.app.App.objects.filter(
            workspace__workspacemember__user=key.owner
        ).distinct()
        data = {
            'username': key.owner.username,
            'apps': [item.id for item in self.filter_queryset(queryset)],
        }

        return Response(data, status=status.HTTP_200_OK)

    def app(self, request, *args, **kwargs):
        app = get_object_or_404(models.app.App, id=kwargs['id'])
        usernames = app.workspace.workspacemember_set.values_list('user__username', flat=True)
        data = {}
        result = models.key.Key.objects \
                       .filter(owner__username__in=usernames) \
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
        if not permissions.IsAppUser().has_object_permission(request, self, app):
            return Response(status=status.HTTP_403_FORBIDDEN)

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


class BuildHookViewSet(BaseServiceViewSet):
    """API hook to create new :class:`~api.models.build.Build`"""
    model = models.build.Build
    serializer_class = serializers.BuildSerializer

    def create(self, request, *args, **kwargs):
        app = get_object_or_404(models.app.App, id=request.data['receive_repo'])
        self.user = request.user = get_object_or_404(User, username=request.data['receive_user'])
        # check the user is authorized for this app
        if not permissions.IsAppUser().has_object_permission(request, self, app):
            return Response(status=status.HTTP_403_FORBIDDEN)
        request.data['app'] = app
        super().create(request, *args, **kwargs)
        # return the application databag
        response = {
            'release': {
                'version': models.release.Release.latest(app).version
            }
        }
        return Response(response, status=status.HTTP_200_OK)

    def perform_create(self, serializer):
        build = serializer.save()
        build.create_release(self.user)


class ConfigHookViewSet(BaseServiceViewSet):
    """API hook to grab latest :class:`~api.models.config.Config`"""
    model = models.config.Config
    serializer_class = serializers.ConfigSerializer

    def create(self, request, *args, **kwargs):
        app = get_object_or_404(models.app.App, id=request.data['receive_repo'])
        request.user = get_object_or_404(User, username=request.data['receive_user'])
        # check the user is authorized for this app
        if not permissions.IsAppUser().has_object_permission(request, self, app):
            return Response(status=status.HTTP_403_FORBIDDEN)
        config = models.release.Release.latest(app).config
        serializer = self.get_serializer(config)
        return Response(serializer.data, status=status.HTTP_200_OK)


class AlertsHookViewSet(BaseServiceViewSet):
    """API hook to ingest alert events and dispatch passport messages."""
    required_oauth_scopes = ['controller:alerts']

    def create(self, request, *args, **kwargs):
        payload = request.data or {}
        workspace = payload.pop('workspace', '')
        if not workspace:
            return Response({"detail": "workspace is required"},
                            status=status.HTTP_400_BAD_REQUEST)
        usernames = self._collect_usernames(workspace)
        if usernames:
            for alert in payload.get("alerts") or []:
                dispatch_alert_message.delay(usernames, alert)
        return Response(status=status.HTTP_204_NO_CONTENT)

    @staticmethod
    def _collect_usernames(workspace):
        if workspace == "drycc":
            qs = User.objects.filter(Q(is_staff=True) | Q(is_superuser=True))
        else:
            qs = User.objects.filter(
                workspacemember__workspace__id=workspace,
                workspacemember__alerts=True,
            )
        return list(qs.values_list("username", flat=True).distinct())


class AppVolumesViewSet(AppFilterViewSet):
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


class GatewayViewSet(AppFilterViewSet):
    """A viewset for interacting with Gateway objects."""
    model = models.gateway.Gateway
    filter_backends = [filters.SearchFilter]
    search_fields = ['^id', ]
    serializer_class = serializers.GatewaySerializer

    def get_object(self):
        return get_object_or_404(self.get_app().gateway_set, name=self.kwargs["name"])

    def create(self, request, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        gateway = serializer.save(app=self.get_app())
        gateway.save()
        return Response(self.get_serializer(gateway).data, status=status.HTTP_201_CREATED)

    def upsert(self, request, **kwargs):
        name = kwargs["name"]
        gateway = self.get_app().gateway_set.filter(name=name).first()
        serializer = self.get_serializer(instance=gateway, data=request.data)
        serializer.is_valid(raise_exception=True)
        if not serializer.validated_data["ports"]:
            if gateway.pk:
                gateway.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)

        gateway = serializer.save(app=self.get_app(), name=name)
        gateway.save()
        return Response(self.get_serializer(gateway).data, status=status.HTTP_200_OK)


class RouteViewSet(AppFilterViewSet):
    """A viewset for interacting with Route objects."""
    model = models.gateway.Route
    filter_backends = [filters.SearchFilter]
    search_fields = ['^id', ]
    serializer_class = serializers.RouteSerializer

    def get_object(self):
        return get_object_or_404(self.get_app().route_set, name=self.kwargs["name"])

    def create(self, request, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        route = serializer.save(app=self.get_app())
        route.save()
        return Response(self.get_serializer(route).data, status=status.HTTP_201_CREATED)

    @transaction.atomic
    def upsert(self, request, **kwargs):
        name = kwargs["name"]
        route = self.get_app().route_set.filter(name=name).first()
        serializer = self.get_serializer(instance=route, data=request.data)
        serializer.is_valid(raise_exception=True)
        route = serializer.save(app=self.get_app(), name=name)
        route.save()
        return Response(self.get_serializer(route).data, status=status.HTTP_200_OK)


class MetricView(AppFilterViewSet):
    """Getting monitoring indicators from monitor database"""

    @method_decorator(cache_page(settings.DRYCC_METRICS_EXPIRY))
    @method_decorator(vary_on_headers("Authorization"))
    def metric(self, request, **kwargs):
        warnings.warn(
            'this interface will be removed in the next version.', PendingDeprecationWarning)
        app_id = self.get_app().id
        return StreamingHttpResponse(
            streaming_content=monitor.last_metrics(app_id)
        )


class MetricsProxyView(View):
    cache = {}
    cache_lock = asyncio.Lock()
    match_meta = staticmethod(
        re.compile(r'^(?:# (?:HELP|TYPE) )([a-zA-Z_][a-zA-Z0-9_:.-]*)').match)
    match_data = staticmethod(
        re.compile(r'^([a-zA-Z_][a-zA-Z0-9_:]*)(?:\{([^}]*)\})?\s+(\S+)').match)

    vm_tenant_cls = namedtuple('VMTenant', ['account_id', 'project_id'])
    default_cache_value = (None, -1)

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
            if '=' not in pair:
                continue
            k, v = pair.split('=', 1)
            if k in fields:
                labels[k] = v.strip(' "')
        app_id = labels.get("namespace", labels.get(settings.DRYCC_METRICS_CONFIG[name][0]))
        if not app_id:
            return None
        async with self.cache_lock:
            tenant, timeout = self.cache.get(app_id, self.default_cache_value)
            if tenant is None or time.time() > timeout:
                app = await models.app.App.objects.select_related(
                    'workspace').filter(id=app_id).afirst()
                if app:
                    tenant = self.vm_tenant_cls(app.workspace.uid, app.uid)
                else:
                    tenant = None
                self.cache[app_id] = (
                    tenant, time.time() + random.randint(600, 1200))
        if tenant is None:
            return None
        labels.update({'vm_account_id': tenant.account_id, 'vm_project_id': tenant.project_id})
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
class QuickwitProxyView(viewsets.BaseServiceView):
    timeout = aiohttp.ClientTimeout(total=30, connect=10, sock_read=15)
    required_oauth_scopes = ['controller:logs']

    index_url_match = re.compile(r"^indexes/?$").match
    search_url_match = re.compile(r"^(?P<index>[a-zA-Z*][\w.*-，]{0,})/search/?$").match
    msearch_url_match = re.compile(r"^_elastic/_msearch/?$").match
    field_caps_url_match = re.compile(
        r"_elastic/(?P<index>[a-zA-Z*][\w.*-，]{0,})/_field_caps/?$").match

    async def proxy(self, request, workspace, path):
        kwargs = {"request": request, "workspace": workspace}
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

    async def index(self, request, workspace, index):
        base_url = settings.QUICKWIT_SEARCHER_URL
        index = await self.get_app_indexes(workspace, index)
        url, params = urljoin(base_url, "/api/v1/indexes"), dict(request.GET)
        params["index_id_patterns"] = index
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params, timeout=self.timeout) as response:
                    data, status = await response.json(), response.status
        except aiohttp.ClientError as e:
            data, status = {'error': f'quickwit connection failed: {str(e)}'}, 502
        return JsonResponse(data, status=status, safe=False)

    async def query(self, request, workspace, index):
        base_url = settings.QUICKWIT_SEARCHER_URL
        index = await self.get_app_indexes(workspace, index)
        url, params = urljoin(base_url, f"/api/v1/{index}/search"), dict(request.GET)
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params, timeout=self.timeout) as response:
                    data, status = await response.json(), response.status
        except aiohttp.ClientError as e:
            data, status = {'error': f'quickwit connection failed: {str(e)}'}, 502
        return JsonResponse(data, status=status)

    async def msearch(self, request, workspace):
        base_url = settings.QUICKWIT_SEARCHER_URL
        json_lines = request.body.decode('utf-8').strip().split('\n')
        for i, json_line in enumerate(json_lines):
            if i % 2 == 0:
                request_header = json.loads(json_line)
                request_header['index'] = ",".join(
                    [await self.get_app_indexes(workspace, i) for i in request_header['index']]
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

    async def field_caps(self, request, workspace, index):
        base_url = settings.QUICKWIT_SEARCHER_URL
        index = await self.get_app_indexes(workspace, index)
        url, params = urljoin(
            base_url, f"/api/v1/_elastic/{index}/_field_caps"), dict(request.GET)
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params, timeout=self.timeout) as response:
                    data, status = await response.json(), response.status
        except aiohttp.ClientError as e:
            data, status = {'error': f'quickwit connection failed: {str(e)}'}, 502
        return JsonResponse(data, status=status)

    async def get_app_indexes(self, workspace, index):
        if workspace == "drycc":
            return index
        if "," in index:
            match = re.compile("|".join([f"^{i}$" for i in index.split(",")])).match
        else:
            match = re.compile(f"^{index}$").match
        log_index_prefix = settings.QUICKWIT_LOG_INDEX_PREFIX
        cache_key = f"quickwit:app_ids:{workspace}"
        app_ids = await cache.aget(cache_key)
        if app_ids is None:
            app_ids = [
                app.id async for app in models.app.App.objects.filter(
                    workspace__id=workspace).only('id').distinct()]
            await cache.aset(cache_key, app_ids, timeout=300)
        app_indexes = []
        for app_id in app_ids:
            app_index = f"{log_index_prefix}{app_id}"
            if match(app_index):
                app_indexes.append(app_index)
        return ",".join(app_indexes)

    get = post = proxy


@method_decorator(csrf_exempt, name='dispatch')
class PrometheusProxyView(viewsets.BaseServiceView):
    timeout = aiohttp.ClientTimeout(total=30, connect=10, sock_read=15)
    required_oauth_scopes = ['controller:metrics']

    async def proxy(self, request, workspace, path):
        data = dict(request.GET) if request.method == "GET" else dict(request.POST)
        if workspace == "drycc":
            workspace_uid = 0
        else:
            workspace_obj = await database_sync_to_async(get_object_or_404)(
                models.workspace.Workspace, id=workspace)
            workspace_uid = workspace_obj.uid
        data['extra_filters[]'] = '{vm_account_id="%s"}' % workspace_uid
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{settings.DRYCC_VICTORIAMETRICS_URL.rstrip("/")}/{path}",
                    data=data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    timeout=self.timeout
                ) as response:
                    data, status = await response.json(), response.status
        except aiohttp.ClientError as e:
            data, status = {'error': f'victoriametrics connection failed: {str(e)}'}, 502
        return JsonResponse(data, status=status)

    get = post = proxy
