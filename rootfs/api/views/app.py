"""
App and release views.
"""
import re
from django.conf import settings
from django.db import transaction
from django.db.models import Q
from rest_framework import filters, status
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.response import Response
from django.shortcuts import get_object_or_404

from api import models, serializers
from api.exceptions import AlreadyExists, DryccException
from api.viewsets import BaseAppViewSet


class AppFilterViewSet(BaseAppViewSet):
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


class AppViewSet(BaseAppViewSet):
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
            is_loopback = re.compile(r'^(localhost|127\.0\.0\.1)(:\d+)?/').match
            if is_loopback(image):
                raise DryccException("image must not use the loopback address")
        build.create_release(self.request.user)


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
