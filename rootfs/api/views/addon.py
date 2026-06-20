"""
Addon views.
"""
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.exceptions import NotFound
from rest_framework.mixins import ListModelMixin, RetrieveModelMixin
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet

from api import models, serializers
from api.utils import get_scheduler, jsonpath
from api.views.app import AppFilterViewSet
from scheduler import KubeException


class AddonClassViewSet(ListModelMixin, RetrieveModelMixin, GenericViewSet):
    lookup_field = 'name'
    lookup_value_regex = r'[a-z0-9]([a-z0-9-]*[a-z0-9])?'
    serializer_class = serializers.AddonClassSerializer
    permission_classes = [IsAuthenticated]

    def filter_item(self, addonclass):
        """
        Remove plan fields not listed in spec.visiblePaths (end-user view).
        Entries in spec.visiblePaths are interpreted as dot-separated jsonpaths,
        so a nested field (e.g. ``defaults.imagePullPolicy``) may be exposed
        individually without revealing its siblings.
        """
        _MISSOBJ = object()
        spec = addonclass.get('spec', {})
        visible = spec.get('visiblePaths', ['name', 'description', 'allowCreate', 'allowUpdate'])
        plans = []
        for plan in spec.get('plans', []):
            filtered = {}
            for path in visible:
                value = jsonpath(plan, path, default=_MISSOBJ)
                if value is not _MISSOBJ:
                    jsonpath(filtered, path, action='set', value=value)
            plans.append(filtered)
        return {**addonclass, 'spec': {**spec, 'plans': plans}}

    def get_object(self):
        name = self.kwargs['name']
        scheduler = get_scheduler()
        try:
            response = scheduler.addonclasses.get(name, ignore_exception=False)
        except KubeException:
            raise NotFound(f"AddonClass '{name}' not found")
        return self.filter_item(response.json())

    def get_queryset(self):
        scheduler = get_scheduler()
        response = scheduler.addonclasses.get()
        return [self.filter_item(item) for item in response.json().get('items', [])]

    def list(self, request, *args, **kwargs):
        items = self.get_queryset()
        data = self.get_serializer(items, many=True).data
        return Response({'count': len(data), 'results': data}, status=status.HTTP_200_OK)

    def retrieve(self, request, *args, **kwargs):
        item = self.get_object()
        data = self.get_serializer(item).data
        return Response(data, status=status.HTTP_200_OK)


class AddonInstanceViewSet(AppFilterViewSet):
    """A viewset for addon instances scoped under an application."""
    model = models.addon.AddonInstance
    lookup_field = 'name'
    lookup_value_regex = r'[a-z0-9]([a-z0-9-]*[a-z0-9])?'
    serializer_class = serializers.AddonInstanceSerializer

    def get_object(self):
        return get_object_or_404(
            models.addon.AddonInstance, app__id=self.kwargs['id'],
            name=self.kwargs['name'])

    def upsert(self, request, *args, **kwargs):
        name = kwargs['name']
        app = self.get_app()
        instance = models.addon.AddonInstance.objects.filter(
            app=app, name=name).first()
        created = instance is None
        serializer = self.get_serializer(instance, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(app=app, name=name)
        http_status = (
            status.HTTP_201_CREATED if created else status.HTTP_200_OK)
        return Response(serializer.data, status=http_status)


class AddonConnectionViewSet(AppFilterViewSet):
    """A viewset for addon connection scoped under an application."""

    def get_object(self):
        app = self.get_app()
        return get_object_or_404(
            models.addon.AddonInstance, app=app, name=self.kwargs['name'])

    def retrieve(self, request, *args, **kwargs):
        data = self.get_object().get_conn()
        return Response(data, status=status.HTTP_200_OK)
