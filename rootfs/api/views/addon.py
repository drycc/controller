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
from api.utils import get_scheduler
from api.views.app import AppFilterViewSet
from scheduler import KubeException


class AddonClassViewSet(ListModelMixin, RetrieveModelMixin, GenericViewSet):
    lookup_field = 'name'
    lookup_value_regex = r'[a-z0-9]([a-z0-9-]*[a-z0-9])?'
    serializer_class = serializers.AddonClassSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        name = self.kwargs['name']
        scheduler = get_scheduler()
        try:
            response = scheduler.addonclasses.get(name, ignore_exception=False)
        except KubeException:
            raise NotFound(f"AddonClass '{name}' not found")
        return response.json()

    def get_queryset(self):
        scheduler = get_scheduler()
        response = scheduler.addonclasses.get()
        return response.json().get('items', [])

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
        serializer = self.get_serializer(instance, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(app=app, name=name)
        return Response(serializer.data, status=status.HTTP_200_OK)
