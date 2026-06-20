"""
Gateway and route views.
"""
from django.db import transaction
from django.shortcuts import get_object_or_404
from rest_framework import filters, status
from rest_framework.response import Response

from api import models, serializers
from api.views.app import AppFilterViewSet


class GatewayViewSet(AppFilterViewSet):
    """A viewset for interacting with Gateway objects."""
    model = models.gateway.Gateway
    filter_backends = [filters.SearchFilter]
    search_fields = ['^id', ]
    serializer_class = serializers.GatewaySerializer

    def get_object(self):
        return get_object_or_404(self.get_app().gateway_set, name=self.kwargs["name"])

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

    @transaction.atomic
    def upsert(self, request, **kwargs):
        name = kwargs["name"]
        route = self.get_app().route_set.filter(name=name).first()
        serializer = self.get_serializer(instance=route, data=request.data)
        serializer.is_valid(raise_exception=True)
        route = serializer.save(app=self.get_app(), name=name)
        route.save()
        return Response(self.get_serializer(route).data, status=status.HTTP_200_OK)
