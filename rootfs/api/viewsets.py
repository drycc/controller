from django.core.exceptions import ImproperlyConfigured
from rest_framework import viewsets, renderers
from rest_framework.permissions import IsAuthenticated

from api import permissions


class OwnerViewSet(viewsets.ModelViewSet):
    """
    A simple ViewSet for objects filtered by their 'owner' attribute.

    To use it, at minimum you'll need to provide the `serializer_class` attribute and
    the `model` attribute shortcut.
    """
    permission_classes = [IsAuthenticated, permissions.IsOwner]

    def get_queryset(self):
        return self.model.objects.filter(owner=self.request.user)

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)


class BaseAppViewSet(viewsets.ModelViewSet):
    """
    A ViewSet for the Workspace model, which filters workspaces by membership and role.
    """
    lookup_field = 'id'
    permission_classes = [IsAuthenticated, permissions.IsAppUser]
    renderer_classes = [renderers.JSONRenderer]

    def get_queryset(self):
        # Prefer direct workspace relation, then support app->workspace chain.
        if hasattr(self.model, 'workspace'):
            return self.model.objects.filter(
                workspace__workspacemember__user=self.request.user).distinct()
        elif hasattr(self.model, 'app'):
            return self.model.objects.filter(
                app__workspace__workspacemember__user=self.request.user).distinct()
        raise ImproperlyConfigured(
            f"{self.__class__.__name__} requires a model with a 'workspace' or 'app' field."
        )
