"""
Token views.
"""
from django.core.cache import cache

from api import models, serializers
from api.viewsets import OwnerViewSet


class TokenViewSet(OwnerViewSet):
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
