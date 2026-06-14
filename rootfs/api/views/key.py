"""
Key views.
"""
from api import models, serializers
from api.viewsets import OwnerViewSet


class KeyViewSet(OwnerViewSet):
    """A viewset for interacting with Key objects."""
    http_method_names = ['get', 'post', 'delete', 'head', 'options']
    lookup_field = 'id'
    lookup_value_regex = r'.+'
    model = models.key.Key
    serializer_class = serializers.KeySerializer
