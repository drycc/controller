"""
Limit views.
"""
import re
from django.db.models import Q
from rest_framework.viewsets import ReadOnlyModelViewSet
from django.shortcuts import get_object_or_404

from api import models, serializers


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
