"""
User management views.
"""
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet

from api import serializers


User = get_user_model()


class UserManagementViewSet(GenericViewSet):
    serializer_class = serializers.UserSerializer

    def whoami(self, request, **kwargs):
        user = get_object_or_404(User, pk=self.request.user.pk)
        serializer = self.get_serializer(user, many=False)
        return Response(serializer.data)
