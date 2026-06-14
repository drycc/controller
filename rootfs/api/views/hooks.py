"""
Hook views for external integrations.
"""
from django.contrib.auth import get_user_model
from django.db.models import Q
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.response import Response

from api import models, serializers, permissions, authentication
from api.viewsets import BaseAppViewSet


User = get_user_model()


class BaseServiceViewSet(BaseAppViewSet):
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
            from api.tasks import dispatch_alert_message
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
