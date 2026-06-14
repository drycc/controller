"""
Authentication views.
"""
import json
import uuid
import requests
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.http import HttpResponse, JsonResponse
from django.shortcuts import redirect
from django.views.decorators.csrf import csrf_exempt
from rest_framework.permissions import AllowAny
from rest_framework.viewsets import GenericViewSet

from api import models, serializers
from api.exceptions import DryccException
from api.apps_extra.social_core.backends import OauthCacheManager
from social_django.utils import psa
from social_django.views import _do_login


oauth_cache_manager = OauthCacheManager()
NAMESPACE = 'social'


@csrf_exempt
@psa('{0}:complete'.format(NAMESPACE))
def auth(request, backend):
    from api.apps_extra.social_core.actions import do_auth
    return do_auth(request.backend, redirect_name=REDIRECT_FIELD_NAME)


@csrf_exempt
@psa('{0}:complete'.format(NAMESPACE))
def complete(request, backend, *args, **kwargs):
    """Authentication complete view"""
    from api.apps_extra.social_core.actions import do_complete
    return do_complete(request.backend, _do_login, user=None,
                       redirect_name=REDIRECT_FIELD_NAME, request=request,
                       *args, **kwargs)


class AuthLoginView(GenericViewSet):
    permission_classes = (AllowAny, )
    serializer_class = serializers.AuthSerializer

    def login(self, request, *args, **kwargs):
        key = uuid.uuid4().hex
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        username = serializer.validated_data.get('username')
        password = serializer.validated_data.get('password')
        if username and password:
            return self._create_interactive_response(username, password, key)
        return self._create_browser_response(key)

    def _create_browser_response(self, key):
        uri = self.request.build_absolute_uri()
        return redirect(f"{uri[0:uri.find(self.request.path)]}/v2/login/drycc/?key={key}")

    def _create_interactive_response(self, username, password, key):
        # Get token endpoint from OIDC discovery
        token_url = oauth_cache_manager.drycc_oauth.access_token_url()
        client_id, client_secret = oauth_cache_manager.drycc_oauth.get_key_and_secret()
        response = requests.post(
            token_url,
            data={
                'grant_type': 'password',
                'client_id': client_id,
                'client_secret': client_secret,
                'username': username,
                'password': password,
            },
        )
        if response.status_code != 200:
            content_type = response.headers.get('Content-Type', '')
            if 'application/json' in content_type:
                try:
                    return JsonResponse(response.json(), status=response.status_code)
                except ValueError:
                    pass
            raise DryccException(response.text or "Authentication failed")
        state = uuid.uuid4().hex
        oauth_cache_manager.set_state(key, state)
        oauth_cache_manager.set_token(state, response.json())
        return HttpResponse(json.dumps({"key": key}))


class AuthTokenView(GenericViewSet):
    """Exchange OAuth code for Drycc API token."""
    permission_classes = (AllowAny, )

    def token(self, request, *args, **kwargs):
        if 'key' in self.kwargs:
            oauth = oauth_cache_manager.get_token(self.kwargs['key'])
        else:
            try:
                oauth = json.loads(request.body.decode("utf8"))
            except json.decoder.JSONDecodeError:
                return HttpResponse(status=400)
        if oauth and 'access_token' in oauth:
            user = oauth_cache_manager.get_user(oauth['access_token'])
            alias = request.query_params.get('alias', '')
            token = models.base.Token(owner=user, alias=alias, oauth=oauth)
            token.save()
            return HttpResponse(json.dumps(
                {"uuid": str(token.uuid), "token": token.key, "username": user.username}))
        return HttpResponse(status=404)
