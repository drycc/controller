from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist

from api import serializers
from api.oauth import OAuthManager


class DryccOauthBackend(object):

    # The Django auth backend API
    def authenticate(self, request, username=None, password=None, **kwargs):
        if username is None:
            return None

        with OAuthManager() as client:
            client.fetch_token(username, password)
            user_info = client.get_user()
            user_info['username'] = username
            user_info['password'] = password
            if not user_info.get('email'):
                user_info['email'] = client.get_email()
            user = serializers.UserSerializer.update_or_create(user_info)
        return user

    def get_user(self, user_id):
        user = None
        try:
            user = get_user_model().objects.get(pk=user_id)
        except ObjectDoesNotExist:
            pass
        return user
