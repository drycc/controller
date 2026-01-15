import logging
from django.conf import settings
from django.core.cache import cache
from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy

from social_core.backends.open_id_connect import OpenIdConnectAuth
from rest_framework import exceptions


logger = logging.getLogger(__name__)
User = get_user_model()


class DryccOIDC(OpenIdConnectAuth):
    """Drycc Openid Connect authentication backend"""
    name = 'drycc'
    EXTRA_DATA = [
        ('id', 'id'),
        ('access_token', 'access_token'),
        ('refresh_token', 'refresh_token'),
        ('expires_in', 'expires_in'),
        ('token_type', 'token_type'),
        ('id_token', 'id_token'),
        ('scope', 'scope'),
    ]

    def get_user_data(self, access_token):
        """Loads user data from service"""
        response = self.get_json(
            self.userinfo_url(),
            headers={
                'authorization': 'Bearer ' + access_token
            },
        )
        return {
            'id': response.get('id'),
            'username': response.get('username'),
            'email': response.get('email') or '',
            'first_name': response.get('first_name'),
            'last_name': response.get('last_name'),
            'is_superuser': response.get('is_superuser'),
            'is_staff': response.get('is_staff'),
            'is_active': response.get('is_active'),
        }

    def refresh_token(self, refresh_token):
        # Get token URL from OIDC discovery if not already cached
        return self.get_json(
            self.access_token_url(),
            method='POST',
            data={
                'grant_type': 'refresh_token',
                'client_id': self.get_key_and_secret()[0],
                'refresh_token': refresh_token,
            },
        )


class OauthCacheManager(object):

    def __init__(self):
        self.drycc_oauth = DryccOIDC()

    def get_user(self, access_token):
        def _get_user(access_token):
            from api import serializers
            try:
                user_info = self.drycc_oauth.get_user_data(access_token)
                user, _ = serializers.UserSerializer.update_or_create(user_info)
                return user
            except Exception as e:
                logger.info(e)
                raise exceptions.AuthenticationFailed(gettext_lazy('Verify token fail.'))
        return cache.get_or_set(
            access_token, lambda: _get_user(access_token), settings.DRYCC_CACHE_USER_TIME)

    def set_state(self, key, state):
        cache.set("oidc_key_" + key, state, settings.DRYCC_CACHE_USER_TIME)

    def set_token(self, state, data):
        cache.set("oidc_state_" + state, data, settings.DRYCC_CACHE_USER_TIME)

    def get_token(self, key):
        state = cache.get("oidc_key_" + key, "")
        return cache.get("oidc_state_" + state, {})
