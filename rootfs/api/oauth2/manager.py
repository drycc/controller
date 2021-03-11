from django.conf import settings
from django.core.cache import cache

from api.oauth2 import OAuthBase


class OAuthManager(OAuthBase):

    def get_password_token(self, username, password):
        params = {
            'grant_type': 'password',
            'username': username,
            'password': password,
        }
        response = self.oauth_post(settings.OAUTH2_ACCESS_TOKEN_URL, params)
        result = response.json()
        self.access_token = result['access_token']
        cache.set('token_' + result['access_token'],
                  True,
                  int(result['expires_in'] - 60))
        return result


oauth_client = OAuthManager()
