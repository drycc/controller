from typing import Dict

import requests
from django.conf import settings
from django.core.cache import cache
from authlib.integrations.requests_client import OAuth2Session


class TokenManager(object):

    def __init__(self, timeout=60 * 10):
        self.timeout = timeout

    def set_state(self, key, state):
        cache.set("oidc_key_" + key, state, self.timeout)

    def set_token(self, state, token, username):
        cache.set("oidc_state_" + state, {"token": token, "username": username}, self.timeout)

    def get_token(self, key):
        state = cache.get("oidc_key_" + key, "")
        return cache.get("oidc_state_" + state, {})


class OAuthManager(object):

    def __init__(self):
        self.client_id = settings.SOCIAL_AUTH_DRYCC_KEY
        self.client_secret = settings.SOCIAL_AUTH_DRYCC_SECRET
        self.token_url = settings.SOCIAL_AUTH_DRYCC_ACCESS_TOKEN_URL
        self.api_url = settings.SOCIAL_AUTH_DRYCC_ACCESS_API_URL
        self.client = OAuth2Session(self.client_id, self.client_secret)

    def get_user_by_token(self, token: str) -> Dict:
        response = requests.get(f'{self.api_url}/user/info/', headers={
            'Authorization': f'Bearer {token}'
        })
        result = response.json()
        return result

    def get_email_by_token(self, token: str) -> Dict:
        response = requests.get(f'{self.api_url}/user/email/', headers={
            'Authorization': f'Bearer {token}'
        })
        result = response.json()
        return result
