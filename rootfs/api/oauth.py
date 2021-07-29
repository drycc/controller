from typing import Dict

import requests
from django.conf import settings
from authlib.integrations.requests_client import OAuth2Session


class OAuthManager(object):

    def __init__(self):
        self.client_id = settings.SOCIAL_AUTH_DRYCC_KEY
        self.client_secret = settings.SOCIAL_AUTH_DRYCC_SECRET
        self.token_url = settings.SOCIAL_AUTH_DRYCC_ACCESS_TOKEN_URL
        self.api_url = settings.SOCIAL_AUTH_DRYCC_ACCESS_API_URL
        self.client = OAuth2Session(self.client_id, self.client_secret)

    def get_user_by_token(self, token: str) -> Dict:
        response = requests.get(f'{self.api_url}/users', headers={
            'Authorization': f'Bearer {token}'
        })
        result = response.json()
        return result

    def get_email_by_token(self, token: str) -> Dict:
        response = requests.get(f'{self.api_url}/users/emails', headers={
            'Authorization': f'Bearer {token}'
        })
        result = response.json()
        return result
