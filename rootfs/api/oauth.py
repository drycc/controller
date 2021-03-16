from typing import Dict

import requests
from django.conf import settings
from authlib.integrations.requests_client import OAuth2Session


class OAuthManager(object):
    def __enter__(self):
        return self

    def __init__(self):
        self.client_id = settings.OAUTH_CLIENT_ID
        self.client_secret = settings.OAUTH_CLIENT_SECRET
        self.token_url = settings.OAUTH_ACCESS_TOKEN_URL
        self.api_url = settings.OAUTH_ACCESS_API_URL
        self.client = OAuth2Session(self.client_id, self.client_secret)

    def fetch_token(self, username: str, password: str) -> Dict:
        response = self.client.fetch_token(self.token_url,
                                           username=username,
                                           password=password)
        return response

    def get_user(self) -> Dict:
        response = self.client.get(f'{self.api_url}/users')
        result = response.json()
        return result

    def get_email(self) -> str:
        response = self.client.get(f'{self.api_url}/users/emails')
        result = response.json()
        return result['email']

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

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.client.close()
