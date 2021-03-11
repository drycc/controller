import base64
import logging
import urllib
import requests
from django.conf import settings

from api.exceptions import Oauth2Exception

logger = logging.getLogger(__name__)


class OAuthBase(object):
    def __init__(self):
        self.client_id = settings.OAUTH2_CLIENT_ID
        self.client_key = settings.OAUTH2_CLIENT_SECRET
        self.api_url = settings.OAUTH2_ACCESS_API_URL
        self.access_token = None

    def oauth_get(self, url, data):
        request_url = '%s?%s' % (url, urllib.parse.urlencode(data))
        headers = {
            'Authorization': f'Bearer {self.access_token}'
        }
        try:
            response = requests.get(request_url, headers=headers, timeout=5)
        except requests.exceptions.ConnectionError as err:
            message = "There was a problem retrieving data from " \
                      "the oauth2 server. URL: {}, params: {}".format(url, data)
            logger.error(message)
            raise Oauth2Exception(message) from err
        return response

    def oauth_post(self, url, data):
        token = base64.b64encode(
            ('{}:{}').format(self.client_id, self.client_key).encode()).decode(
            encoding='UTF-8')
        headers = {
            'Authorization': f'Basic {token}'
        }
        try:
            response = requests.post(url, headers=headers, data=data, timeout=5)
        except requests.exceptions.ConnectionError as err:
            message = "There was a problem retrieving accecc_token from " \
                      "the oauth2 server. URL: {}, params: {}".format(url, data)
            logger.error(message)
            raise Oauth2Exception(message) from err
        return response

    def get_auth_url(self):
        pass

    def get_user_info(self):
        params = {'access_token': self.access_token}
        response = self.oauth_get(f'{self.api_url}/users', params)
        result = response.json()
        return result

    def get_email(self):
        response = self.oauth_get(f'{self.api_url}/users/emails')
        result = response.json()
        return result['email']
