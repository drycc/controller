# -*- coding: utf-8 -*-
"""
Unit tests for the Drycc api app.

Run the tests with "./manage.py test api"
"""
from django.contrib.auth import get_user_model
from api.models.base import Token
from api.tests import adapter, DryccTransactionTestCase
import requests_mock

User = get_user_model()


@requests_mock.Mocker(real_http=True, adapter=adapter)
class TokenTest(DryccTransactionTestCase):
    """Tests setting and updating config values"""

    fixtures = ['tests.json']

    def test_token(self, *args, **kwargs):
        user = User.objects.get(username='autotest')
        key1 = self.get_or_create_token(user)
        url = '/v2/tokens'
        response = self.client.get(url, HTTP_AUTHORIZATION='token {}'.format(key1))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['count'], 1)
        token = Token.objects.create(
            owner=user,
            alias="workflow-cli",
            oauth={
                "access_token": "test",
                "expires_in": 3600 * 24 * 7,
                "token_type": "Bearer",
                "scope": "openid",
                "refresh_token": "test",
            },
        )
        uuid, key2 = token.pk, token.key
        response = self.client.get(url, HTTP_AUTHORIZATION='token {}'.format(key2))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['count'], 2)
        self.assertEqual(
            [item["alias"] for item in response.json()["results"]], ['', 'workflow-cli'])

        response = self.client.delete(
            '%s/%s' % (url, uuid), HTTP_AUTHORIZATION='Token {}'.format(key2))
        self.assertEqual(response.status_code, 204)

        response = self.client.get(url, HTTP_AUTHORIZATION='token {}'.format(key1))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['count'], 1)

        response = self.client.get(url, HTTP_AUTHORIZATION='token {}'.format(key2))
        self.assertEqual(response.status_code, 401)
