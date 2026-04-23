# -*- coding: utf-8 -*-
"""
Unit tests for the Drycc api app.

Run the tests with "./manage.py test api"
"""
from django.core.cache import cache
from django.contrib.auth import get_user_model
from api.tests import adapter, DryccTransactionTestCase
import requests_mock

User = get_user_model()


@requests_mock.Mocker(real_http=True, adapter=adapter)
class BlocklistTest(DryccTransactionTestCase):
    """Tests setting and updating config values"""

    fixtures = ['tests.json']

    def setUp(self):
        from unittest.mock import patch
        self.patcher = patch('api.apps_extra.social_core.backends.OauthCacheManager.get_user')
        self.mock_get_user = self.patcher.start()
        self.mock_get_user.return_value = User.objects.get(username='autotest')

        self.user = User.objects.get(username='autotest')
        self.token = self.get_or_create_token(self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)
        self.app_id = self.create_app()
        self.user_id = 7
        # workflow manager token
        self.client.credentials(HTTP_AUTHORIZATION='Bearer mock_oauth_token')

    def tearDown(self):
        self.patcher.stop()

        # make sure every test has a clean slate for k8s mocking
        cache.clear()

    def test_block(self, mock_requests):
        response = self.client.post(
            '/v2/blocklists/',
            data={'id': self.app_id, 'type': 1, 'remark': 'Arrears blockade'},
        )
        self.assertEqual(response.status_code, 201)

    def test_unblock(self, mock_requests):
        response = self.client.post(
            '/v2/blocklists/',
            data={'id': self.app_id, 'type': 1, 'remark': 'Arrears blockade'},
        )
        self.assertEqual(response.status_code, 201)
        response = self.client.delete(
            '/v2/blocklists/app/{}/'.format(self.app_id),
        )
        self.assertEqual(response.status_code, 204)

    def test_retrieve(self, mock_requests):
        response = self.client.post(
            '/v2/blocklists/',
            data={'id': self.app_id, 'type': 1, 'remark': 'Arrears blockade'},
        )
        self.assertEqual(response.status_code, 201)
        response = self.client.get(
            '/v2/blocklists/app/{}/'.format(self.app_id),
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['id'], self.app_id)
        self.assertEqual(response.data['type'], 1)
