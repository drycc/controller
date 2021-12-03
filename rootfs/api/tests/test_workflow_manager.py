# -*- coding: utf-8 -*-
"""
Unit tests for the Drycc api app.

Run the tests with "./manage.py test api"
"""
import base64
from django.core.cache import cache
from django.conf import settings
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
from api.tests import adapter, DryccTransactionTestCase
import requests_mock


@requests_mock.Mocker(real_http=True, adapter=adapter)
class ManagerTest(DryccTransactionTestCase):
    """Tests setting and updating config values"""

    fixtures = ['tests.json']

    def setUp(self):

        self.user = User.objects.get(username='autotest')
        self.token = Token.objects.get(user=self.user).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)
        self.app_id = self.create_app()
        self.user_id = 7
        # workflow manager token
        token = base64.b85encode(b"%s:%s" % (
            settings.WORKFLOW_MANAGER_ACCESS_KEY.encode("utf8"),
            settings.WORKFLOW_MANAGER_SECRET_KEY.encode("utf8"),
        )).decode("utf8")
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token)

    def tearDown(self):
        # Restore default tags to empty string
        settings.DRYCC_DEFAULT_CONFIG_TAGS = ''
        # make sure every test has a clean slate for k8s mocking
        cache.clear()

    def test_block(self, mock_requests):
        response = self.client.post(
            '/v2/manager/{}/{}/block/'.format("users", 7),
            data={'remark': 'Arrears blockade'},
        )
        self.assertEqual(response.status_code, 201)

    def test_unblock(self, mock_requests):
        response = self.client.post(
            '/v2/manager/{}/{}/block/'.format("users", 7),
            data={'remark': 'Arrears blockade'},
        )
        self.assertEqual(response.status_code, 201)
        response = self.client.delete(
            '/v2/manager/{}/{}/unblock/'.format("users", 7),
        )
        self.assertEqual(response.status_code, 204)
