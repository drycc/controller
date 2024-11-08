import json
import requests_mock

from django.core.cache import cache
from django.contrib.auth import get_user_model

from api.tests import adapter, DryccTransactionTestCase

User = get_user_model()


@requests_mock.Mocker(real_http=True, adapter=adapter)
class TestRegistry(DryccTransactionTestCase):
    """Tests setting and updating config values"""

    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = self.get_or_create_token(self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

    def tearDown(self):
        # make sure every test has a clean slate for k8s mocking
        cache.clear()

    def test_registry(self, mock_requests):
        """
        Test that registry information can be set on an application
        """
        app_id = self.create_app()

        # check default
        url = f'/v2/apps/{app_id}/config'
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertIn('registry', response.data)
        self.assertEqual(response.data['registry'], {})

        # set some registry information without PORT
        body = {'registry': {'web': {'username': 'bob'}}}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        registry1 = response.data

        # set required PORT
        body = {'values': [{"name": "PORT", "value": "80", "group": "global"}]}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        registry1 = response.data

        # no change error
        body = {'registry': {'web': {'username': 'bobb'}}}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        registry1 = response.data

        # check registry information again
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertIn('registry', response.data)
        registry = response.data['registry']['web']
        self.assertIn('username', registry)
        self.assertEqual(registry['username'], 'bobb')

        # set an additional value
        body = {'registry': {'web': {'password': 's3cur3pw1'}}}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        registry2 = response.data
        self.assertNotEqual(registry1['uuid'], registry2['uuid'])
        registry = response.data['registry']['web']
        self.assertIn('password', registry)
        self.assertEqual(registry['password'], 's3cur3pw1')
        self.assertIn('username', registry)
        self.assertEqual(registry['username'], 'bobb')

        # read the registry information again
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        registry3 = response.data
        self.assertEqual(registry2, registry3)
        registry = response.data['registry']['web']
        self.assertIn('password', registry)
        self.assertEqual(registry['password'], 's3cur3pw1')
        self.assertIn('username', registry)
        self.assertEqual(registry['username'], 'bobb')

        # unset a value
        body = {'registry': {'web': {'password': None}}}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        registry4 = response.data
        self.assertNotEqual(registry3['uuid'], registry4['uuid'])
        self.assertNotIn('password', json.dumps(response.data['registry']))

        # key error
        body = {'registry': {'web': {'pa$$w0rd': 'woop'}}}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 400, response.data)
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 400, response.data)

        # disallow put/patch/delete
        response = self.client.put(url)
        self.assertEqual(response.status_code, 405, response.data)
        response = self.client.patch(url)
        self.assertEqual(response.status_code, 405, response.data)

    def test_registry_deploy(self, mock_requests):
        """
        Test that registry information can be applied
        """
        app_id = self.create_app()

        # Set mandatory PORT
        response = self.client.post(
            f'/v2/apps/{app_id}/config',
            {'values': [{"name": "PORT", "value": "4999", "group": "global"}]}
        )

        # Set registry information
        body = {
            'registry': {
                'web': {
                    'username': 'bob',
                    'password': 's3cur3pw1'
                }
            }
        }
        response = self.client.post(
            f'/v2/apps/{app_id}/config',
            body
        )
        self.assertEqual(response.status_code, 201, response.data)
        self.assertIn('username', response.data['registry']['web'])
        self.assertIn('password', response.data['registry']['web'])
        self.assertEqual(response.data['registry']['web']['username'], 'bob')
        self.assertEqual(response.data['registry']['web']['password'], 's3cur3pw1')
