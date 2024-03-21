# -*- coding: utf-8 -*-
"""
Unit tests for the Drycc api app.

Run the tests with "./manage.py test api"
"""
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.conf import settings
from rest_framework.authtoken.models import Token
from api.tests import adapter, DryccTransactionTestCase
from api.exceptions import DryccException
import requests_mock

User = get_user_model()


@requests_mock.Mocker(real_http=True, adapter=adapter)
class ResourceTest(DryccTransactionTestCase):
    """Tests setting and updating config values"""

    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = Token.objects.get(user=self.user).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)
        self.app_id = self.create_app()

    def tearDown(self):
        # Restore default tags to empty string
        settings.DRYCC_DEFAULT_CONFIG_TAGS = ''
        # make sure every test has a clean slate for k8s mocking
        cache.clear()

    def test_resources_create(self, mock_requests):
        """Test that the serialized response contains only relevant data."""
        app_id = self.create_app()

        response = self.client.post(
            '/v2/apps/{}/resources'.format(app_id),
            data={'name': 'mysql', 'plan': 'mysql:5.6'}
        )
        self.assertEqual(response.status_code, 201, response.data)

        for key in response.data:
            self.assertIn(key,
                          ['uuid', 'owner', 'created', 'updated', 'app', 'plan',
                           'options', 'data', 'status', 'binding', 'name'])

        expected = {
            'owner': self.user.username,
            'app': app_id,
            'name': 'mysql',
            'plan': 'mysql:5.6'
        }
        self.assertEqual(response.data, expected | response.data)

    def test_resources_list(self, mock_requests):
        """
        Test that list resources from a app
        """
        # create
        app_id = self.create_app()
        data = [
            {'name': 'mysql', 'plan': 'mysql:5.6'}
        ]
        for _ in data:
            self.client.post('/v2/apps/{}/resources'.format(app_id), data=_)
        # Fetch
        url = '/v2/apps/{app_id}/resources'.format(app_id=app_id)
        response = self.client.get(url)
        expected = [res['name'] for res in response.data['results']]
        self.assertEqual(sorted([_['name'] for _ in data]), sorted(expected))

    def test_resource_get(self, mock_requests):
        """
        Test that resource is get detail from a app
        """
        # create
        app_id = self.create_app()
        data = {'name': 'mysql', 'plan': 'mysql:5.6'}
        self.client.post('/v2/apps/{}/resources/'.format(app_id), data=data)
        # Get
        url = '/v2/apps/{app_id}/resources/{name}/'.format(app_id=app_id,
                                                           name='mysql')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_resource_delete(self, mock_requests):
        """
        Test that resource is delete from a app
        """
        # create
        app_id = self.create_app()
        data = [
            {'name': 'mysql', 'plan': 'mysql:5.6'}
        ]
        for _ in data:
            self.client.post('/v2/apps/{}/resources'.format(app_id), data=_)

        # Delete
        url = '/v2/apps/{app_id}/resources/{name}'.format(app_id=app_id,
                                                          name='mysql')
        response = self.client.delete(url)
        self.assertEqual(response.status_code, 204)

    def test_resource_bind(self, mock_requests):
        # create
        app_id = self.create_app()
        data = {'name': 'mysql', 'plan': 'mysql:5.6'}
        self.client.post('/v2/apps/{}/resources'.format(app_id), data=data)
        # bind
        url = '/v2/apps/{app_id}/resources/mysql/binding/'.format(app_id=app_id)
        data = {"bind_action": "bind"}
        self.client.patch(url, data=data)
        self.assertRaises(
            DryccException,
            msg='the resource instance is not ready'
        )

    def test_resource_unbind(self, mock_requests):
        # create
        app_id = self.create_app()
        data = {'name': 'mysql', 'plan': 'mysql:5.6'}
        self.client.post('/v2/apps/{}/resources'.format(app_id), data=data)
        # unbind
        url = '/v2/apps/{app_id}/resources/mysql/binding/'.format(app_id=app_id)
        data = {"bind_action": "unbind"}
        self.client.patch(url, data=data)
        # expected = response.data['path']
        self.assertRaises(
            DryccException,
            msg='the resource instance is not binding'
        )

    def call_command(self, *args, **kwargs):
        from io import StringIO
        from django.core.management import call_command
        out = StringIO()
        call_command(
            "measure_resources",
            *args,
            stdout=out,
            stderr=StringIO(),
            **kwargs,
        )
        return out.getvalue()

    def test_measure_resources(self, *args, **kwargs):
        # create
        app_id = self.create_app()
        data = [
            {'name': 'mysql', 'plan': 'mysql:5.6'}
        ]
        for _ in data:
            self.client.post('/v2/apps/{}/resources'.format(app_id), data=_)
        out = self.call_command()
        self.assertIn(out, "done\n")

    def test_services(self, *args, **kwargs):
        # Get
        url = '/v2/resources/services/'
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)

    def test_plans(self, *args, **kwargs):
        # Get
        url = '/v2/resources/services/mysql/plans/'
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
