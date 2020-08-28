# -*- coding: utf-8 -*-
"""
Unit tests for the Drycc api app.

Run the tests with "./manage.py test api"
"""
from django.contrib.auth.models import User
from django.core.cache import cache
from django.conf import settings
from rest_framework.authtoken.models import Token
from api.tests import adapter, DryccTransactionTestCase
import requests_mock


@requests_mock.Mocker(real_http=True, adapter=adapter)
class VolumeTest(DryccTransactionTestCase):
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

    def test_volumecreate(self, mock_requests):
        """Test that the serialized response contains only relevant data."""
        app_id = self.create_app()

        response = self.client.post(
            '/v2/apps/{}/volumes'.format(app_id),
            data={'name': 'myvolume', 'size': '500M'}
        )
        self.assertEqual(response.status_code, 201, response.data)

        for key in response.data:
            self.assertIn(key,
                          ['uuid', 'owner', 'created', 'updated', 'app', 'name',
                           'size', 'path'])

        expected = {
            'owner': self.user.username,
            'app': app_id,
            'name': 'myvolume',
            'size': '500M'
        }
        self.assertDictContainsSubset(expected, response.data)

    def test_volume_list_unmount(self, mock_requests):
        """
        Test that volume is auto-created for a new app and that
        volume can be updated using a PATCH
        """
        # create
        app_id = self.create_app()
        data = [
            {'name': 'myvolume1', 'size': '500M'},
            {'name': 'myvolume2', 'size': '500M'}
        ]
        for _ in data:
            self.client.post('/v2/apps/{}/volumes'.format(app_id), data=_)
        # Fetch
        url = '/v2/apps/{app_id}/volumes'.format(app_id=app_id)
        response = self.client.get(url)
        expected = [res['name'] for res in response.data['results']]
        self.assertEqual(sorted([_['name'] for _ in data]), sorted(expected))

    def test_volume_delete(self, mock_requests):
        """
        Test that volume is delete for a new app and that
        volume can be updated using a PATCH
        """
        # create
        app_id = self.create_app()
        data = [
            {'name': 'myvolume1', 'size': '500M'},
            {'name': 'myvolume2', 'size': '500M'}
        ]
        for _ in data:
            self.client.post('/v2/apps/{}/volumes'.format(app_id), data=_)

        # Delete
        url = '/v2/apps/{app_id}/volumes/{volume}'.format(app_id=app_id,
                                                          volume='myvolume1')
        response = self.client.delete(url)
        self.assertEqual(response.status_code, 204)

        # Fetch
        url = '/v2/apps/{app_id}/volumes'.format(app_id=app_id)
        response = self.client.get(url)
        expected = [res['name'] for res in response.data['results']]
        self.assertEqual(
            sorted([_['name'] for _ in data if _['name'] != 'myvolume1']),
            sorted(expected))  # noqa

    def test_volume_mount(self, mock_requests):
        # create
        app_id = self.create_app()
        data = [
            {'name': 'myvolume1', 'size': '500M'}
        ]
        for _ in data:
            self.client.post('/v2/apps/{}/volumes'.format(app_id), data=_)

        self.build_deploy(app_id)
        # mount
        url = '/v2/apps/{app_id}/volumes/myvolume1/path'.format(app_id=app_id)
        mount_path = {"path": {"web": "/data/web1"}}
        response = self.client.patch(url, data=mount_path)
        expected = response.data['path']
        self.assertEqual(mount_path['path'], expected)

    def test_volume_unmount(self, mock_requests):
        # create
        app_id = self.create_app()
        data = [
            {'name': 'myvolume1', 'size': '500M'}
        ]
        for _ in data:
            self.client.post('/v2/apps/{}/volumes'.format(app_id), data=_)

        # Fetch
        url = '/v2/apps/{app_id}/volumes'.format(app_id=app_id)
        response = self.client.get(url)
        expected = [res['path'] for res in response.data['results']]
        self.assertEqual({}, expected[0])

        self.build_deploy(app_id)
        # mount
        url = '/v2/apps/{app_id}/volumes/myvolume1/path'.format(app_id=app_id)
        mount_path = {"path": {"web": "/data/web1"}}
        response = self.client.patch(url, data=mount_path)
        expected = response.data['path']
        self.assertEqual(mount_path['path'], expected)

        # unmount
        url = '/v2/apps/{app_id}/volumes/myvolume1/path'.format(app_id=app_id)
        mount_path = {"path": {"web": None}}
        response = self.client.patch(url, data=mount_path)
        expected = response.data['path']
        self.assertEqual({}, expected)

    def build_deploy(self, app_id):
        # post a new build with procfile
        url = "/v2/apps/{app_id}/builds".format(app_id=app_id)
        body = {
            'image': 'autotest/example',
            'sha': 'a'*40,
            'stack': 'heroku-18',
            'procfile': {
                'web': 'node server.js',
                'worker': 'node worker.js'
            }
        }
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
