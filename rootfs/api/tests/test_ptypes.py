# -*- coding: utf-8 -*-
"""
Unit tests for the Drycc api app.

Run the tests with "./manage.py test api"
"""
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.conf import settings

from api.models.app import App

from api.tests import adapter, DryccTransactionTestCase
import requests_mock

User = get_user_model()


@requests_mock.Mocker(real_http=True, adapter=adapter)
class PtypesTest(DryccTransactionTestCase):
    """Tests setting and updating config values"""

    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = self.get_or_create_token(self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

        url = '/v2/apps'
        response = self.client.post(url, HTTP_AUTHORIZATION='token {}'.format(self.token))
        self.assertEqual(response.status_code, 201, response.data)
        self.app = App.objects.all()[0]

    def tearDown(self):
        # Restore default tags to empty string
        settings.DRYCC_DEFAULT_CONFIG_TAGS = ''
        # make sure every test has a clean slate for k8s mocking
        cache.clear()

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

    def test_ptype(self, mock_requests):
        """
        Test that config is auto-created for a new app and that
        config can be updated using a PATCH
        """
        app_id = self.create_app()
        self.build_deploy(app_id)

        # list ptypes deployment
        url = f"/v2/apps/{app_id}/ptypes"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)

        # describe ptype deployment
        url = f"/v2/apps/{app_id}/ptypes/{app_id}-web/describe"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)

        ptype_name = "no-exists-ptype-name"
        response = self.client.get(f"/v2/apps/{app_id}/ptypes/{ptype_name}/describe/")
        self.assertEqual(response.status_code, 400, response.data)

    def test_restart_ptypes(self, mock_requests):
        app_id = self.create_app()

        # post a new build
        build_url = f"/v2/apps/{app_id}/builds"
        body = {
            'image': 'autotest/example',
            'stack': 'heroku-18',
            'sha': 'a'*40,
            'procfile': {
                'web': 'node server.js',
                'worker': 'node worker.js'
            }
        }
        response = self.client.post(build_url, body)

        url = f"/v2/apps/{app_id}/ptypes/scale"
        body = {'web': 4, 'worker': 8}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)

        # setup app object
        application = App.objects.get(id=app_id)

        # restart all ptypes deployments
        response = self.client.post('/v2/apps/{}/ptypes/restart'.format(app_id))
        self.assertEqual(response.status_code, 204, response.data)

        # restart web and workers ptype deployments
        body = {"types": "web,worker"}
        response = self.client.post('/v2/apps/{}/ptypes/restart'.format(app_id), body)
        self.assertEqual(response.status_code, 204, response.data)

        # restart invalid ptypes
        body = {"types": "web1"}
        response = self.client.post('/v2/apps/{}/ptypes/restart'.format(app_id), body)
        self.assertEqual(response.status_code, 400, response.data)

        # restart only one of the web ptype deployments
        pods = application.list_pods(type='web')
        self.assertEqual(len(pods), 4)
