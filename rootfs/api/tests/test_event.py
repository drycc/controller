# -*- coding: utf-8 -*-
"""
Unit tests for the Drycc api app.

Run the tests with "./manage.py test api"
"""
from django.contrib.auth import get_user_model
from django.core.cache import cache

from api.models.app import App

from api.tests import adapter, DryccTransactionTestCase
import requests_mock

User = get_user_model()


@requests_mock.Mocker(real_http=True, adapter=adapter)
class EventTest(DryccTransactionTestCase):
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

    def test_events(self, mock_requests):
        """
        Test that config is auto-created for a new app and that
        config can be updated using a PATCH
        """
        app_id = self.create_app()
        self.build_deploy(app_id)

        # list events of pod
        url = f"/v2/apps/{app_id}/pods"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        pod_name = response.data['results'][0]["name"]
        response = self.client.get(f"/v2/apps/{app_id}/pods/{pod_name}/describe/")
        url = f"/v2/apps/{app_id}/events"
        response = self.client.get(url, {"pod_name": pod_name})
        self.assertEqual(response.status_code, 200, response.data)

        # list events of deployment
        url = f"/v2/apps/{app_id}/events"
        response = self.client.get(url, {"ptype_name": f"{app_id}-web"})
        self.assertEqual(response.status_code, 200, response.data)
