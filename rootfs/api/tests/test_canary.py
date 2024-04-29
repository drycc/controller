import json
from django.contrib.auth import get_user_model
from django.core.cache import cache

from api.models.app import App
from api.tests import adapter, DryccTransactionTestCase
import requests_mock

User = get_user_model()


@requests_mock.Mocker(real_http=True, adapter=adapter)
class CanaryTest(DryccTransactionTestCase):

    """Tests push notification from build system"""

    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = self.get_or_create_token(self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

    def tearDown(self):
        # make sure every test has a clean slate for k8s mocking
        cache.clear()

    def pre_data(self):
        app_id = self.create_app()
        # check that updating config rolls a new release
        url = f'/v2/apps/{app_id}/config'
        body = {'values': json.dumps({'NEW_URL1': 'http://localhost:8080/'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertIn('NEW_URL1', response.data['values'])
        # check that updating the build rolls a new release
        url = f'/v2/apps/{app_id}/builds'
        body = {'image': 'autotest/example:v1', 'stack': 'container'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data['image'], body['image'])
        # create v2 release
        url = f'/v2/apps/{app_id}/builds'
        body = {'image': 'autotest/example:v2', 'stack': 'container'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data['image'], body['image'])
        # get deployments
        app = App.objects.get(id=app_id)
        response = app.scheduler().deployments.get(app_id)
        self.assertEqual(len(response.json()["items"]), 1)
        # add canary
        self.client.post(
            f'/v2/apps/{app_id}/settings',
            {'canaries': ["web"]}
        )
        # add v3 release
        url = f'/v2/apps/{app_id}/builds'
        body = {'image': 'autotest/example:v3', 'stack': 'container'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data['image'], body['image'])
        return app

    def test_release(self, mock_requests):
        app = self.pre_data()
        # get deployments
        response = app.scheduler().deployments.get(app.id)
        self.assertEqual(len(response.json()["items"]), 2)
        response = self.client.post(f'/v2/apps/{app.id}/canary/release/')
        self.assertEqual(response.status_code, 201)
        response = app.scheduler().deployments.get(app.id)
        self.assertEqual(len(response.json()["items"]), 1)
        self.assertEqual(
            response.json()["items"][0]["spec"]["template"]["spec"]["containers"][0]["image"],
            'autotest/example:v3',
        )

    def test_rollback(self, mock_requests):
        app = self.pre_data()
        response = app.scheduler().deployments.get(app.id)
        self.assertEqual(len(response.json()["items"]), 2)
        response = self.client.post(f'/v2/apps/{app.id}/canary/rollback/')
        self.assertEqual(response.status_code, 201)
        response = app.scheduler().deployments.get(app.id)
        self.assertEqual(len(response.json()["items"]), 1)
        self.assertEqual(
            response.json()["items"][0]["spec"]["template"]["spec"]["containers"][0]["image"],
            'autotest/example:v2',
        )
