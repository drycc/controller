import requests_mock

from django.core.cache import cache
from django.contrib.auth import get_user_model
from rest_framework.authtoken.models import Token

from api.models.app import App
from api.models.tls import TLS
from api.tests import adapter, DryccTransactionTestCase

User = get_user_model()


@requests_mock.Mocker(real_http=True, adapter=adapter)
class TestTLS(DryccTransactionTestCase):
    """Tests setting and updating config values"""

    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = Token.objects.get(user=self.user).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

    def tearDown(self):
        # make sure every test has a clean slate for k8s mocking
        cache.clear()

    def change_certs_auto(self, app_id, enabled):
        data = {'certs_auto_enabled': enabled}
        response = self.client.post(f'/v2/apps/{app_id}/tls', data)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data.get('certs_auto_enabled'), enabled, response.data)

    def test_tls_enforced(self, mock_requests):
        """
        Test that tls redirection can be enforced
        """
        app_id = self.create_app()
        app = App.objects.get(id=app_id)

        data = {'https_enforced': True}
        response = self.client.post(
            '/v2/apps/{app_id}/tls'.format(**locals()),
            data)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertTrue(response.data.get('https_enforced'), response.data)
        self.assertTrue(app.tls_set.latest().https_enforced)

        data = {'https_enforced': False}
        response = self.client.post(
            '/v2/apps/{app_id}/tls'.format(**locals()),
            data)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertFalse(app.tls_set.latest().https_enforced)

        # when the same data is sent again, a 409 is returned
        conflict_response = self.client.post(
            '/v2/apps/{app_id}/tls'.format(**locals()),
            data)
        self.assertEqual(conflict_response.status_code, 409, conflict_response.data)
        self.assertFalse(app.tls_set.latest().https_enforced)
        # also ensure that the previous tls UUID matches the latest,
        # confirming this conflicting TLS object was deleted
        self.assertEqual(response.data['uuid'], str(app.tls_set.latest().uuid))

        # sending bad data returns a 400
        data['https_enforced'] = "test"
        response = self.client.post(
            '/v2/apps/{app_id}/tls'.format(**locals()),
            data)
        self.assertEqual(response.status_code, 400, response.data)

    def test_tls_events(self, mock_requests):
        app_id = self.create_app()

        response = self.client.post(
            '/v2/apps/{}/domains'.format(app_id),
            {'domain': 'test-domain.example.com'}
        )
        self.assertEqual(response.status_code, 201, response.data)
        self.change_certs_auto(app_id, True)
        tls = TLS.objects.get(app__id=app_id)
        tls.refresh_certificate_to_k8s()
        response = self.client.get('/v2/apps/{}/tls'.format(app_id))
        self.assertEqual(len(response.json()["events"]), 3)

    def test_tls_created_on_app_create(self, mock_requests):
        """
        Ensure that a TLS object is created for an App with default values.

        See https://github.com/drycc/controller/issues/1042
        """
        app_id = self.create_app()
        response = self.client.get('/v2/apps/{}/tls'.format(app_id))
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data['https_enforced'], None)
