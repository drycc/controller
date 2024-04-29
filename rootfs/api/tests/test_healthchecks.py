import json
import requests_mock

from django.core.cache import cache
from django.contrib.auth import get_user_model

from api.tests import adapter, DryccTransactionTestCase

User = get_user_model()


@requests_mock.Mocker(real_http=True, adapter=adapter)
class TestHealthchecks(DryccTransactionTestCase):
    """Tests setting and updating config values"""

    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = self.get_or_create_token(self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

    def tearDown(self):
        # make sure every test has a clean slate for k8s mocking
        cache.clear()

    def test_config_healthchecks(self, mock_requests):
        """
        Test that healthchecks can be applied
        """
        app_id = self.create_app()
        readiness_probe = {
            'healthcheck': {'web': {'readinessProbe': {'httpGet': {'port': 5000}}}}
        }
        response = self.client.post(
            f'/v2/apps/{app_id}/config',
            readiness_probe)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertIn('readinessProbe', response.data['healthcheck']['web'])
        self.assertEqual(response.data['healthcheck'], readiness_probe['healthcheck'])

        liveness_probe = {'healthcheck': {'web': {'livenessProbe':
                                          {'httpGet': {'port': 5000},
                                           'successThreshold': 1}}}}
        response = self.client.post(
            f'/v2/apps/{app_id}/config',
            liveness_probe)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertIn('livenessProbe', response.data['healthcheck']['web'])
        self.assertEqual(
            response.data['healthcheck']['web']['livenessProbe'],
            liveness_probe['healthcheck']['web']['livenessProbe'])
        # check that the readiness probe is still there too!
        self.assertIn('readinessProbe', response.data['healthcheck']['web'])
        self.assertEqual(
            response.data['healthcheck']['web']['readinessProbe'],
            readiness_probe['healthcheck']['web']['readinessProbe'])

        # check that config fails if trying to unset non-existing healthcheck
        response = self.client.post(
            f'/v2/apps/{app_id}/config',
            {'healthcheck': {'invalid_proctype': None}})
        self.assertEqual(response.status_code, 400, response.data)

        # remove a probeType
        response = self.client.post(
            f'/v2/apps/{app_id}/config',
            {'healthcheck': {'web': {'livenessProbe': None}}})
        self.assertEqual(response.status_code, 201, response.data)
        self.assertNotIn('livenessProbe', response.data['healthcheck']['web'])
        self.assertIn('readinessProbe', response.data['healthcheck']['web'])

        # check that config fails if trying to unset non-existing probeType
        response = self.client.post(
            f'/v2/apps/{app_id}/config',
            {'healthcheck': {'web': {'livenessProbe': None}}})
        self.assertEqual(response.status_code, 422, response.data)

        # check that config fails if trying to unset non-existing probeType
        response = self.client.post(
            f'/v2/apps/{app_id}/config',
            {'healthcheck': {'invalid_proctype': {'livenessProbe': None}}})
        self.assertEqual(response.status_code, 400, response.data)

        # check that config fails if trying to unset non-existing probeType
        response = self.client.post(
            f'/v2/apps/{app_id}/config',
            {'healthcheck': {'web': None}})
        self.assertEqual(response.status_code, 201, response.data)
        self.assertNotIn('web', response.data['healthcheck'])

        # post a new build
        response = self.client.post(
            f"/v2/apps/{app_id}/builds",
            {'image': 'quay.io/autotest/example', 'stack': 'container'}
        )
        self.assertEqual(response.status_code, 201, response.data)

    def test_config_healthchecks_validations(self, mock_requests):
        """
        Test that healthchecks validations work
        """
        app_id = self.create_app()

        # Set a probe different from liveness/readiness
        response = self.client.post(
            f'/v2/apps/{app_id}/config',
            {'healthcheck': json.dumps({'web': {'testProbe':
                                        {'httpGet': {'port': '50'}, 'initialDelaySeconds': "1"}}})}
        )
        self.assertEqual(response.status_code, 400, response.data)

        # Set one of the values that require a numeric value to a string
        response = self.client.post(
            f'/v2/apps/{app_id}/config',
            {'healthcheck': json.dumps({'web': {'livenessProbe':
                                        {'httpGet': {'port': '50'}, 'initialDelaySeconds': "t"}}})}
        )
        self.assertEqual(response.status_code, 400, response.data)

        # Don't set one of the mandatory value
        response = self.client.post(
            f'/v2/apps/{app_id}/config',
            {'healthcheck': json.dumps({'web': {'livenessProbe':
                                        {'httpGet': {'path': '/'}, 'initialDelaySeconds': 1}}})}
        )
        self.assertEqual(response.status_code, 400, response.data)
