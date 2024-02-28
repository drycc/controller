from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.conf import settings
from rest_framework.authtoken.models import Token

from api.models.app import App
from api.tests import DryccTransactionTestCase
from api.tests.test_gateway import RouteTest

User = get_user_model()


class ServiceTest(DryccTransactionTestCase):

    """Tests push notification from build system"""

    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = Token.objects.get(user=self.user).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)
        self.test_route = RouteTest()
        self.test_route.user = self.user
        self.test_route.token = self.token
        self.test_route.client = self.client

    def tearDown(self):
        # make sure every test has a clean slate for k8s mocking
        cache.clear()

    def test_service_basic_ops(self):
        """Test basic service operations."""
        app_id = self.create_app()
        # list non-existing services
        response = self.client.get('/v2/apps/{}/services'.format(app_id))
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['services']), 0)
        # create 1st service
        response = self.client.post(
            '/v2/apps/{}/services'.format(app_id),
            {
                'port': 5000,
                'protocol': 'UDP',
                'target_port': 5000,
                'procfile_type': 'test'
            }
        )
        self.assertEqual(response.status_code, 201, response.data)
        # list 1st service
        response = self.client.get('/v2/apps/{}/services'.format(app_id))
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['services']), 1)
        expected0 = {
            "domain": "%s-%s.%s.svc.%s" % (
                app_id, "test", app_id, settings.KUBERNETES_CLUSTER_DOMAIN),
            "ports": [{
                'name': "%s-%s-%s-%s" % (app_id, "test", 'udp', 5000),
                'port': 5000,
                'protocol': 'UDP',
                'targetPort': 5000,
            }],
            "procfile_type": "test"
        }
        self.assertDictContainsSubset(expected0, response.data['services'][0])
        # port is occupied
        response = self.client.post(
            '/v2/apps/{}/services'.format(app_id),
            {
                'port': 5000,
                'protocol': 'UDP',
                'target_port': 5000,
                'procfile_type': 'test'
            }
        )
        self.assertEqual(response.status_code, 400, response.data)

        # add new port
        expected1 = {
            "domain": "%s-%s.%s.svc.%s" % (
                app_id, "test", app_id, settings.KUBERNETES_CLUSTER_DOMAIN),
            "ports": [
                {
                    'name': "%s-%s-%s-%s" % (app_id, "test", 'udp', 5000),
                    'port': 5000,
                    'protocol': 'UDP',
                    'targetPort': 5000,
                },
                {
                    'name': "%s-%s-%s-%s" % (app_id, "test", 'tcp', 6000),
                    'port': 6000,
                    'protocol': 'TCP',
                    'targetPort': 6000,
                }
            ],
            "procfile_type": "test"
        }
        response = self.client.post(
            '/v2/apps/{}/services'.format(app_id),
            {
                'port': 6000,
                'protocol': 'TCP',
                'target_port': 6000,
                'procfile_type': 'test'
            }
        )
        self.assertEqual(response.status_code, 204, response.data)
        response = self.client.get('/v2/apps/{}/services'.format(app_id))
        self.assertEqual(response.status_code, 200, response.data)
        self.assertDictContainsSubset(expected1, response.data['services'][0])

        # create 2nd service
        response = self.client.post(
            '/v2/apps/{}/services'.format(app_id),
            {
                'port': 5000,
                'protocol': 'UDP',
                'target_port': 5000,
                'procfile_type': 'test2'
            }
        )
        self.assertEqual(response.status_code, 201, response.data)
        # list two services
        response = self.client.get('/v2/apps/{}/services'.format(app_id))
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['services']), 2)
        expected2 = {
            "domain": "%s-%s.%s.svc.%s" % (
                app_id, "test2", app_id, settings.KUBERNETES_CLUSTER_DOMAIN),
            "ports": [{
                'name': "%s-%s-%s-%s" % (app_id, "test2", 'udp', 5000),
                'port': 5000,
                'protocol': 'UDP',
                'targetPort': 5000,
            }],
            "procfile_type": "test2"
        }
        self.assertDictContainsSubset(expected2, response.data['services'][0])
        self.assertDictContainsSubset(expected1, response.data['services'][1])
        # delete port
        response = self.client.delete(
            '/v2/apps/{}/services'.format(app_id),
            {'procfile_type': 'test', "protocol": "TCP", "port": 6000}
        )
        response = self.client.get('/v2/apps/{}/services'.format(app_id))
        self.assertDictContainsSubset(expected0, response.data['services'][1])
        # delete 1st
        response = self.client.delete(
            '/v2/apps/{}/services'.format(app_id),
            {'procfile_type': 'test', "protocol": "UDP", "port": 5000}
        )
        self.assertEqual(response.status_code, 204, response.data)
        # delete 2nd
        response = self.client.delete(
            '/v2/apps/{}/services'.format(app_id),
            {'procfile_type': 'test2',  "protocol": "UDP", "port": 5000}
        )
        self.assertEqual(response.status_code, 204, response.data)
        response = self.client.get('/v2/apps/{}/services'.format(app_id))
        self.assertEqual(response.data["services"], [])
        # delete non-existing (1st again)
        response = self.client.delete(
            '/v2/apps/{}/services'.format(app_id),
            {'procfile_type': 'test', "protocol": "UDP", "port": 5000}
        )
        self.assertEqual(response.status_code, 404, response.data)

    def test_app_settings_change_canaries(self):
        procfile_type, app_id, _, _, _, _ = self.test_route.test_route_attach()
        # Add canaries
        response = self.client.post(
            f'/v2/apps/{app_id}/settings',
            {'canaries': [procfile_type]}
        )
        self.assertEqual(response.status_code, 201, response.data)
        app = App.objects.get(id=app_id)
        response = app.scheduler().svc.get(app_id)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()["items"]), 2)
        # Remove canaries to false
        response = self.client.delete(
            f'/v2/apps/{app_id}/settings',
            {'canaries': [procfile_type]}
        )
        self.assertEqual(response.status_code, 204, response.data)
        response = app.scheduler().svc.get(app_id)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()["items"]), 1)
