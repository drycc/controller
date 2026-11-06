from django.contrib.auth import get_user_model
from django.core.cache import cache

from api.models.service import Service
from api.tests import DryccTransactionTestCase

User = get_user_model()


class ServiceTest(DryccTransactionTestCase):

    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = self.get_or_create_token(self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

    def tearDown(self):
        # make sure every test has a clean slate for k8s mocking
        cache.clear()

    def apply_service(self, app_id, ptype, ports, body_ptype=None):
        return self.client.put(
            f'/v2/apps/{app_id}/services/{ptype}/',
            {'ptype': body_ptype or ptype, 'ports': ports},
            format='json',
        )

    def assert_status(self, response, expected):
        self.assertEqual(response.status_code, expected, getattr(response, 'data', None))

    def assert_service_ports(self, service, expected):
        self.assertEqual(service.ports, expected)
        response = service.scheduler.svc.get(service.app.id, service.name)
        self.assertEqual(response.status_code, 200, response.json())
        self.assertEqual(response.json()['spec']['ports'], expected)

    def test_service_basic_ops(self):
        app_id = self.create_app()
        collection_url = f'/v2/apps/{app_id}/services/'
        detail_url = f'/v2/apps/{app_id}/services/test/'

        response = self.client.get(collection_url)
        self.assert_status(response, 200)
        self.assertEqual(response.data.get('count'), 0)
        self.assertEqual(response.data['results'], [])

        response = self.client.post(collection_url, {}, format='json')
        self.assert_status(response, 405)
        response = self.client.delete(collection_url, {}, format='json')
        self.assert_status(response, 405)

        ports = [
            {'port': 5000, 'protocol': 'UDP', 'target_port': 5000},
            {'port': 6000, 'protocol': 'TCP', 'target_port': 6000},
        ]
        response = self.apply_service(app_id, 'test', ports)
        self.assert_status(response, 201)
        self.assertEqual(response.data['app'], app_id)
        self.assertEqual(response.data['ptype'], 'test')
        self.assertEqual(response.data['domain'], f'{app_id}-test.{app_id}.svc')
        self.assertNotIn('name', response.data)
        self.assertEqual(response.data['ports'], [
            {'name': 'udp-5000', 'port': 5000, 'protocol': 'UDP', 'target_port': 5000},
            {'name': 'tcp-6000', 'port': 6000, 'protocol': 'TCP', 'target_port': 6000},
        ])
        self.assertIsInstance(response.data['ports'][0]['port'], int)
        self.assertIsInstance(response.data['ports'][0]['target_port'], int)

        service = Service.objects.get(app__id=app_id, ptype='test')
        self.assert_service_ports(service, [
            {'name': 'udp-5000', 'port': 5000, 'protocol': 'UDP', 'targetPort': 5000},
            {'name': 'tcp-6000', 'port': 6000, 'protocol': 'TCP', 'targetPort': 6000},
        ])

        response = self.client.get(detail_url)
        self.assert_status(response, 200)
        self.assertEqual(response.data['domain'], f'{app_id}-test.{app_id}.svc')
        self.assertNotIn('name', response.data)
        response = self.client.get(collection_url)
        self.assertEqual(response.data.get('count'), 1)
        self.assertEqual(len(response.data['results']), 1)

        ports = [
            {'port': 5000, 'protocol': 'UDP', 'target_port': 5001},
            {'port': 7000, 'protocol': 'TCP', 'target_port': 7000},
        ]
        response = self.apply_service(app_id, 'test', ports)
        self.assert_status(response, 200)
        response = self.apply_service(app_id, 'test', ports)
        self.assert_status(response, 200)
        self.assertEqual(response.data['ports'], [
            {'name': 'udp-5000', 'port': 5000, 'protocol': 'UDP', 'target_port': 5001},
            {'name': 'tcp-7000', 'port': 7000, 'protocol': 'TCP', 'target_port': 7000},
        ])
        service.refresh_from_db()
        self.assert_service_ports(service, [
            {'name': 'udp-5000', 'port': 5000, 'protocol': 'UDP', 'targetPort': 5001},
            {'name': 'tcp-7000', 'port': 7000, 'protocol': 'TCP', 'targetPort': 7000},
        ])

        response = self.client.delete(detail_url)
        self.assert_status(response, 204)
        response = self.client.get(detail_url)
        self.assert_status(response, 404)
        response = self.client.delete(detail_url)
        self.assert_status(response, 404)
        response = self.client.get(collection_url)
        self.assertEqual(response.data.get('count'), 0)

    def test_service_same_port_allows_different_protocols(self):
        app_id = self.create_app()
        response = self.apply_service(app_id, 'test', [
            {'port': 80, 'protocol': 'TCP', 'target_port': 5000},
            {'port': 80, 'protocol': 'UDP', 'target_port': 5000},
        ])
        self.assert_status(response, 201)
        self.assertEqual(response.data['ports'], [
            {'name': 'tcp-80', 'port': 80, 'protocol': 'TCP', 'target_port': 5000},
            {'name': 'udp-80', 'port': 80, 'protocol': 'UDP', 'target_port': 5000},
        ])

        response = self.apply_service(app_id, 'test', [
            {'port': 80, 'protocol': 'TCP', 'target_port': 5000},
            {'port': 80, 'protocol': 'TCP', 'target_port': 5001},
        ])
        self.assert_status(response, 400)

    def test_service_ports_schema_validation(self):
        app_id = self.create_app()
        invalid_ports = [
            [],
            {},
            [{'port': 80, 'protocol': 'TCP'}],
            [{'port': 0, 'protocol': 'TCP', 'target_port': 80}],
            [{'port': 80, 'protocol': 'TLS', 'target_port': 80}],
            [{'name': 'tcp-80', 'port': 80, 'protocol': 'TCP', 'target_port': 80}],
            [{'port': 80, 'protocol': 'TCP', 'target_port': 80, 'node_port': 30080}],
        ]
        for ports in invalid_ports:
            with self.subTest(ports=ports):
                response = self.apply_service(app_id, 'test', ports)
                self.assert_status(response, 400)
        self.assertFalse(Service.objects.filter(app__id=app_id, ptype='test').exists())

    def test_service_url_ptype_is_authoritative(self):
        app_id = self.create_app()
        ports = [{'port': 80, 'protocol': 'TCP', 'target_port': 5000}]

        response = self.client.put(
            f'/v2/apps/{app_id}/services/test/',
            {'ports': ports},
            format='json',
        )
        self.assert_status(response, 400)

        response = self.apply_service(app_id, 'test', ports, body_ptype='other')
        self.assert_status(response, 201)
        self.assertEqual(response.data['ptype'], 'test')
        self.assertTrue(Service.objects.filter(app__id=app_id, ptype='test').exists())
        self.assertFalse(Service.objects.filter(app__id=app_id, ptype='other').exists())
