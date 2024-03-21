"""
Unit tests for the Drycc scheduler module.

Run the tests with './manage.py test scheduler'
"""
from scheduler import KubeHTTPException
from scheduler.tests import TestCase
from scheduler.utils import generate_random_name


class ServicesTest(TestCase):
    """Tests scheduler service calls"""

    def create(self, port=5000, protocol="TCP", target_port=5000):
        """
        Helper function to create and verify a service on the namespace
        """
        name = generate_random_name()
        service = self.scheduler.svc.create(self.namespace, name, ports=[{
            "port": port,
            "protocol": protocol,
            "targetPort": target_port,
        }])
        data = service.json()
        self.assertEqual(service.status_code, 201, data)
        self.assertEqual(data['metadata']['name'], name)
        return name

    def test_create_failure(self):
        # Kubernetes does not throw a 404 if queried on a non-existant Namespace
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to create Service doesnotexist in Namespace {}: 404 Not Found'.format(self.namespace)  # noqa
        ):
            self.scheduler.svc.create('doesnotexist', 'doesnotexist')

    def test_create(self):
        # helper method takes care of the verification
        name = self.create()

        service = self.scheduler.svc.get(self.namespace, name).json()
        self.assertEqual(service['spec']['ports'][0]['targetPort'], 5000, service)

    def test_update_failure(self):
        # test failure
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to update Service foo in Namespace {}: 404 Not Found'.format(self.namespace)  # noqa
        ):
            self.scheduler.svc.patch(self.namespace, 'foo', {})

    def test_patch(self):
        name = self.create()
        expect = {
            "ports": [{
                "port": 6000,
                "protocol": "UDP",
                "targetPort": "6000",
            }],
            "version": 1,
        }
        self.scheduler.svc.patch(self.namespace, name, **expect)
        service = self.scheduler.svc.get(self.namespace, name).json()
        self.assertEqual(expect, {
            "ports": [{
                "port": service['spec']['ports'][0]['port'],
                "protocol": service['spec']['ports'][0]['protocol'],
                "targetPort": service['spec']['ports'][0]['targetPort'],
            }],
            "version": service['metadata']['resourceVersion']
        })

    def test_update(self):
        # test success
        name = self.create()
        service = self.scheduler.svc.get(self.namespace, name).json()
        self.assertEqual(service['spec']['ports'][0]['targetPort'], 5000, service)

        response = self.scheduler.svc.patch(self.namespace, name, ports=[{
            "port": service['spec']['ports'][0]['port'],
            "protocol": service['spec']['ports'][0]['protocol'],
            "targetPort": 5001,
        }])
        self.assertEqual(response.status_code, 200, response.json())

        service = self.scheduler.svc.get(self.namespace, name).json()
        self.assertEqual(service['spec']['ports'][0]['targetPort'], 5001, service)

    def test_delete_failure(self):
        # test failure
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to delete Service foo in Namespace {}: 404 Not Found'.format(self.namespace)  # noqa
        ):
            self.scheduler.svc.delete(self.namespace, 'foo')

    def test_delete(self):
        # test success
        name = self.create()
        response = self.scheduler.svc.delete(self.namespace, name)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)

    def test_get_services(self):
        # test success
        name = self.create()
        response = self.scheduler.svc.get(self.namespace)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertIn('items', data)
        self.assertEqual(1, len(data['items']), data['items'])
        # simple verify of data
        self.assertEqual(data['items'][0]['metadata']['name'], name)

    def test_get_service_failure(self):
        # test failure
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to get Service doesnotexist in Namespace {}: 404 Not Found'.format(self.namespace)  # noqa
        ):
            self.scheduler.svc.get(self.namespace, 'doesnotexist')

    def test_get_service(self):
        # test success
        name = self.create()
        response = self.scheduler.svc.get(self.namespace, name)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data['apiVersion'], 'v1')
        self.assertEqual(data['kind'], 'Service')
        metadata = {
            'name': name,
            'labels': {
                'app': self.namespace,
                'heritage': 'drycc'
            }
        }
        self.assertEqual(data['metadata'], data['metadata'] | metadata)
        self.assertEqual(data['spec']['ports'][0]['targetPort'], 5000)
