"""
Unit tests for the Drycc ingress module.

Run the tests with './manage.py test ingress'
"""
from scheduler import KubeHTTPException
from scheduler.tests import TestCase


class IngressTest(TestCase):
    """Tests scheduler ingress calls"""

    def test_create_ingress(self):
        # Ingress assumes that the namespace and ingress name are always the same
        self.scheduler.ns.create("test-ingress")
        self.scheduler.ingress("default").create(
            "test-ingress", "nginx", hosts=["test-ingress"], tls=[])

    def test_get_ingresses(self):
        response = self.scheduler.ingress("default").get("test-ingress")
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertIn('items', data)

    def test_get_ingress(self):
        with self.assertRaises(
            KubeHTTPException,
            msg="failed to get Ingress doesnotexist: 404 Not Found"
        ):
            self.scheduler.ingress("default").get('doesnotexist', 'doesnotexist')

        self.scheduler.ns.create("test-ingress-create")
        self.scheduler.ingress("default").create(
            "test-ingress-create", "test-ingress-create", hosts=["test-ingress-create", ])
        response = self.scheduler.ingress("default").get(
            "test-ingress-create", "test-ingress-create")
        data = response.json()

        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data['apiVersion'], 'networking.k8s.io/v1')
        self.assertEqual(data['kind'], 'Ingress')

    def test_delete_failure(self):
        # test failure
        with self.assertRaises(
            KubeHTTPException,
            msg="failed to delete Ingress doesnotexist: 404 Not Found"
        ):
            self.scheduler.ns.delete('doesnotexist')

    def test_delete_namespace(self):
        self.scheduler.ns.create("test-ingress-delete")
        self.scheduler.ingress("default").create(
            "test-ingress-delete", "test-ingress-delete", hosts=["test-ingress-delete", ])
        response = self.scheduler.ingress("default").delete(
            "test-ingress-delete", "test-ingress-delete")
        self.assertEqual(response.status_code, 200, response.json())
