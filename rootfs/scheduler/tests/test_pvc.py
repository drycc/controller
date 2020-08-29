"""
Unit tests for the Drycc scheduler module.

Run the tests with './manage.py test scheduler'
"""
from scheduler import KubeHTTPException
from scheduler.tests import TestCase
from scheduler.utils import generate_random_name


class PVCTest(TestCase):
    """Tests scheduler pod calls"""

    def create(self, namespace=None, name=generate_random_name(), **kwargs):
        """
        Helper function to create and verify a pvc on the namespace
        """
        namespace = self.namespace if namespace is None else namespace
        # these are all required even if it is kwargs...
        kwargs = {
            'size': '500M'
        }
        pvc = self.scheduler.pvc.create(namespace, name, **kwargs)
        self.assertEqual(pvc.status_code, 201, pvc.json())
        return name

    def test_create_failure(self):
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to create pvc doesnotexist in Namespace {}: 404 Not Found'.format(self.namespace)  # noqa
        ):
            self.create('doesnotexist', 'doesnotexist')

    def test_create(self):
        self.scheduler.ns.create("test-pvc")
        self.create(namespace="test-pvc")

    def test_delete_failure(self):
        # test failure
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to delete pvc foo in Namespace {}: 404 Not Found'.format(self.namespace)  # noqa
        ):
            self.scheduler.pvc.delete(self.namespace, 'foo')

    def test_delete(self):
        # test success
        name = self.create()
        response = self.scheduler.pvc.delete(self.namespace, name)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)

    def test_get_pvcs(self):
        # test success
        name = self.create()
        response = self.scheduler.pvc.get(self.namespace)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertIn('items', data)
        self.assertEqual(1, len(data['items']), data['items'])
        # simple verify of data
        self.assertEqual(data['items'][0]['metadata']['name'], name, data)

    def test_get_pvc(self):
        # test success
        name = self.create()
        response = self.scheduler.pvc.get(self.namespace, name)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        # simple verify of data
        self.assertEqual(data['metadata']['name'], name, data)

    def test_get_pvcs_failure(self):
        # test failure
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to get Pod doesnotexist in Namespace {}: 404 Not Found'.format(self.namespace)  # noqa
        ):
            self.scheduler.pvc.get(self.namespace, 'doesnotexist')
