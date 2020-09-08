"""
Unit tests for the Drycc scheduler module.

Run the tests with './manage.py test scheduler'
"""
from scheduler import KubeHTTPException
from scheduler.tests import TestCase
from scheduler.utils import generate_random_name


class ServiceCatalogTest(TestCase):

    def create_instince(self, namespace=None, name=generate_random_name(),
                        **kwargs):
        """
        Helper function to create and verify a serviceinstances on the namespace
        """
        namespace = self.namespace if namespace is None else namespace
        # these are all required even if it is kwargs...
        kwargs = {
            "instance_class": "server",
            "instance_plan": "1-1",
            "parameters": {
                "param-1": "value-1",
                "param-2": "value-2"
            }
        }
        instance = self.scheduler.servicecatalog.create_instance(namespace,
                                                                 name, **kwargs)
        self.assertEqual(instance.status_code, 201, instance.json())
        return name

    def test_create_instince_failure(self):
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to create serviceinstances doesnotexist in Namespace \
            {}: 404 Not Found'.format(
                self.namespace)  # noqa
        ):
            self.create_instince('doesnotexist', 'doesnotexist')

    def test_create_instance(self):
        self.scheduler.ns.create("test-serviceinstance")
        self.create_instince(namespace="test-serviceinstance")

    def test_delete_instance_failure(self):
        # test failure
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to delete serviceinstance foo in Namespace {}: 404 Not Found'.format(self.namespace)  # noqa
        ):
            self.scheduler.servicecatalog.delete_instance(self.namespace, 'foo')

    def test_instince_delete(self):
        # test success
        name = self.create_instince()
        response = self.scheduler.servicecatalog.delete_instance(self.namespace,
                                                                 name)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)

    def test_get_serviceinstances(self):
        # test success
        name = self.create_instince()
        response = self.scheduler.servicecatalog.get_instance(self.namespace)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertIn('items', data)
        self.assertEqual(1, len(data['items']), data['items'])
        # simple verify of data
        self.assertEqual(data['items'][0]['metadata']['name'], name, data)

    def test_get_serviceinstance(self):
        # test success
        name = self.create_instince()
        response = self.scheduler.servicecatalog.get_instance(self.namespace, name)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        # simple verify of data
        self.assertEqual(data['metadata']['name'], name, data)

    def test_get_serviceinstances_failure(self):
        # test failure
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to get Pod doesnotexist in Namespace {}: 404 Not Found'.format(self.namespace)  # noqa
        ):
            self.scheduler.servicecatalog.get_instance(self.namespace,
                                                       'doesnotexist')

    def create_binding(self, namespace=None, name=generate_random_name(),
                       **kwargs):
        name = self.create_instince()
        # these are all required even if it is kwargs...
        instance = self.scheduler.servicecatalog.create_binding(self.namespace,
                                                                name)
        self.assertEqual(instance.status_code, 201, instance.json())
        return name

    def test_create_binding(self):
        self.scheduler.ns.create("test-serviceinstance")
        self.create_binding(namespace="test-serviceinstance")

    # def test_create_binding_failure(self):
    #     with self.assertRaises(
    #         KubeHTTPException,
    #         msg='failed to create servicebindings doesnotexist in Namespace {}: 404 Not Found'.format(self.namespace) # noqa
    #     ):
    #         self.create_binding(self.namespace, 'doesnotexist')

    def test_binding_delete(self):
        # test success
        name = self.create_binding(namespace="test-serviceinstance")
        response = self.scheduler.servicecatalog.delete_binding(self.namespace,
                                                                name)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)

    def test_get_servicebindings(self):
        # test success
        name = self.create_binding()
        response = self.scheduler.servicecatalog.get_binding(self.namespace)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertIn('items', data)
        self.assertEqual(1, len(data['items']), data['items'])
        # simple verify of data
        self.assertEqual(data['items'][0]['metadata']['name'], name, data)

    def test_get_servicebindings_failure(self):
        # test failure
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to get Pod doesnotexist in Namespace {}: 404 Not Found'.format(self.namespace)  # noqa
        ):
            self.scheduler.servicecatalog.get_binding(self.namespace,
                                                      'doesnotexist')
