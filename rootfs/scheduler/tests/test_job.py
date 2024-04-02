"""
Unit tests for the Drycc scheduler module.

Run the tests with './manage.py test scheduler'
"""
from scheduler.tests import TestCase
from scheduler.utils import generate_random_name


class JobTest(TestCase):
    """Tests scheduler pod calls"""

    def create(self, namespace=None, name=generate_random_name(), **kwargs):
        """
        Helper function to create and verify a pod on the namespace
        """
        namespace = self.namespace if namespace is None else namespace
        # these are all required even if it is kwargs...
        kwargs = {
            'app_type': kwargs.get('app_type', 'web'),
            'version': kwargs.get('version', 'v99'),
            'image': 'quay.io/fake/image',
            'command': 'sh',
            'args': 'start',
            'deploy_timeout': 10,
        }

        job = self.scheduler.job.create(namespace, name, **kwargs)
        self.assertEqual(job.status_code, 201, job.json())
        return name

    def test_create(self):
        self.create()
