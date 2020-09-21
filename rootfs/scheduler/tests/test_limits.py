"""
Unit tests for the Drycc scheduler module.

Run the tests with './manage.py test scheduler'
"""
from scheduler.tests import TestCase
from scheduler import KubeHTTPException


class LimitRangesTest(TestCase):

    def test_create_quota(self):
        namespace_name = self.create_namespace()
        spec = {
            "limits": [
                {
                    "type": "Container",
                    "max": {
                        "cpu": "32",
                        "memory": "128Gi"
                    },
                    "min": {
                        "cpu": "100m",
                        "memory": "128Mi"
                    }
                },
                {
                    "type": "PersistentVolumeClaim",
                    "max": {
                        "storage": "100Gi"
                    },
                    "min": {
                        "storage": "100Mi"
                    }
                }
            ]
        }
        self.scheduler.limits.create(namespace_name, 'test-1', spec=spec)
        response = self.scheduler.limits.get(namespace_name, 'test-1')
        data = response.json()
        self.assertEqual(data.get('spec', {}), spec)
        self.assertEqual(data['metadata']['namespace'], namespace_name)

    def test_create_with_nonexistent_namespace(self):
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to create LimitRanges test-1 for namespace ghost-namespace: 404 Not Found'
        ):
            self.scheduler.quota.create('ghost-namespace', 'test-1', data={})
