"""
Unit tests for the Drycc scheduler module.

Run the tests with "./manage.py test scheduler"
"""
from scheduler.tests import TestCase
from scheduler import KubeHTTPException


class DaemonsetsTest(TestCase):
    """Tests scheduler daemonset calls"""

    def test_get_daemonsets(self):
        response = self.scheduler.daemonset.get('drycc')
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertIn('items', data)
        self.assertEqual(1, len(data['items']))
        # simple verify of data
        self.assertEqual(data['items'][0]['metadata']['name'], 'drycc')

    def test_get_daemonset(self):
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to get Daemonset doesnotexist in Namespace drycc: 404 Not Found'  # noqa
        ):
            self.scheduler.daemonset.get('drycc', 'doesnotexist')
        namespace = 'drycc'
        name = 'drycc'
        response = self.scheduler.daemonset.get(namespace, name)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data['apiVersion'], 'apps/v1')
        self.assertEqual(data['kind'], 'DaemonSet')
        self.assertEqual(data['metadata']['name'], name)

    def test_patch_daemonset(self):
        namespace = 'drycc'
        name = 'drycc'
        manifest_affinity = {
            "nodeAffinity": {
                "requiredDuringSchedulingIgnoredDuringExecution": {
                    "nodeSelectorTerms": [{
                        "matchExpressions": [{
                            "key": "kubernetes.io/hostname",
                            "operator": "In",
                            "values": [
                                "nohostname"
                            ]
                        }]
                    }]
                }
            }
        }
        response = self.scheduler.daemonset.patch(
            namespace,
            name,
            manifest={
                "spec": {
                    "template": {
                        "spec": {
                            "affinity": manifest_affinity
                        }
                    }
                }
            },
        )
        affinity = response.json()["spec"]["template"]['spec']['affinity']
        self.assertEqual(
            affinity,
            manifest_affinity
        )
