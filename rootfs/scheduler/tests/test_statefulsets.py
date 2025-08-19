"""
Unit tests for the Drycc scheduler module.

Run the tests with "./manage.py test scheduler"
"""
from scheduler.tests import TestCase
from scheduler import KubeHTTPException


class StatefulsetsTest(TestCase):
    """Tests scheduler statefulset calls"""

    def test_get_statefulsets(self):
        response = self.scheduler.statefulset.get('drycc')
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertIn('items', data)
        self.assertEqual(1, len(data['items']))
        # simple verify of data
        self.assertEqual(data['items'][0]['metadata']['name'], 'drycc')

    def test_get_statefulset(self):
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to get Statefulset doesnotexist in Namespace drycc: 404 Not Found'  # noqa
        ):
            self.scheduler.statefulset.get('drycc', 'doesnotexist')
        namespace = 'drycc'
        name = 'drycc'
        response = self.scheduler.statefulset.get(namespace, name)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data['apiVersion'], 'apps/v1')
        self.assertEqual(data['kind'], 'StatefulSet')
        self.assertEqual(data['metadata']['name'], name)

    def test_patch_statefulset(self):
        namespace = 'drycc'
        name = 'drycc'
        manifest = {
            'spec': {
                'persistentVolumeClaimRetentionPolicy': {
                    'whenScaled': 'Retain'
                },
                'replicas': 0
            }
        }
        response = self.scheduler.statefulset.patch(
            namespace,
            name,
            manifest=manifest,
        )
        when_scaled = response.json()["spec"]["persistentVolumeClaimRetentionPolicy"]['whenScaled']
        self.assertEqual(
            when_scaled,
            'Retain'
        )
