"""
Unit tests for the Drycc scheduler module.

Run the tests with './manage.py test scheduler'
"""
from scheduler.tests import TestCase


class EventTest(TestCase):
    """Tests scheduler pod calls"""

    def create_event(self, namespace, name, **kwargs):
        """
        Helper function to create and verify a events on the namespace
        """
        self.scheduler.ns.create(namespace)

        message = "Scaled down replica set test-869947c55f to 1 from 2"
        # these are all required even if it is kwargs...
        kwargs = {
            'reason': 'ScalingReplicaSet',
            'type': 'Normal'
        }
        return self.scheduler.events.create(
            namespace,
            name,
            message,
            **kwargs
        )

    def test_create(self):
        response = self.create_event("test-event", "test-event")
        self.assertEqual(response.status_code, 201)

    def test_get_events(self):
        # test success
        response = self.scheduler.events.get("test-event", "test-event")
        self.assertEqual(response.status_code, 200)
