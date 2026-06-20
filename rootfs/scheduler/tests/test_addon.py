"""
Unit tests for the Drycc scheduler addon resource.

Run the tests with './manage.py test scheduler'
"""
from unittest import mock, TestCase

from scheduler.resources.addon import AddonClass


class AddonClassResourceTest(TestCase):
    """Tests scheduler addon class resource URL construction."""

    def test_get_list_url(self):
        """Ensure listing AddonClasses uses the correct API path."""
        client = mock.Mock()
        resource = AddonClass(client)
        resource.get()
        client.http_get.assert_called_once_with(
            '/apis/addons.drycc.cc/v1/addonclasses', params=None)

    def test_get_item_url(self):
        """Ensure fetching a single AddonClass uses the correct API path."""
        client = mock.Mock()
        resource = AddonClass(client)
        resource.get('valkey')
        client.http_get.assert_called_once_with(
            '/apis/addons.drycc.cc/v1/addonclasses/valkey', params=None)
