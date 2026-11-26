from unittest import mock

import requests_mock
from django.test import SimpleTestCase, override_settings

from api.clients import ManagerAPI


class ManagerAPITest(SimpleTestCase):

    @override_settings(
        WORKFLOW_MANAGER_URL='https://manager.example.test/v1/clusters/c1')
    @mock.patch(
        'api.clients.PassportAPI.headers',
        new_callable=mock.PropertyMock,
        return_value={},
    )
    @mock.patch('api.clients.cache.get', return_value=None)
    @mock.patch('api.clients.cache.set')
    def test_workspace_status_request_uses_workspace_slug(
            self, cache_set, cache_get, passport_headers):
        client = ManagerAPI()
        get_workspace_status = getattr(client, 'get_workspace_status', None)
        self.assertIsNotNone(get_workspace_status)

        with requests_mock.Mocker() as mock_requests:
            mock_requests.get(
                'https://manager.example.test/v1/clusters/c1/'
                'workspaces/myworkspace/status/',
                json={'is_active': False, 'message': 'Workspace inactive'},
            )
            result = get_workspace_status('myworkspace')

        self.assertEqual(result, (False, 'Workspace inactive'))
        self.assertEqual(len(mock_requests.request_history), 1)
        self.assertEqual(
            mock_requests.request_history[0].url,
            'https://manager.example.test/v1/clusters/c1/'
            'workspaces/myworkspace/status/',
        )
