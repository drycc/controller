"""Tests for App ResourceQuota provisioning and reporting."""
import json
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

import requests
import requests_mock

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db import connection, connections

from api.exceptions import Conflict, ServiceUnavailable
from api.models.app import App
from api.models.workspace import Workspace, WorkspaceMember
from api.tests import adapter, DryccTestCase, DryccTransactionTestCase
from scheduler import KubeHTTPException

User = get_user_model()
DEFAULT_RESOURCE_QUOTA_TEMPLATE = '{"spec": {"hard": {"pods": "50"}}}'


def scheduler_response(status_code, payload=None, reason=''):
    response = requests.Response()
    response.status_code = status_code
    response.reason = reason
    response._content = json.dumps(payload or {}).encode('utf-8')
    return response


@requests_mock.Mocker(real_http=True, adapter=adapter)
class AppResourceQuotaTest(DryccTestCase):
    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.workspace_id = self._ensure_workspace_admin(self._default_workspace_id())
        self.workspace = Workspace.objects.get(id=self.workspace_id)
        self.token = self.get_or_create_token(self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)
        self.app = App.objects.create(id='quotaapp01', workspace=self.workspace)
        self.scheduler = self.app.scheduler

    def tearDown(self):
        cache.clear()

    def test_create_default_resource_quota(self, mock_requests):
        hard = {'pods': '50', 'requests.cpu': '10'}
        template = '{"spec": {"hard": {"pods": "50", "requests.cpu": "10"}}}'
        with self.settings(DRYCC_RESOURCE_QUOTA_TEMPLATE=template):
            self.app._create_resource_quota()
        response = self.scheduler.resourcequotas.get(
            self.app.id, 'drycc-app', ignore_exception=False)
        self.assertEqual(response.json()['spec']['hard'], hard)

    def test_resource_quota_template_renders_workspace(self, mock_requests):
        template = (
            '{"metadata": {"annotations": {"drycc.cc/template-workspace": "{{workspace}}"}},'
            ' "spec": {"hard": {"pods": "50"}}}'
        )
        with self.settings(DRYCC_RESOURCE_QUOTA_TEMPLATE=template):
            self.app._create_resource_quota()
        response = self.scheduler.resourcequotas.get(
            self.app.id, 'drycc-app', ignore_exception=False)
        annotations = response.json()['metadata']['annotations']
        self.assertEqual(annotations['drycc.cc/template-workspace'], self.workspace.id)

    def test_existing_custom_resource_quota_is_not_overwritten(self, mock_requests):
        custom_hard = {'pods': '99', 'requests.cpu': '25'}
        self.scheduler.resourcequotas.create(
            self.app.id, 'drycc-app', spec={'hard': custom_hard}, ignore_exception=False)
        with self.settings(DRYCC_RESOURCE_QUOTA_TEMPLATE=DEFAULT_RESOURCE_QUOTA_TEMPLATE):
            self.app._create_resource_quota()
        response = self.scheduler.resourcequotas.get(
            self.app.id, 'drycc-app', ignore_exception=False)
        self.assertEqual(response.json()['spec']['hard'], custom_hard)

    def test_missing_resource_quota_is_repaired(self, mock_requests):
        with self.settings(DRYCC_RESOURCE_QUOTA_TEMPLATE=DEFAULT_RESOURCE_QUOTA_TEMPLATE):
            self.app._create_resource_quota()
            response = self.scheduler.http_delete(
                f'/api/v1/namespaces/{self.app.id}/resourcequotas/drycc-app')
            self.assertEqual(response.status_code, 200, response.json())
            self.app._create_resource_quota()
        response = self.scheduler.resourcequotas.get(
            self.app.id, 'drycc-app', ignore_exception=False)
        self.assertEqual(response.json()['spec']['hard'], {'pods': '50'})

    def test_concurrent_create_conflict_is_accepted(self, mock_requests):
        quota = {
            'metadata': {'name': 'drycc-app', 'namespace': self.app.id},
            'spec': {'hard': {'pods': '50'}},
            'status': {'used': {}},
        }
        conflict = scheduler_response(409, reason='Conflict')
        not_found = scheduler_response(404, reason='Not Found')
        with mock.patch.object(App, 'scheduler', new_callable=mock.PropertyMock) as prop:
            prop.return_value = self.scheduler
            with mock.patch.object(self.scheduler.resourcequotas, 'get') as get:
                get.side_effect = [
                    KubeHTTPException(not_found, 'get ResourceQuota'),
                    scheduler_response(200, quota),
                ]
                with mock.patch.object(self.scheduler.resourcequotas, 'create') as create:
                    create.side_effect = KubeHTTPException(conflict, 'create ResourceQuota')
                    with self.settings(
                            DRYCC_RESOURCE_QUOTA_TEMPLATE=DEFAULT_RESOURCE_QUOTA_TEMPLATE):
                        self.app._create_resource_quota()
        self.assertEqual(get.call_count, 2)
        create.assert_called_once()

    def test_disabled_provisioning_does_not_query_kubernetes(self, mock_requests):
        with mock.patch.object(App, 'scheduler', new_callable=mock.PropertyMock) as prop:
            prop.return_value = self.scheduler
            with mock.patch.object(self.scheduler.resourcequotas, 'get') as get:
                with self.settings(DRYCC_RESOURCE_QUOTA_TEMPLATE=''):
                    self.app._create_resource_quota()
        get.assert_not_called()

    def test_empty_object_template_disables_provisioning(self, mock_requests):
        with mock.patch.object(App, 'scheduler', new_callable=mock.PropertyMock) as prop:
            prop.return_value = self.scheduler
            with mock.patch.object(self.scheduler.resourcequotas, 'get') as get:
                with self.settings(DRYCC_RESOURCE_QUOTA_TEMPLATE='{}'):
                    self.app._create_resource_quota()
        get.assert_not_called()

    def test_resource_quota_get_failure(self, mock_requests):
        failure = scheduler_response(500, reason='Internal Error')
        with mock.patch.object(App, 'scheduler', new_callable=mock.PropertyMock) as prop:
            prop.return_value = self.scheduler
            with mock.patch.object(self.scheduler.resourcequotas, 'get') as get:
                get.side_effect = KubeHTTPException(failure, 'get ResourceQuota')
                with self.settings(DRYCC_RESOURCE_QUOTA_TEMPLATE=DEFAULT_RESOURCE_QUOTA_TEMPLATE):
                    with self.assertRaises(ServiceUnavailable):
                        self.app._create_resource_quota()

    def test_resource_quota_create_failure(self, mock_requests):
        failure = scheduler_response(500, reason='Internal Error')
        with mock.patch.object(App, 'scheduler', new_callable=mock.PropertyMock) as prop:
            prop.return_value = self.scheduler
            with mock.patch.object(self.scheduler.resourcequotas, 'create') as create:
                create.side_effect = KubeHTTPException(failure, 'create ResourceQuota')
                with self.settings(DRYCC_RESOURCE_QUOTA_TEMPLATE=DEFAULT_RESOURCE_QUOTA_TEMPLATE):
                    with self.assertRaises(ServiceUnavailable):
                        self.app._create_resource_quota()

    def test_quota_property_ignores_provisioning_setting(self, mock_requests):
        hard = {'pods': '99'}
        self.scheduler.resourcequotas.create(
            self.app.id, 'drycc-app', spec={'hard': hard}, ignore_exception=False)
        with self.settings(DRYCC_RESOURCE_QUOTA_TEMPLATE=''):
            data = self.app.quota
        self.assertEqual(data['metadata']['name'], 'drycc-app')
        self.assertEqual(data['spec']['hard'], hard)

    def test_missing_resource_quota_property_returns_none(self, mock_requests):
        self.assertIsNone(self.app.quota)

    def write_resource_quota(self, hard, used=None):
        self.scheduler.resourcequotas.create(
            self.app.id, 'drycc-app', spec={'hard': hard}, ignore_exception=False)
        if used is not None:
            response = self.scheduler.resourcequotas.get(
                self.app.id, 'drycc-app', ignore_exception=False)
            data = response.json()
            data['status'] = {'hard': hard, 'used': used}
            response = self.scheduler.http_put(
                f'/api/v1/namespaces/{self.app.id}/resourcequotas/drycc-app', json=data)
            self.assertEqual(response.status_code, 200, response.json())

    def test_quota_api_returns_hard_and_used(self, mock_requests):
        hard = {'pods': '50', 'requests.cpu': '10'}
        used = {'pods': '12', 'requests.cpu': '2500m'}
        self.write_resource_quota(hard, used)
        with self.settings(DRYCC_RESOURCE_QUOTA_TEMPLATE=''):
            response = self.client.get(f'/v2/apps/{self.app.id}/quota/')
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.data, {'name': 'drycc-app', 'hard': hard, 'used': used})

    def test_quota_api_defaults_missing_used_to_empty_dict(self, mock_requests):
        self.write_resource_quota({'pods': '50'})
        response = self.client.get(f'/v2/apps/{self.app.id}/quota/')
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.data['used'], {})

    def test_quota_api_returns_404_for_missing_quota(self, mock_requests):
        response = self.client.get(f'/v2/apps/{self.app.id}/quota/')
        self.assertEqual(response['Content-Type'], 'application/json')
        self.assertEqual(response.status_code, 404, response.content)

    def test_quota_api_returns_503_for_kubernetes_failure(self, mock_requests):
        with mock.patch.object(App, 'scheduler', new_callable=mock.PropertyMock) as prop:
            prop.return_value = self.scheduler
            with mock.patch.object(self.scheduler.resourcequotas, 'get') as get:
                get.return_value = scheduler_response(500, reason='Internal Error')
                response = self.client.get(f'/v2/apps/{self.app.id}/quota/')
        self.assertEqual(response.status_code, 503, response.content)

    def test_quota_api_allows_workspace_viewer(self, mock_requests):
        self.write_resource_quota({'pods': '50'}, {'pods': '12'})
        viewer = User.objects.get(username='autotest2')
        WorkspaceMember.objects.create(
            workspace=self.workspace, user=viewer, role='viewer')
        token = self.get_or_create_token(viewer)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token)
        response = self.client.get(f'/v2/apps/{self.app.id}/quota/')
        self.assertEqual(response.status_code, 200, response.content)

    def test_quota_api_rejects_non_member(self, mock_requests):
        self.write_resource_quota({'pods': '50'})
        other = User.objects.get(username='autotest2')
        token = self.get_or_create_token(other)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token)
        response = self.client.get(f'/v2/apps/{self.app.id}/quota/')
        self.assertEqual(response['Content-Type'], 'application/json')
        self.assertEqual(response.status_code, 404, response.content)

    def test_default_workspace_app_limit(self, mock_requests):
        for index in range(2, 11):
            App.objects.create(id=f'defaultapp{index:02d}', workspace=self.workspace)
        with self.assertRaises(Conflict):
            App.objects.create(id='defaultapp11', workspace=self.workspace)
        self.assertEqual(App.objects.filter(workspace=self.workspace).count(), 10)

    def test_workspace_app_limit(self, mock_requests):
        with self.settings(DRYCC_WORKSPACE_MAX_APPS=2):
            App.objects.create(id='quotaapp02', workspace=self.workspace)
            response = self.client.post(
                '/v2/apps', {'id': 'quotaapp03', 'workspace': self.workspace.id})
        self.assertEqual(response.status_code, 409, response.data)
        self.assertEqual(App.objects.filter(workspace=self.workspace).count(), 2)

    def test_workspace_app_limit_disabled(self, mock_requests):
        with self.settings(DRYCC_WORKSPACE_MAX_APPS=0):
            App.objects.create(id='quotaapp02', workspace=self.workspace)
            App.objects.create(id='quotaapp03', workspace=self.workspace)
        self.assertEqual(App.objects.filter(workspace=self.workspace).count(), 3)

    def test_workspace_app_limits_are_independent(self, mock_requests):
        other = Workspace.objects.create(id='quotaother', email='quotaother@example.com')
        with self.settings(DRYCC_WORKSPACE_MAX_APPS=1):
            App.objects.create(id='quotaapp02', workspace=other)
            with self.assertRaises(Conflict):
                App.objects.create(id='quotaapp03', workspace=other)
        self.assertEqual(App.objects.filter(workspace=self.workspace).count(), 1)
        self.assertEqual(App.objects.filter(workspace=other).count(), 1)

    def test_archived_app_consumes_workspace_slot(self, mock_requests):
        App.objects.filter(pk=self.app.pk).update(archived=True)
        with self.settings(DRYCC_WORKSPACE_MAX_APPS=1):
            with self.assertRaises(Conflict):
                App.objects.create(id='quotaapp02', workspace=self.workspace)

    def test_deleting_app_frees_workspace_slot(self, mock_requests):
        self.app.delete()
        with self.settings(DRYCC_WORKSPACE_MAX_APPS=1):
            App.objects.create(id='quotaapp02', workspace=self.workspace)
        self.assertEqual(App.objects.filter(workspace=self.workspace).count(), 1)

    def test_app_transfer_checks_destination_workspace(self, mock_requests):
        destination = Workspace.objects.create(id='quotadest01', email='dest@example.com')
        App.objects.create(id='quotaapp02', workspace=destination)
        self.app.workspace = destination
        with self.settings(DRYCC_WORKSPACE_MAX_APPS=1):
            with self.assertRaises(Conflict):
                self.app.save()

    def test_app_transfer_to_available_workspace(self, mock_requests):
        destination = Workspace.objects.create(id='quotadest02', email='dest@example.com')
        self.app.workspace = destination
        with self.settings(DRYCC_WORKSPACE_MAX_APPS=1):
            self.app.save()
        self.assertEqual(App.objects.filter(workspace=destination).count(), 1)
        self.assertEqual(App.objects.filter(workspace=self.workspace).count(), 0)

    def test_existing_app_save_and_provisioning_at_limit(self, mock_requests):
        with self.settings(DRYCC_WORKSPACE_MAX_APPS=1):
            self.app.save()
            self.app.create()
        self.assertTrue(App.objects.filter(pk=self.app.pk).exists())

    def test_workspace_app_limit_lock_failure(self, mock_requests):
        with mock.patch('api.models.app.CacheLock.acquire', return_value=False):
            with self.settings(DRYCC_WORKSPACE_MAX_APPS=2):
                with self.assertRaises(ServiceUnavailable):
                    App.objects.create(id='quotaapp02', workspace=self.workspace)


@requests_mock.Mocker(real_http=True, adapter=adapter)
class AppWorkspaceLimitConcurrencyTest(DryccTransactionTestCase):
    fixtures = ['tests.json']

    def setUp(self):
        self.workspace = Workspace.objects.create(
            id='quotaconcur', email='quotaconcur@example.com')

    def tearDown(self):
        cache.clear()
        connections.close_all()

    def test_parallel_creation_never_exceeds_workspace_limit(self, mock_requests):
        attempts = 8
        limit = 3

        def create(index):
            try:
                App.objects.create(id=f'parallel{index:02d}', workspace=self.workspace)
                return 'created'
            except Conflict:
                return 'conflict'
            finally:
                connection.close()

        with self.settings(DRYCC_WORKSPACE_MAX_APPS=limit):
            with mock.patch.object(App, 'create', autospec=True, return_value=None):
                with ThreadPoolExecutor(max_workers=attempts) as executor:
                    results = list(executor.map(create, range(attempts)))

        self.assertEqual(results.count('created'), limit, results)
        self.assertEqual(results.count('conflict'), attempts - limit, results)
        self.assertEqual(App.objects.filter(workspace=self.workspace).count(), limit)
