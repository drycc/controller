import requests_mock
from unittest import mock

from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.contrib.auth import get_user_model

from api.exceptions import Conflict
from api.management.commands.load_db_state_to_k8s import Command
from api.models.app import App
from api.models.workspace import WorkspaceMember
from api.tests import adapter, DryccTestCase
from api.views.app import AppViewSet
from scheduler import KubeException

User = get_user_model()


@requests_mock.Mocker(real_http=True, adapter=adapter)
class AppArchiveTest(DryccTestCase):
    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = self.get_or_create_token(self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)
        self.workspace_id = self._ensure_workspace_admin(self._default_workspace_id())

    def tearDown(self):
        cache.clear()

    def test_archive_and_unarchive_app(self, mock_requests):
        app_id = self.create_app(workspace=self.workspace_id)
        archive_url = f'/v2/apps/{app_id}/archive'
        unarchive_url = f'/v2/apps/{app_id}/unarchive'

        response = self.client.post(archive_url)
        self.assertEqual(response.status_code, 204)
        app = App.objects.get(id=app_id)
        self.assertTrue(app.archived)

        response = self.client.post(archive_url)
        self.assertEqual(response.status_code, 409, response.data)

        response = self.client.post(unarchive_url)
        self.assertEqual(response.status_code, 204, response.data)
        app.refresh_from_db()
        self.assertFalse(app.archived)
        response = self.client.get(f'/v2/apps/{app_id}')
        self.assertFalse(response.data['archived'])

        response = self.client.post(unarchive_url)
        self.assertEqual(response.status_code, 409, response.data)

    def test_archived_app_rejects_regular_requests(self, mock_requests):
        app_id = self.create_app(workspace=self.workspace_id)
        app_url = f'/v2/apps/{app_id}'
        self.client.post(f'{app_url}/archive')

        response = self.client.get(app_url)
        self.assertEqual(response.status_code, 409, response.data)

        response = self.client.patch(app_url, {'workspace': self.workspace_id})
        self.assertEqual(response.status_code, 409, response.data)

    def test_archive_requires_workspace_admin(self, mock_requests):
        app_id = self.create_app(workspace=self.workspace_id)
        WorkspaceMember.objects.filter(
            workspace__id=self.workspace_id, user=self.user).update(role='member')

        response = self.client.post(f'/v2/apps/{app_id}/archive')

        self.assertEqual(response.status_code, 403, response.data)
        self.assertFalse(App.objects.get(id=app_id).archived)

    def test_archived_app_preserves_permission_responses(self, mock_requests):
        app_id = self.create_app(workspace=self.workspace_id)
        self.client.post(f'/v2/apps/{app_id}/archive')
        viewer = User.objects.get(username='autotest2')
        WorkspaceMember.objects.create(
            workspace=App.objects.get(id=app_id).workspace,
            user=viewer,
            role='viewer',
        )
        viewer_token = self.get_or_create_token(viewer)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + viewer_token)
        response = self.client.patch(f'/v2/apps/{app_id}', {'workspace': self.workspace_id})
        self.assertEqual(response.status_code, 403, response.data)

        other_user = User.objects.get(username='autotest3')
        other_token = self.get_or_create_token(other_user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + other_token)
        response = self.client.patch(f'/v2/apps/{app_id}', {'workspace': self.workspace_id})
        self.assertEqual(response.status_code, 404, response.data)

    def test_has_app_access_preserves_archived_error(self, mock_requests):
        try:
            from api.permissions import HasAppAccess
        except ImportError as error:
            self.fail(f'HasAppAccess is not implemented: {error}')
        app_id = self.create_app(workspace=self.workspace_id)
        app = App.objects.get(id=app_id)
        App.objects.filter(id=app_id).update(archived=True)
        app.refresh_from_db()
        viewset = AppViewSet()
        viewset.action = 'retrieve'
        request = mock.Mock(method='GET', user=self.user)

        with self.assertRaises(Conflict):
            HasAppAccess().has_object_permission(request, viewset, app)

    def test_non_app_object_is_configuration_error(self, mock_requests):
        viewset = AppViewSet()
        viewset.action = 'retrieve'
        request = mock.Mock(method='GET', user=self.user)

        with self.assertRaises(ImproperlyConfigured):
            viewset.check_object_permissions(request, object())

    def test_archive_failures_keep_archived_state(self, mock_requests):
        app_id = self.create_app(workspace=self.workspace_id)
        app = App.objects.get(id=app_id)

        with mock.patch('api.models.app.NamespaceArchiver') as archiver_class:
            archiver = archiver_class.return_value
            archiver.archive.side_effect = KubeException('archive failed')
            response = self.client.post(f'/v2/apps/{app_id}/archive')
            self.assertEqual(response.status_code, 503, response.data)
            app.refresh_from_db()
            self.assertTrue(app.archived)

            archiver.unarchive.side_effect = KubeException('unarchive failed')
            response = self.client.post(f'/v2/apps/{app_id}/unarchive')
            self.assertEqual(response.status_code, 503, response.data)
            app.refresh_from_db()
            self.assertTrue(app.archived)

            archiver.unarchive.side_effect = None
            response = self.client.post(f'/v2/apps/{app_id}/unarchive')
            self.assertEqual(response.status_code, 204, response.data)
            app.refresh_from_db()
            self.assertFalse(app.archived)

    def test_archived_app_rejects_build_and_config_hooks(self, mock_requests):
        app_id = self.create_app(workspace=self.workspace_id)
        App.objects.filter(id=app_id).update(archived=True)
        data = {'receive_repo': app_id, 'receive_user': self.user.username}
        self.client.credentials(HTTP_AUTHORIZATION='Bearer test-token')

        response = self.client.post('/v2/hooks/build', data)
        self.assertEqual(response.status_code, 409, response.data)

        response = self.client.post('/v2/hooks/config', data)
        self.assertEqual(response.status_code, 409, response.data)

    def test_hooks_check_manager_app_status(self, mock_requests):
        app_id = self.create_app(workspace=self.workspace_id)
        data = {'receive_repo': app_id, 'receive_user': self.user.username}
        self.client.credentials(HTTP_AUTHORIZATION='Bearer test-token')

        with mock.patch(
            'api.clients.ManagerAPI.get_app_status',
            return_value=(False, 'app inactive'),
        ):
            response = self.client.post('/v2/hooks/build', data)
            self.assertEqual(response.status_code, 403, response.data)

            response = self.client.post('/v2/hooks/config', data)
            self.assertEqual(response.status_code, 403, response.data)

            response = self.client.get(f'/v2/hooks/keys/{app_id}/{self.user.username}/')
            self.assertEqual(response.status_code, 403, response.data)

    def test_archived_app_skips_state_sync_with_stale_model(self, mock_requests):
        app_id = self.create_app(workspace=self.workspace_id)
        App.objects.filter(id=app_id).update(archived=True)
        app = App.objects.get(id=app_id)
        app.archived = False

        with mock.patch('api.models.app.Release.latest') as latest:
            app.state_to_k8s()

        latest.assert_not_called()

    def test_load_db_state_skips_archived_app_deploy(self, mock_requests):
        active_id = self.create_app(workspace=self.workspace_id)
        archived_id = self.create_app(workspace=self.workspace_id)
        App.objects.filter(id=archived_id).update(archived=True)

        with (
            mock.patch.object(Command, 'save_apps'),
            mock.patch.object(Command, '_deploy') as deploy,
        ):
            Command().handle()

        deployed_ids = [call.args[0].id for call in deploy.call_args_list]
        self.assertIn(active_id, deployed_ids)
        self.assertNotIn(archived_id, deployed_ids)
