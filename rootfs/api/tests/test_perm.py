from django.test import tag
from django.contrib.auth import get_user_model

from api.tests import DryccTestCase
from api.models.workspace import WorkspaceMember
from api.models.app import App


User = get_user_model()


class TestWorkspacePerm(DryccTestCase):

    fixtures = ['tests.json']

    @tag('auth')
    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = self.get_or_create_token(self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

        self.user2 = User.objects.get(username='autotest2')
        self.token2 = self.get_or_create_token(self.user2)

    @tag('auth')
    def _create_workspace_and_app(self, ws_name='testws01', app_id='testapp01'):
        response = self.client.post('/v2/workspaces', {
            'name': ws_name,
            'email': 'ws@example.com',
        })
        self.assertEqual(response.status_code, 201, response.data)

        response = self.client.post('/v2/apps', {
            'id': app_id,
            'workspace': ws_name,
        })
        self.assertEqual(response.status_code, 201, response.data)
        return ws_name, app_id

    @tag('auth')
    def test_workspace_member_can_access_app(self):
        ws_name, app_id = self._create_workspace_and_app()

        # non-member cannot access app
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token2)
        response = self.client.get(f'/v2/apps/{app_id}')
        self.assertEqual(response.status_code, 404, response.data)

        # add user2 into workspace, then user2 can access app
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)
        workspace = WorkspaceMember.objects.get(user=self.user, workspace__name=ws_name).workspace
        WorkspaceMember.objects.get_or_create(
            user=self.user2,
            workspace=workspace,
            defaults={'role': 'member'},
        )

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token2)
        response = self.client.get(f'/v2/apps/{app_id}')
        self.assertEqual(response.status_code, 200, response.data)

    @tag('auth')
    def test_non_admin_cannot_manage_workspace_members(self):
        ws_name, _ = self._create_workspace_and_app(ws_name='testws02', app_id='testapp02')

        workspace = WorkspaceMember.objects.get(user=self.user, workspace__name=ws_name).workspace
        WorkspaceMember.objects.get_or_create(
            user=self.user2,
            workspace=workspace,
            defaults={'role': 'member'},
        )

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token2)
        response = self.client.patch(
            f'/v2/workspaces/{ws_name}/members/{self.user.username}',
            {'role': 'viewer'},
        )
        self.assertEqual(response.status_code, 403, response.data)

    @tag('auth')
    def test_admin_can_manage_workspace_members(self):
        ws_name, _ = self._create_workspace_and_app(ws_name='testws03', app_id='testapp03')

        workspace = WorkspaceMember.objects.get(user=self.user, workspace__name=ws_name).workspace
        WorkspaceMember.objects.get_or_create(
            user=self.user2,
            workspace=workspace,
            defaults={'role': 'member'},
        )

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)
        response = self.client.patch(
            f'/v2/workspaces/{ws_name}/members/{self.user2.username}',
            {'role': 'viewer'},
        )
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data['role'], 'viewer')

    @tag('auth')
    def test_non_member_cannot_run_app(self):
        _, app_id = self._create_workspace_and_app(ws_name='testws04', app_id='testapp04')

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token2)
        response = self.client.post(
            f'/v2/apps/{app_id}/run',
            {'command': 'echo hello'},
        )
        self.assertEqual(response.status_code, 404, response.data)

    @tag('auth')
    def test_workspace_member_can_run_but_without_build_gets_business_error(self):
        ws_name, app_id = self._create_workspace_and_app(ws_name='testws05', app_id='testapp05')
        workspace = WorkspaceMember.objects.get(user=self.user, workspace__name=ws_name).workspace
        WorkspaceMember.objects.get_or_create(
            user=self.user2,
            workspace=workspace,
            defaults={'role': 'member'},
        )

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token2)
        response = self.client.post(
            f'/v2/apps/{app_id}/run',
            {'command': 'echo hello'},
        )
        self.assertEqual(response.status_code, 400, response.data)
        self.assertEqual(
            str(response.data['detail']),
            'no build available, please deploy a release',
        )

    @tag('auth')
    def test_non_admin_cannot_update_workspace(self):
        ws_name, _ = self._create_workspace_and_app(ws_name='testws06', app_id='testapp06')
        workspace = WorkspaceMember.objects.get(user=self.user, workspace__name=ws_name).workspace
        WorkspaceMember.objects.get_or_create(
            user=self.user2,
            workspace=workspace,
            defaults={'role': 'member'},
        )

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token2)
        response = self.client.patch(
            f'/v2/workspaces/{ws_name}',
            {'email': 'new@example.com'},
        )
        self.assertEqual(response.status_code, 403, response.data)

    @tag('auth')
    def test_non_admin_cannot_transfer_app(self):
        ws_name, app_id = self._create_workspace_and_app(ws_name='testws07', app_id='testapp07')
        response = self.client.post('/v2/workspaces', {
            'name': 'testws08',
            'email': 'ws2@example.com',
        })
        self.assertEqual(response.status_code, 201, response.data)

        workspace = WorkspaceMember.objects.get(user=self.user, workspace__name=ws_name).workspace
        WorkspaceMember.objects.get_or_create(
            user=self.user2,
            workspace=workspace,
            defaults={'role': 'member'},
        )

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token2)
        response = self.client.patch(
            f'/v2/apps/{app_id}',
            {'workspace': 'testws08'},
        )
        self.assertEqual(response.status_code, 400, response.data)
        self.assertEqual(
            str(response.data['detail']),
            'you must be an admin of the current workspace',
        )

    @tag('auth')
    def test_admin_can_transfer_app(self):
        _, app_id = self._create_workspace_and_app(ws_name='testws09', app_id='testapp09')
        response = self.client.post('/v2/workspaces', {
            'name': 'testws10',
            'email': 'ws10@example.com',
        })
        self.assertEqual(response.status_code, 201, response.data)

        response = self.client.patch(
            f'/v2/apps/{app_id}',
            {'workspace': 'testws10'},
        )
        self.assertEqual(response.status_code, 204, response.data)

        app = App.objects.get(id=app_id)
        self.assertEqual(app.workspace.name, 'testws10')
