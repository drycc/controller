from django.contrib.auth import get_user_model
from django.core.cache import cache
from unittest import mock

from api.models.workspace import Workspace, WorkspaceMember, WorkspaceInvitation
from api.tests import DryccTestCase

User = get_user_model()


class WorkspaceTest(DryccTestCase):
    """Tests creation and management of workspaces"""

    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = self.get_or_create_token(self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

        self.user2 = User.objects.get(username='autotest2')
        self.token2 = self.get_or_create_token(self.user2)

    def tearDown(self):
        cache.clear()

    def test_workspace_lifecycle(self):
        """Test workspace create, list, retrieve, update, delete"""
        # Create
        response = self.client.post(
            '/v2/workspaces', {'name': 'testworkspace', 'email': 'test@example.com'}
        )
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data['name'], 'testworkspace')

        # Verify admin member created
        workspace = Workspace.objects.get(name='testworkspace')
        self.assertTrue(workspace.has_member(self.user, role='admin'))

        # List
        response = self.client.get('/v2/workspaces')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 1)

        # Retrieve
        response = self.client.get('/v2/workspaces/testworkspace')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data['name'], 'testworkspace')

        # Update (personal workspace NOT allowed)
        response = self.client.patch(
            f'/v2/workspaces/{self.user.username}', {'email': 'new@example.com'}
        )
        self.assertEqual(response.status_code, 404, response.data)

        # Update
        response = self.client.patch('/v2/workspaces/testworkspace', {'email': 'new@example.com'})
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data['email'], 'new@example.com')

        # Delete
        response = self.client.delete('/v2/workspaces/testworkspace')
        self.assertEqual(response.status_code, 204, response.data)

    def test_workspace_isolation(self):
        # User 1 creates workspace
        self.client.post('/v2/workspaces', {'name': 'testisolated', 'email': 'test@example.com'})

        # User 2 tries to access User 1's workspace
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token2)
        response = self.client.get('/v2/workspaces/testisolated')
        self.assertEqual(response.status_code, 404, response.data)  # Not found for user2


class WorkspaceMemberTest(DryccTestCase):
    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.user2 = User.objects.get(username='autotest2')
        self.token = self.get_or_create_token(self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

        # Create a workspace
        self.client.post('/v2/workspaces', {'name': 'testmembers', 'email': 'test@example.com'})
        self.workspace = Workspace.objects.get(name='testmembers')

    def test_member_management(self):
        # Add member via DB (since POST /members is not supported, users join via invitations)
        WorkspaceMember.objects.create(user=self.user2, workspace=self.workspace, role='member')

        # List members
        response = self.client.get('/v2/workspaces/testmembers/members')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 2)

        # Update member role (admin updating user2)
        response = self.client.patch(
            f'/v2/workspaces/testmembers/members/{self.user2.username}', {'role': 'viewer'}
        )
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data['role'], 'viewer')

        # Non-admin user2 cannot update other members
        token2 = self.get_or_create_token(self.user2)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token2)
        response = self.client.patch(
            f'/v2/workspaces/testmembers/members/{self.user.username}', {'role': 'viewer'}
        )
        self.assertEqual(response.status_code, 403, response.data)

        # Admin delete member
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)
        response = self.client.delete(f'/v2/workspaces/testmembers/members/{self.user2.username}')
        self.assertEqual(response.status_code, 204, response.data)


class WorkspaceInvitationTest(DryccTestCase):
    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.user2 = User.objects.get(username='autotest2')
        self.token = self.get_or_create_token(self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

        self.client.post('/v2/workspaces', {'name': 'testinvite', 'email': 'test@example.com'})
        self.workspace = Workspace.objects.get(name='testinvite')

    @mock.patch('api.models.workspace.send_mail')
    def test_invitation_lifecycle(self, mock_send_mail):
        # Create invitation
        response = self.client.post(
            '/v2/workspaces/testinvite/invitations', {'email': self.user2.email}
        )
        self.assertEqual(response.status_code, 201, response.data)
        mock_send_mail.assert_called_once()

        invitation = WorkspaceInvitation.objects.get(email=self.user2.email)

        # List invitations
        response = self.client.get('/v2/workspaces/testinvite/invitations')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 1)

        # Accept invitation (retrieve with UID)
        response = self.client.get(f'/v2/workspaces/testinvite/invitations/{invitation.token}')
        self.assertEqual(response.status_code, 200, response.data)

        # Verify user became a member
        self.assertTrue(
            WorkspaceMember.objects.filter(
                workspace=self.workspace,
                user=self.user2
            ).exists()
        )

        # Test delete invitation
        response = self.client.post(
            '/v2/workspaces/testinvite/invitations', {'email': 'test-invite2@example.com'}
        )
        invitation2 = WorkspaceInvitation.objects.get(email='test-invite2@example.com')
        response = self.client.delete(
            f'/v2/workspaces/testinvite/invitations/{invitation2.token}'
        )
        self.assertEqual(response.status_code, 204, response.data)
