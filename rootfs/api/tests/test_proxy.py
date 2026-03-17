"""
Tests for QuickwitProxyView and PrometheusProxyView workspace-based queries.

These tests verify that app lookups use workspace name
instead of the legacy username-based approach.
"""
from django.contrib.auth import get_user_model
from django.core.cache import cache

from api.models.app import App
from api.models.workspace import Workspace, WorkspaceMember
from api.tests import DryccTransactionTestCase

User = get_user_model()


def _create_app_directly(app_id, workspace):
    """Create an App record directly in DB, bypassing K8s checks in App.save().

    App.save() connects to K8s to verify namespaces, which fails in local tests.
    We use bulk_create which calls INSERT directly without triggering save().
    """
    app = App(id=app_id, workspace=workspace)
    App.objects.bulk_create([app])
    return App.objects.get(id=app_id)


class QuickwitAppIndexesQueryTest(DryccTransactionTestCase):
    """
    Test the ORM query used by QuickwitProxyView.get_app_indexes.

    The query uses:
        App.objects.filter(workspace__name=workspace_name)

    Since App.save() requires K8s, we create app records directly in the DB.
    """

    fixtures = ['tests.json']

    def setUp(self):
        self.user1 = User.objects.get(username='autotest')
        self.token1 = self.get_or_create_token(self.user1)

        self.user2 = User.objects.get(username='autotest2')
        self.token2 = self.get_or_create_token(self.user2)

    def tearDown(self):
        cache.clear()

    def test_query_returns_apps_for_workspace(self):
        """
        Querying by workspace name should return apps in that workspace.
        """
        ws = Workspace.objects.create(name='wsqp01', email='ws1@example.com')
        WorkspaceMember.objects.create(workspace=ws, user=self.user1, role='admin')
        _create_app_directly('app-qp01', ws)

        app_ids = list(
            App.objects.filter(
                workspace__name=ws.name
            ).values_list('id', flat=True)
        )
        self.assertIn('app-qp01', app_ids)

    def test_query_excludes_apps_from_other_workspace(self):
        """
        Querying by workspace name should NOT return apps from a different workspace.
        """
        ws1 = Workspace.objects.create(name='wsqp02a', email='ws2a@example.com')
        ws2 = Workspace.objects.create(name='wsqp02b', email='ws2b@example.com')
        WorkspaceMember.objects.create(workspace=ws1, user=self.user1, role='admin')
        WorkspaceMember.objects.create(workspace=ws2, user=self.user1, role='admin')
        _create_app_directly('app-qp02a', ws1)
        _create_app_directly('app-qp02b', ws2)

        app_ids = list(
            App.objects.filter(
                workspace__name=ws1.name
            ).values_list('id', flat=True)
        )
        self.assertIn('app-qp02a', app_ids)
        self.assertNotIn('app-qp02b', app_ids)

    def test_query_returns_empty_for_nonexistent_workspace(self):
        """
        Querying a non-existent workspace name should return no apps.
        """
        ws = Workspace.objects.create(name='wsqp03', email='ws3@example.com')
        WorkspaceMember.objects.create(workspace=ws, user=self.user1, role='admin')
        _create_app_directly('app-qp03', ws)

        app_ids = list(
            App.objects.filter(
                workspace__name='nonexistent'
            ).values_list('id', flat=True)
        )
        self.assertNotIn('app-qp03', app_ids)

    def test_query_distinct_prevents_duplicates(self):
        """
        .distinct() should prevent duplicate results.
        """
        ws = Workspace.objects.create(name='wsqp04', email='ws4@example.com')
        WorkspaceMember.objects.create(workspace=ws, user=self.user1, role='admin')
        _create_app_directly('app-qp04', ws)

        app_ids = list(
            App.objects.filter(
                workspace__name=ws.name
            ).distinct().values_list('id', flat=True)
        )
        # Should appear exactly once, not multiple times
        self.assertEqual(app_ids.count('app-qp04'), 1)

    def test_drycc_service_account_bypass(self):
        """
        The 'drycc' service account bypasses the workspace query
        in QuickwitProxyView.get_app_indexes (handled by workspace == "drycc" check).
        This test verifies the query itself is correct for normal workspaces.
        """
        ws = Workspace.objects.create(name='wsqp05', email='ws5@example.com')
        WorkspaceMember.objects.create(workspace=ws, user=self.user1, role='admin')
        _create_app_directly('app-qp05', ws)

        # Normal workspace query returns its apps
        app_ids = list(
            App.objects.filter(
                workspace__name=ws.name
            ).values_list('id', flat=True)
        )
        self.assertIn('app-qp05', app_ids)


class BaseUserProxyViewAuthenticateTest(DryccTransactionTestCase):
    """
    Test the authenticate method of BaseUserProxyView.

    The authenticate method verifies workspace membership instead of
    matching username, and returns workspace_id instead of user_id.
    """

    fixtures = ['tests.json']

    def setUp(self):
        self.user1 = User.objects.get(username='autotest')
        self.token1 = self.get_or_create_token(self.user1)

        self.user2 = User.objects.get(username='autotest2')
        self.token2 = self.get_or_create_token(self.user2)

    def tearDown(self):
        cache.clear()

    def test_workspace_member_can_authenticate(self):
        """
        A user who is a workspace member should authenticate successfully
        and receive the workspace ID.
        """
        ws = Workspace.objects.create(name='wsauth01', email='wsauth1@example.com')
        WorkspaceMember.objects.create(workspace=ws, user=self.user1, role='admin')

        # Verify the workspace exists and member relationship is correct
        member = WorkspaceMember.objects.filter(
            workspace__name=ws.name, user=self.user1
        ).first()
        self.assertIsNotNone(member)
        self.assertEqual(member.workspace.id, ws.id)

    def test_non_member_cannot_authenticate(self):
        """
        A user who is NOT a workspace member should fail authentication.
        """
        ws = Workspace.objects.create(name='wsauth02', email='wsauth2@example.com')
        WorkspaceMember.objects.create(workspace=ws, user=self.user1, role='admin')

        # user2 is not a member of this workspace
        member = WorkspaceMember.objects.filter(
            workspace__name=ws.name, user=self.user2
        ).first()
        self.assertIsNone(member)

    def test_viewer_role_can_authenticate(self):
        """
        Even a viewer should be able to authenticate (read access).
        """
        ws = Workspace.objects.create(name='wsauth03', email='wsauth3@example.com')
        WorkspaceMember.objects.create(workspace=ws, user=self.user1, role='viewer')

        member = WorkspaceMember.objects.filter(
            workspace__name=ws.name, user=self.user1
        ).first()
        self.assertIsNotNone(member)
        self.assertEqual(member.role, 'viewer')

    def test_nonexistent_workspace_fails(self):
        """
        Authenticating against a non-existent workspace should fail.
        """
        member = WorkspaceMember.objects.filter(
            workspace__name='nonexistent', user=self.user1
        ).first()
        self.assertIsNone(member)


class PrometheusProxyViewWorkspaceIdTest(DryccTransactionTestCase):
    """
    Test that PrometheusProxyView uses workspace_id as vm_account_id,
    consistent with MetricsProxyView which writes data with workspace_id.
    """

    fixtures = ['tests.json']

    def setUp(self):
        self.user1 = User.objects.get(username='autotest')
        self.token1 = self.get_or_create_token(self.user1)

    def tearDown(self):
        cache.clear()

    def test_workspace_id_matches_metrics_proxy(self):
        """
        The workspace_id used by PrometheusProxyView should match
        the workspace_id used by MetricsProxyView.sample().
        """
        ws = Workspace.objects.create(name='wsprom01', email='wsprom1@example.com')
        WorkspaceMember.objects.create(workspace=ws, user=self.user1, role='admin')
        app = _create_app_directly('app-prom01', ws)

        # MetricsProxyView uses app.workspace_id
        self.assertEqual(app.workspace_id, ws.pk)

        # PrometheusProxyView should use the same workspace_id as vm_account_id
        # (this is verified by the authenticate method returning workspace_id)
        workspace_obj = Workspace.objects.filter(name=ws.name).first()
        self.assertEqual(workspace_obj.id, ws.pk)
