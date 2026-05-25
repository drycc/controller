"""
Unit tests for the alerts hook (POST /v2/alerts).

Run the tests with "./manage.py test api"
"""
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.cache import cache
import requests_mock

from api.models.workspace import Workspace, WorkspaceMember
from api.tests import DryccTestCase

User = get_user_model()


@requests_mock.Mocker(real_http=True, adapter=requests_mock.Adapter())
class AlertsHookTest(DryccTestCase):
    """Tests POST /v2/alerts ingestion and Celery dispatch."""

    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = self.get_or_create_token(self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Bearer mock_oauth_token')

        self.delay_patcher = mock.patch('api.views.dispatch_alert_message.delay')
        self.mock_delay = self.delay_patcher.start()

    def tearDown(self):
        self.delay_patcher.stop()
        cache.clear()

    @staticmethod
    def _payload(workspace, alerts=None):
        return {"workspace": workspace, "alerts": alerts or []}

    @staticmethod
    def _make_workspace(id, members):
        ws, _ = Workspace.objects.get_or_create(
            id=id, defaults={'email': f'{id}@example.com'},
        )
        for user, alerts in members:
            WorkspaceMember.objects.update_or_create(
                workspace=ws, user=user,
                defaults={'role': 'member', 'alerts': alerts},
            )
        return ws

    # ── validation ──────────────────────────────────────────────────────

    def test_missing_workspace_returns_400(self, mock_requests):
        response = self.client.post(
            '/v2/alerts', data={"alerts": []}, format='json',
        )
        self.assertEqual(response.status_code, 400, response.data)

    def test_empty_alerts_returns_no_content(self, mock_requests):
        opted_in = User.objects.get(username='autotest2')
        self._make_workspace('emptyws', [(opted_in, True)])

        response = self.client.post(
            '/v2/alerts', data=self._payload('emptyws'), format='json',
        )
        self.assertEqual(response.status_code, 204, getattr(response, 'data', None))
        self.mock_delay.assert_not_called()

    def test_unknown_workspace_returns_no_content(self, mock_requests):
        response = self.client.post(
            '/v2/alerts',
            data=self._payload('nosuch', alerts=[{"title": "x"}]),
            format='json',
        )
        self.assertEqual(response.status_code, 204, getattr(response, 'data', None))
        self.mock_delay.assert_not_called()

    # ── workspace branch ──────────────────────────────────────────────

    def test_workspace_alerts_filters_opted_out_members(self, mock_requests):
        opted_in = User.objects.get(username='autotest2')
        opted_out = User.objects.get(username='autotest3')
        self._make_workspace('teamone', [(opted_in, True), (opted_out, False)])

        response = self.client.post(
            '/v2/alerts',
            data=self._payload('teamone', alerts=[{"title": "x"}]),
            format='json',
        )
        self.assertEqual(response.status_code, 204, getattr(response, 'data', None))
        self.mock_delay.assert_called_once()
        usernames, _ = self.mock_delay.call_args.args
        self.assertEqual(set(usernames), {'autotest2'})

    def test_workspace_with_no_opted_in_members_skips_dispatch(self, mock_requests):
        opted_out = User.objects.get(username='autotest3')
        self._make_workspace('teamtwo', [(opted_out, False)])

        response = self.client.post(
            '/v2/alerts',
            data=self._payload('teamtwo', alerts=[{"title": "x"}]),
            format='json',
        )
        self.assertEqual(response.status_code, 204, getattr(response, 'data', None))
        self.mock_delay.assert_not_called()

    def test_multiple_alerts_queue_per_alert(self, mock_requests):
        opted_in = User.objects.get(username='autotest2')
        self._make_workspace('teamthree', [(opted_in, True)])

        alerts = [
            {"title": "a", "content": "desc a", "severity": "warning"},
            {"title": "b", "content": "desc b", "severity": "success"},
        ]
        response = self.client.post(
            '/v2/alerts',
            data=self._payload('teamthree', alerts=alerts),
            format='json',
        )
        self.assertEqual(response.status_code, 204, getattr(response, 'data', None))
        self.assertEqual(self.mock_delay.call_count, 2)

    # ── drycc branch ──────────────────────────────────────────────────

    def test_drycc_workspace_resolves_to_staff_and_superuser(self, mock_requests):
        # Fixture: autotest is staff+superuser; autotest2/3/4 are neither.
        response = self.client.post(
            '/v2/alerts',
            data=self._payload('drycc', alerts=[{"title": "x"}]),
            format='json',
        )
        self.assertEqual(response.status_code, 204, getattr(response, 'data', None))
        self.mock_delay.assert_called_once()
        usernames, _ = self.mock_delay.call_args.args
        self.assertEqual(set(usernames), {'autotest'})

    # ── message passthrough ─────────────────────────────────────────────

    def test_alert_message_passed_through_untouched(self, mock_requests):
        opted_in = User.objects.get(username='autotest2')
        self._make_workspace('passthrough', [(opted_in, True)])

        alert = {
            "title": "the title",
            "content": "the content",
            "severity": "error",
            "action_link": "http://example.com",
            "action_text": "Click me",
        }
        response = self.client.post(
            '/v2/alerts',
            data=self._payload('passthrough', alerts=[alert]),
            format='json',
        )
        self.assertEqual(response.status_code, 204, getattr(response, 'data', None))
        self.mock_delay.assert_called_once()
        _, message = self.mock_delay.call_args.args
        self.assertEqual(message['title'], 'the title')
        self.assertEqual(message['content'], 'the content')
        self.assertEqual(message['severity'], 'error')
        self.assertEqual(message['action_link'], 'http://example.com')
        self.assertEqual(message['action_text'], 'Click me')

    def test_alert_message_without_optional_fields(self, mock_requests):
        opted_in = User.objects.get(username='autotest2')
        self._make_workspace('minimal', [(opted_in, True)])

        alert = {"title": "minimal", "content": "x", "severity": "info"}
        response = self.client.post(
            '/v2/alerts',
            data=self._payload('minimal', alerts=[alert]),
            format='json',
        )
        self.assertEqual(response.status_code, 204, getattr(response, 'data', None))
        self.mock_delay.assert_called_once()
        _, message = self.mock_delay.call_args.args
        self.assertEqual(message['title'], 'minimal')
        self.assertNotIn('action_link', message)
        self.assertNotIn('action_text', message)
