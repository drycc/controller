import logging
import random
import requests_mock
import time
import unittest
from os.path import dirname, realpath

from django.test.runner import DiscoverRunner
from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase, APITransactionTestCase

from api.models.base import Token
from api.models.workspace import Workspace, WorkspaceMember

User = get_user_model()


# Mock out router requests and add in some jitter
# Used for application is available in router checks
def fake_responses(request, context):
    responses = [
        # increasing the chance of 404
        {'text': 'Not Found', 'status_code': 404},
        {'text': 'Not Found', 'status_code': 404},
        {'text': 'Not Found', 'status_code': 404},
        {'text': 'Not Found', 'status_code': 404},
        {'text': 'OK', 'status_code': 200},
        {'text': 'Gateway timeout', 'status_code': 504},
        {'text': 'Bad gateway', 'status_code': 502},
    ]
    random.shuffle(responses)
    response = responses.pop()

    context.status_code = response['status_code']
    context.reason = response['text']
    # Random float x, 1.0 <= x < 4.0 for some sleep jitter
    time.sleep(random.uniform(1, 4))
    return response['text']


adapter = requests_mock.Adapter()
adapter.register_uri('GET', '/', text=fake_responses)
adapter.register_uri('GET', '/health', text=fake_responses)
adapter.register_uri('GET', '/healthz', text=fake_responses)

# Root of the test directory (for files and such)
TEST_ROOT = dirname(realpath(__file__))


class SilentDjangoTestSuiteRunner(DiscoverRunner):
    """Prevents api log messages from cluttering the console during tests."""

    def run_tests(self, test_labels, **kwargs):
        """Run tests with all but critical log messages disabled."""
        # hide any log messages less than critical
        logging.disable(logging.ERROR)
        return super(SilentDjangoTestSuiteRunner, self).run_tests(
            test_labels, **kwargs)


class DryccBaseTestCase(unittest.TestCase):

    def _get_authenticated_user(self):
        credentials = getattr(getattr(self, 'client', None), '_credentials', {})
        auth = credentials.get('HTTP_AUTHORIZATION', '')
        if auth.startswith('Token '):
            token_key = auth.split(' ', 1)[1]
            token = Token.objects.filter(key=token_key).select_related('owner').first()
            if token is not None:
                return token.owner
        return getattr(self, 'user', None)

    def _default_workspace_name(self):
        user = self._get_authenticated_user()
        if user and user.username:
            base = ''.join(ch for ch in user.username.lower() if ch.isalnum())
            if len(base) >= 5:
                return base
        return 'autotest'

    def _ensure_workspace_admin(self, workspace_name):
        user = self._get_authenticated_user()
        if user is None:
            user = User.objects.filter(username='autotest').first()
        if user is None:
            raise AssertionError('No test user available for workspace membership')

        workspace, _ = Workspace.objects.get_or_create(
            name=workspace_name,
            defaults={'email': user.email or f'{workspace_name}@example.com'},
        )
        WorkspaceMember.objects.update_or_create(
            workspace=workspace,
            user=user,
            defaults={'role': 'admin'},
        )
        return workspace.name

    def create_app(self, name=None, workspace=None):
        workspace_name = workspace or self._default_workspace_name()
        workspace_name = self._ensure_workspace_admin(workspace_name)

        body = {'workspace': workspace_name}
        if name:
            body['id'] = name

        response = self.client.post('/v2/apps', body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertIn('id', response.data)
        return response.data['id']

    def get_or_create_token(self, user):
        token, _ = Token.objects.get_or_create(
            owner=user,
            defaults={
                "oauth": {
                    "access_token": "test",
                    "expires_in": 3600 * 24 * 7,
                    "token_type": "Bearer",
                    "scope": "openid",
                    "refresh_token": "test",
                }
            }
        )
        return token.key

    def assertPodContains(self, pods, app_id, ptype, version, state="up"):
        for pod in pods:
            if (pod["type"] == ptype and
                    pod["release"] == version and pod["state"] == state):
                pod_name = app_id + '-%s-[0-9]{1,10}-[a-z0-9]{5}' % ptype
                self.assertRegex(pod['name'], pod_name)
                return
        raise ValueError(
            "pod not contains: ptype={}, version={}, state={}".format(
                ptype, version, state
            )
        )


class DryccTransactionTestCase(DryccBaseTestCase, APITransactionTestCase):
    pass


class DryccTestCase(DryccBaseTestCase, APITestCase):
    pass
