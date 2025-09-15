import logging
import random
import requests_mock
import time
import unittest
from os.path import dirname, realpath

from django.test.runner import DiscoverRunner
from rest_framework.test import APITestCase, APITransactionTestCase

from api.models.base import Token


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

    def create_app(self, name=None):
        body = {}
        if name:
            body = {'id': name}

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
