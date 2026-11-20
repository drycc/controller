"""Tests for scheduler ResourceQuota calls."""
from django.conf import settings

from scheduler import KubeHTTPException
from scheduler import mock as scheduler_mock
from scheduler.tests import TestCase
from scheduler.tests.utils import generate_random_name


class ResourceQuotaTest(TestCase):
    """Tests scheduler ResourceQuota calls."""

    def create_quota(self, namespace=None, name=None, **kwargs):
        namespace = namespace or self.namespace
        name = name or generate_random_name()
        spec = kwargs.pop('spec', {'hard': {'pods': '50', 'requests.cpu': '10'}})
        response = self.scheduler.resourcequotas.create(
            namespace, name, spec=spec, ignore_exception=False, **kwargs)
        self.assertEqual(response.status_code, 201, response.json())
        return name, response

    def test_create(self):
        name, response = self.create_quota()
        data = response.json()
        self.assertEqual(data['apiVersion'], 'v1')
        self.assertEqual(data['kind'], 'ResourceQuota')
        self.assertEqual(data['metadata']['name'], name)
        self.assertEqual(data['metadata']['namespace'], self.namespace)
        self.assertEqual(data['metadata']['labels']['heritage'], 'drycc')
        self.assertEqual(data['spec']['hard'], {'pods': '50', 'requests.cpu': '10'})

    def test_create_with_metadata_injection(self):
        scheduler = scheduler_mock.MockSchedulerClient(
            settings.SCHEDULER_URL,
            metadata={
                'labels': {'drycc.cc/app': 'test-app'},
                'annotations': {'app.kubernetes.io/managed-by': 'drycc'},
            },
        )
        response = scheduler.resourcequotas.create(
            self.namespace, 'drycc-app', spec={'hard': {'pods': '50'}}, ignore_exception=False)
        data = response.json()
        self.assertEqual(response.status_code, 201, data)
        self.assertEqual(data['metadata']['labels']['drycc.cc/app'], 'test-app')
        self.assertEqual(
            data['metadata']['annotations']['app.kubernetes.io/managed-by'], 'drycc')

    def test_get(self):
        name, _ = self.create_quota()
        response = self.scheduler.resourcequotas.get(
            self.namespace, name, ignore_exception=False)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data['metadata']['name'], name)
        self.assertEqual(data['spec']['hard'], {'pods': '50', 'requests.cpu': '10'})

    def test_list(self):
        name, _ = self.create_quota()
        response = self.scheduler.resourcequotas.get(self.namespace, ignore_exception=False)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(len(data['items']), 1, data)
        self.assertEqual(data['items'][0]['metadata']['name'], name)

    def test_get_ignore_exception(self):
        with self.assertRaises(KubeHTTPException):
            self.scheduler.resourcequotas.get(self.namespace, 'doesnotexist')
        response = self.scheduler.resourcequotas.get(
            self.namespace, 'doesnotexist', ignore_exception=True)
        self.assertEqual(response.status_code, 404, response.json())

    def test_create_failure_and_ignore_exception(self):
        with self.assertRaises(KubeHTTPException):
            self.scheduler.resourcequotas.create(
                'doesnotexist', 'drycc-app', spec={'hard': {'pods': '50'}})
        response = self.scheduler.resourcequotas.create(
            'doesnotexist', 'drycc-app', spec={'hard': {'pods': '50'}},
            ignore_exception=True)
        self.assertEqual(response.status_code, 404, response.json())
