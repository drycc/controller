"""
Unit tests for the Drycc scheduler module.

Run the tests with './manage.py test scheduler'
"""
import copy
from unittest import mock
from packaging.version import parse, Version, InvalidVersion
from scheduler import KubeHTTPException, KubeException
from scheduler.tests import TestCase
from scheduler.utils import generate_random_name


class DeploymentsTest(TestCase):
    """Tests scheduler deployment calls"""

    def create(self, namespace=None, name=generate_random_name(), **kwargs):
        """
        Helper function to create and verify a deployment on the namespace
        """
        namespace = self.namespace if namespace is None else namespace
        # these are all required even if it is kwargs...
        kwargs = {
            'app_type': kwargs.get('app_type', 'web'),
            'version': kwargs.get('version', 'v99'),
            'replicas': kwargs.get('replicas', 4),
            'pod_termination_grace_period_seconds': 2,
            'image': 'quay.io/fake/image',
            'command': 'sh',
            'args': 'start',
            'spec_annotations': kwargs.get('spec_annotations', {}),
        }

        deployment = self.scheduler.deployment.create(namespace, name, **kwargs)
        self.assertEqual(deployment.status_code, 201, deployment.json())
        return name

    def update(self, namespace=None, name=generate_random_name(), **kwargs):
        """
        Helper function to update and verify a deployment on the namespace
        """
        namespace = self.namespace if namespace is None else namespace
        # these are all required even if it is kwargs...
        kwargs = {
            'app_type': kwargs.get('app_type', 'web'),
            'version': kwargs.get('version', 'v99'),
            'replicas': kwargs.get('replicas', 4),
            'pod_termination_grace_period_seconds': 2,
            'image': 'quay.io/fake/image',
            'command': 'sh',
            'args': 'start',
            'spec_annotations': kwargs.get('spec_annotations', {}),
        }

        deployment = self.scheduler.deployment.update(namespace, name, **kwargs)
        data = deployment.json()
        self.assertEqual(deployment.status_code, 200, data)
        return name

    def scale(self, namespace=None, name=generate_random_name(), **kwargs):
        """
        Helper function to scale and verify a deployment on the namespace
        """
        namespace = self.namespace if namespace is None else namespace
        # these are all required even if it is kwargs...
        kwargs = {
            'app_type': kwargs.get('app_type', 'web'),
            'version': kwargs.get('version', 'v99'),
            'replicas': kwargs.get('replicas', 4),
            'pod_termination_grace_period_seconds': 2,
            'image': 'quay.io/fake/image',
            'command': 'sh',
            'args': 'start',
        }

        self.scheduler.scale(namespace, name, **kwargs)
        return name

    def test_good_init_api_version(self):
        try:
            data = "1.13"
            Version('{}'.format(data))
        except InvalidVersion:
            self.fail("Version {} raised InvalidVersion exception!".format(data))

    def test_bad_init_api_version(self):
        data = "1.13+"
        with self.assertRaises(
            InvalidVersion,
            msg='packaging.version.InvalidVersion: Invalid version: {}'.format(data)  # noqa
        ):
            Version('{}'.format(data))

    def test_deployment_api_version_1_9_and_up(self):
        cases = ['1.12', '1.11', '1.10', '1.9']

        deployment = copy.deepcopy(self.scheduler.deployment)

        expected = 'apps/v1'

        for canonical in cases:
            deployment.version = mock.MagicMock(return_value=parse(canonical))
            actual = deployment.api_version
            self.assertEqual(
                    expected,
                    actual,
                    "{} breaks - expected {}, got {}".format(
                        canonical,
                        expected,
                        actual))

    def test_deployment_api_version_1_8_and_lower(self):
        cases = ['1.8', '1.7', '1.6', '1.5', '1.4', '1.3', '1.2']

        deployment = copy.deepcopy(self.scheduler.deployment)

        expected = 'apps/v1'

        for canonical in cases:
            deployment.version = mock.MagicMock(return_value=parse(canonical))
            actual = deployment.api_version
            self.assertEqual(
                    expected,
                    actual,
                    "{} breaks - expected {}, got {}".format(
                        canonical,
                        expected,
                        actual))

    def test_create_failure(self):
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to create Deployment doesnotexist in Namespace {}: 404 Not Found'.format(self.namespace)  # noqa
        ):
            self.create('doesnotexist', 'doesnotexist')

    def test_create(self):
        self.create()

    def test_update_deployment_failure(self):
        # test failure
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to update Deployment foo in Namespace {}: 404 Not Found'.format(self.namespace)  # noqa
        ):
            self.update(self.namespace, 'foo')
        name = 'image-pull-failed-test'
        self.create(name=name)
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to update Deployment "{}": 503 Network Unreachable'.format(name)
        ):
            self.update(self.namespace, name)

    def test_update(self):
        # test success
        name = self.create()
        deployment = self.scheduler.deployment.get(self.namespace, name).json()
        self.assertEqual(deployment['spec']['replicas'], 4, deployment)

        # emulate scale without calling scale
        self.update(self.namespace, name, replicas=2)

        deployment = self.scheduler.deployment.get(self.namespace, name).json()
        self.assertEqual(deployment['spec']['replicas'], 2, deployment)

    def test_delete_failure(self):
        # test failure
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to delete Deployment foo in Namespace {}: 404 Not Found'.format(self.namespace)  # noqa
        ):
            self.scheduler.deployment.delete(self.namespace, 'foo')

    def test_delete(self):
        # test success
        name = self.create()
        response = self.scheduler.deployment.delete(self.namespace, name)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)

    def test_get_deployments(self):
        # test when no deployments exist
        response = self.scheduler.deployment.get(self.namespace)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertIn('items', data)
        self.assertEqual(data['items'], [])
        # test success
        name = self.create()
        response = self.scheduler.deployment.get(self.namespace)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertIn('items', data)
        self.assertEqual(1, len(data['items']), data['items'])
        # simple verify of data
        self.assertEqual(data['items'][0]['metadata']['name'], name, data)

    def test_get_deployment_failure(self):
        # test failure
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to get Deployment doesnotexist in Namespace {}: 404 Not Found'.format(self.namespace)  # noqa
        ):
            self.scheduler.deployment.get(self.namespace, 'doesnotexist')

    def test_get_deployment(self):
        # test success
        name = self.create()
        response = self.scheduler.deployment.get(self.namespace, name)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data['apiVersion'], 'apps/v1')
        self.assertEqual(data['kind'], 'Deployment')
        self.assertEqual(data['metadata']['name'], name)
        labels = {
            'app': self.namespace,
            'heritage': 'drycc'
        }
        self.assertEqual(data['metadata']['labels'], data['metadata']['labels'] | labels)

    def test_scale(self):
        name = self.scale()
        data = self.scheduler.deployment.get(self.namespace, name).json()
        self.assertEqual(data['kind'], 'Deployment')
        self.assertEqual(data['metadata']['name'], name)

        labels = {'app': self.namespace, 'version': 'v99', 'type': 'web'}
        pods = self.scheduler.pod.get(self.namespace, labels=labels).json()
        self.assertEqual(len(pods['items']), 4)

        # scale to 8
        name = self.scale(replicas=8)
        pods = self.scheduler.pod.get(self.namespace, labels=labels).json()
        self.assertEqual(len(pods['items']), 8)

        # scale to 3
        name = self.scale(replicas=3)
        pods = self.scheduler.pod.get(self.namespace, labels=labels).json()
        self.assertEqual(len(pods['items']), 3)

    def test_get_deployment_replicasets(self):
        """
        Look at ReplicaSets that a Deployment created
        """
        # test success
        deployment = self.create()
        data = self.scheduler.deployment.get(self.namespace, deployment).json()

        response = self.scheduler.rs.get(self.namespace, labels=data['metadata']['labels'])
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertIn('items', data)
        self.assertEqual(1, len(data['items']), data['items'])
        # simple verify of data
        self.assertEqual(data['items'][0]['metadata']['labels']['app'], self.namespace, data)

    def test_get__deployment_replicaset_failure(self):
        """
        Look at ReplicaSets that a Deployment created
        """
        # test failure
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to get ReplicaSet doesnotexist in Namespace {}: 404 Not Found'.format(self.namespace)  # noqa
        ):
            self.scheduler.rs.get(self.namespace, 'doesnotexist')

    def test_get_deployment_replicaset(self):
        """
        Look at ReplicaSets that a Deployment created
        """
        # test success
        deployment = self.create()
        data = self.scheduler.deployment.get(self.namespace, deployment).json()

        # get all replicasets and fish out the first one to match on
        response = self.scheduler.rs.get(self.namespace, labels=data['metadata']['labels'])
        data = response.json()

        replica_name = data['items'][0]['metadata']['name']
        response = self.scheduler.rs.get(self.namespace, replica_name)
        data = response.json()

        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data['apiVersion'], 'apps/v1', data)
        self.assertEqual(data['kind'], 'ReplicaSet', data)
        self.assertEqual(data['metadata']['name'], replica_name, data)
        labels = {
            'app': self.namespace,
            'heritage': 'drycc'
        }
        self.assertEqual(data['metadata']['labels'], data['metadata']['labels'] | labels, data)

    def test_get_deployment_annotations(self):
        """
        Look at the annotations on the Deployment object
        """
        # test success
        kwargs = {
            'spec_annotations': {'iam.amazonaws.com/role': 'role-arn'},
        }
        deployment = self.create(**kwargs)
        data = self.scheduler.deployment.get(self.namespace, deployment).json()
        annotations = {
            'iam.amazonaws.com/role': 'role-arn'
        }
        self.assertEqual(
            data['spec']['template']['metadata']['annotations'],
            data['spec']['template']['metadata']['annotations'] | annotations,
        )

    def test_get_pod_annotations(self):
        """
        Look at the Pod annotations that the Deployment created
        """
        kwargs = {
            'spec_annotations': {
                'iam.amazonaws.com/role': 'role-arn-pods',
                'nginx.ingress.kubernetes.io/app-root': '/rootfs',
                'sidecar.istio.io/inject': 'true'
            },
        }
        deployment = self.create(**kwargs)
        data = self.scheduler.deployment.get(self.namespace, deployment).json()
        self.assertEqual(data['kind'], 'Deployment')
        self.assertEqual(data['metadata']['name'], deployment)

        labels = {'app': self.namespace, 'version': 'v99', 'type': 'web'}
        pods = self.scheduler.pod.get(self.namespace, labels=labels).json()
        self.assertDictEqual(
            {
                'iam.amazonaws.com/role': 'role-arn-pods',
                'nginx.ingress.kubernetes.io/app-root': '/rootfs',
                'sidecar.istio.io/inject': 'true'
            },
            pods['items'][0]['metadata']['annotations']
        )

    def test_check_for_failed_events(self):
        deploy_name = self.create(self.namespace)
        deployment = self.scheduler.deployment.get(self.namespace, deploy_name).json()
        response = self.scheduler.rs.get(self.namespace, labels=deployment['metadata']['labels'])
        rs = response.json()
        regarding = {
            'regarding.kind': 'ReplicaSet',
            'regarding.name': rs['items'][0]['metadata']['name'],
            'regarding.namespace': self.namespace,
            'regarding.uid': rs['items'][0]['metadata']['uid'],
        }
        message = 'Quota exeeded'
        self.scheduler.ev.create(self.namespace,
                                 '{}'.format(generate_random_name()),
                                 message,
                                 type='Warning',
                                 regarding=regarding,
                                 reason='FailedCreate')
        with self.assertRaisesRegex(KubeException,
                                    'Message: {}.*'.format(message)):
            self.scheduler.deployment._check_for_failed_events(self.namespace,
                                                               labels=deployment['metadata']['labels'])  # noqa
