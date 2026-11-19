import json

from scheduler import KubeException
from scheduler.drycc.archiver import NamespaceArchiver
from scheduler.tests import TestCase
from scheduler.tests.utils import generate_random_name


class NamespaceArchiverTest(TestCase):

    def create_deployment(self, replicas=3):
        name = generate_random_name()
        response = self.scheduler.deployment.create(
            self.namespace,
            name,
            app_type='web',
            version='v1',
            replicas=replicas,
            termination_grace_period_seconds=2,
            image='quay.io/fake/image',
            command='sh',
            args='start',
            spec_annotations={},
        )
        self.assertEqual(response.status_code, 201, response.json())
        return name

    def create_statefulset(self, replicas=2):
        name = generate_random_name()
        manifest = {
            'apiVersion': 'apps/v1',
            'kind': 'StatefulSet',
            'metadata': {'name': name, 'labels': {}, 'annotations': {}},
            'spec': {'replicas': replicas},
        }
        response = self.scheduler.http_post(
            f'/apis/apps/v1/namespaces/{self.namespace}/statefulsets', json=manifest)
        self.assertEqual(response.status_code, 201, response.json())
        return name

    def create_hpa(self, target, scale_up=None):
        name = generate_random_name()
        spec = {
            'minReplicas': 2,
            'maxReplicas': 6,
            'scaleTargetRef': {
                'apiVersion': 'apps/v1',
                'kind': 'Deployment',
                'name': target,
            },
            'metrics': [{
                'type': 'Resource',
                'resource': {
                    'name': 'cpu',
                    'target': {'type': 'Utilization', 'averageUtilization': 50},
                },
            }],
        }
        if scale_up is not None:
            spec['behavior'] = {'scaleUp': scale_up}
        manifest = {
            'apiVersion': 'autoscaling/v2',
            'kind': 'HorizontalPodAutoscaler',
            'metadata': {'name': name, 'labels': {}, 'annotations': {}},
            'spec': spec,
        }
        response = self.scheduler.http_post(
            f'/apis/autoscaling/v2/namespaces/{self.namespace}/horizontalpodautoscalers',
            json=manifest,
        )
        self.assertEqual(response.status_code, 201, response.json())
        return name

    def get_hpa(self, name):
        response = self.scheduler.http_get(
            f'/apis/autoscaling/v2/namespaces/{self.namespace}/horizontalpodautoscalers/{name}')
        self.assertEqual(response.status_code, 200, response.json())
        return response.json()

    def test_archive_deployment_saves_replicas_and_scales_to_zero(self):
        name = self.create_deployment(replicas=3)

        NamespaceArchiver(self.scheduler).archive(self.namespace)

        deployment = self.scheduler.deployment.get(self.namespace, name).json()
        self.assertEqual(deployment['spec']['replicas'], 0)
        restore = json.loads(
            deployment['metadata']['annotations']['drycc.cc/archive'])
        self.assertEqual(restore, {'spec': {'replicas': 3}})

    def test_unarchive_deployment_restores_replicas_and_removes_annotation(self):
        name = self.create_deployment(replicas=4)
        archiver = NamespaceArchiver(self.scheduler)
        archiver.archive(self.namespace)

        try:
            archiver.unarchive(self.namespace)
        except AttributeError as error:
            self.fail(f'NamespaceArchiver.unarchive is not implemented: {error}')

        deployment = self.scheduler.deployment.get(self.namespace, name).json()
        self.assertEqual(deployment['spec']['replicas'], 4)
        self.assertNotIn('drycc.cc/archive', deployment['metadata']['annotations'])

    def test_archive_and_unarchive_statefulset(self):
        name = self.create_statefulset(replicas=2)
        archiver = NamespaceArchiver(self.scheduler)

        archiver.archive(self.namespace)
        statefulset = self.scheduler.statefulset.get(self.namespace, name).json()
        self.assertEqual(statefulset['spec']['replicas'], 0)
        restore = json.loads(
            statefulset['metadata']['annotations']['drycc.cc/archive'])
        self.assertEqual(restore, {'spec': {'replicas': 2}})

        archiver.unarchive(self.namespace)
        statefulset = self.scheduler.statefulset.get(self.namespace, name).json()
        self.assertEqual(statefulset['spec']['replicas'], 2)
        self.assertNotIn('drycc.cc/archive', statefulset['metadata']['annotations'])

    def test_archive_and_unarchive_hpa_created_with_v1(self):
        target = self.create_deployment(replicas=2)
        deployment = self.scheduler.deployment.get(self.namespace, target).json()
        response = self.scheduler.hpa.create(
            self.namespace,
            target,
            app_type='web',
            target=deployment,
            min=2,
            max=6,
            cpu_percent=45,
            wait=True,
        )
        self.assertEqual(response.status_code, 201, response.json())
        archiver = NamespaceArchiver(self.scheduler)

        archiver.archive(self.namespace)
        hpa = self.get_hpa(target)
        self.assertEqual(hpa['spec']['behavior']['scaleUp']['selectPolicy'], 'Disabled')

        archiver.unarchive(self.namespace)
        hpa = self.get_hpa(target)
        self.assertNotIn('scaleUp', hpa['spec'].get('behavior', {}))
        self.assertNotIn('drycc.cc/archive', hpa['metadata']['annotations'])

    def test_archive_and_unarchive_hpa_scale_up(self):
        target = self.create_deployment(replicas=3)
        original_scale_up = {
            'selectPolicy': 'Max',
            'policies': [{'type': 'Percent', 'value': 100, 'periodSeconds': 15}],
        }
        name = self.create_hpa(target, scale_up=original_scale_up)
        archiver = NamespaceArchiver(self.scheduler)

        archiver.archive(self.namespace)
        hpa = self.get_hpa(name)
        self.assertEqual(hpa['spec']['behavior']['scaleUp']['selectPolicy'], 'Disabled')
        self.assertEqual(hpa['spec']['minReplicas'], 2)
        self.assertEqual(hpa['spec']['maxReplicas'], 6)
        restore = json.loads(hpa['metadata']['annotations']['drycc.cc/archive'])
        self.assertEqual(
            restore,
            {'spec': {'behavior': {'scaleUp': original_scale_up}}},
        )

        archiver.unarchive(self.namespace)
        hpa = self.get_hpa(name)
        self.assertEqual(hpa['spec']['behavior']['scaleUp'], original_scale_up)
        self.assertNotIn('drycc.cc/archive', hpa['metadata']['annotations'])

    def test_unarchive_hpa_restores_missing_scale_up(self):
        target = self.create_deployment(replicas=2)
        name = self.create_hpa(target)
        archiver = NamespaceArchiver(self.scheduler)

        archiver.archive(self.namespace)
        hpa = self.get_hpa(name)
        restore = json.loads(hpa['metadata']['annotations']['drycc.cc/archive'])
        self.assertEqual(restore, {'spec': {'behavior': {'scaleUp': None}}})

        archiver.unarchive(self.namespace)
        hpa = self.get_hpa(name)
        self.assertNotIn('scaleUp', hpa['spec'].get('behavior', {}))
        self.assertNotIn('drycc.cc/archive', hpa['metadata']['annotations'])

    def test_repeated_archive_does_not_overwrite_original_replicas(self):
        name = self.create_deployment(replicas=3)
        archiver = NamespaceArchiver(self.scheduler)
        archiver.archive(self.namespace)
        self.scheduler.deployment.patch(
            self.namespace, name, manifest={'spec': {'replicas': 5}}, wait=False)

        archiver.archive(self.namespace)

        deployment = self.scheduler.deployment.get(self.namespace, name).json()
        self.assertEqual(deployment['spec']['replicas'], 0)
        restore = json.loads(
            deployment['metadata']['annotations']['drycc.cc/archive'])
        self.assertEqual(restore, {'spec': {'replicas': 3}})

    def test_unarchive_rejects_invalid_restore_structures_without_changes(self):
        invalid_restores = (
            {},
            {'metadata': None},
            {'metadata': {'annotations': None}},
            {'spec': {}},
            {'spec': {'replicas': '3'}},
        )
        name = self.create_deployment(replicas=3)
        archiver = NamespaceArchiver(self.scheduler)
        archiver.archive(self.namespace)

        for restore in invalid_restores:
            with self.subTest(restore=restore):
                self.scheduler.deployment.patch(
                    self.namespace,
                    name,
                    manifest={
                        'metadata': {
                            'annotations': {'drycc.cc/archive': json.dumps(restore)},
                        }
                    },
                    wait=False,
                )
                with self.assertRaises(KubeException):
                    archiver.unarchive(self.namespace)
                deployment = self.scheduler.deployment.get(self.namespace, name).json()
                self.assertEqual(deployment['spec']['replicas'], 0)
                self.assertEqual(
                    deployment['metadata']['annotations']['drycc.cc/archive'],
                    json.dumps(restore),
                )

    def test_unarchive_rejects_invalid_hpa_restore_structures(self):
        target = self.create_deployment(replicas=2)
        name = self.create_hpa(target)
        archiver = NamespaceArchiver(self.scheduler)
        archiver.archive(self.namespace)

        for restore in ({}, {'metadata': None}, {'spec': {'behavior': {}}}):
            with self.subTest(restore=restore):
                self.scheduler.hpa.patch(
                    self.namespace,
                    name,
                    manifest={
                        'metadata': {
                            'annotations': {'drycc.cc/archive': json.dumps(restore)},
                        }
                    },
                    api_version='autoscaling/v2',
                )
                with self.assertRaises(KubeException):
                    archiver.unarchive(self.namespace)
                hpa = self.get_hpa(name)
                self.assertEqual(
                    hpa['spec']['behavior']['scaleUp']['selectPolicy'], 'Disabled')
                self.assertEqual(
                    hpa['metadata']['annotations']['drycc.cc/archive'],
                    json.dumps(restore),
                )

    def test_unarchive_rejects_invalid_restore_json_without_changes(self):
        name = self.create_deployment(replicas=3)
        archiver = NamespaceArchiver(self.scheduler)
        archiver.archive(self.namespace)
        self.scheduler.deployment.patch(
            self.namespace,
            name,
            manifest={'metadata': {'annotations': {'drycc.cc/archive': 'invalid'}}},
            wait=False,
        )

        try:
            archiver.unarchive(self.namespace)
        except json.JSONDecodeError as error:
            self.fail(f'Expected KubeException instead of JSONDecodeError: {error}')
        except KubeException:
            pass
        else:
            self.fail('Expected KubeException for invalid restore JSON')

        deployment = self.scheduler.deployment.get(self.namespace, name).json()
        self.assertEqual(deployment['spec']['replicas'], 0)
        self.assertEqual(
            deployment['metadata']['annotations']['drycc.cc/archive'], 'invalid')
