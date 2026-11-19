import json

from scheduler.exceptions import KubeException


ARCHIVE_ANNOTATION = 'drycc.cc/archive'


class NamespaceArchiver(object):

    def __init__(self, scheduler):
        self.scheduler = scheduler

    def archive(self, namespace):
        hpas = self.scheduler.hpa.get(
            namespace, api_version='autoscaling/v2').json()['items']
        for hpa in hpas:
            self._archive_hpa(namespace, hpa)
        for resource in (self.scheduler.deployment, self.scheduler.statefulset):
            workloads = resource.get(namespace).json()['items']
            for workload in workloads:
                self._archive_workload(resource, namespace, workload)

    def unarchive(self, namespace):
        for resource in (self.scheduler.deployment, self.scheduler.statefulset):
            workloads = resource.get(namespace).json()['items']
            for workload in workloads:
                self._unarchive_workload(resource, namespace, workload)
        hpas = self.scheduler.hpa.get(
            namespace, api_version='autoscaling/v2').json()['items']
        for hpa in hpas:
            self._unarchive_workload(
                self.scheduler.hpa, namespace, hpa, api_version='autoscaling/v2')

    def _archive_hpa(self, namespace, hpa):
        target = hpa['spec']['scaleTargetRef']
        if target['kind'] not in ('Deployment', 'StatefulSet'):
            return
        annotations = hpa['metadata'].get('annotations', {})
        manifest = {
            'spec': {'behavior': {'scaleUp': {'selectPolicy': 'Disabled'}}},
        }
        if ARCHIVE_ANNOTATION not in annotations:
            scale_up = hpa['spec'].get('behavior', {}).get('scaleUp')
            restore = {'spec': {'behavior': {'scaleUp': scale_up}}}
            manifest['metadata'] = {
                'annotations': {
                    ARCHIVE_ANNOTATION: json.dumps(restore, separators=(',', ':')),
                }
            }
        self.scheduler.hpa.patch(
            namespace, hpa['metadata']['name'], manifest=manifest,
            api_version='autoscaling/v2')

    def _archive_workload(self, resource, namespace, workload):
        name = workload['metadata']['name']
        annotations = workload['metadata'].get('annotations', {})
        manifest = {'spec': {'replicas': 0}}
        if ARCHIVE_ANNOTATION not in annotations:
            restore = {'spec': {'replicas': workload['spec']['replicas']}}
            manifest['metadata'] = {
                'annotations': {
                    ARCHIVE_ANNOTATION: json.dumps(restore, separators=(',', ':')),
                }
            }
        resource.patch(namespace, name, manifest=manifest, wait=False)

    def _unarchive_workload(self, resource, namespace, workload, **kwargs):
        annotations = workload['metadata'].get('annotations', {})
        archived = annotations.get(ARCHIVE_ANNOTATION)
        if archived is None:
            return
        manifest = self._load_restore_manifest(workload, archived)
        metadata = manifest.setdefault('metadata', {})
        metadata.setdefault('annotations', {})[ARCHIVE_ANNOTATION] = None
        resource.patch(
            namespace, workload['metadata']['name'], manifest=manifest, wait=False, **kwargs)

    def _load_restore_manifest(self, workload, archived):
        error = KubeException(
            f"Invalid {ARCHIVE_ANNOTATION} annotation on "
            f"{workload['kind']}/{workload['metadata']['name']}"
        )
        try:
            manifest = json.loads(archived)
        except (TypeError, json.JSONDecodeError) as exc:
            raise error from exc
        if not isinstance(manifest, dict):
            raise error
        spec = manifest.get('spec')
        if not isinstance(spec, dict):
            raise error
        kind = workload['kind']
        if kind in ('Deployment', 'StatefulSet'):
            replicas = spec.get('replicas')
            if type(replicas) is not int or replicas < 0:
                raise error
        elif kind == 'HorizontalPodAutoscaler':
            behavior = spec.get('behavior')
            if not isinstance(behavior, dict) or 'scaleUp' not in behavior:
                raise error
            scale_up = behavior['scaleUp']
            if scale_up is not None and not isinstance(scale_up, dict):
                raise error
        else:
            raise error
        metadata = manifest.get('metadata', {})
        if not isinstance(metadata, dict):
            raise error
        annotations = metadata.get('annotations', {})
        if not isinstance(annotations, dict):
            raise error
        return manifest
