import json
import logging

from scheduler.resources import Resource
from scheduler.exceptions import KubeException, KubeHTTPException


class HorizontalPodAutoscaler(Resource):
    api_prefix = 'apis'
    api_version = 'autoscaling/v1'
    short_name = 'hpa'

    def get(self, namespace, name=None, **kwargs):
        """
        Fetch a single HorizontalPodAutoscaler or a list
        """
        url = '/namespaces/{}/horizontalpodautoscalers'
        args = [namespace]
        if name is not None:
            args.append(name)
            url += '/{}'
            message = 'get HorizontalPodAutoscaler "{}" in Namespace "{}"'
        else:
            message = 'get HorizontalPodAutoscalers in Namespace "{}"'

        url = self.api(url, *args)
        response = self.http_get(url, params=self.query_params(**kwargs))
        if self.unhealthy(response.status_code):
            args.reverse()  # error msg is in reverse order
            raise KubeHTTPException(response, message, *args)

        return response

    def manifest(self, namespace, name, **kwargs):
        app_type = kwargs.get('app_type')
        target = kwargs.get('target')
        min_replicas = kwargs.get('min')
        max_replicas = kwargs.get('max')
        cpu_percent = kwargs.get('cpu_percent')

        if min_replicas < 1:
            raise KubeException('min replicas needs to be 1 or higher')

        if max_replicas < min_replicas:
            raise KubeException('max replicas can not be smaller than min replicas')

        labels = {
            'app': namespace,
            'type': app_type,
            'heritage': 'drycc',
        }

        manifest = {
            'kind': 'HorizontalPodAutoscaler',
            'apiVersion': self.api_version,
            'metadata': {
                'name': name,
                'namespace': namespace,
                'labels': labels,
            },
            'spec': {
                'minReplicas': min_replicas,
                'maxReplicas': max_replicas,
                'targetCPUUtilizationPercentage': cpu_percent,
                'scaleTargetRef': {
                    'apiVersion': target['apiVersion'],
                    'kind': target['kind'],
                    'name': target['metadata']['name'],
                }
            }
        }

        return manifest

    def create(self, namespace, name, **kwargs):
        manifest = self.manifest(namespace, name, **kwargs)

        url = self.api("/namespaces/{}/horizontalpodautoscalers", namespace)
        response = self.http_post(url, json=manifest)
        if self.unhealthy(response.status_code):
            self.log(namespace, 'template used: {}'.format(
                json.dumps(manifest, indent=4)), logging.DEBUG)
            raise KubeHTTPException(
                response,
                'create HorizontalPodAutoscaler "{}" in Namespace "{}"', name, namespace
            )

        if kwargs.get('wait', False):
            self.wait(namespace, name)

        return response

    def update(self, namespace, name, **kwargs):
        manifest = self.manifest(namespace, name, **kwargs)

        url = self.api("/namespaces/{}/horizontalpodautoscalers/{}", namespace, name)
        response = self.http_put(url, json=manifest)
        if self.unhealthy(response.status_code):
            self.log(namespace, 'template used: {}'.format(
                json.dumps(manifest, indent=4)), logging.DEBUG)
            raise KubeHTTPException(response, 'update HorizontalPodAutoscaler "{}"', name)

        if kwargs.get('wait', False):
            self.wait(namespace, name)

        return response

    def delete(self, namespace, name, **kwargs):
        url = self.api("/namespaces/{}/horizontalpodautoscalers/{}", namespace, name)
        response = self.http_delete(url)
        if not kwargs.get('ignore_exception', False) and self.unhealthy(response.status_code):
            raise KubeHTTPException(
                response,
                'delete HorizontalPodAutoscaler "{}" in Namespace "{}"', name, namespace
            )

        return response

    def wait(self, namespace, name):
        """Wait for HPA to stabilize."""
        hpa = self.hpa.get(namespace, name).json()

        for _ in range(30):
            resource_kind = hpa['spec']['scaleTargetRef']['kind'].lower()
            resource_name = hpa['spec']['scaleTargetRef']['name']

            resource = getattr(self, resource_kind)
            resource = getattr(resource, 'get')(namespace, resource_name).json()

            if resource_kind in ['replicationcontroller', 'replicaset']:
                replicas = resource['status']['replicas']
            elif resource_kind == 'deployment':
                replicas = resource['status']['availableReplicas']

            if replicas <= hpa['spec']['maxReplicas'] or replicas >= hpa['spec']['minReplicas']:
                break
