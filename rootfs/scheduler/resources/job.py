from scheduler.resources import Resource
from scheduler.exceptions import KubeHTTPException


class Job(Resource):

    api_prefix = 'apis'
    api_version = 'batch/v1'

    def manifest(self, namespace, name, **kwargs):
        image = kwargs.get('image')
        command = kwargs.get('command')
        args = kwargs.get('args')
        manifest = {
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {
                "name": name,
                'labels': {
                    'app': namespace,
                    'type': kwargs.get('app_type', 'run'),
                    'heritage': 'drycc',
                },
            },
            "spec": {
                "backoffLimit": kwargs.get('backoff_limit', 0),
                "activeDeadlineSeconds": kwargs.get('active_deadline_seconds', 3600),
                "ttlSecondsAfterFinished": kwargs.get('ttl_seconds_after_finished', 86400),
            }
        }
        manifest['metadata']['labels'].update(kwargs.get('labels', {}))
        pod_kwargs = {k: v for k, v in kwargs.items() if k not in ('image', 'command', 'args')}
        pod_kwargs['command'] = command
        pod_kwargs['args'] = args
        manifest['spec']['template'] = self.pod.manifest(namespace, name, image, **pod_kwargs)
        return manifest

    def create(self, namespace, name, **kwargs):
        data = self.manifest(namespace, name, **kwargs)
        url = self.api("/namespaces/{}/jobs", namespace)
        response = self.http_post(url, json=data)

        if not kwargs.get('ignore_exception', False) and self.unhealthy(response.status_code):
            raise KubeHTTPException(response, "create Job {}".format(namespace))
        return response
