from scheduler.resources import Resource
from scheduler.exceptions import KubeHTTPException


class Job(Resource):

    api_prefix = 'apis'
    api_version = 'batch/v1'

    def manifest(self, namespace, name, image, command, args, **kwargs):
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
        # tell pod how to execute the process
        kwargs['command'] = command
        kwargs['args'] = args
        # job labels
        manifest['metadata']['labels'].update(kwargs.get('labels', {}))
        # pod manifest spec
        manifest['spec']['template'] = self.pod.manifest(namespace, name, image, **kwargs)
        return manifest

    def create(self, namespace, name, image, command,
               args, ignore_exception=False, **kwargs):
        data = self.manifest(namespace, name, image, command, args, **kwargs)
        url = self.api("/namespaces/{}/jobs", namespace)
        response = self.http_post(url, json=data)

        if not ignore_exception and self.unhealthy(response.status_code):
            raise KubeHTTPException(response, "create Job {}".format(namespace))
        return response
