from scheduler.exceptions import KubeHTTPException
from scheduler.resources import Resource
from datetime import datetime
import uuid

DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


class Events(Resource):
    """
    Events resource.
    """
    api_prefix = 'apis'
    api_version = 'events.k8s.io/v1'
    short_name = 'ev'

    def create(self, namespace, name, message, **kwargs):
        url = self.api('/namespaces/{}/events'.format(namespace))
        data = {
            'kind': 'Event',
            'apiVersion': self.api_version,
            'metadata': {
                'creationTimestamp': datetime.now().strftime(DATETIME_FORMAT),
                'namespace': namespace,
                'name': name,
                'resourceVersion': kwargs.get('resourceVersion', ''),
                'uid': str(uuid.uuid4()),
            },
            'note': message,
            'type': kwargs.get('type', 'Normal'),
            'reason': kwargs.get('reason', ''),
            'regarding': kwargs.get('regarding', {})
        }

        response = self.http_post(url, json=data)
        if not response.status_code == 201:
            raise KubeHTTPException(response, 'create Event for namespace {}'.format(namespace))  # noqa

        return response

    def get(self, namespace, ignore_exception=False, **kwargs):
        """
        Fetch Events
        """
        url = '/namespaces/{}/events'
        args = [namespace]
        message = 'get Events in Namespace "{}"'

        url = self.api(url, *args)
        response = self.http_get(url, params=self.query_params(**kwargs))
        if self.unhealthy(response.status_code) and not ignore_exception:
            args.reverse()  # error msg is in reverse order
            raise KubeHTTPException(response, message, *args)
        return response
