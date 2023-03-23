from scheduler.exceptions import KubeHTTPException
from scheduler.resources import Resource


class Quota(Resource):
    short_name = 'quota'

    def get(self, namespace_name, name):
        """
        Fetch a single quota
        """
        url = '/namespaces/{}/resourcequotas/{}'.format(namespace_name, name)
        message = 'get quota {} for namespace {}'.format(name, namespace_name)
        url = self.api(url)
        response = self.http_get(url)
        if self.unhealthy(response.status_code):
            raise KubeHTTPException(response, message)

        return response

    def create(self, namespace_name, name, **kwargs):
        """
        Create resource quota for namespace
        """
        url = self.api("/namespaces/{}/resourcequotas".format(namespace_name))
        manifest = {
            "kind": "ResourceQuota",
            "apiVersion": self.api_version,
            "metadata": {
                "namespace": namespace_name,
                "name": name,
                'labels': {
                    'app': namespace_name,
                    'heritage': 'drycc'
                },
            },
            'spec': kwargs.get('spec', {})
        }
        response = self.http_post(url, json=manifest)
        if not response.status_code == 201:
            raise KubeHTTPException(response,
                                    "create quota {} for namespace {}".format(
                                        name, namespace_name))

        return response
