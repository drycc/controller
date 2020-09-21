from scheduler.exceptions import KubeHTTPException
from scheduler.resources import Resource


class LimitRanges(Resource):
    short_name = 'limits'

    def get(self, namespace_name, name):
        """
        Fetch a single LimitRanges
        """
        url = '/namespaces/{}/limitranges/{}'.format(namespace_name, name)
        message = 'get LimitRanges {} for namespace {}'.format(name, namespace_name)
        url = self.api(url)
        response = self.http_get(url)
        if self.unhealthy(response.status_code):
            raise KubeHTTPException(response, message)

        return response

    def create(self, namespace_name, name, **kwargs):
        """
        Create resource LimitRanges for namespace
        """
        url = self.api("/namespaces/{}/limitranges".format(namespace_name))
        manifest = {
            "apiVersion": "v1",
            "kind": "LimitRange",
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
                                    "create LimitRanges {} for namespace {}".format(
                                        name, namespace_name))
        return response
