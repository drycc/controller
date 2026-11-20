from api import utils
from scheduler.exceptions import KubeHTTPException
from scheduler.resources import Resource


class ResourceQuota(Resource):
    def manifest(self, namespace, name, **kwargs):
        data = {
            'apiVersion': self.api_version,
            'kind': 'ResourceQuota',
            'metadata': {
                'name': name,
                'namespace': namespace,
                'labels': {'heritage': 'drycc'},
            },
        }
        return utils.dict_merge(data, kwargs)

    def get(self, namespace, name=None, ignore_exception=False, **kwargs):
        url = self.api('/namespaces/{}/resourcequotas', namespace)
        message = f'get ResourceQuotas in Namespace "{namespace}"'
        if name is not None:
            url += '/{}'
            url = url.format(name)
            message = f'get ResourceQuota "{name}" in Namespace "{namespace}"'
        response = self.http_get(url, params=self.query_params(**kwargs))
        if not ignore_exception and self.unhealthy(response.status_code):
            raise KubeHTTPException(response, message)
        return response

    def create(self, namespace, name, ignore_exception=False, **kwargs):
        manifest = self.manifest(namespace, name, **kwargs)
        url = self.api('/namespaces/{}/resourcequotas', namespace)
        response = self.http_post(url, json=manifest)
        if not ignore_exception and self.unhealthy(response.status_code):
            raise KubeHTTPException(
                response, f'create ResourceQuota "{name}" in Namespace "{namespace}"')
        return response
