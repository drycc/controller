from scheduler.exceptions import KubeHTTPException
from scheduler.resources import Resource


class Service(Resource):
    short_name = 'svc'

    def manifest(self, namespace, name, **kwargs):
        data = {
            'kind': 'Service',
            'apiVersion': self.api_version,
            'metadata': {
                'name': name,
                'labels': {
                    'app': namespace,
                    'heritage': 'drycc'
                },
                'annotations': {}
            },
            'spec': {
                'type': kwargs.get("type", "ClusterIP"),
                'ports': kwargs.get("ports"),
                'selector': {
                    'app': namespace,
                    'heritage': 'drycc'
                }
            }
        }
        if "version" in kwargs:
            data["metadata"]["resourceVersion"] = kwargs.get("version")
        if "procfile_type" in kwargs:
            data["spec"]["selector"]['type'] = kwargs.get("procfile_type")
        return data

    def get(self, namespace, name=None, **kwargs):
        """
        Fetch a single Service or a list
        """
        url = '/namespaces/{}/services'
        args = [namespace]
        if name is not None:
            args.append(name)
            url += '/{}'
            message = 'get Service "{}" in Namespace "{}"'
        else:
            message = 'get Services in Namespace "{}"'

        url = self.api(url, *args)
        response = self.http_get(url, params=self.query_params(**kwargs))
        if self.unhealthy(response.status_code):
            args.reverse()  # error msg is in reverse order
            raise KubeHTTPException(response, message, *args)

        return response

    def create(self, namespace, name, **kwargs):
        data = self.manifest(namespace, name, **kwargs)
        url = self.api("/namespaces/{}/services", namespace)
        response = self.http_post(url, json=data)
        if self.unhealthy(response.status_code):
            raise KubeHTTPException(
                response,
                'create Service "{}" in Namespace "{}"', namespace, namespace
            )

        return response

    def patch(self, namespace, name, ignore_exception=False, **kwargs):
        url = self.api("/namespaces/{}/services/{}", namespace, name)
        data = self.manifest(namespace, name, **kwargs)
        response = self.http_patch(
            url,
            json=data,
            headers={"Content-Type": "application/merge-patch+json"}
        )
        if not ignore_exception and self.unhealthy(response.status_code):
            raise KubeHTTPException(response, "patch svc {}".format(namespace))
        return response

    def update(self, namespace, name, data):
        url = self.api("/namespaces/{}/services/{}", namespace, name)
        response = self.http_put(url, json=data)
        if self.unhealthy(response.status_code):
            raise KubeHTTPException(
                response,
                'update Service "{}" in Namespace "{}"', namespace, name
            )

        return response

    def delete(self, namespace, name):
        url = self.api("/namespaces/{}/services/{}", namespace, name)
        response = self.http_delete(url)
        if self.unhealthy(response.status_code):
            raise KubeHTTPException(
                response,
                'delete Service "{}" in Namespace "{}"', name, namespace
            )

        return response
