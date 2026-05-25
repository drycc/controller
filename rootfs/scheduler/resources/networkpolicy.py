from api import utils
from scheduler.resources import Resource
from scheduler.exceptions import KubeHTTPException


class NetworkPolicy(Resource):
    api_prefix = 'apis'
    api_version = 'networking.k8s.io/v1'

    def manifest(self, namespace, name, **kwargs):
        data = {
            "apiVersion": self.api_version,
            "kind": "NetworkPolicy",
            "metadata": {
                "name": name,
                "namespace": namespace,
                "labels": {
                    "heritage": "drycc"
                }
            }
        }
        data = utils.dict_merge(data, kwargs)
        if "version" in kwargs:
            data["metadata"]["resourceVersion"] = kwargs.get("version")
        return data

    def get(self, namespace, name=None, ignore_exception=False, **kwargs):
        """
        Fetch a single NetworkPolicy or a list
        """
        if name is not None:
            url = self.api("/namespaces/{}/networkpolicies/{}", namespace, name)
            message = 'get NetworkPolicy "{}" in Namespace "{}"'.format(name, namespace)
        else:
            url = self.api("/namespaces/{}/networkpolicies", namespace)
            message = 'get NetworkPolicies in Namespace "{}"'.format(namespace)

        response = self.http_get(url, params=self.query_params(**kwargs))
        if not ignore_exception and self.unhealthy(response.status_code):
            raise KubeHTTPException(response, message)

        return response

    def create(self, namespace, name, ignore_exception=False, **kwargs):
        url = self.api("/namespaces/{}/networkpolicies", namespace)
        data = self.manifest(namespace, name, **kwargs)
        response = self.http_post(url, json=data)

        if not ignore_exception and self.unhealthy(response.status_code):
            raise KubeHTTPException(
                response, 'create NetworkPolicy "{}" in Namespace "{}"', name, namespace)

        return response

    def patch(self, namespace, name, ignore_exception=False, **kwargs):
        url = self.api("/namespaces/{}/networkpolicies/{}", namespace, name)
        data = self.manifest(namespace, name, **kwargs)
        response = self.http_patch(
            url,
            json=data,
            headers={"Content-Type": "application/merge-patch+json"}
        )
        if not ignore_exception and self.unhealthy(response.status_code):
            raise KubeHTTPException(
                response, 'patch NetworkPolicy "{}" in Namespace "{}"', name, namespace)
        return response

    def delete(self, namespace, name, ignore_exception=False):
        url = self.api("/namespaces/{}/networkpolicies/{}", namespace, name)
        response = self.http_delete(url)
        if not ignore_exception and self.unhealthy(response.status_code):
            raise KubeHTTPException(
                response, 'delete NetworkPolicy "{}" in Namespace "{}"', name, namespace)
        return response
