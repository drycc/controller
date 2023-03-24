from scheduler.resources import Resource
from scheduler.exceptions import KubeHTTPException


class Gateway(Resource):
    api_prefix = 'apis'
    api_version = 'gateway.networking.k8s.io/v1beta1'

    def manifest(self, namespace, name, **kwargs):
        data = {
            "apiVersion": self.api_version,
            "kind": "Gateway",
            "metadata": {
                "name": name,
                "namespace": namespace
            },
            "spec": {
                "gatewayClassName": kwargs.get("gateway_class", "default"),
                "listeners": kwargs.get("listeners")
            }
        }
        if "version" in kwargs:
            data["metadata"]["resourceVersion"] = kwargs.get("version")
        return data

    def get(self, namespace, name=None, ignore_exception=False, **kwargs):
        """
        Fetch a single Gateway or a list of Gateways
        """
        if name is not None:
            url = self.api("/namespaces/{}/gateways/{}", namespace, name)
            message = 'get Gateway ' + name
        else:
            url = self.api("/namespaces/{}/gateways", namespace)
            message = 'get Gateways'

        response = self.http_get(url, params=self.query_params(**kwargs))
        if not ignore_exception and self.unhealthy(response.status_code):
            raise KubeHTTPException(response, message)

        return response

    def create(self, namespace, name, ignore_exception=False, **kwargs):
        url = self.api("/namespaces/{}/gateways", namespace)
        data = self.manifest(namespace, name,  **kwargs)
        response = self.http_post(url, json=data)

        if not ignore_exception and self.unhealthy(response.status_code):
            raise KubeHTTPException(response, "create gateway {}".format(namespace))

        return response

    def patch(self, namespace, name, ignore_exception=False, **kwargs):
        url = self.api("/namespaces/{}/gateways/{}", namespace, name)
        data = self.manifest(namespace, name, **kwargs)
        response = self.http_patch(
            url,
            json=data,
            headers={"Content-Type": "application/merge-patch+json"}
        )
        if not ignore_exception and self.unhealthy(response.status_code):
            raise KubeHTTPException(response, "put gateway {}".format(namespace))
        return response

    def delete(self, namespace, name, ignore_exception=True):
        url = self.api("/namespaces/{}/gateways/{}", namespace, name)
        response = self.http_delete(url)
        if not ignore_exception and self.unhealthy(response.status_code):
            raise KubeHTTPException(response, 'delete gateway "{}"', namespace)
        return response


class BaseRoute(Resource):
    abstract = True
    kind = "BaseRoute"
    api_prefix = 'apis'
    api_version = 'gateway.networking.k8s.io/v1beta1'

    def manifest(self, namespace, name, **kwargs):
        data = {
            "apiVersion": self.api_version,
            "kind": self.kind,
            "metadata": {
                "name": name,
                "namespace": namespace
            },
            "spec": {
                "parentRefs": kwargs["parent_refs"],
                "rules": kwargs["rules"]
            }
        }
        if "version" in kwargs:
            data["metadata"]["resourceVersion"] = kwargs.get("version")
        return data

    def get(self, namespace, name=None, ignore_exception=False, **kwargs):
        """
        Fetch a single Route or a list of Routes
        """
        if name is not None:
            url = self.api("/namespaces/{}/{}s/{}", namespace, self.kind.lower(), name)
            message = 'get %s %s' % (self.kind, name)
        else:
            url = self.api("/namespaces/{}/{}s", namespace, self.kind.lower())
            message = 'get %s' % self.kind

        response = self.http_get(url, params=self.query_params(**kwargs))
        if not ignore_exception and self.unhealthy(response.status_code):
            raise KubeHTTPException(response, message)

        return response

    def create(self, namespace, name, ignore_exception=False, **kwargs):
        url = self.api("/namespaces/{}/{}s", namespace, self.kind.lower())
        data = self.manifest(namespace, name,  **kwargs)
        response = self.http_post(url, json=data)

        if not ignore_exception and self.unhealthy(response.status_code):
            raise KubeHTTPException(response, "create {} {}".format(self.kind.lower(), namespace))

        return response

    def patch(self, namespace, name, ignore_exception=False, **kwargs):
        url = self.api("/namespaces/{}/{}s/{}", namespace, self.kind.lower(), name)
        data = self.manifest(namespace, name, **kwargs)
        response = self.http_patch(
            url,
            json=data,
            headers={"Content-Type": "application/merge-patch+json"}
        )
        if not ignore_exception and self.unhealthy(response.status_code):
            raise KubeHTTPException(response, "put {} {}".format(self.kind.lower(), namespace))
        return response

    def delete(self, namespace, name, ignore_exception=True):
        url = self.api("/namespaces/{}/{}s/{}", namespace, self.kind.lower(), name)
        response = self.http_delete(url)
        if not ignore_exception and self.unhealthy(response.status_code):
            raise KubeHTTPException(response, 'delete {} "{}"', self.kind.lower(), namespace)
        return response


class HTTPRoute(BaseRoute):
    kind = "HTTPRoute"

    def manifest(self, namespace, name, **kwargs):
        data = super().manifest(namespace, name, **kwargs)
        if "hostnames" in kwargs:
            data["spec"]["hostnames"] = kwargs["hostnames"]
        return data


class GRPCRoute(HTTPRoute):
    kind = "GRPCRoute"


class TCPRoute(BaseRoute):
    kind = "TCPRoute"
    api_version = 'gateway.networking.k8s.io/v1alpha2'


class UDPRoute(BaseRoute):
    kind = "UDPRoute"
    api_version = 'gateway.networking.k8s.io/v1alpha2'
