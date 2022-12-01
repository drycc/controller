from scheduler.resources import Resource
from scheduler.exceptions import KubeHTTPException
from .base import (
    BaseIngress,
    MEM_REQUEST_BODY_BYTES,
    MAX_REQUEST_BODY_BYTES,
    MEM_RESPONSE_BODY_BYTES,
    MAX_RESPONSE_BODY_BYTES,
)


class BaseMiddleware(Resource):
    abstract = True
    api_version = 'traefik.containo.us/v1alpha1'
    api_prefix = 'apis'
    name_suffix = ''

    def fullname(self, base_name):
        return f"{base_name}{self.name_suffix}"

    def manifest(self, name, resource_version=None):
        manifest = {
            "apiVersion": self.api_version,
            "kind": "Middleware",
            "metadata": {
                "name": name
            },
        }
        if resource_version:
            manifest["metadata"]["resourceVersion"] = resource_version
        return manifest

    def get(self, namespace, name=None, **kwargs):
        """
        Fetch a single Middleware or a list of Middlewares
        """
        if name is not None:
            url = self.api("/namespaces/{}/middlewares/{}", namespace, name)
        else:
            url = self.api("/namespaces/{}/middlewares", namespace)
        return self.http_get(url, params=self.query_params(**kwargs))

    def create(self, namespace, ignore_exception=False, **kwargs):
        url = self.api("/namespaces/{}/middlewares", namespace)
        data = self.manifest(**kwargs)
        response = self.http_post(url, json=data)
        if not ignore_exception and self.unhealthy(response.status_code):
            raise KubeHTTPException(response, "create middleware {}".format(namespace))
        return response

    def put(self, namespace, name, ignore_exception=False, **kwargs):
        url = self.api("/namespaces/{}/middlewares/{}", namespace, name)
        if kwargs.get("resource_version") is None:
            response = self.get(namespace, name)
            if self.unhealthy(response.status_code):
                raise KubeHTTPException(response, "get middleware {}".format(name))
            resource_version = response.json()["metadata"]["resourceVersion"]
            kwargs["resource_version"] = resource_version
        data = self.manifest(name, **kwargs)
        response = self.http_put(url, json=data)
        if not ignore_exception and self.unhealthy(response.status_code):
            raise KubeHTTPException(response, "put middleware {}".format(namespace))
        return response

    def delete(self, namespace, name, ignore_exception=True):
        url = self.api("/namespaces/{}/middlewares/{}", namespace, name)
        response = self.http_delete(url)
        if not ignore_exception and self.unhealthy(response.status_code):
            raise KubeHTTPException(response, 'delete middlewares "{}"', namespace)

        return response


class BufferingMiddleware(BaseMiddleware):
    name_suffix = "-buffering"

    def manifest(self, name, resource_version=None):
        data = super().manifest(name, resource_version)
        data.update({
            "spec": {
                "buffering": {
                    "memRequestBodyBytes": MEM_REQUEST_BODY_BYTES,
                    "maxRequestBodyBytes": MAX_REQUEST_BODY_BYTES,
                    "memResponseBodyBytes": MEM_RESPONSE_BODY_BYTES,
                    "maxResponseBodyBytes": MAX_RESPONSE_BODY_BYTES,
                }
            }
        })
        return data


class IPWhiteListMiddleware(BaseMiddleware):
    name_suffix = "-ip-white-list"

    def manifest(self, name, allowlist=None, resource_version=None):
        data = super().manifest(name, resource_version)
        data.update({
            "spec": {
                "ipWhiteList": {
                    "sourceRange": allowlist if allowlist is not None else []
                }
            }
        })
        return data


class RedirectSchemeMiddleware(BaseMiddleware):
    name_suffix = "-redirect-scheme"

    def manifest(self, name, resource_version=None):
        data = super().manifest(name, resource_version)
        data.update({
            "spec": {
                "redirectScheme": {
                    "scheme": "https",
                    "permanent": True
                }
            }
        })
        return data


class TraefikIngress(BaseIngress):

    def __init__(self, url, k8s_api_verify_tls=True):
        super().__init__(url, k8s_api_verify_tls)
        self.middlewares = {
            "buffering": BufferingMiddleware(url, k8s_api_verify_tls),
            "allowlist": IPWhiteListMiddleware(url, k8s_api_verify_tls),
            "ssl_redirect": RedirectSchemeMiddleware(url, k8s_api_verify_tls),
        }

    def manifest(self, namespace, ingress, **kwargs):
        data = BaseIngress.manifest(self, namespace, ingress, **kwargs)
        middlewares = []
        for middleware in self.middlewares.keys():
            if middleware == "buffering" or (middleware in kwargs and kwargs[middleware]):
                name = self.middlewares[middleware].fullname(ingress)
                middlewares.append(f"{namespace}-{name}@kubernetescrd")
        data["metadata"]["annotations"].update({
            "traefik.ingress.kubernetes.io/router.middlewares": ",".join(middlewares)
        })
        return data

    def create(self, namespace, ingress, **kwargs):
        response = super().create(ingress, namespace, **kwargs)
        for middleware in self.middlewares.keys():
            name = self.middlewares[middleware].fullname(ingress)
            self.middlewares[middleware].create(namespace, name=name)
        return response

    def put(self, namespace, ingress, version, **kwargs):
        response = super().put(ingress, namespace, version, **kwargs)
        if "allowlist" in kwargs:
            name = self.middlewares["allowlist"].fullname(ingress)
            self.middlewares["allowlist"].put(
                namespace,
                name,
                allowlist=kwargs["allowlist"],
            )
        return response

    def delete(self, namespace, ingress):
        response = super().delete(namespace, ingress)
        for middleware in self.middlewares.keys():
            name = self.middlewares[middleware].fullname(ingress)
            self.middlewares[middleware].delete(namespace, name)
        return response
