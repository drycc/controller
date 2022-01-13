from scheduler.exceptions import KubeHTTPException
from scheduler.resources import Resource


class BaseIngress(Resource):
    abstract = True
    api_version = 'networking.k8s.io/v1'
    api_prefix = 'apis'
    short_name = 'ingress'
    ingress_path = "/"
    ingress_class = None

    def manifest(self, ingress, **kwargs):
        hosts, tls = kwargs.pop("hosts", None), kwargs.pop("tls", None)
        version = kwargs.pop("version", None)
        data = {
            "kind": "Ingress",
            "apiVersion": self.api_version,
            "metadata": {
                "name": ingress,
                "annotations": {
                    "kubernetes.io/tls-acme": "true",
                    "kubernetes.io/ingress.class": self.ingress_class
                }
            },
            "spec": {}
        }
        if hosts:
            data["spec"]["rules"] = [{
                "host": host,
                "http": {
                    "paths": [
                        {
                            "path": self.ingress_path,
                            "pathType": "Prefix",
                            "backend": {
                                "service": {
                                    "name": ingress,
                                    "port": {
                                        "number": 80
                                    }
                                }
                            }
                        }
                    ]
                }
            } for host in hosts]
        if tls:
            data["spec"]["tls"] = tls
        if version:
            data["metadata"]["resourceVersion"] = version
        return data

    def get(self, namespace, ingress=None, **kwargs):
        """
        Fetch a single Ingress or a list of Ingresses
        """
        if ingress is not None:
            url = self.api("/namespaces/{}/ingresses/{}", namespace, ingress)
            message = 'get Ingress ' + ingress
        else:
            url = self.api("/namespaces/{}/ingresses", namespace)
            message = 'get Ingresses'

        response = self.http_get(url, params=self.query_params(**kwargs))
        if self.unhealthy(response.status_code):
            raise KubeHTTPException(response, message)

        return response

    def create(self, namespace, ingress, **kwargs):
        url = self.api("/namespaces/{}/ingresses", namespace)
        data = self.manifest(ingress, **kwargs)
        response = self.http_post(url, json=data)

        if self.unhealthy(response.status_code):
            raise KubeHTTPException(response, "create Ingress {}".format(namespace))

        return response

    def put(self, namespace, ingress, version, **kwargs):
        url = self.api("/namespaces/{}/ingresses/{}", namespace, ingress)
        kwargs["version"] = version
        data = self.manifest(ingress, **kwargs)
        response = self.http_put(url, json=data)

        if self.unhealthy(response.status_code):
            raise KubeHTTPException(response, "put Ingress {}".format(namespace))

        return response

    def patch(self, namespace, ingress, data, **kwargs):
        url = self.api("/namespaces/{}/ingresses/{}", namespace, ingress)
        response = self.http_put(url, json=data)

        if self.unhealthy(response.status_code):
            raise KubeHTTPException(response, "patch Ingress {}".format(namespace))

        return response

    def delete(self, namespace, ingress):
        url = self.api("/namespaces/{}/ingresses/{}", namespace, ingress)
        response = self.http_delete(url)
        if self.unhealthy(response.status_code):
            raise KubeHTTPException(response, 'delete Ingress "{}"', namespace)

        return response


class IngressFactory(Resource):

    short_name = 'ingress'
    ingress_class_map = {
        "default": BaseIngress
    }

    def __call__(self, ingress_name):
        ingress_cls = self.ingress_class_map.get(ingress_name, self.ingress_class_map["default"])
        ingress_cls.ingress_class = ingress_name
        return ingress_cls(self.url, self.k8s_api_verify_tls)

    @classmethod
    def register(cls, ingress_name, ingress_cls):
        cls.ingress_class_map[ingress_name] = ingress_cls


class NginxIngress(BaseIngress):

    def manifest(self, ingress, **kwargs):
        data = BaseIngress.manifest(self, ingress, **kwargs)
        if "allowlist" in kwargs:
            allowlist = ", ".join(kwargs.pop("allowlist"))
            data["metadata"]["annotations"].update({
                "nginx.ingress.kubernetes.io/whitelist-source-range": allowlist
            })
        if "ssl_redirect" in kwargs:
            ssl_redirect = kwargs.pop("ssl_redirect")
            data["metadata"]["annotations"].update({
                "nginx.ingress.kubernetes.io/ssl-redirect": ssl_redirect
            })
        return data


class TraefikIngress(BaseIngress):

    class Middleware(Resource):
        abstract = True
        api_version = 'traefik.containo.us/v1alpha1'
        api_prefix = 'apis'

        def manifest(self, name, allowlist, ssl_redirect, resource_version=None):
            manifest = {
                "apiVersion": self.api_version,
                "kind": "Middleware",
                "metadata": {
                    "name": name
                },
                "spec": {}
            }
            if allowlist:
                manifest["spec"]["ipWhiteList"] = {
                    "sourceRange": allowlist
                }
            if ssl_redirect:
                manifest["spec"]["redirectScheme"] = {
                    "scheme": "https",
                    "permanent": True
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

        def create(self, namespace, name, allowlist, ssl_redirect):
            url = self.api("/namespaces/{}/middlewares", namespace)
            data = self.manifest(name, allowlist, ssl_redirect)
            response = self.http_put(url, json=data)
            if self.unhealthy(response.status_code):
                raise KubeHTTPException(response, "create middleware {}".format(namespace))
            return response

        def put(self, namespace, name, allowlist, ssl_redirect, resource_version):
            url = self.api("/namespaces/{}/middlewares/{}", namespace, name)
            data = self.manifest(allowlist, ssl_redirect, resource_version)
            response = self.http_put(url, json=data)
            if self.unhealthy(response.status_code):
                raise KubeHTTPException(response, "put middleware {}".format(namespace))
            return response

        def create_or_put(self, namespace, name, allowlist, ssl_redirect):
            response = self.get(namespace, name)
            if response.status_code == 404:
                return self.create(namespace, name, allowlist, ssl_redirect)
            elif self.unhealthy(response.status_code):
                raise KubeHTTPException(response, "get middleware {}".format(namespace))
            resource_version = response.json()["metadata"]["resourceVersion"]
            return self.put(namespace, name, allowlist, ssl_redirect, resource_version)

        def delete(self, namespace, name):
            url = self.api("/namespaces/{}/middlewares/{}", namespace, name)
            response = self.http_delete(url)
            if self.unhealthy(response.status_code):
                raise KubeHTTPException(response, 'delete middlewares "{}"', namespace)

            return response

    def __init__(self, url, k8s_api_verify_tls=True):
        super().__init__(url, k8s_api_verify_tls)
        self.middleware = self.Middleware(url, k8s_api_verify_tls)

    def create(self, namespace, ingress, **kwargs):
        response = super().create(ingress, namespace, **kwargs)
        if "allowlist" in kwargs or "ssl_redirect" in kwargs:
            self.middleware.create_or_put(
                namespace, ingress,
                kwargs.get("allowlist"), kwargs.get("ssl_redirect")
            )
        return response

    def put(self, namespace, ingress, version, **kwargs):
        response = super().put(ingress, namespace, version, **kwargs)
        if "allowlist" in kwargs or "ssl_redirect" in kwargs:
            self.middleware.create_or_put(
                namespace, ingress,
                kwargs.get("allowlist"), kwargs.get("ssl_redirect")
            )
        return response

    def patch(self, namespace, ingress, data, **kwargs):
        response = super().patch(ingress, namespace, data, **kwargs)
        if "allowlist" in kwargs or "ssl_redirect" in kwargs:
            self.middleware.create_or_put(
                namespace, ingress,
                kwargs.get("allowlist"), kwargs.get("ssl_redirect")
            )
        return response

    def delete(self, namespace, ingress):
        response = super().delete(namespace, ingress)
        if not self.unhealthy(self.middleware.get(namespace, ingress)):
            self.middleware.delete(namespace, ingress)
        return response


class WildcardPathIngress(BaseIngress):
    ingress_path = "/*"


IngressFactory.register("nginx", NginxIngress)
IngressFactory.register("traefik", TraefikIngress)
IngressFactory.register("gce", WildcardPathIngress)
IngressFactory.register("alb", WildcardPathIngress)
