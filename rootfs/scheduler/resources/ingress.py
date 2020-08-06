from scheduler.exceptions import KubeHTTPException
from scheduler.resources import Resource

MANIFEAT_CLASSES = {}


class BaseManifest(object):

    def manifest(self, api_version, ingress, ingress_class, namespace, **kwargs):
        path = "/*" if ingress_class in ("gce", "alb") else "/"
        hosts, tls = kwargs.pop("hosts", None), kwargs.pop("tls", None)
        version = kwargs.pop("version", None)
        data = {
            "kind": "Ingress",
            "apiVersion": api_version,
            "metadata": {
                "name": ingress,
                "annotations": {
                    "kubernetes.io/tls-acme": "true",
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
                            "path": path,
                            "backend": {
                                "serviceName": ingress,
                                "servicePort": 80
                            }
                        }
                    ]
                }
            } for host in hosts]
        if ingress_class:
            data["metadata"]["annotations"].update({
                "kubernetes.io/ingress.class": ingress_class
            })
        if tls:
            data["spec"]["tls"] = tls
        if version:
            data["metadata"]["resourceVersion"] = version
        return data


class NginxManifest(BaseManifest):

    def manifest(self, api_version, ingress, ingress_class, namespace, **kwargs):
        data = BaseManifest.manifest(
            self, api_version, ingress, ingress_class, namespace, **kwargs)
        if "whitelist" in kwargs:
            whitelist = ", ".join(kwargs.pop("whitelist"))
            data["metadata"]["annotations"].update({
                "nginx.ingress.kubernetes.io/whitelist-source-range": whitelist
            })
        if "ssl_redirect" in kwargs:
            ssl_redirect = kwargs.pop("ssl_redirect")
            data["metadata"]["annotations"].update({
                "nginx.ingress.kubernetes.io/ssl-redirect": ssl_redirect
            })
        return data


MANIFEAT_CLASSES["nginx"] = NginxManifest


class TraefikManifest(BaseManifest):

    def manifest(self, api_version, ingress, ingress_class, namespace, **kwargs):
        data = BaseManifest.manifest(
            self, api_version, ingress, ingress_class, namespace, **kwargs)
        if "whitelist" in kwargs:
            whitelist = ", ".join(kwargs.pop("whitelist"))
            data["metadata"]["annotations"].update({
                "ingress.kubernetes.io/whitelist-x-forwarded-for": "true",
                "traefik.ingress.kubernetes.io/whitelist-source-range": whitelist
            })
        if "ssl_redirect" in kwargs:
            ssl_redirect = kwargs.pop("ssl_redirect")
            data["metadata"]["annotations"].update({
                "ingress.kubernetes.io/ssl-redirect": ssl_redirect
            })
        return data


MANIFEAT_CLASSES["traefik"] = TraefikManifest


class Ingress(Resource):

    api_version = 'networking.k8s.io/v1beta1'
    api_prefix = 'apis'
    short_name = 'ingress'

    def manifest(self, api_version, ingress, ingress_class, namespace, **kwargs):
        return MANIFEAT_CLASSES.get(ingress_class, BaseManifest)().manifest(
            api_version, ingress, ingress_class, namespace, **kwargs
        )

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

    def create(self, ingress, ingress_class, namespace, **kwargs):
        url = self.api("/namespaces/{}/ingresses", namespace)
        data = self.manifest(self.api_version, ingress, ingress_class, namespace, **kwargs)
        response = self.http_post(url, json=data)

        if not response.status_code == 201:
            raise KubeHTTPException(response, "create Ingress {}".format(namespace))

        return response

    def put(self, ingress, ingress_class, namespace, version, **kwargs):
        url = self.api("/namespaces/{}/ingresses/{}", namespace, ingress)
        kwargs["version"] = version
        data = self.manifest(self.api_version, ingress, ingress_class, namespace, **kwargs)
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
