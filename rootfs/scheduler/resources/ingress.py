from scheduler.exceptions import KubeHTTPException
from scheduler.resources import Resource

MANIFEAT_CLASSES = {}


class BaseManifest(object):

    def manifest(self, ingress, ingress_class, namespace, **kwargs):
        path = "/*" if ingress_class in ("gce", "alb") else "/"
        hosts, tls = kwargs.pop("hosts"), kwargs.pop("tls")
        data = {
            "kind": "Ingress",
            "apiVersion": "extensions/v1beta1",
            "metadata": {
                "name": ingress,
                "annotations": {
                    "kubernetes.io/tls-acme": "true",
                    "kubernetes.io/ingress.class": ingress_class
                }
            },
            "spec": {
                "rules": [{
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
                } for host in hosts],
                "tls": tls
            }
        }
        return data
MANIFEAT_CLASSES["default"] = BaseManifest


class NginxManifest(BaseManifest):

    def manifest(self, ingress, ingress_class, namespace, **kwargs):
        data = BaseManifest.manifest(
            self, ingress, ingress_class, namespace, **kwargs)
        if "whitelist" in kwargs:
            whitelist = ", ".join(kwargs.pop("whitelist"))
            data.update({
                "nginx.ingress.kubernetes.io/whitelist-source-range": whitelist
            })
        if "ssl_redirect" in kwargs:
            ssl_redirect = kwargs.pop("ssl_redirect")
            data.update({
                "nginx.ingress.kubernetes.io/ssl-redirect": ssl_redirect
            })
        return data
MANIFEAT_CLASSES["nginx"] = NginxManifest


class TraefikManifest(BaseManifest):

    def manifest(self, ingress, ingress_class, namespace, **kwargs):
        data = BaseManifest.manifest(
            self, ingress, ingress_class, namespace, **kwargs)
        if "whitelist" in kwargs:
            whitelist = ", ".join(kwargs.pop("whitelist"))
            data.update({
                "ingress.kubernetes.io/whitelist-x-forwarded-for": "true",
                "traefik.ingress.kubernetes.io/whitelist-source-range": whitelist
            })
        if "ssl_redirect" in kwargs:
            ssl_redirect = kwargs.pop("ssl_redirect")
            data.update({
                "ingress.kubernetes.io/ssl-redirect": ssl_redirect
            })
        return data
MANIFEAT_CLASSES["traefik"] = TraefikManifest


class Ingress(Resource):
    short_name = 'ingress'

    def manifest(self, ingress, ingress_class, namespace, **kwargs):
        if ingress_class not in MANIFEAT_CLASSES:
            ingress_class = "default"
        return MANIFEAT_CLASSES.get(ingress_class)().manifest(
            ingress, ingress_class, namespace, **kwargs
        )

    def get(self, name=None, **kwargs):
        """
        Fetch a single Ingress or a list of Ingresses
        """
        if name is not None:
            url = "/apis/extensions/v1beta1/namespaces/%s/ingresses/%s" % (name, name)
            message = 'get Ingress ' + name
        else:
            url = "/apis/extensions/v1beta1/namespaces/%s/ingresses" % name
            message = 'get Ingresses'

        response = self.http_get(url, params=self.query_params(**kwargs))
        if self.unhealthy(response.status_code):
            raise KubeHTTPException(response, message)

        return response

    def create(self, ingress, ingress_class, namespace, **kwargs):
        url = "/apis/extensions/v1beta1/namespaces/%s/ingresses" % namespace
        data = self.manifest(ingress, ingress_class, namespace, **kwargs)
        response = self.http_post(url, json=data)

        if not response.status_code == 201:
            raise KubeHTTPException(response, "create Ingress {}".format(namespace))

        return response

    def update(self, ingress, ingress_class, namespace, **kwargs):
        url = "/apis/extensions/v1beta1/namespaces/%s/ingresses/%s" % (namespace, ingress)
        data = self.manifest(ingress, ingress_class, namespace, **kwargs)
        response = self.http_put(url, json=data)

        if self.unhealthy(response.status_code):
            raise KubeHTTPException(response, "update Ingress {}".format(namespace))

        return response

    def delete(self, namespace, ingress):
        url = "/apis/extensions/v1beta1/namespaces/%s/ingresses/%s" % (namespace, ingress)
        response = self.http_delete(url)
        if self.unhealthy(response.status_code):
            raise KubeHTTPException(response, 'delete Ingress "{}"', namespace)

        return response