import os
from scheduler.exceptions import KubeHTTPException
from scheduler.resources import Resource

MEM_REQUEST_BODY_BYTES = int(os.environ.get('MEM_REQUEST_BODY_BYTES', 1024))
MAX_REQUEST_BODY_BYTES = int(os.environ.get('MAX_REQUEST_BODY_BYTES', 1024 * 1024 * 1024))
MEM_RESPONSE_BODY_BYTES = int(os.environ.get('MEM_RESPONSE_BODY_BYTES', 1024 * 1024))
MAX_RESPONSE_BODY_BYTES = int(os.environ.get('MAX_RESPONSE_BODY_BYTES', 1024 * 1024 * 1024))


class BaseIngress(Resource):
    abstract = True
    api_version = 'networking.k8s.io/v1'
    api_prefix = 'apis'
    short_name = 'ingress'
    ingress_path = "/"
    ingress_class = None

    def manifest(self, namespace, ingress, **kwargs):
        hosts, tls = kwargs.pop("hosts", None), kwargs.pop("tls", None)
        version = kwargs.pop("version", None)
        data = {
            "kind": "Ingress",
            "apiVersion": self.api_version,
            "metadata": {
                "name": ingress,
                "namespace": namespace,
                "annotations": {
                    "kubernetes.io/tls-acme": "true"
                }
            },
            "spec": {
                "ingressClassName": self.ingress_class
            }
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

    def get(self, namespace, ingress=None, ignore_exception=False, **kwargs):
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
        if not ignore_exception and self.unhealthy(response.status_code):
            raise KubeHTTPException(response, message)

        return response

    def create(self, namespace, ingress, ignore_exception=False, **kwargs):
        url = self.api("/namespaces/{}/ingresses", namespace)
        data = self.manifest(namespace, ingress, **kwargs)
        response = self.http_post(url, json=data)

        if not ignore_exception and self.unhealthy(response.status_code):
            raise KubeHTTPException(response, "create Ingress {}".format(namespace))

        return response

    def put(self, namespace, ingress, version, ignore_exception=False, **kwargs):
        url = self.api("/namespaces/{}/ingresses/{}", namespace, ingress)
        kwargs["version"] = version
        data = self.manifest(namespace, ingress, **kwargs)
        response = self.http_put(url, json=data)

        if not ignore_exception and self.unhealthy(response.status_code):
            raise KubeHTTPException(response, "put Ingress {}".format(namespace))

        return response

    def delete(self, namespace, ingress, ignore_exception=True):
        url = self.api("/namespaces/{}/ingresses/{}", namespace, ingress)
        response = self.http_delete(url)
        if not ignore_exception and self.unhealthy(response.status_code):
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


class WildcardPathIngress(BaseIngress):
    ingress_path = "/*"
