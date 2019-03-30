import json
from scheduler.resources import Resource
from scheduler.exceptions import KubeHTTPException, KubeException


class Certificate(Resource):

    def manifest(self, namespace, name, ingress_class, hosts):
        data = {
            "apiVersion": "certmanager.k8s.io/v1alpha1",
            "kind": "Certificate",
            "metadata": {
                "name": name,
                "namespace": namespace
            },
            "spec": {
                "secretName": "%s-auto-tls" % name,
                "issuerRef": {
                    "name": "drycc-controller-letsencrypt",
                    "kind": "ClusterIssuer"
                },
                "dnsNames": hosts,
                "acme": {
                    "config": [
                        {
                            "http01": {
                                "ingressClass": ingress_class
                            },
                            "domains": hosts
                        }
                    ]
                }
            }
        }
        return data

    def get(self, namespace, name):
        """
        Fetch a single Ingress or a list of Ingresses
        """
        if name is not None:
            url = "/apis/certmanager/v1alpha1/namespaces/%s/certificates/%s" % (namespace, name)
            message = 'get Ingress ' + name
        else:
            url = "/apis/certmanager/v1alpha1/namespaces/%s/certificates" % namespace
            message = 'get Ingresses'

    def create(self, namespace, name, ingress_class, hosts):
        pass

    def put(self, namespace, name, ingress_class, hosts):
        pass

    def delete(self, namespace, name):
        pass