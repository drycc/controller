from scheduler.resources import Resource
from scheduler.exceptions import KubeHTTPException


class Certificate(Resource):

    def manifest(self, namespace, name, ingress_class, hosts, version=None):
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
                    "name": "drycc-cluster-issuer",
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
        if version:
            data["metadata"]["resourceVersion"] = version
        return data

    def get(self, namespace, name=None, **kwargs):
        """
        Fetch a single certificate or a list of certificates
        """
        if name is not None:
            url = "/apis/certmanager.k8s.io/v1alpha1/namespaces/%s/certificates/%s" % (
                namespace, name)
            message = 'get certificate ' + name
        else:
            url = "/apis/certmanager.k8s.io/v1alpha1/namespaces/%s/certificates" % namespace
            message = 'get certificates'
        response = self.http_get(url)
        if self.unhealthy(response.status_code):
            raise KubeHTTPException(response, message)

        return response

    def create(self, namespace, name, ingress_class, hosts):
        url = "/apis/certmanager.k8s.io/v1alpha1/namespaces/%s/certificates" % namespace
        data = self.manifest(namespace, name, ingress_class, hosts)
        response = self.http_post(url, json=data)

        if not response.status_code == 201:
            raise KubeHTTPException(response, "create certificate {}".format(namespace))

        return response

    def put(self, namespace, name, ingress_class, hosts, version):
        url = "/apis/certmanager.k8s.io/v1alpha1/namespaces/%s/certificates/%s" % (namespace, name)
        data = self.manifest(namespace, name, ingress_class, hosts, version)
        response = self.http_put(url, json=data)

        if self.unhealthy(response.status_code):
            raise KubeHTTPException(response, "put certificate {}".format(namespace))
        return response

    def delete(self, namespace, name):
        """
        Delete certificate
        """
        url = "/apis/certmanager.k8s.io/v1alpha1/namespaces/%s/certificates/%s" % (namespace, name)
        response = self.http_delete(url)
        if self.unhealthy(response.status_code):
            raise KubeHTTPException(response, 'delete certificate ' + name)
        return response
