from scheduler.resources import Resource
from scheduler.exceptions import KubeHTTPException


class Certificate(Resource):
    api_version = 'cert-manager.io/v1alpha2'
    api_prefix = 'apis'

    @staticmethod
    def manifest(api_version, namespace, name, hosts, version=None):
        data = {
            "apiVersion": api_version,
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
                "dnsNames": hosts
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
            url = self.api('/namespaces/{}/certificates/{}', namespace, name)
            message = 'get certificate ' + name
        else:
            url = self.api('/namespaces/{}/certificates', namespace)
            message = 'get certificates'
        response = self.http_get(url)
        if self.unhealthy(response.status_code):
            raise KubeHTTPException(response, message)

        return response

    def create(self, namespace, name, hosts):

        url = self.api('/namespaces/{}/certificates', namespace)
        data = self.manifest(self.api_version, namespace, name, hosts)
        response = self.http_post(url, json=data)

        if not response.status_code == 201:
            raise KubeHTTPException(response, "create certificate {}".format(namespace))

        return response

    def put(self, namespace, name, hosts, version):
        url = self.api('/namespaces/{}/certificates/{}', namespace, name)
        data = self.manifest(self.api_version, namespace, name, hosts, version)
        response = self.http_put(url, json=data)

        if self.unhealthy(response.status_code):
            raise KubeHTTPException(response, "put certificate {}".format(namespace))
        return response

    def delete(self, namespace, name):
        """
        Delete certificate
        """
        url = self.api('/namespaces/{}/certificates/{}', namespace, name)
        response = self.http_delete(url)
        if self.unhealthy(response.status_code):
            raise KubeHTTPException(response, 'delete certificate ' + name)
        return response
