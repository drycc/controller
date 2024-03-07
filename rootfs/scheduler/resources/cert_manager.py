from scheduler.resources import Resource
from scheduler.exceptions import KubeHTTPException


class Issuer(Resource):
    api_prefix = 'apis'
    api_version = 'cert-manager.io/v1'

    def get(self, namespace, name=None, ignore_exception=True, **kwargs):
        """
        Fetch a single Issuer or a list of Issuers
        """
        if name is not None:
            url = self.api("/namespaces/{}/issuers/{}", namespace, name)
            message = 'get Issuer ' + name
        else:
            url = self.api("/namespaces/{}/issuers", namespace)
            message = 'get Issuers'

        response = self.http_get(url, params=self.query_params(**kwargs))
        if not ignore_exception and self.unhealthy(response.status_code):
            raise KubeHTTPException(response, message)

        return response

    def manifest(self, namespace, name, **kwargs):
        data = {
            "apiVersion": "cert-manager.io/v1",
            "kind": "Issuer",
            "metadata": {
                "name": name,
                "namespace": namespace,
            },
            "spec": {
                "acme": {
                    "email": "drycc@drycc.cc",
                    "privateKeySecretRef": {
                        "name": f"{name}-acme-private-key-secret"
                    },
                    "server": kwargs["server"],
                    "solvers": [{
                        "http01": {
                            "gatewayHTTPRoute": {
                                "parentRefs": kwargs["parent_refs"]
                            }
                        }
                    }]
                }
            }
        }
        if "version" in kwargs:
            data["metadata"]["resourceVersion"] = kwargs.get("version")
        if "key_id" in kwargs and "key_secret" in kwargs:
            data["spec"]["acme"]["externalAccountBinding"] = {
                "keyID": kwargs["key_id"],
                "keySecretRef": {
                    "key": "secret",
                    "name": f"{name}-acme-external-account-binding-secret"
                }
            }
        return data

    def create(self, namespace, name, ignore_exception=True, **kwargs):
        manifest = self.manifest(namespace, name, **kwargs)
        url = self.api("/namespaces/{}/issuers", namespace)
        response = self.http_post(url, json=manifest)
        if not ignore_exception and self.unhealthy(response.status_code):
            raise KubeHTTPException(
                response,
                'failed to create issuer "{}" in Namespace "{}"', name, namespace
            )

        return response

    def put(self, namespace, name, ignore_exception=True, **kwargs):
        manifest = self.manifest(namespace, name, **kwargs)
        url = self.api("/namespaces/{}/issuers/{}", namespace, name)
        response = self.http_put(url, json=manifest)
        if not ignore_exception and self.unhealthy(response.status_code):
            raise KubeHTTPException(
                response,
                'failed to update issuer "{}" in Namespace "{}"',
                name, namespace
            )

        return response

    def delete(self, namespace, name, ignore_exception=False):
        url = self.api("/namespaces/{}/issuers/{}", namespace, name)
        response = self.http_delete(url)
        if not ignore_exception and self.unhealthy(response.status_code):
            raise KubeHTTPException(
                response,
                'delete issuer "{}" in Namespace "{}"', name, namespace
            )

        return response


class Certificate(Resource):
    api_version = 'cert-manager.io/v1'
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
                "secretName": "%s-certificate-auto" % name,
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

    def get(self, namespace, name=None, ignore_exception=True, **kwargs):
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
        if not ignore_exception and self.unhealthy(response.status_code):
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

    def delete(self, namespace, name, ignore_exception=False):
        """
        Delete certificate
        """
        url = self.api('/namespaces/{}/certificates/{}', namespace, name)
        response = self.http_delete(url)
        if not ignore_exception and self.unhealthy(response.status_code):
            raise KubeHTTPException(response, 'delete certificate ' + name)
        return response
