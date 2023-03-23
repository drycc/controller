import json
from scheduler.resources import Resource
from scheduler.exceptions import KubeHTTPException


class PersistentVolumeClaim(Resource):
    short_name = 'pvc'

    def manifest(self, namespace, name, version=None, **kwargs):
        labels = {
            'heritage': 'drycc',
        }
        data = {
            "apiVersion": self.api_version,
            "kind": "PersistentVolumeClaim",
            "metadata": {
                "name": name,
                "namespace": namespace,
                'labels': labels
            },
            "spec": {
                "accessModes": [
                    "ReadWriteMany"
                ],
                "resources": {
                    "requests": {
                        "storage": kwargs.get('size')
                    },
                },
                "storageClassName": kwargs.get("storage_class"),
                "volumeMode": "Filesystem",
            }
        }
        if version:
            data["metadata"]["resourceVersion"] = version
        return data

    def get(self, namespace, name=None):
        """
        Fetch a single persistentvolumeclaim or a list of persistentvolumeclaim
        """
        if name is not None:
            url = self.api('/namespaces/{}/persistentvolumeclaims/{}',
                           namespace, name)
            message = 'get persistentvolumeclaim ' + name
        else:
            url = self.api('/namespaces/{}/persistentvolumeclaims', namespace)
            message = 'get persistentvolumeclaims'
        response = self.http_get(url)
        if self.unhealthy(response.status_code):
            raise KubeHTTPException(response, message)
        return response

    def create(self, namespace, name, **kwargs):
        """
        Create persistentvolumeclaim
        """
        url = self.api('/namespaces/{}/persistentvolumeclaims', namespace)
        data = self.manifest(namespace, name, **kwargs)
        response = self.http_post(url, json=data)
        if not response.status_code == 201:
            raise KubeHTTPException(
                response,
                "create persistentvolumeclaim {}".format(namespace))
        return response

    def patch(self, namespace, name, **kwargs):
        url = self.api('/namespaces/{}/persistentvolumeclaims/{}', namespace,
                       name)
        data = self.manifest(namespace, name, **kwargs)
        response = self.http_patch(url, json=data, headers={"Content-Type": "application/merge-patch+json"})  # noqa
        if self.unhealthy(response.status_code):
            self.log(namespace, 'template used: {}'.format(json.dumps(data, indent=4)), 'DEBUG')  # noqa
            raise KubeHTTPException(response, 'update persistentvolumeclaims "{}"', name)
        return response

    def delete(self, namespace, name):
        """
        Delete persistentvolumeclaim
        """
        url = self.api('/namespaces/{}/persistentvolumeclaims/{}', namespace,
                       name)
        response = self.http_delete(url)
        if self.unhealthy(response.status_code):
            raise KubeHTTPException(response,
                                    'delete persistentvolumeclaim ' + name)
        return response
