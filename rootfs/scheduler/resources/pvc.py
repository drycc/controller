from api.settings.production import DRYCC_APP_KUBERNETES_STORAGE_CLASS
from scheduler.resources import Resource
from scheduler.exceptions import KubeHTTPException


class PersistentVolumeClaim(Resource):
    short_name = 'pvc'

    @staticmethod
    def manifest(namespace, name, version=None, **kwargs):
        labels = {
            'heritage': 'drycc',
        }
        data = {
            "apiVersion": "v1",
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
                "storageClassName": DRYCC_APP_KUBERNETES_STORAGE_CLASS,
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
