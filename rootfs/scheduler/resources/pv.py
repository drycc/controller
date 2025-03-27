import json
from scheduler.resources import Resource
from scheduler.exceptions import KubeHTTPException


class PersistentVolume(Resource):
    short_name = 'pv'

    def manifest(self, name, version=None, **kwargs):
        labels = {
            'heritage': 'drycc',
        }
        data = {
            "apiVersion": self.api_version,
            "kind": "PersistentVolume",
            "metadata": {
                "name": name,
                'labels': labels
            },
        }
        data.update(kwargs)
        if version:
            data["metadata"]["resourceVersion"] = version
        return data

    def get(self, name=None):
        """
        Fetch a single persistentvolume or a list of persistentvolumes
        """
        if name is not None:
            url = self.api('/persistentvolumes/{}', name)
            message = 'get persistentvolume ' + name
        else:
            url = self.api('/persistentvolumes')
            message = 'get persistentvolumes'
        response = self.http_get(url)
        if self.unhealthy(response.status_code):
            raise KubeHTTPException(response, message)
        return response

    def create(self, name, **kwargs):
        """
        Create persistentvolume
        """
        url = self.api('/persistentvolumes')
        data = self.manifest(name, **kwargs)
        response = self.http_post(url, json=data)
        if not response.status_code == 201:
            raise KubeHTTPException(
                response,
                "create persistentvolume"
            )
        return response

    def patch(self, name, **kwargs):
        url = self.api('/persistentvolumes/{}', name)
        data = self.manifest(name, **kwargs)
        response = self.http_patch(url, json=data, headers={"Content-Type": "application/merge-patch+json"})  # noqa
        if self.unhealthy(response.status_code):
            self.log('template used: {}'.format(json.dumps(data, indent=4)), 'DEBUG')
            raise KubeHTTPException(response, 'update persistentvolume "{}"', name)
        return response

    def delete(self, name):
        """
        Delete persistentvolume
        """
        url = self.api('/persistentvolumes/{}', name)
        response = self.http_delete(url)
        if self.unhealthy(response.status_code):
            raise KubeHTTPException(response,
                                    'delete persistentvolume ' + name)
        return response
