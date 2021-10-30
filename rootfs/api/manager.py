import requests
from typing import List, Dict
from requests_toolbelt import user_agent
from django.conf import settings
from api import __version__ as drycc_version


class ManagerAPI(object):

    def __init__(self):
        self.headers = {
                'Content-Type': 'application/json',
                'Authorization': 'token %s' % settings.WORKFLOW_MANAGER_TOKEN,
                'User-Agent': user_agent('Drycc Controller ', drycc_version)
        }

    def requests(self, method, url, **kwargs):
        headers = kwargs.get("headers", {})
        headers.update(self.headers)
        kwargs["headers"] = headers
        requests.request(method, url, **kwargs)

    def get(self, url, params=None, **kwargs):
        return self.request('get', url, params=params, **kwargs)

    def options(self, url, **kwargs):
        return self.request('options', url, **kwargs)

    def head(self, url, **kwargs):
        kwargs.setdefault('allow_redirects', False)
        return self.request('head', url, **kwargs)

    def post(self, url, data=None, json=None, **kwargs):
        return self.request('post', url, data=data, json=json, **kwargs)

    def put(self, url, data=None, **kwargs):
        return self.request('put', url, data=data, **kwargs)

    def patch(self, url, data=None, **kwargs):
        return self.request('patch', url, data=data, **kwargs)

    def delete(self, url, **kwargs):
        return self.request('delete', url, **kwargs)


class User(ManagerAPI):

    def get_status(self, username):
        """
        {
            "is_active": false,
            "message": "The user is in arrears"
        }
        """
        url = f"{settings.WORKFLOW_MANAGER_URL}/users/{username}/status/"
        return self.get(url=url).json()


class Measurement(ManagerAPI):

    def post_config(self, config: List[Dict[str, str]]):
        """
        [
            {
                "app_id":  "test",
                "owner_id": "test",
                "container_type": web,
                "cpu": "1",
                "memory": "2G",
                "timestamp": 1609231998.9103732
            }
        ]
        """
        url = "%s/measurements/config/" % settings.WORKFLOW_MANAGER_URL
        return self.post(url=url, json=config)

    def post_volumes(self, volumes: List[Dict[str, str]]):
        """
        [
            {
                "name": "disk",
                "app_id": "test",
                "owner_id": "test",
                "size": "100G",
                "timestamp": "1609231998.9103732"
            }
        ]
        """
        url = "%s/measurements/volumes/" % settings.WORKFLOW_MANAGER_URL,
        return self.post(url=url, json=volumes)

    def post_networks(self, networks: List[Dict[str, str]]):
        """
        [
            {
                "app_id": "test",
                "owner_id": "test",
                "pod_name": "django2test-web-xxxxxx",
                "rx_bytes": "10000",
                "tx_bytes": "200000",
                "timestamp": "1609231998.9103732"
            }
        ]
        """
        url = "%s/measurements/networks/" % settings.WORKFLOW_MANAGER_URL
        return self.post(url=url, json=networks)

    def post_instances(self, instances: List[Dict[str, str]]):
        """
        [
            {
                "app_id": "test",
                "owner_id":  "test",
                "container_type": "web",
                "container_count": 1,
                "timestamp": "1609231998.9103732"
            }
        ]
        """
        url = "%s/measurements/instances/" % settings.WORKFLOW_MANAGER_URL
        return self.post(url=url, json=instances)

    def post_resources(self, resources: List[Dict[str, str]]):
        """
        [
            {
                "name": "test1",
                "app_id": "redis",
                "owener_id": "test",
                "plan": "redis:small",
                "timestamp": "1609231998.9103732"
            }
        ]
        """
        url = "%s/measurements/resources/" % settings.WORKFLOW_MANAGER_URL
        return self.post(url=url, json=resources)
