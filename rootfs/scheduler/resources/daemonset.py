import json
import logging
from scheduler.resources import Resource
from scheduler.exceptions import KubeHTTPException


class Daemonset(Resource):
    api_prefix = 'apis'
    api_version = 'apps/v1'

    def get(self, namespace, name=None, ignore_exception=False, **kwargs):
        """
        Fetch a single Daemonsets or a list
        """
        url = '/namespaces/{}/daemonsets'
        args = [namespace]
        if name is not None:
            args.append(name)
            url += '/{}'
            message = 'get Daemonset "{}" in Namespace "{}"'
        else:
            message = 'get Daemonsets in Namespace "{}"'

        url = self.api(url, *args)
        response = self.http_get(url, params=self.query_params(**kwargs))
        if self.unhealthy(response.status_code) and not ignore_exception:
            args.reverse()  # error msg is in reverse order
            raise KubeHTTPException(response, message, *args)

        return response

    def patch(self, namespace, name, manifest, ignore_exception=False, **kwargs):
        url = self.api("/namespaces/{}/daemonsets/{}", namespace, name)
        response = self.http_patch(
            url,
            json=manifest,
            headers={"Content-Type": "application/merge-patch+json"}
        )

        if self.unhealthy(response.status_code):
            self.log(
                namespace, 'template: {}'.format(json.dumps(manifest, indent=4)), logging.DEBUG)
            if not ignore_exception:
                raise KubeHTTPException(response, 'patch Daemonset "{}"', name)
        return response
