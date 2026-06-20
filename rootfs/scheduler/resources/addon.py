from scheduler.resources import Resource
from scheduler.exceptions import KubeException, KubeHTTPException


class AddonClass(Resource):
    api_prefix = 'apis'
    api_version = 'addons.drycc.cc/v1'
    short_name = 'addonclasses'

    def get(self, name=None, ignore_exception=True):
        url = "/addonclasses"
        args = []
        if name is not None:
            args.append(name)
            url += "/{}"
            message = 'get AddonClass "{}"'
        else:
            message = 'get AddonClasses'
        url = self.api(url, *args)
        response = self.http_get(url)
        if not ignore_exception and self.unhealthy(response.status_code):
            raise KubeHTTPException(response, message, *args)
        return response


class AddonResource(Resource):
    api_prefix = 'apis'
    api_version = 'addons.drycc.cc/v1'

    def get(self, namespace, name=None, ignore_exception=True, **kwargs):
        kind = kwargs.pop("kind", None)
        if kind is None:
            raise KubeException("kind is required for AddonResource operations")
        plural = kind.lower()
        if name is not None:
            url = self.api("/namespaces/{}/{}/{}", namespace, plural, name)
            message = 'get {} {}'.format(kind, name)
        else:
            url = self.api("/namespaces/{}/{}", namespace, plural)
            message = 'get {}s'.format(kind)
        response = self.http_get(url, params=self.query_params(**kwargs))
        if not ignore_exception and self.unhealthy(response.status_code):
            raise KubeHTTPException(response, message)
        return response

    def create(self, namespace, name, ignore_exception=True, **kwargs):
        kind = kwargs.pop("kind", None)
        if kind is None:
            raise KubeException("kind is required for AddonResource operations")
        manifest = kwargs["manifest"]
        plural = kind.lower()
        url = self.api("/namespaces/{}/{}", namespace, plural)
        response = self.http_post(url, json=manifest)
        if not ignore_exception and self.unhealthy(response.status_code):
            raise KubeHTTPException(
                response, 'create {} "{}" in Namespace "{}"',
                kind, name, namespace)
        return response

    def put(self, namespace, name, ignore_exception=True, **kwargs):
        kind = kwargs.pop("kind", None)
        if kind is None:
            raise KubeException("kind is required for AddonResource operations")
        manifest = kwargs["manifest"]
        plural = kind.lower()
        url = self.api("/namespaces/{}/{}/{}", namespace, plural, name)
        response = self.http_put(url, json=manifest)
        if not ignore_exception and self.unhealthy(response.status_code):
            raise KubeHTTPException(
                response, 'update {} "{}" in Namespace "{}"', kind, name, namespace)
        return response

    def delete(self, namespace, name, ignore_exception=True, **kwargs):
        kind = kwargs.pop("kind", None)
        if kind is None:
            raise KubeException("kind is required for AddonResource operations")
        plural = kind.lower()
        url = self.api("/namespaces/{}/{}/{}", namespace, plural, name)
        response = self.http_delete(url)
        if not ignore_exception and self.unhealthy(response.status_code):
            raise KubeHTTPException(
                response, 'delete {} "{}" in Namespace "{}"', kind, name, namespace)
        return response
