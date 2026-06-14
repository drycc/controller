import logging


class ResourceRegistry(type):
    """
    A registry of all Resources subclassed
    """
    def __init__(cls, name, bases, nmspc):
        super().__init__(name, bases, nmspc)
        if not hasattr(cls, 'registry'):
            cls.registry = set()

        cls.registry.add(cls)
        cls.registry -= set(bases)  # Remove base classes

    # Meta methods, called on class objects:
    def __iter__(cls):
        return iter(cls.registry)


class Resource(metaclass=ResourceRegistry):
    """Base class for Kubernetes resources. Uses composition with KubeHTTPClient."""
    api_version = 'v1'
    api_prefix = 'api'
    short_name = None

    def __init__(self, client):
        self.client = client

    @property
    def url(self):
        return self.client.url

    @property
    def metadata(self):
        return self.client.metadata

    def api(self, tmpl, *args):
        """Return a fully-qualified Kubernetes API URL from a string template with args."""
        return "/{}/{}".format(self.api_prefix, self.api_version) + tmpl.format(*args)

    def http_head(self, path, **kwargs):
        return self.client.http_head(path, **kwargs)

    def http_get(self, path, params=None, **kwargs):
        return self.client.http_get(path, params=params, **kwargs)

    def http_post(self, path, json=None, **kwargs):
        return self.client.http_post(path, json=json, **kwargs)

    def http_put(self, path, json=None, **kwargs):
        return self.client.http_put(path, json=json, **kwargs)

    def http_patch(self, path, json=None, **kwargs):
        return self.client.http_patch(path, json=json, **kwargs)

    def http_delete(self, path, **kwargs):
        return self.client.http_delete(path, **kwargs)

    def query_params(self, **kwargs):
        return self.client.query_params(**kwargs)

    def unhealthy(self, status_code):
        return self.client.unhealthy(status_code)

    def log(self, namespace, message, level=logging.INFO):
        return self.client.log(namespace, message, level)

    def version(self):
        return self.client.version()

    def parse_date(self, date):
        return self.client.parse_date(date)

    def __getattr__(self, name):
        """Delegate attribute access to the client for cross-resource access."""
        if name.startswith('__') and name.endswith('__'):
            raise AttributeError(f"'{type(self).__name__}' object has no attribute '{name}'")
        return getattr(self.client, name)
