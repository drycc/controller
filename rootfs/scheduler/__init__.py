
import re
import logging
import urllib3
import requests
import requests.exceptions

from collections import OrderedDict
from datetime import datetime, timezone
from packaging.version import Version, parse
from requests_toolbelt import user_agent
from urllib.parse import urljoin

from api import utils, __version__ as drycc_version
from scheduler.exceptions import KubeException, KubeHTTPException


logger = logging.getLogger(__name__)


def _create_k8s_session(k8s_api_verify_tls):
    """Create a new requests.Session configured for the Kubernetes API."""
    with open('/var/run/secrets/kubernetes.io/serviceaccount/token') as token_file:
        token = token_file.read().strip("\r\n\t")
    session = requests.Session()
    session.headers = {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json',
        'User-Agent': user_agent('Drycc Controller', drycc_version)
    }
    if k8s_api_verify_tls:
        session.verify = '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt'
    else:
        session.verify = False
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return session


class KubeHTTPClient(object):
    api_version = 'v1'
    api_prefix = 'api'
    # ISO-8601 which is used by kubernetes
    DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
    resource_mapping = OrderedDict()

    def __init__(self, url, k8s_api_verify_tls=True, metadata=None):
        self.url = url
        self.k8s_api_verify_tls = k8s_api_verify_tls
        self._session = None
        self.metadata = {} if metadata is None else metadata

        # map the various k8s Resources to an internal property
        from scheduler.resources import Resource  # lazy load
        KubeHTTPClient.resource_mapping = OrderedDict()
        for res in Resource:
            name = str(res.__name__).lower()  # singular
            component = name + 's'  # make plural
            # check if component has already been processed
            if component in self.resource_mapping:
                continue

            # get past recursion problems in case of self reference
            self.resource_mapping[component] = ''
            self.resource_mapping[component] = res(self)
            # map singular Resource name to the plural one
            self.resource_mapping[name] = component
            if res.short_name is not None:
                # map short name to long name so a resource can be named rs
                # but have the main object live at replicasets
                self.resource_mapping[str(res.short_name).lower()] = component

    @property
    def session(self):
        """Lazy-create the Kubernetes API session on first access."""
        if self._session is None:
            self._session = _create_k8s_session(self.k8s_api_verify_tls)
        return self._session

    def api(self, tmpl, *args):
        """Return a fully-qualified Kubernetes API URL from a string template with args."""
        return "/{}/{}".format(self.api_prefix, self.api_version) + tmpl.format(*args)

    def __getattr__(self, name):
        if name in self.resource_mapping:
            # resolve to final name if needed
            component = self.resource_mapping[name]
            if type(component) is not str:
                # already a component object
                return component

            return self.resource_mapping[component]

        return object.__getattribute__(self, name)

    def version(self):
        """Get Kubernetes version"""
        response = self.http_get('/version')
        if self.unhealthy(response.status_code):
            raise KubeHTTPException(response, 'fetching Kubernetes version')

        data = response.json()
        parsed_version = parse(
            re.sub(r"[^0-9\.]", '', str('{}.{}'.format(data['major'], data['minor']))))
        return Version('{}'.format(parsed_version))

    @staticmethod
    def parse_date(date):
        return datetime.strptime(date, KubeHTTPClient.DATETIME_FORMAT).replace(tzinfo=timezone.utc)

    @staticmethod
    def unhealthy(status_code):
        return not 200 <= status_code <= 299

    @staticmethod
    def query_params(labels=None, fields=None, resource_version=None, pretty=False):
        query = {}

        # labels and fields are encoded slightly differently than python-requests can do
        if labels:
            selectors = []
            for key, value in labels.items():
                # http://kubernetes.io/docs/user-guide/labels/#set-based-requirement
                if '__notin' in key:
                    key = key.replace('__notin', '')
                    selectors.append('{} notin({})'.format(key, ','.join(value)))
                # list is automagically a in()
                elif '__in' in key or isinstance(value, list):
                    key = key.replace('__in', '')
                    selectors.append('{} in({})'.format(key, ','.join(value)))
                elif value is None:
                    # allowing a check if a label exists (or not) without caring about value
                    selectors.append(key)
                # http://kubernetes.io/docs/user-guide/labels/#equality-based-requirement
                elif isinstance(value, str):
                    selectors.append('{}={}'.format(key, value))

            query['labelSelector'] = ','.join(selectors)

        if fields:
            fields = ['{}={}'.format(key, value) for key, value in fields.items()]
            query['fieldSelector'] = ','.join(fields)

        # Which resource version to start from. Otherwise starts from the beginning
        if resource_version:
            query['resourceVersion'] = resource_version

        # If output should pretty print, only True / False allowed
        if pretty:
            query['pretty'] = pretty

        return query

    @staticmethod
    def log(namespace, message, level=logging.INFO):
        """Logs a message in the context of this application.

        This prefixes log messages with a namespace "tag".
        When it's seen, the message-- usually an application event of some
        sort like releasing or scaling, will be considered as "belonging" to the application
        instead of the controller and will be handled accordingly.
        """
        utils.send_app_log(namespace, message, level)
        logger.log(level, "[{}]: {}".format(namespace, message))

    def _request(self, method, path, **kwargs):
        """Execute an HTTP request to the Kubernetes API server."""
        url = urljoin(self.url, path)
        method_fn = getattr(self.session, method.lower())
        try:
            return method_fn(url, **kwargs)
        except requests.exceptions.ConnectionError as err:
            raise KubeException(
                "There was a problem communicating with the Kubernetes API server. "
                "URL: {}, method: {}".format(url, method)
            ) from err

    def http_head(self, path, **kwargs):
        """Make a HEAD request to the k8s server."""
        return self._request('HEAD', path, **kwargs)

    def http_get(self, path, params=None, **kwargs):
        """Make a GET request to the k8s server."""
        return self._request('GET', path, params=params, **kwargs)

    def _merge_metadata(self, json_body):
        """Merge instance metadata into the JSON body (mutates json_body in place)."""
        if json_body is not None and "metadata" in json_body and self.metadata:
            json_body["metadata"] = utils.dict_merge(json_body["metadata"], self.metadata)
        return json_body

    def http_post(self, path, json=None, **kwargs):
        """Make a POST request to the k8s server."""
        self._merge_metadata(json)
        return self._request('POST', path, json=json, **kwargs)

    def http_put(self, path, json=None, **kwargs):
        """Make a PUT request to the k8s server."""
        self._merge_metadata(json)
        return self._request('PUT', path, json=json, **kwargs)

    def http_patch(self, path, json=None, **kwargs):
        """Make a PATCH request to the k8s server."""
        self._merge_metadata(json)
        return self._request('PATCH', path, json=json, **kwargs)

    def http_delete(self, path, **kwargs):
        """Make a DELETE request to the k8s server."""
        return self._request('DELETE', path, **kwargs)

    def deploy(self, namespace, name, image, command, args, **kwargs):
        """Deploy Deployment depending on what's requested.
        Delegates to the Deployment resource."""
        return self.deployment.deploy_release(namespace, name, image, command, args, **kwargs)

    def scale(self, namespace, name, image, command, args, **kwargs):
        """Scale Deployment.
        Delegates to the Deployment resource."""
        return self.deployment.scale_with_fallback(namespace, name, image, command, args, **kwargs)


SchedulerClient = KubeHTTPClient
