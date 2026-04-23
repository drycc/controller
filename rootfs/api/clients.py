import base64
import logging
import requests
import urllib.parse
from typing import List, Dict
from django.core.cache import cache
from requests_toolbelt import user_agent
from django.conf import settings
from api import __version__ as drycc_version

logger = logging.getLogger(__name__)


class ManagerAPI(object):

    def __init__(self, timeout=3):
        self.timeout = timeout
        token = base64.b85encode(b"%s:%s" % (
            settings.SOCIAL_AUTH_DRYCC_KEY.encode("utf8"),
            settings.SOCIAL_AUTH_DRYCC_SECRET.encode("utf8"),
        )).decode("utf8")
        self.headers = {
            'Content-Type': 'application/json',
            'Authorization': 'token %s' % token,
            'User-Agent': user_agent('Drycc Controller ', drycc_version)
        }

    def request(self, method, url, **kwargs):
        headers = kwargs.get("headers", {})
        headers.update(self.headers)
        kwargs["headers"] = headers
        kwargs["timeout"] = self.timeout
        return requests.request(method, url, **kwargs)

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


class WorkspaceAPI(ManagerAPI):

    def get_status(self, workspace_id):
        """
        {
            "is_active": False,
            "message": "The user is in arrears"
        }
        """
        key = f"workspace:status:{workspace_id}"
        status = cache.get(key)
        if not status:
            url = f"{settings.WORKFLOW_MANAGER_URL}/workspaces/{workspace_id}/status/"
            try:
                status = self.get(url=url, timeout=self.timeout).json()
            except requests.exceptions.Timeout as ex:
                msg = f"request workspace {workspace_id} timeout, skipping verification."
                status = {"is_active": True, "message": msg}
                logger.error(msg)
                logger.exception(ex)
            cache.set(key, status, timeout=settings.DRYCC_CACHE_USER_TIME)
        return status


class UserAPI(WorkspaceAPI):
    """Backward-compatible alias for legacy call sites."""


class UsageAPI(ManagerAPI):

    def post(self, usages: List[Dict[str, str]]):
        """
        [
            {
                "app_id":  "test",
                "workspace": "test",
                "name": "web",
                "type": "limits",
                "unit": "std1.large.c1m1",
                "usage": "2",
                "timestamp": "1609231998.9103732"
            }
        ]
        """
        url = "%s/usages/" % settings.WORKFLOW_MANAGER_URL
        return super().post(url=url, json=usages)


class PassportAPI(object):
    """Service-to-service client for Drycc Passport using OAuth2 client_credentials."""

    TOKEN_CACHE_KEY = "controller:passport:m2m_token"
    TOKEN_REFRESH_LEEWAY = 60

    def __init__(self, timeout=10):
        self.timeout = timeout
        self.base_url = settings.DRYCC_PASSPORT_URL.rstrip("/")

    def _get_token(self) -> str:
        token = cache.get(self.TOKEN_CACHE_KEY)
        if token and self.get_scopes(token) == set(settings.DRYCC_PASSPORT_SCOPES.split()):
            return token
        resp = requests.post(
            f"{self.base_url}/oauth/token/",
            data={
                "grant_type": "client_credentials",
                "client_id": settings.SOCIAL_AUTH_DRYCC_KEY,
                "client_secret": settings.SOCIAL_AUTH_DRYCC_SECRET,
                "scope": settings.DRYCC_PASSPORT_SCOPES,
            },
            timeout=self.timeout,
        )
        resp.raise_for_status()
        body = resp.json()
        token = body["access_token"]
        ttl = max(int(body.get("expires_in", 3600)) - self.TOKEN_REFRESH_LEEWAY, 60)
        cache.set(self.TOKEN_CACHE_KEY, token, timeout=ttl)
        return token

    def get_scopes(self, token):
        def _get_scopes():
            endpoint = getattr(settings, 'SOCIAL_AUTH_DRYCC_OIDC_ENDPOINT', None)
            if not endpoint:
                return set()
            oauth_introspect_url = urllib.parse.urljoin(endpoint + "/", "introspect/")
            key = getattr(settings, 'SOCIAL_AUTH_DRYCC_KEY', '')
            secret = getattr(settings, 'SOCIAL_AUTH_DRYCC_SECRET', '')
            try:
                resp = requests.post(
                    oauth_introspect_url, auth=(key, secret), data={'token': token}, timeout=5)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("active"):
                        return set(data.get("scope", "").split())
            except Exception as e:
                logger.info(f"Error introspecting token: {e}")
            return set()
        return cache.get_or_set(
            f"drycc_oauth_scopes_v2_{token}", _get_scopes, settings.DRYCC_CACHE_USER_TIME)

    def send_message(self, username: str, message: Dict) -> None:
        token = self._get_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": user_agent("Drycc Controller", drycc_version),
        }
        body = {**message, "username": username}
        resp = requests.post(
            f"{self.base_url}/messages/",
            json=body,
            headers=headers,
            timeout=self.timeout,
        )
        resp.raise_for_status()
