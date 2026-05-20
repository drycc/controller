import logging
import requests
import urllib.parse
from typing import List, Dict
from django.core.cache import cache
from requests_toolbelt import user_agent
from django.conf import settings
from api import __version__ as drycc_version

logger = logging.getLogger(__name__)


class PassportAPI(object):
    """Service-to-service client for Drycc Passport using OAuth2 client_credentials."""

    TOKEN_CACHE_KEY = "controller:passport:m2m_token"
    TOKEN_REFRESH_LEEWAY = 60

    def __init__(self, timeout=10):
        self.timeout = timeout
        self.base_url = settings.DRYCC_PASSPORT_URL.rstrip("/")

    @property
    def headers(self) -> str:
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
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": user_agent("Drycc Controller", drycc_version),
        }

    @staticmethod
    def get_scopes(token):
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
        body = {**message, "username": username}
        resp = requests.post(
            f"{self.base_url}/messages/",
            json=body,
            headers=self.headers,
            timeout=self.timeout,
        )
        resp.raise_for_status()


class ManagerAPI(object):

    def __init__(self, timeout=10):
        self.timeout = timeout
        self.headers = PassportAPI(timeout=timeout).headers if self.enabled else None
        self.base_url = settings.WORKFLOW_MANAGER_URL.rstrip("/") if self.enabled else None

    @property
    def enabled(self):
        return settings.WORKFLOW_MANAGER_URL is not None

    def send_usage(self, usage: List[Dict[str, str]]):
        if not self.enabled:
            logger.info("WORKFLOW_MANAGER_URL is not set, skipping send_usage")
            return
        url = f"{self.base_url}/usage/"
        return requests.post(url=url, json=usage, headers=self.headers, timeout=self.timeout)

    def get_status(self, resource_type: str, resource_id: str):
        if not self.enabled:
            logger.info("WORKFLOW_MANAGER_URL is not set, skipping get_status")
            return True, None
        key = f"{resource_type}:status:{resource_id}"
        status = cache.get(key)
        if not status:
            url = f"{self.base_url}/{resource_type}s/{resource_id}/status/"
            try:
                status = requests.get(url=url, headers=self.headers, timeout=self.timeout).json()
            except requests.exceptions.Timeout as ex:
                msg = f"request {resource_type} {resource_id} timeout, skipping verification."
                status = {"is_active": True, "message": msg}
                logger.error(msg)
                logger.exception(ex)
            cache.set(key, status, timeout=settings.DRYCC_CACHE_USER_TIME)
        return status.get("is_active", True), status.get("message", None)

    def get_app_status(self, app_id):
        return self.get_status("app", app_id)

    def get_user_status(self, user_id):
        return self.get_status("user", user_id)
