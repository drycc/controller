import uuid
import logging
import requests
from django.conf import settings
from django.core.cache import cache
from requests.auth import HTTPBasicAuth

from .utils import random_string, get_session, CacheLock

logger = logging.getLogger(__name__)


class FilerClient(object):

    def __init__(self, app_id, volume, scheduler):
        self.bind = ":9000"
        self.path = "/data"
        self.app_id = app_id
        self.volume = volume
        self.scheduler = scheduler

    def log(self, message, level=logging.INFO):
        logger.log(level, "[{}]: {}".format(self.app_id, message))

    @property
    def server(self):
        lock_key = f"filer:lock:{self.app_id}:{self.volume.name}"
        lock = CacheLock(lock_key)
        try:
            lock.acquire()
            _server = cache.get(self.cache_key, None)
            if not _server or not self.health(_server):
                _server = self.get_server()
                cache.set(self.cache_key, _server, timeout=settings.DRYCC_FILER_DURATION)
        finally:
            lock.release()
        return _server

    @property
    def cache_key(self):
        return f"filer:{self.app_id}:{self.volume.name}"

    def get_server(self):
        self.clean()  # clean old filer
        pod_name = f"drycc-filer-{uuid.uuid4().hex}"
        k8s_volume = {"name": self.volume.name}
        if self.volume.type == "csi":
            k8s_volume.update({"persistentVolumeClaim": {"claimName": self.volume.name}})
        else:
            k8s_volume.update(self.volume.parameters)
        username, password = random_string(32), random_string(32)
        self.scheduler.pod.create(self.app_id, pod_name, settings.DRYCC_FILER_IMAGE, **{
            "args": [
                "filer",
                "--bind", self.bind, "--path", self.path,
                "--duration", f"{settings.DRYCC_FILER_DURATION}",
                "--waittime", f"{settings.DRYCC_FILER_WAITTIME}",
                "--username", f"{username}", "--password", f"{password}",
            ],
            "labels": {"app": self.app_id, "pod": pod_name, "volume": self.volume.name},
            "app_type": "filer", "replicas": 1, "deploy_timeout": 120, "volumes": [k8s_volume],
            "volume_mounts": [{"mountPath": self.path, "name": self.volume.name}],
            "restart_policy": "Never", "image_pull_policy": settings.DRYCC_FILER_IMAGE_PULL_POLICY,
            "pod_security_context": {"fsGroup": 1001, "runAsGroup": 1001, "runAsUser": 1001},
        })
        address = self.scheduler.pod.get(self.app_id, pod_name).json()["status"]["podIP"]
        return {"address": address, "username": username, "password": password}

    def clean(self):
        response = self.scheduler.pod.get(
            self.app_id, labels={"app": self.app_id, "type": "filer"})
        if response.status_code != 200:
            self.log("clean up old filter errors")
            return False
        for item in response.json()["items"]:
            if item['status']['phase'] in ('Succeeded', 'Failed'):
                pod_name = item['metadata']['name']
                self.scheduler.pod.delete(self.app_id, pod_name)
        self.log("clean up old filter completed")
        return True

    def health(self, server):
        try:
            return self.request(
                "OPTIONS", server, timeout=2).headers.get('server') == 'drycc-filer'
        except requests.exceptions.Timeout:
            return False

    def request(self, method, server, path="/", **kwargs):
        cache.touch(self.cache_key, timeout=settings.DRYCC_FILER_DURATION)
        url = f"http://{server["address"]}:{self.bind.split(":")[1]}/{path}"
        kwargs["auth"] = HTTPBasicAuth(server["username"], server["password"])
        return get_session().request(method, url, **kwargs)

    def get(self, path, **kwargs):
        return self.request("GET", self.server, path, **kwargs)

    def post(self, path, **kwargs):
        return self.request("POST", self.server, path, **kwargs)

    def delete(self, path, **kwargs):
        return self.request("DELETE", self.server, path, **kwargs)
