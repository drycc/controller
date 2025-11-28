import uuid
import logging
import asyncio
import aiohttp
from django.conf import settings
from django.core.cache import cache
from asgiref.sync import sync_to_async

from .exceptions import DryccException
from .tasks import send_app_log
from .utils import random_string, CacheLock, get_scheduler

logger = logging.getLogger(__name__)


class FilerClient(object):

    def __init__(self, app_id, volume, url_path):
        self.path = "/data"
        self.ports = (9000, 9100)
        self.app_id = app_id
        self.volume = volume
        self.url_path = url_path
        self.scheduler = get_scheduler()

    def log(self, message, level=logging.INFO):
        logger.log(level, "[{}]: {}".format(self.app_id, message))
        send_app_log.delay(self.app_id, message, logging.INFO)

    async def bind(self):
        lock_key = f"filer:lock:{self.app_id}:{self.volume.name}"
        lock = CacheLock(lock_key)
        try:
            await sync_to_async(lock.acquire)()
            if _filer := await self.info():
                return _filer
            else:
                _filer = await sync_to_async(self._filer_bind)()
                await cache.aset(self._cache_key, _filer, timeout=settings.DRYCC_FILER_DURATION)
        finally:
            await sync_to_async(lock.release)()
        return _filer

    async def info(self):
        _filer = await cache.aget(self._cache_key, None)
        if _filer and await self._check_health(_filer):
            await cache.atouch(self._cache_key, timeout=settings.DRYCC_FILER_DURATION)
            return _filer
        return None

    @property
    def _cache_key(self):
        return f"filer:{self.app_id}:{self.volume.name}"

    def _filer_bind(self):
        username, password = random_string(32), random_string(32)
        filer = {"username": username, "password": password}
        job_ip = self._get_job_ip(self._create_job(username, password))
        filer.update({
            "endpoint": f"http://{job_ip}:{self.ports[1]}",
            "ping_url": f"http://{job_ip}:{self.ports[0]}/_/ping",
        })
        return filer

    def _create_job(self, username, password: str) -> str:
        job_name, k8s_volume = f"drycc-filer-{uuid.uuid4()}", {"name": self.volume.name}
        if self.volume.type == "csi":
            k8s_volume.update({"persistentVolumeClaim": {"claimName": self.volume.name}})
        else:
            k8s_volume.update(self.volume.parameters)
        self.scheduler.job.create(self.app_id, job_name, settings.DRYCC_FILER_IMAGE, **{
            "command": ["init-stack", "/usr/bin/pingguard"],
            "args": [
                f"--bind=:{self.ports[0]}", f"--interval={settings.DRYCC_FILER_DURATION}s",
                "--",
                "rclone", "serve", "webdav", self.path, f"--addr=:{self.ports[1]}",
                f"--user={username}", f"--pass={password}", f"--baseurl={self.url_path}",
            ],
            "app_type": "filer", "replicas": 1, "deploy_timeout": 120, "volumes": [k8s_volume],
            "volume_mounts": [{"mountPath": self.path, "name": self.volume.name}],
            "restart_policy": "Never", "image_pull_policy": settings.DRYCC_FILER_IMAGE_PULL_POLICY,
            "pod_security_context": {"fsGroup": 1001, "runAsGroup": 1001, "runAsUser": 1001},
            "active_deadline_seconds": 2 ** 32,
            "ttl_seconds_after_finished": settings.DRYCC_FILER_DURATION,
        })
        return job_name

    def _get_job_ip(self, job_name: str) -> str:
        state, labels = 'initializing', {'job-name': job_name}
        for count, state in enumerate(self.scheduler.pod.watch(
            self.app_id, labels, settings.DRYCC_PILELINE_RUN_TIMEOUT,
            until_states=['up', 'down', 'crashed', 'error'],
        )):
            self.log(f"waiting for filer bind: {state} * {count}")
        if state != 'up':
            raise DryccException(f'filer startup failed, current status: {state}')
        pods = self.scheduler.pod.get(self.app_id, labels=labels).json()
        if not pods["items"]:
            raise DryccException('filer pod not found after run completed')
        return pods["items"][0]["status"]["podIP"]

    async def _check_health(self, filer):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    filer["ping_url"],
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as response:
                    return response.status == 200
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return False
