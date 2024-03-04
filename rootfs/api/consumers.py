import json
import time
import six
import ssl
import aiohttp
import asyncio
import collections
from django.conf import settings

from asgiref.sync import sync_to_async, async_to_sync

from kubernetes.client import Configuration, exceptions
from kubernetes.client.api import core_v1_api
from kubernetes.stream import stream
from kubernetes.stream.ws_client import STDOUT_CHANNEL, STDERR_CHANNEL, ERROR_CHANNEL

from channels.db import database_sync_to_async
from channels.exceptions import DenyConnection
from channels.generic.websocket import AsyncWebsocketConsumer

from .models.app import App
from .permissions import has_app_permission


Request = collections.namedtuple("Request", ["user", "method"])


class BaseAppConsumer(AsyncWebsocketConsumer):

    @database_sync_to_async
    def has_perm(self):
        if self.scope["user"] is None:
            return False, "user not login"
        request = Request(self.scope["user"], "POST")
        try:
            app = App.objects.get(id=self.id)
            return has_app_permission(request, app)
        except App.DoesNotExist:
            return False, "user not exists"

    async def connect(self):
        self.id = self.scope["url_route"]["kwargs"]["id"]
        is_ok, message = await self.has_perm()
        if is_ok:
            await self.accept()
        else:
            raise DenyConnection(message)


class BaseK8sConsumer(BaseAppConsumer):

    @property
    def kubernetes(self):
        with open('/var/run/secrets/kubernetes.io/serviceaccount/token') as token_file:
            token = token_file.read()
        config = Configuration(host=settings.SCHEDULER_URL)
        config.api_key = {"authorization": "Bearer " + token}
        config.verify_ssl = settings.K8S_API_VERIFY_TLS
        if config.verify_ssl:
            config.ssl_ca_cert = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
        Configuration.set_default(config)
        return core_v1_api.CoreV1Api()


class AppLogsConsumer(BaseAppConsumer):

    async def receive(self, text_data=None, bytes_data=None):
        if text_data is not None:
            kwargs = json.loads(text_data)
            lines = kwargs.get("lines", 100)
            follow = kwargs.get("follow", False)
            timeout = kwargs.get("timeout", 300)
            url = "http://{}:{}/logs/{}?log_lines={}&follow={}&timeout={}".format(
                settings.LOGGER_HOST,
                settings.LOGGER_PORT,
                self.id,
                lines,
                follow,
                timeout,
            )
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    async for data in response.content.iter_any():
                        await self.send(text_data=data)
            await self.close(code=1000)
        else:
            raise ValueError("text_data cannot be empty!")


class AppPodLogsConsumer(BaseK8sConsumer):

    async def connect(self):
        await super().connect()
        self.pod_id = self.scope["url_route"]["kwargs"]["pod_id"]

    @sync_to_async
    def receive(self, text_data=None, bytes_data=None):
        kwargs = json.loads(text_data)
        try:
            stream = self.kubernetes.read_namespaced_pod_log(self.pod_id, self.id, **{
                "tail_lines": kwargs.get("lines", 100),
                "follow": kwargs.get("follow", False),
                "container": kwargs.get("container", ""),
                "_preload_content": False,
            }).stream()
            for line in stream:
                async_to_sync(self.send)(text_data=line)
        except exceptions.ApiException as e:
            async_to_sync(self.send)(text_data=str(e))
        async_to_sync(self.close)(code=1000)


class AppPodExecConsumer(BaseK8sConsumer):

    async def connect(self):
        self.stream = None
        self.conneted = True
        await super().connect()
        self.pod_id = self.scope["url_route"]["kwargs"]["pod_id"]

    async def send(self, data, channel=STDOUT_CHANNEL):
        channel_prefix = chr(channel)
        if data is None:
            return
        elif isinstance(data, bytes):
            channel_prefix = six.binary_type(channel_prefix, "ascii")
            await super().send(bytes_data=channel_prefix+data)
        elif isinstance(data, str):
            await super().send(text_data=channel_prefix+data)

    async def task(self):
        deadline = time.time() + settings.DRYCC_APP_POD_EXEC_TIMEOUT
        while self.stream.is_open() and self.conneted and time.time() < deadline:
            try:
                await sync_to_async(self.stream.update)(0.1)
                for channel in (ERROR_CHANNEL, STDOUT_CHANNEL, STDERR_CHANNEL):
                    if channel in self.stream._channels:
                        data = self.stream.read_channel(channel)
                        await self.send(data, channel)
            except ssl.SSLEOFError:
                break
        await self.close(code=1000)

    async def disconnect(self, close_code):
        if self.stream:
            self.stream.close()
        self.conneted = False

    async def receive(self, text_data=None, bytes_data=None):
        if self.stream is None and text_data is not None:
            args = (self.kubernetes.connect_get_namespaced_pod_exec, self.pod_id, self.id)
            kwargs = json.loads(text_data)
            kwargs.update({"stderr": True, "stdout": True, "_preload_content": False})
            try:
                self.stream = stream(*args, **kwargs)
            except exceptions.ApiException as e:
                await self.send(str(e), STDERR_CHANNEL)
                await self.close(code=1000)
            else:
                asyncio.create_task(self.task())
        elif self.stream is not None:
            data = text_data if text_data else bytes_data
            channel, data = ord(data[0]), data[1:]
            await sync_to_async(self.stream.write_channel)(channel, data)
        else:
            raise ValueError("This operation is not supported!")
