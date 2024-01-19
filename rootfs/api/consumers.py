import json
import time
import aiohttp
import asyncio
import collections
from django.conf import settings

from asgiref.sync import sync_to_async

from kubernetes.client import Configuration
from kubernetes.client.api import core_v1_api
from kubernetes.stream import stream

from channels.db import database_sync_to_async
from channels.exceptions import DenyConnection
from channels.generic.websocket import AsyncWebsocketConsumer

from .models.app import App
from .permissions import has_app_permission


Request = collections.namedtuple("Request", ["user", "method"])


class BaseAppConsumer(AsyncWebsocketConsumer):

    async def has_perm(self):
        if self.scope["user"] is None:
            return False, "user not login"
        request = Request(self.scope["user"], "POST")
        app = await database_sync_to_async(App.objects.get)(id=self.id)
        return await database_sync_to_async(has_app_permission)(request, app)

    async def connect(self):
        self.id = self.scope["url_route"]["kwargs"]["id"]
        is_ok, message = await self.has_perm()
        if is_ok:
            await self.accept()
        else:
            raise DenyConnection(message)


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


class AppPodExecConsumer(BaseAppConsumer):

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

    async def connect(self):
        self.stream = None
        self.conneted = True
        await super().connect()
        self.pod_id = self.scope["url_route"]["kwargs"]["pod_id"]

    async def send(self, data):
        if data is None:
            return
        elif isinstance(data, bytes):
            await super().send(bytes_data=data)
        elif isinstance(data, str):
            await super().send(text_data=data)

    async def task(self):
        deadline = time.time() + settings.DRYCC_APP_POD_EXEC_TIMEOUT
        while self.stream.is_open() and self.conneted and time.time() < deadline:
            await sync_to_async(self.stream.update)(0.1)
            if self.stream.peek_stdout():
                data = self.stream.read_stdout()
            elif self.stream.peek_stderr():
                data = self.stream.read_stderr()
            else:
                data = None
            await self.send(data)
        await self.close(code=1000)

    async def disconnect(self, close_code):
        if self.stream:
            self.stream.close()
        self.conneted = False

    async def receive(self, text_data=None, bytes_data=None):
        if self.stream is None and text_data is not None:
            args = (self.kubernetes.connect_get_namespaced_pod_exec, self.pod_id, self.id)
            kwargs = json.loads(text_data)
            kwargs.update({"stderr": True, "stdout": True})
            if kwargs["stdin"]:
                kwargs.update({"_preload_content": False})
                self.stream = stream(*args, **kwargs)
                asyncio.create_task(self.task())
            else:
                await self.send(stream(*args, **kwargs))
                await self.close(code=1000)
        elif self.stream is not None:
            data = text_data if text_data else bytes_data
            channel, data = ord(data[0]), data[1:]
            await sync_to_async(self.stream.write_channel)(channel, data)
        else:
            raise ValueError("This operation is not supported!")
