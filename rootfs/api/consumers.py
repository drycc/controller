import json
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


class AppPodExecConsumer(AsyncWebsocketConsumer):

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

    async def check(self):
        self.id = self.scope["url_route"]["kwargs"]["id"]
        self.pod_id = self.scope["url_route"]["kwargs"]["pod_id"]
        if self.scope["user"] is None:
            return False, "user not login"
        request = Request(self.scope["user"], "POST")
        app = await database_sync_to_async(App.objects.get)(id=self.id)
        return await database_sync_to_async(has_app_permission)(request, app)

    async def connect(self):
        self.stream = None
        self.conneted = True
        is_ok, message = await self.check()
        if is_ok:
            await self.accept()
        else:
            raise DenyConnection(message)

    async def send(self, data):
        if data is None:
            return
        elif isinstance(data, bytes):
            await super().send(bytes_data=data)
        elif isinstance(data, str):
            await super().send(text_data=data)

    async def task(self):
        while self.stream.is_open() and self.conneted:
            self.stream.update(timeout=9)
            if await sync_to_async(self.stream.peek_stdout)():
                data = self.stream.read_stdout()
            elif await sync_to_async(self.stream.peek_stderr)():
                data = self.stream.peek_stderr()
            else:
                data = None
            await self.send(data)

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
            await sync_to_async(self.stream.write_stdin)(data)
        else:
            raise ValueError("This operation is not supported!")
