import json
import time
import six
import ssl
import aiohttp
import asyncio
from django.conf import settings
from django.core.cache import cache

from asgiref.sync import sync_to_async

from urllib3.response import HTTPResponse
from kubernetes.client import Configuration, exceptions
from kubernetes.client.api import core_v1_api
from kubernetes.stream import stream
from kubernetes.stream.ws_client import STDOUT_CHANNEL, STDERR_CHANNEL, ERROR_CHANNEL

from channels.db import database_sync_to_async
from channels.exceptions import DenyConnection
from channels.generic.websocket import AsyncWebsocketConsumer

from .models.app import App
from .permissions import has_object_permission


class BaseAppConsumer(AsyncWebsocketConsumer):
    timeout = 60 * 60

    @database_sync_to_async
    def has_perm(self):
        if self.scope["user"] is None:
            return False, "user not login"
        key = f"permission:user:{self.scope["user"].id}:app:{self.id}"
        permission = cache.get(key)
        if permission is None:
            try:
                app = App.objects.get(id=self.id)
                permission = has_object_permission(self.scope["user"], app, "GET")
                if permission[0]:
                    cache.set(key, permission, timeout=self.timeout)
            except App.DoesNotExist:
                permission = (False, "user not exists")
        return permission

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

    async def connect(self):
        await super().connect()
        self.session = None
        self.running = False
        self.conneted = True

    async def task(self, **kwargs):
        lines = kwargs.get("lines", 100)
        follow = kwargs.get("follow", False)
        timeout = kwargs.get("timeout", 300)
        url = "http://{}:{}/logs/{}?log_lines={}&follow={}&timeout={}".format(
            settings.LOGGER_HOST, settings.LOGGER_PORT, self.id, lines, follow, timeout,
        )
        try:
            async with aiohttp.ClientSession() as session:
                self.session = session
                async with session.get(url) as response:
                    async for data in response.content.iter_any():
                        if not self.conneted:
                            break
                        await self.send(text_data=data)
        except asyncio.TimeoutError:
            pass
        finally:
            await self.close(code=1000)

    async def receive(self, text_data=None, bytes_data=None):
        if self.running:
            return
        self.running = True
        kwargs = json.loads(text_data)
        asyncio.create_task(self.task(**kwargs))

    async def disconnect(self, close_code):
        if self.session:
            await self.session.close()
        self.conneted = False


class AppPodLogsConsumer(BaseK8sConsumer):

    async def connect(self):
        await super().connect()
        self.running = False
        self.response = None
        self.conneted = True
        self.buffer = b''
        self.delimiter = b"\r\n"
        self.pod_id = self.scope["url_route"]["kwargs"]["pod_id"]

    def reader(self, sock):
        self.buffer += sock.read()
        try:
            while self.buffer and self.buffer.endswith(self.delimiter):
                index = self.buffer.index(self.delimiter)
                length = int(self.buffer[:index], base=16)
                if length == 0:
                    asyncio.create_task(self.close(code=1000))
                    break
                start_pos = index + len(self.delimiter)
                end_pos = start_pos + length + len(self.delimiter)
                asyncio.create_task(
                    self.send(bytes_data=self.buffer[start_pos:end_pos].strip(self.delimiter)))
                self.buffer = self.buffer[end_pos:]
        except BaseException:
            asyncio.create_task(self.close(code=1000))

    async def receive(self, text_data=None, bytes_data=None):
        if self.running:
            return
        self.running = True
        data = json.loads(text_data)
        args = (self.pod_id, self.id)
        lines = data.get("lines", 300)
        follow = data.get("follow", False)
        kwargs = {
            "follow": follow,
            "container": data.get("container", ""),
            "_preload_content": not follow,
        }
        if lines > 0:
            kwargs["tail_lines"] = lines
        self.response = await sync_to_async(self.kubernetes.read_namespaced_pod_log)(
            *args, **kwargs)
        if follow:
            loop = asyncio.get_event_loop()
            loop.add_reader(
                self.response.connection.sock, self.reader, self.response.connection.sock)
        else:
            asyncio.create_task(self.send(text_data=self.response))
            asyncio.create_task(self.close(code=1000))

    async def disconnect(self, close_code):
        if isinstance(self.response, HTTPResponse):
            loop = asyncio.get_event_loop()
            loop.remove_reader(self.response.connection.sock)
            await sync_to_async(self.response.close)()
        self.conneted = False


class AppPodExecConsumer(BaseK8sConsumer):

    async def connect(self):
        await super().connect()
        self.stream = None
        self.conneted = True
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

    async def wait(self):
        future, loop = asyncio.Future(), asyncio.get_event_loop()
        loop.add_reader(self.stream.sock, future.set_result, None)
        future.add_done_callback(lambda f: loop.remove_reader(self.stream.sock))
        await future

    async def task(self):
        try:
            deadline = time.time() + settings.DRYCC_APP_POD_EXEC_TIMEOUT
            while self.stream.is_open() and self.conneted and time.time() < deadline:
                try:
                    await self.wait()
                    self.stream.update()
                    for channel in (ERROR_CHANNEL, STDOUT_CHANNEL, STDERR_CHANNEL):
                        if channel in self.stream._channels:
                            data = self.stream.read_channel(channel)
                            await self.send(data, channel)
                except ssl.SSLEOFError:
                    break
        except exceptions.ApiException as e:
            await self.send(str(e), STDERR_CHANNEL)
        finally:
            await self.close(code=1000)

    async def disconnect(self, close_code):
        if self.stream:
            await sync_to_async(self.stream.close)()
        self.conneted = False

    async def receive(self, text_data=None, bytes_data=None):
        if self.stream is None and text_data is not None:
            args = (self.kubernetes.connect_get_namespaced_pod_exec, self.pod_id, self.id)
            kwargs = json.loads(text_data)
            kwargs.update({"stderr": True, "stdout": True, "_preload_content": False})
            self.stream = await sync_to_async(stream)(*args, **kwargs)
            asyncio.create_task(self.task())
        elif self.stream is not None:
            data = text_data if text_data else bytes_data
            channel, data = ord(data[0]), data[1:]
            await sync_to_async(self.stream.write_channel)(channel, data)
        else:
            raise ValueError("This operation is not supported!")
