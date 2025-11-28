import json
import time
import six
import ssl
import aiohttp
import asyncio
from urllib.parse import urljoin
from django.conf import settings
from django.core.cache import cache

from asgiref.sync import sync_to_async

from urllib3.response import HTTPResponse
from kubernetes.client import Configuration, exceptions
from kubernetes.client.api import core_v1_api
from kubernetes.stream import stream
from kubernetes.stream.ws_client import STDOUT_CHANNEL, STDERR_CHANNEL, ERROR_CHANNEL

from channels.exceptions import DenyConnection
from channels.generic.http import AsyncHttpConsumer
from channels.generic.websocket import AsyncWebsocketConsumer

from .models.app import App
from .models.volume import Volume
from .permissions import has_app_permission


class AppPermChecker(object):
    timeout = 60 * 60

    def __init__(self, scope):
        self.scope = scope

    async def has_perm(self):
        if self.scope["user"] is None:
            return False, "user not login"
        app_id = self.scope["url_route"]["kwargs"]["id"]
        key = f"permission:user:{self.scope["user"].id}:app:{app_id}"
        permission = await cache.aget(key)
        if permission is None:
            try:
                app = await App.objects.aget(id=app_id)
                permission = await sync_to_async(has_app_permission)(
                    self.scope["user"], app, "GET")
                if permission[0]:
                    await cache.aset(key, permission, timeout=self.timeout)
            except App.DoesNotExist:
                permission = (False, "app not exists")
        return permission


class BaseAppConsumer(AsyncWebsocketConsumer):

    async def connect(self):
        app_perm_checker = AppPermChecker(self.scope)
        is_ok, message = await app_perm_checker.has_perm()
        if is_ok:
            await self.accept()
            self.id = self.scope["url_route"]["kwargs"]["id"]
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


class AppPodLogsConsumer(BaseK8sConsumer):

    async def connect(self):
        await super().connect()
        self.running = False
        self.response = None
        self.conneted = True
        self.buffer = b''
        self.delimiter = b"\r\n"
        self.pod_name = self.scope["url_route"]["kwargs"]["name"]

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
        args = (self.pod_name, self.id)
        lines = data.get("lines", 300)
        follow = data.get("follow", False)
        previous = data.get("previous", False)
        kwargs = {
            "follow": follow,
            "container": data.get("container", ""),
            "_preload_content": not follow,
            "previous": previous
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
        self.pod_name = self.scope["url_route"]["kwargs"]["name"]

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
            args = (self.kubernetes.connect_get_namespaced_pod_exec, self.pod_name, self.id)
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


class FilerProxyConsumer(AsyncHttpConsumer):
    from .middleware import ChannelOAuthMiddleware
    chunk_size = 64 * 1024
    middleware = ChannelOAuthMiddleware(None)
    SKIP_REQUEST_HEADERS = {
        'host', 'connection', 'keep-alive', 'proxy-connection', 'te', 'trailers', 'upgrade',
    }
    SKIP_RESPONSE_HEADERS = {
        'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers',
        'transfer-encoding', 'upgrade',
    }

    async def handle(self, body: bytes):
        path = self.scope["url_route"]["kwargs"]["path"]
        client = await self._get_client(url_path=f"{self.scope["path"].removesuffix(path)}webdav/")
        if not client:
            await self.send_response(status=404, body=b'app or volume not found')
            return
        if path in ['_/ping', '_/bind']:  # need authentication
            await self._handle_controller_request(client, path)
            return
        elif not path.startswith('webdav/') or (filer := await client.info()) is None:
            await self.send_response(status=428, body=b'filer service unavailable')
            return
        filer_target_url = "{}?{}".format(
            urljoin(filer["endpoint"], self.scope["path"]), self.scope.get("query_string"))
        method = self.scope['method'].upper()
        headers = {
            name_bytes.decode('latin-1').lower(): value_bytes.decode('latin-1')
            for name_bytes, value_bytes in self.scope.get('headers', [])
            if name_bytes.decode('latin-1').lower() not in self.SKIP_REQUEST_HEADERS
        }
        await self._handle_proxy_request(filer_target_url, method, headers, body)

    async def _get_client(self, url_path):
        try:
            from .filer import FilerClient
            app = await App.objects.aget(id=self.scope["url_route"]["kwargs"]["id"])
            volume = await Volume.objects.filter(
                app=app, name=self.scope["url_route"]["kwargs"]["name"]).afirst()
            if not volume:
                return None
            return FilerClient(app.id, volume, url_path)
        except App.DoesNotExist:
            return None

    async def _forward_response(self, response: aiohttp.ClientResponse):
        response_headers = [
            [name.encode('latin-1'), value.encode('latin-1')]
            for name, value in response.headers.items()
            if name.lower() not in self.SKIP_RESPONSE_HEADERS
        ]
        await self.send_headers(status=response.status, headers=response_headers)
        async for chunk in response.content.iter_chunked(self.chunk_size):
            if chunk:
                await self.send_body(chunk, more_body=True)
        # Send final empty chunk to indicate end of body
        await self.send_body(b'', more_body=False)

    async def _handle_proxy_request(self, url, method: str, headers: dict[str, str], data: bytes):
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=settings.DRYCC_FILER_DURATION)
        ) as session:
            try:
                async with session.request(
                    method=method, url=url, headers=headers, data=data, allow_redirects=False
                ) as response:
                    await self._forward_response(response)
            except aiohttp.ClientError as e:
                await self.send_response(502, f"proxy service unavailable: {e}".encode('utf-8'))
            except asyncio.TimeoutError:
                await self.send_response(504, b'proxy request to backend filer timeout')

    async def _handle_controller_request(self, client, path: str):
        await self.middleware.login(self.scope)
        app_perm_checker = AppPermChecker(self.scope)
        is_ok, message = await app_perm_checker.has_perm()
        status, body = 200, b''
        if not is_ok:
            status, body = 403, message.encode('utf-8')
        elif path == '_/ping':
            if (filer := await client.info()) is not None:
                body = b'pong'
            else:
                status, body = 503, b'filer service unavailable'
        elif path == '_/bind':
            filer = await client.bind()
            body = json.dumps({
                "username": filer["username"], "password": filer["password"],
            }).encode('utf-8')
        await self.send_response(status, body)
