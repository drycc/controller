"""
Unit tests for the Drycc api consumers.

Run the tests with "./manage.py test api.tests.test_consumers"
"""
import json
import asyncio
import aiohttp
from unittest import mock
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from channels.exceptions import DenyConnection

from api.models.app import App
from api.models.volume import Volume
from api.consumers import (
    AppPermChecker,
    BaseAppConsumer,
    BaseK8sConsumer,
    AppPodLogsConsumer,
    AppPodExecConsumer,
    FilerProxyConsumer
)
from api.tests import adapter, DryccTransactionTestCase
import requests_mock

User = get_user_model()


@requests_mock.Mocker(real_http=True, adapter=adapter)
class ConsumerTestCase(DryccTransactionTestCase):
    """Base test case for consumer tests"""

    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = self.get_or_create_token(self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)
        self.app_id = self.create_app()
        self.app = App.objects.get(id=self.app_id)

    def tearDown(self):
        # make sure every test has a clean slate for k8s mocking
        cache.clear()


class AppPermCheckerTest(ConsumerTestCase):
    """Tests for AppPermChecker"""

    def test_has_perm_with_logged_in_user(self):
        """Test permission check with valid user and app"""
        checker = AppPermChecker({
            'user': self.user,
            'url_route': {'kwargs': {'id': self.app_id}}
        })

        # Mock the async method
        async def test_async():
            result = await checker.has_perm()
            self.assertTrue(result[0])  # Should have permission
            # When permission is granted, message is None

        asyncio.run(test_async())

    def test_has_perm_with_anonymous_user(self):
        """Test permission check with anonymous user"""
        checker = AppPermChecker({
            'user': None,
            'url_route': {'kwargs': {'id': self.app_id}}
        })

        async def test_async():
            result = await checker.has_perm()
            self.assertFalse(result[0])  # Should not have permission
            self.assertEqual(result[1], "user not login")

        asyncio.run(test_async())

    def test_has_perm_with_nonexistent_app(self):
        """Test permission check with non-existent app"""
        checker = AppPermChecker({
            'user': self.user,
            'url_route': {'kwargs': {'id': 'nonexistent-app'}}
        })

        async def test_async():
            result = await checker.has_perm()
            self.assertFalse(result[0])  # Should not have permission
            self.assertEqual(result[1], "app not exists")

        asyncio.run(test_async())

    def test_has_perm_with_cache(self):
        """Test permission check with cached permissions"""
        checker = AppPermChecker({
            'user': self.user,
            'url_route': {'kwargs': {'id': self.app_id}}
        })

        # Set cache
        cache_key = f"permission:user:{self.user.id}:app:{self.app_id}"
        cache.set(cache_key, (True, "cached permission"))

        async def test_async():
            result = await checker.has_perm()
            self.assertTrue(result[0])
            self.assertEqual(result[1], "cached permission")

        asyncio.run(test_async())


@requests_mock.Mocker(real_http=True, adapter=adapter)
class BaseAppConsumerTest(ConsumerTestCase):
    """Tests for BaseAppConsumer"""

    def test_connect_with_permission(self, mock_requests):
        """Test WebSocket connection with valid permissions"""
        async def test_async():
            # Mock the has_perm method to return True
            async def mock_has_perm():
                return (True, "permission granted")

            with patch.object(AppPermChecker, 'has_perm', side_effect=mock_has_perm):
                with patch.object(BaseAppConsumer, 'accept') as mock_accept:
                    consumer = BaseAppConsumer()
                    consumer.scope = {
                        'user': self.user,
                        'url_route': {'kwargs': {'id': self.app_id}}
                    }

                    await consumer.connect()
                    mock_accept.assert_called_once()

        asyncio.run(test_async())

    def test_connect_without_permission(self, mock_requests):
        """Test WebSocket connection without valid permissions"""
        async def test_async():
            # Mock the has_perm method to return False
            async def mock_has_perm():
                return (False, "permission denied")

            with patch.object(AppPermChecker, 'has_perm', side_effect=mock_has_perm):
                consumer = BaseAppConsumer()
                consumer.scope = {
                    'user': self.user,
                    'url_route': {'kwargs': {'id': self.app_id}}
                }

                with self.assertRaises(DenyConnection):
                    await consumer.connect()

        asyncio.run(test_async())


@requests_mock.Mocker(real_http=True, adapter=adapter)
class BaseK8sConsumerTest(ConsumerTestCase):
    """Tests for BaseK8sConsumer"""

    def test_kubernetes_property(self, mock_requests):
        """Test kubernetes property initialization"""
        consumer = BaseK8sConsumer()

        # Mock the token file reading and Kubernetes API client
        with patch('builtins.open', mock.mock_open(read_data='mock-token')):
            with patch('api.consumers.Configuration') as mock_config:
                with patch('api.consumers.core_v1_api.CoreV1Api') as mock_api:
                    mock_config_instance = MagicMock()
                    mock_config.return_value = mock_config_instance

                    consumer.kubernetes

                    # Verify configuration was called
                    mock_config.assert_called_once()
                    mock_api.assert_called_once()


@requests_mock.Mocker(real_http=True, adapter=adapter)
class AppPodLogsConsumerTest(ConsumerTestCase):
    """Tests for AppPodLogsConsumer"""

    def test_connect(self, mock_requests):
        """Test WebSocket connection for pod logs"""
        async def test_async():
            with patch.object(BaseAppConsumer, 'connect') as mock_super_connect:
                consumer = AppPodLogsConsumer()
                consumer.scope = {
                    'user': self.user,
                    'url_route': {'kwargs': {'name': 'test-pod', 'id': self.app_id}}
                }

                await consumer.connect()

                mock_super_connect.assert_called_once()
                self.assertFalse(consumer.running)
                self.assertIsNone(consumer.response)
                self.assertTrue(consumer.conneted)
                self.assertEqual(consumer.buffer, b'')
                self.assertEqual(consumer.pod_name, 'test-pod')

        asyncio.run(test_async())

    def test_receive_log_request(self, mock_requests):
        """Test receiving log request message"""
        async def test_async():
            consumer = AppPodLogsConsumer()
            consumer.scope = {
                'user': self.user,
                'url_route': {'kwargs': {'name': 'test-pod', 'id': self.app_id}}
            }
            consumer.running = False
            consumer.id = self.app_id
            consumer.pod_name = 'test-pod'

            # Mock kubernetes client
            mock_k8s = MagicMock()
            mock_response = MagicMock()
            mock_k8s.read_namespaced_pod_log.return_value = mock_response

            with patch.object(type(consumer), 'kubernetes', new_callable=lambda: mock_k8s):
                # Create a proper async function instead of using AsyncMock
                async def mock_sync_to_async_func(*args, **kwargs):
                    return mock_response

                with patch('api.consumers.sync_to_async') as mock_sync_to_async:
                    mock_sync_to_async.return_value = mock_sync_to_async_func
                    with patch.object(consumer, 'send'):
                        with patch.object(consumer, 'close'):

                            test_data = {
                                "lines": 100,
                                "follow": False,
                                "previous": False,
                                "container": "web"
                            }

                            await consumer.receive(text_data=json.dumps(test_data))

                            self.assertTrue(consumer.running)

        asyncio.run(test_async())

    def test_disconnect(self, mock_requests):
        """Test WebSocket disconnection"""
        async def test_async():
            consumer = AppPodLogsConsumer()
            consumer.conneted = True
            consumer.response = MagicMock()
            consumer.response.connection.sock = MagicMock()

            with patch('asyncio.get_event_loop') as mock_loop:
                mock_event_loop = MagicMock()
                mock_loop.return_value = mock_event_loop
                with patch('api.consumers.sync_to_async') as mock_sync_to_async:
                    # Create a proper async function instead of AsyncMock
                    async def mock_sync_close():
                        pass
                    mock_sync_to_async.return_value = mock_sync_close

                    await consumer.disconnect(1000)

                    self.assertFalse(consumer.conneted)

        asyncio.run(test_async())


@requests_mock.Mocker(real_http=True, adapter=adapter)
class AppPodExecConsumerTest(ConsumerTestCase):
    """Tests for AppPodExecConsumer"""

    def test_connect(self, mock_requests):
        """Test WebSocket connection for pod exec"""
        async def test_async():
            with patch.object(BaseAppConsumer, 'connect') as mock_super_connect:
                consumer = AppPodExecConsumer()
                consumer.scope = {
                    'user': self.user,
                    'url_route': {'kwargs': {'name': 'test-pod', 'id': self.app_id}}
                }
                await consumer.connect()
                mock_super_connect.assert_called_once()
                self.assertIsNone(consumer.stream)
                self.assertTrue(consumer.conneted)
                self.assertEqual(consumer.pod_name, 'test-pod')

        asyncio.run(test_async())

    def test_send_stdout(self, mock_requests):
        """Test sending stdout data"""
        async def test_async():
            consumer = AppPodExecConsumer()

            with patch.object(consumer.__class__.__bases__[0], 'send') as mock_super_send:
                # Test sending bytes data
                await consumer.send(b'test output', channel=1)  # STDOUT_CHANNEL
                mock_super_send.assert_called_with(bytes_data=b'\x01test output')

                # Test sending string data
                await consumer.send('test string', channel=1)
                mock_super_send.assert_called_with(text_data='\x01test string')

        asyncio.run(test_async())

    def test_send_none_data(self, mock_requests):
        """Test sending None data"""
        async def test_async():
            consumer = AppPodExecConsumer()

            with patch.object(consumer.__class__.__bases__[0], 'send') as mock_super_send:
                await consumer.send(None)
                mock_super_send.assert_not_called()

        asyncio.run(test_async())

    def test_receive_exec_request(self, mock_requests):
        """Test receiving exec request"""
        async def test_async():
            consumer = AppPodExecConsumer()
            consumer.scope = {
                'user': self.user,
                'url_route': {'kwargs': {'name': 'test-pod', 'id': self.app_id}}
            }
            consumer.stream = None
            consumer.pod_name = 'test-pod'
            consumer.id = self.app_id

            exec_request = {
                "command": ["/bin/bash"],
                "stdin": True,
                "tty": True
            }

            # Mock the kubernetes property
            mock_k8s = MagicMock()
            mock_k8s.connect_get_namespaced_pod_exec = MagicMock()

            with patch.object(type(consumer), 'kubernetes', new_callable=lambda: mock_k8s):
                with patch('api.consumers.sync_to_async') as mock_sync_to_async:
                    with patch('api.consumers.stream'):
                        mock_stream_obj = MagicMock()
                        # Create a proper async function instead of AsyncMock

                        async def mock_sync_to_async_func(*args, **kwargs):
                            return mock_stream_obj
                        mock_sync_to_async.return_value = mock_sync_to_async_func

                        # Mock the task method to avoid creating unawaited coroutine
                        async def mock_task():
                            pass
                        with patch.object(
                            consumer, 'task', side_effect=mock_task
                        ) as mock_task_method:
                            await consumer.receive(text_data=json.dumps(exec_request))
                            self.assertEqual(consumer.stream, mock_stream_obj)
                            mock_task_method.assert_called_once()

        asyncio.run(test_async())

    def test_receive_command_data(self, mock_requests):
        """Test receiving command input data"""
        async def test_async():
            consumer = AppPodExecConsumer()
            mock_stream = MagicMock()
            consumer.stream = mock_stream

            with patch('api.consumers.sync_to_async') as mock_sync_to_async:
                # Create a proper async function instead of AsyncMock
                async def mock_write_stdin(channel, data):
                    pass
                mock_sync_to_async.return_value = mock_write_stdin

                # Test text data
                await consumer.receive(text_data='\x00test input')
                mock_sync_to_async.assert_called()

        asyncio.run(test_async())

    def test_receive_invalid_operation(self, mock_requests):
        """Test receiving data when stream is None and no valid text data"""
        async def test_async():
            consumer = AppPodExecConsumer()
            consumer.stream = None

            with self.assertRaises(ValueError) as context:
                await consumer.receive(bytes_data=b'invalid')

            self.assertEqual(str(context.exception), "This operation is not supported!")

        asyncio.run(test_async())

    def test_disconnect(self, mock_requests):
        """Test WebSocket disconnection"""
        async def test_async():
            consumer = AppPodExecConsumer()
            consumer.stream = MagicMock()
            consumer.conneted = True

            with patch('api.consumers.sync_to_async') as mock_sync_to_async:
                # Create a proper async function instead of AsyncMock
                async def mock_close_stream():
                    pass
                mock_sync_to_async.return_value = mock_close_stream

                await consumer.disconnect(1000)

                self.assertFalse(consumer.conneted)

        asyncio.run(test_async())


@requests_mock.Mocker(real_http=True, adapter=adapter)
class FilerProxyConsumerTest(ConsumerTestCase):
    """Tests for FilerProxyConsumer"""

    def setUp(self):
        super().setUp()
        # Create a test volume using Volume.objects.create to avoid k8s calls
        # We'll patch the save method to prevent k8s interactions
        with patch.object(Volume, 'save_to_k8s'), patch.object(Volume, 'delete_from_k8s'):
            self.test_volume = Volume.objects.create(
                owner=self.user,
                app=self.app,
                name='test-volume',
                size='1G',
                path={'web': '/data'},
                type='csi',
                parameters={'csi': {'driver': 'test-driver'}}
            )

    def test_handle_without_permission(self, mock_requests):
        """Test handling request without permission"""
        async def test_async():
            consumer = FilerProxyConsumer()
            consumer.scope = {
                'user': self.user,
                'path': f'/v2/apps/{self.app_id}/volumes/test-volume/filer/_/ping',
                'url_route': {
                    'kwargs': {'path': '_/ping', 'name': 'test-volume', 'id': self.app_id}
                },
                'method': 'GET',
                'headers': []
            }
            # Set the id attribute that FilerProxyConsumer expects
            consumer.id = self.app_id

            async def mock_has_perm():
                return (False, "permission denied")

            async def mock_bind_func():
                return {'endpoint': '', 'username': 'test', 'password': 'test'}

            async def mock_send_response(*args, **kwargs):
                pass

            with patch.object(AppPermChecker, 'has_perm', side_effect=mock_has_perm):
                with patch.object(
                    consumer, 'send_response', side_effect=mock_send_response
                ) as mock_send_response_obj:
                    with patch('api.filer.FilerClient') as mock_filer_client:
                        mock_client = MagicMock()
                        mock_client.bind = mock_bind_func
                        mock_filer_client.return_value = mock_client
                        await consumer.handle(b'')
                        mock_send_response_obj.assert_awaited_once_with(403, b'permission denied')

        asyncio.run(test_async())

    def test_handle_ping_endpoint(self, mock_requests):
        """Test handling ping endpoint"""
        async def test_async():
            consumer = FilerProxyConsumer()
            consumer.scope = {
                'user': self.user,
                'path': f'/v2/apps/{self.app_id}/volumes/test-volume/filer/_/ping',
                'url_route': {
                    'kwargs': {'path': '_/ping', 'name': 'test-volume', 'id': self.app_id}
                },
                'method': 'GET',
                'headers': []
            }
            # Set the id attribute that FilerProxyConsumer expects
            consumer.id = self.app_id

            async def mock_has_perm():
                return (True, "permission granted")

            async def mock_send_response(*args, **kwargs):
                pass

            with patch.object(AppPermChecker, 'has_perm', side_effect=mock_has_perm):
                with patch.object(
                    consumer, 'send_response', side_effect=mock_send_response
                ) as mock_send_response_obj:
                    # Create a proper async function instead of AsyncMock
                    async def mock_bind_func():
                        return {'username': 'test', 'password': 'test'}

                    with patch('api.filer.FilerClient') as mock_filer_client:
                        mock_client = MagicMock()
                        mock_client.info = mock_client.bind = mock_bind_func
                        mock_filer_client.return_value = mock_client

                        await consumer.handle(b'')

                        mock_send_response_obj.assert_called_once_with(200, b"pong")

        asyncio.run(test_async())

    def test_handle_bind_endpoint(self, mock_requests):
        """Test handling bind endpoint"""
        async def test_async():
            consumer = FilerProxyConsumer()
            consumer.scope = {
                'user': self.user,
                'path': f'/v2/apps/{self.app_id}/volumes/test-volume/filer/',
                'url_route': {
                    'kwargs': {'path': '_/bind', 'name': 'test-volume', 'id': self.app_id}
                },
                'method': 'GET',
                'headers': []
            }
            # Set the id attribute that FilerProxyConsumer expects
            consumer.id = self.app_id

            filer_data = {
                'username': 'test-username',
                'password': 'test-password'
            }

            async def mock_has_perm():
                return (True, "permission granted")

            async def mock_send_response(*args, **kwargs):
                pass

            with patch.object(AppPermChecker, 'has_perm', side_effect=mock_has_perm):
                with patch.object(
                    consumer, 'send_response', side_effect=mock_send_response
                ) as mock_send_response_obj:
                    # Create a proper async function instead of AsyncMock
                    async def mock_bind_func():
                        return filer_data

                    with patch('api.filer.FilerClient') as mock_filer_client:
                        mock_client = MagicMock()
                        mock_client.bind = mock_bind_func
                        mock_filer_client.return_value = mock_client

                        await consumer.handle(b'')

                        expected_response = json.dumps({
                            "username": "test-username",
                            "password": "test-password"
                        }).encode('utf-8')

                        mock_send_response_obj.assert_called_once_with(200, expected_response)

        asyncio.run(test_async())

    def test_handle_proxy_request(self, mock_requests):
        """Test handling proxy request to filer"""
        path = 'webdav/files/test.txt'

        async def test_async():
            consumer = FilerProxyConsumer()
            consumer.scope = {
                'user': self.user,
                'path': f'/v2/apps/{self.app_id}/volumes/test-volume/filer/{path}',
                'url_route': {
                    'kwargs': {'path': path, 'name': 'test-volume', 'id': self.app_id}
                },
                'method': 'GET',
                'headers': [(b'host', b'example.com'), (b'user-agent', b'test-agent')],
                'query_string': 'param=value'
            }
            # Set the id attribute that FilerProxyConsumer expects
            consumer.id = self.app_id

            filer_data = {
                'endpoint': 'http://filer.example.com',
                'username': 'test-username',
                'password': 'test-password'
            }

            async def mock_has_perm():
                return (True, "permission granted")

            with patch.object(AppPermChecker, 'has_perm', side_effect=mock_has_perm):
                with patch.object(consumer, '_handle_proxy_request') as mock_handle_proxy:
                    # Create a proper async function instead of AsyncMock
                    async def mock_bind_func():
                        return filer_data

                    with patch('api.filer.FilerClient') as mock_filer_client:
                        mock_client = MagicMock()
                        mock_client.info = mock_client.bind = mock_bind_func
                        mock_filer_client.return_value = mock_client

                        await consumer.handle(b'test body')

                        expected_url = "http://filer.example.com{}?param=value".format(
                            consumer.scope['path']
                        )
                        expected_headers = {'user-agent': 'test-agent'}

                        mock_handle_proxy.assert_called_once_with(
                            expected_url,
                            'GET',
                            expected_headers,
                            b'test body'
                        )

        asyncio.run(test_async())

    def test_forward_response(self, mock_requests):
        """Test forwarding response from filer"""
        async def test_async():
            consumer = FilerProxyConsumer()
            consumer.config = MagicMock()
            consumer.config.chunk_size = 1024

            # Mock aiohttp response
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.headers = {'content-type': 'application/json', 'content-length': '100'}

            # Create an async iterator for iter_chunked
            class AsyncIterator:
                def __init__(self, items):
                    self.items = iter(items)

                def __aiter__(self):
                    return self

                async def __anext__(self):
                    try:
                        return next(self.items)
                    except StopIteration:
                        raise StopAsyncIteration

            # Mock the iter_chunked method to return our async iterator
            mock_response.content.iter_chunked = MagicMock(
                return_value=AsyncIterator([b'chunk1', b'chunk2', b''])
            )

            # Mock async methods properly
            async def mock_send_response(*args, **kwargs):
                pass

            async def mock_send_body(*args, **kwargs):
                pass

            async def mock_send_headers(*args, **kwargs):
                pass

            with patch.object(
                consumer, 'send_body', side_effect=mock_send_body
            ) as mock_send_body_obj:
                with patch.object(
                    consumer, 'send_headers', side_effect=mock_send_headers
                ) as mock_send_headers_obj:
                    await consumer._forward_response(mock_response)
                    # Check that response headers were sent
                    expected_headers = [
                        [b'content-type', b'application/json'],
                        [b'content-length', b'100']
                    ]
                    mock_send_headers_obj.assert_called_once_with(
                        status=200,
                        headers=expected_headers
                    )
                    # Check that body chunks were sent
                    self.assertEqual(mock_send_body_obj.call_count, 3)

        asyncio.run(test_async())

    def test_handle_proxy_request_connection_error(self, mock_requests):
        """Test handling connection error during proxy request"""
        async def test_async():
            consumer = FilerProxyConsumer()
            consumer.config = MagicMock()
            consumer.config.timeout = aiohttp.ClientTimeout(total=30)

            # Mock the entire session context manager flow
            mock_session_instance = MagicMock()

            async def mock_aenter(self):
                return mock_session_instance

            async def mock_aexit(self, *args):
                return None
            mock_session_instance.__aenter__ = mock_aenter
            mock_session_instance.__aexit__ = mock_aexit

            # Mock the request context manager to raise an exception
            mock_request_cm = MagicMock()

            async def mock_request_aenter(self):
                raise aiohttp.ClientError("Connection failed")

            async def mock_request_aexit(self, *args):
                return None
            mock_request_cm.__aenter__ = mock_request_aenter
            mock_request_cm.__aexit__ = mock_request_aexit
            mock_session_instance.request = MagicMock(return_value=mock_request_cm)

            async def mock_send_response(*args, **kwargs):
                pass

            with patch('aiohttp.ClientSession', return_value=mock_session_instance):
                with patch.object(
                    consumer, 'send_response', side_effect=mock_send_response
                ):
                    await consumer._handle_proxy_request(
                        'http://example.com/test',
                        'GET',
                        {},
                        b'proxy service unavailable: Connection failed'
                    )

        asyncio.run(test_async())

    def test_handle_proxy_request_timeout(self, mock_requests):
        """Test handling timeout during proxy request"""
        async def test_async():
            consumer = FilerProxyConsumer()
            consumer.config = MagicMock()
            consumer.config.timeout = aiohttp.ClientTimeout(total=30)

            # Mock the entire session context manager flow
            mock_session_instance = MagicMock()

            async def mock_aenter(self):
                return mock_session_instance

            async def mock_aexit(self, *args):
                return None
            mock_session_instance.__aenter__ = mock_aenter
            mock_session_instance.__aexit__ = mock_aexit

            # Mock the request context manager to raise a timeout
            mock_request_cm = MagicMock()

            async def mock_request_aenter(self):
                raise asyncio.TimeoutError()

            async def mock_request_aexit(self, *args):
                return None
            mock_request_cm.__aenter__ = mock_request_aenter
            mock_request_cm.__aexit__ = mock_request_aexit
            mock_session_instance.request = MagicMock(return_value=mock_request_cm)

            with patch('aiohttp.ClientSession', return_value=mock_session_instance):
                with patch.object(consumer, 'send_response') as mock_send_response:
                    await consumer._handle_proxy_request(
                        'http://example.com/test',
                        'GET',
                        {},
                        b''
                    )

                    mock_send_response.assert_called_once_with(
                        504,
                        b'proxy request to backend filer timeout'
                    )

        asyncio.run(test_async())

    def test_skip_request_headers(self, mock_requests):
        """Test that certain headers are skipped in proxy requests"""
        consumer = FilerProxyConsumer()

        # Verify that SKIP_REQUEST_HEADERS contains expected headers
        expected_skip_headers = {
            'host', 'connection', 'keep-alive', 'proxy-connection',
            'te', 'trailers', 'upgrade'
        }

        self.assertEqual(consumer.SKIP_REQUEST_HEADERS, expected_skip_headers)

    def test_skip_response_headers(self, mock_requests):
        """Test that certain headers are skipped in proxy responses"""
        consumer = FilerProxyConsumer()

        # Verify that SKIP_RESPONSE_HEADERS contains expected headers
        expected_skip_headers = {
            'connection', 'keep-alive', 'proxy-authenticate',
            'proxy-authorization', 'te', 'trailers',
            'transfer-encoding', 'upgrade'
        }

        self.assertEqual(consumer.SKIP_RESPONSE_HEADERS, expected_skip_headers)

    def test_get_client_with_existing_volume(self, mock_requests):
        """Test _get_client method with existing volume"""
        path = 'test/file.txt'

        async def test_async():
            consumer = FilerProxyConsumer()
            consumer.scope = {
                'user': self.user,
                'url_route': {
                    'kwargs': {'path': path, 'name': 'test-volume', 'id': self.app_id}
                }
            }
            consumer.id = self.app_id

            with patch('api.filer.FilerClient') as mock_filer_client:
                mock_client = MagicMock()
                mock_filer_client.return_value = mock_client
                # Test the _get_client method
                client = await consumer._get_client(path)
                # Verify that FilerClient was called with correct parameters
                mock_filer_client.assert_called_once_with(self.app_id, self.test_volume, path)
                self.assertEqual(client, mock_client)

        asyncio.run(test_async())

    def test_get_client_with_nonexistent_volume(self, mock_requests):
        """Test _get_client method with non-existent volume"""
        path = 'test/file.txt'

        async def test_async():
            consumer = FilerProxyConsumer()
            consumer.scope = {
                'user': self.user,
                'url_route': {
                    'kwargs': {
                        'path': path, 'name': 'nonexistent-volume', 'id': self.app_id,
                    }
                }
            }
            consumer.id = self.app_id
            # Test the _get_client method
            client = await consumer._get_client(path)
            # Should return None when volume doesn't exist
            self.assertIsNone(client)

        asyncio.run(test_async())

    def test_handle_with_volume_not_found(self, mock_requests):
        """Test handling request when volume is not found"""
        async def test_async():
            consumer = FilerProxyConsumer()
            path = 'test/file.txt'
            consumer.scope = {
                'user': self.user,
                'path': f'/v2/apps/{self.app_id}/volumes/nonexistent-volume/filer/{path}',
                'url_route': {
                    'kwargs': {
                        'path': path, 'name': 'nonexistent-volume', 'id': self.app_id,
                    }
                },
                'method': 'GET',
                'headers': []
            }
            consumer.id = self.app_id

            async def mock_has_perm():
                return (True, "permission granted")

            async def mock_send_response(*args, **kwargs):
                pass

            with patch.object(AppPermChecker, 'has_perm', side_effect=mock_has_perm):
                with patch.object(
                    consumer, 'send_response', side_effect=mock_send_response
                ) as mock_send_response_obj:
                    await consumer.handle(b'test body')
                    mock_send_response_obj.assert_called_once_with(
                        status=404,
                        body=b'app or volume not found'
                    )

        asyncio.run(test_async())

    def test_handle_with_existing_volume(self, mock_requests):
        """Test handling request with existing volume"""
        path = 'webdav/test/file.txt'

        async def test_async():
            consumer = FilerProxyConsumer()
            consumer.scope = {
                'user': self.user,
                'path': f'/v2/apps/{self.app_id}/volumes/nonexistent-volume/filer/{path}',
                'url_route': {
                    'kwargs': {'path': path, 'name': 'test-volume', 'id': self.app_id}
                },
                'method': 'GET',
                'headers': [(b'host', b'example.com'), (b'user-agent', b'test-agent')],
                'query_string': 'param=value'
            }
            consumer.id = self.app_id

            filer_data = {
                'endpoint': 'http://filer.example.com',
                'username': 'test-username',
                'password': 'test-password'
            }

            async def mock_has_perm():
                return (True, "permission granted")

            with patch.object(AppPermChecker, 'has_perm', side_effect=mock_has_perm):
                with patch.object(consumer, '_handle_proxy_request') as mock_handle_proxy:
                    # Create a proper async function instead of AsyncMock
                    async def mock_bind_func():
                        return filer_data

                    with patch('api.filer.FilerClient') as mock_filer_client:
                        mock_client = MagicMock()
                        mock_client.bind = mock_client.info = mock_bind_func
                        mock_filer_client.return_value = mock_client

                        await consumer.handle(b'test body')

                        expected_url = "http://filer.example.com{}?param=value".format(
                            consumer.scope['path']
                        )
                        expected_headers = {'user-agent': 'test-agent'}

                        mock_handle_proxy.assert_called_once_with(
                            expected_url,
                            'GET',
                            expected_headers,
                            b'test body'
                        )

        asyncio.run(test_async())
