# chat/routing.py
from django.urls import re_path

from . import consumers

http_urlpatterns = [
    re_path(
        r'^v2/apps/(?P<id>([\w-]*))/volumes/(?P<name>([\w-]*))/filer/(?P<path>.*)$',
        consumers.FilerProxyConsumer.as_asgi()),
]

websocket_urlpatterns = [
    re_path(
        r'^v2/apps/(?P<id>([\w-]*))/pods/(?P<name>([\w-]*))/logs/?$',
        consumers.AppPodLogsConsumer.as_asgi()),
    re_path(
        r'^v2/apps/(?P<id>([\w-]*))/pods/(?P<name>([\w-]*))/exec/?$',
        consumers.AppPodExecConsumer.as_asgi()),
]
