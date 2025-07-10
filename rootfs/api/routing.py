# chat/routing.py
from django.urls import re_path

from . import consumers

websocket_urlpatterns = [
    re_path(
        r'^v2/apps/(?P<id>([\w-]*))/pods/(?P<pod_id>([\w-]*))/logs/?$',
        consumers.AppPodLogsConsumer.as_asgi()),
    re_path(
        r'^v2/apps/(?P<id>([\w-]*))/pods/(?P<pod_id>([\w-]*))/exec/?$',
        consumers.AppPodExecConsumer.as_asgi()),
]
