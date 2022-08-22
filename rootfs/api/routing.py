# chat/routing.py
from django.urls import re_path

from . import consumers

websocket_urlpatterns = [
    re_path(
        r'^v2/apps/(?P<id>.*)/pods/(?P<pod_id>.*)/exec/?$',
        consumers.AppPodExecConsumer.as_asgi())
]
