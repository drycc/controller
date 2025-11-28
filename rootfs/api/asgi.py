"""
ASGI config for Drycc Workflow Controller project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/4.1/howto/deployment/asgi/
"""

import os

from django.urls import re_path
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.security.websocket import AllowedHostsOriginValidator


os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'api.settings.production')
django_asgi_app = get_asgi_application()

from .routing import http_urlpatterns, websocket_urlpatterns  # noqa
from .middleware import ChannelOAuthMiddleware, ChannelAPIVersionMiddleware  # noqa

application = ProtocolTypeRouter({
    "http": ChannelAPIVersionMiddleware(URLRouter([
        *http_urlpatterns,
        re_path(r'', django_asgi_app),
    ])),
    "websocket": AllowedHostsOriginValidator(ChannelOAuthMiddleware(URLRouter(
        websocket_urlpatterns
    )))
})
