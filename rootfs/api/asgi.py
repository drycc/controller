"""
ASGI config for Drycc Workflow Controller project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/4.1/howto/deployment/asgi/
"""

import os

from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.security.websocket import AllowedHostsOriginValidator


os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'api.settings.production')
http = get_asgi_application()

from .routing import websocket_urlpatterns  # noqa
from .middleware import ChannelOAuthMiddleware  # noqa
websocket = AllowedHostsOriginValidator(ChannelOAuthMiddleware(URLRouter(
    websocket_urlpatterns
)))

application = ProtocolTypeRouter({"http": http, "websocket": websocket})
