"""
HTTP middleware for the Drycc REST API.

See https://docs.djangoproject.com/en/1.11/topics/http/middleware/
"""
from api import __version__
from django.http.request import HttpRequest

from channels.middleware import BaseMiddleware
from channels.db import database_sync_to_async
from api.authentication import DryccAuthentication


class APIVersionMiddleware(object):
    """
    Include that REST API version with each response.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        """
        Include the controller's REST API major and minor version in
        a response header.
        """
        response = self.get_response(request)
        # clients shouldn't care about the patch release
        version = __version__.rsplit('.', 1)[0]
        response['DRYCC_API_VERSION'] = version
        response['DRYCC_PLATFORM_VERSION'] = __version__
        return response


class ChannelOAuthMiddleware(BaseMiddleware):
    """
    Middleware which populates scope["user"] from a auth2 token.
    """
    authentication = DryccAuthentication()

    @database_sync_to_async
    def get_user(self, scope):
        headers = {}
        for header in scope["headers"]:
            if header[0] in (b"authorization", ):
                key = "HTTP_%s" % header[0].decode().replace("-", "_").upper()
                headers[key] = header[1].decode()
        if len(headers) < 1:
            return None
        request = HttpRequest()
        request.META = headers
        user, _ = self.authentication.authenticate(request)
        return user

    async def __call__(self, scope, receive, send):
        scope = dict(scope)
        scope["user"] = await self.get_user(scope)
        return await super().__call__(scope, receive, send)
