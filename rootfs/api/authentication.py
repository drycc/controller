import logging
from django.core.cache import cache
from django.contrib.auth.models import AnonymousUser
from rest_framework import authentication
from rest_framework.authentication import TokenAuthentication
from rest_framework import exceptions

logger = logging.getLogger(__name__)


class AnonymousAuthentication(authentication.BaseAuthentication):

    def authenticate(self, request):
        """
        Authenticate the request for anyone!
        """
        return AnonymousUser(), None


class AnonymousOrAuthenticatedAuthentication(authentication.BaseAuthentication):

    def authenticate(self, request):
        """
        Authenticate the request for anyone or if a valid token is provided, a user.
        """
        try:
            return TokenAuthentication.authenticate(TokenAuthentication(), request)
        except Exception as e:
            logger.debug(e)
            return AnonymousUser(), None


class ExpiringTokenAuthentication(TokenAuthentication):
    def authenticate_credentials(self, key):
        model = self.get_model()
        has_key = cache.get('token_' + key)
        if not has_key:
            model.objects.select_related('user').filter(key=key).delete()
            raise exceptions.AuthenticationFailed('Token has expired, please login')
        return super(ExpiringTokenAuthentication, self).authenticate_credentials(key)
