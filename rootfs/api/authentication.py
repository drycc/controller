import logging
from django.conf import settings
from django.contrib.auth.models import AnonymousUser
from django.core.cache import cache
from django.utils.translation import gettext_lazy as _
from rest_framework import authentication
from rest_framework.authentication import TokenAuthentication, \
    get_authorization_header
from rest_framework import exceptions

from api.oauth import OAuthManager

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


class DryccOIDCAuthentication(TokenAuthentication):
    def authenticate(self, request):
        if 'Drycc' in request.META.get('HTTP_USER_AGENT', ''):
            auth = get_authorization_header(request).split()

            if not auth or auth[0].lower() != self.keyword.lower().encode():
                return None

            if len(auth) == 1:
                msg = _('Invalid token header. No credentials provided.')
                raise exceptions.AuthenticationFailed(msg)
            elif len(auth) > 2:
                msg = _('Invalid token header. Token string should not contain spaces.')  # noqa
                raise exceptions.AuthenticationFailed(msg)

            try:
                token = auth[1].decode()
            except UnicodeError:
                msg = _('Invalid token header. Token string should not contain invalid characters.')  # noqa
                raise exceptions.AuthenticationFailed(msg)
            return cache.get_or_set(
                token, lambda: self._get_user(token), settings.OAUTH_CACHE_USER_TIME), None  # noqa
        return super(DryccOIDCAuthentication, self).authenticate(request)  # noqa

    @staticmethod
    def _get_user(key):
        try:
            user_info = OAuthManager().get_user_by_token(key)
            if not user_info.get('email'):
                user_info['email'] = OAuthManager().get_email_by_token(key)
        except Exception as e:
            logger.info(e)
            raise exceptions.AuthenticationFailed(_('Verify token fail.'))
        from api import serializers
        return serializers.UserSerializer.update_or_create(user_info)
