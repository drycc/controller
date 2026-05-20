import logging
from django.contrib.auth.models import AnonymousUser
from django.core.cache import cache
from django.utils.translation import gettext_lazy
from rest_framework import authentication
from rest_framework.authentication import get_authorization_header
from rest_framework import exceptions
from api.clients import ManagerAPI

logger = logging.getLogger(__name__)


class AnonymousAuthentication(authentication.BaseAuthentication):

    def authenticate(self, request):
        """
        Authenticate the request for anyone!
        """
        return AnonymousUser(), None


class DryccAuthentication(authentication.BaseAuthentication):

    keywords = ('token', 'bearer')
    manager_api = ManagerAPI()

    def parse_header(self, request):
        try:
            auth = get_authorization_header(request).split()
            if not auth or auth[0].decode().lower() not in self.keywords:
                return None, None
            if len(auth) == 1:
                msg = gettext_lazy('Invalid token header. No credentials provided.')
                raise exceptions.AuthenticationFailed(msg)
            elif len(auth) > 2:
                msg = gettext_lazy(
                    'Invalid token header. Token string should not contain spaces.')
                raise exceptions.AuthenticationFailed(msg)
            return auth[0].decode().lower(), auth[1].decode()
        except UnicodeError:
            msg = gettext_lazy(
                'Invalid token header. Token string should not contain invalid characters.')
            raise exceptions.AuthenticationFailed(msg)

    def authenticate(self, request):
        user, (token_type, token) = None, self.parse_header(request)
        if token_type is None or token is None:
            return None
        if token_type == 'bearer':  # drycc oauth access token
            from api.apps_extra.social_core.backends import OauthCacheManager
            user = OauthCacheManager().get_user(token)
        elif token_type == 'token':  # drycc token
            user = cache.get(token, None)
            if not user:
                user, token = self.authenticate_credentials(token)
        if user:
            is_active, message = self.manager_api.get_user_status(user.id)
            if not is_active:
                raise exceptions.AuthenticationFailed(message)
        return user, token if user else None

    def authenticate_credentials(self, key):
        from api.models.base import Token
        try:
            token = Token.objects.select_related('owner').get(key=key)
        except Token.DoesNotExist:
            raise exceptions.AuthenticationFailed(gettext_lazy('Invalid token.'))
        if not token.owner.is_active:
            raise exceptions.AuthenticationFailed(gettext_lazy('User inactive or deleted.'))
        if token.expires():
            try:
                from api.apps_extra.social_core.backends import OauthCacheManager
                user = OauthCacheManager().get_user(token.oauth['access_token'])
                cache.set(key, user, timeout=token.oauth['expires_in'])
                token.refresh_token()
                return user, token.key
            except exceptions.AuthenticationFailed:
                return None, None
        return (token.owner, token.key)

    def authenticate_header(self, request):
        keyword = self.keywords[0]
        try:
            auth = self.parse_header(request)
            if auth[0]:
                keyword = auth[0]
        except exceptions.AuthenticationFailed:
            pass
        return keyword
