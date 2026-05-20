from django.contrib.auth import get_user_model
from django.core.cache import cache
from rest_framework.test import APIRequestFactory
from rest_framework.exceptions import AuthenticationFailed
from unittest import mock

from api.authentication import DryccAuthentication
from api.tests import DryccTransactionTestCase

User = get_user_model()


class AuthenticationTest(DryccTransactionTestCase):
    fixtures = ['tests.json']

    def setUp(self):
        super().setUp()
        self.factory = APIRequestFactory()
        self.auth = DryccAuthentication()
        self.user = User.objects.get(username='autotest')
        self.token_key = self.get_or_create_token(self.user)

    def test_authenticate_no_auth_header(self):
        """Test authentication without an authorization header"""
        request = self.factory.get('/')
        result = self.auth.authenticate(request)
        self.assertIsNone(result)

    def test_authenticate_invalid_header_format(self):
        """Test authentication with invalid header format"""
        # Unknown scheme
        request = self.factory.get('/', HTTP_AUTHORIZATION='unknown_scheme token')
        result = self.auth.authenticate(request)
        self.assertIsNone(result)

        # Single word header
        request = self.factory.get('/', HTTP_AUTHORIZATION='token')
        with self.assertRaises(AuthenticationFailed):
            self.auth.authenticate(request)

    @mock.patch('api.clients.ManagerAPI.get_user_status')
    @mock.patch('api.apps_extra.social_core.backends.OauthCacheManager.get_user')
    def test_authenticate_bearer_token_success(self, mock_get_user, mock_get_status):
        """Test authentication with a valid bearer token for an active user"""
        mock_get_user.return_value = self.user
        mock_get_status.return_value = (True, "User acts normally")

        request = self.factory.get('/', HTTP_AUTHORIZATION='bearer fake_bearer_token')
        user, token = self.auth.authenticate(request)

        self.assertEqual(user, self.user)
        self.assertEqual(token, 'fake_bearer_token')
        mock_get_user.assert_called_once_with('fake_bearer_token')
        mock_get_status.assert_called_once_with(self.user.id)

    @mock.patch('api.clients.ManagerAPI.get_user_status')
    @mock.patch('api.apps_extra.social_core.backends.OauthCacheManager.get_user')
    def test_authenticate_bearer_token_inactive(self, mock_get_user, mock_get_status):
        """Test authentication with a valid bearer token for an inactive user (from ManagerAPI)"""
        mock_get_user.return_value = self.user
        mock_get_status.return_value = (False, "User is inactive")

        request = self.factory.get('/', HTTP_AUTHORIZATION='bearer fake_bearer_token')
        with self.assertRaisesMessage(AuthenticationFailed, "User is inactive"):
            self.auth.authenticate(request)

    @mock.patch('api.clients.ManagerAPI.get_user_status')
    def test_authenticate_drycc_token_cache_miss_success(self, mock_get_status):
        """Test authentication with a valid drycc token, no cache hit"""
        mock_get_status.return_value = (True, "User acts normally")

        # Clear cache to force DB lookup
        cache.delete(self.token_key)

        request = self.factory.get('/', HTTP_AUTHORIZATION=f'token {self.token_key}')
        user, token = self.auth.authenticate(request)

        self.assertEqual(user, self.user)
        self.assertEqual(token, self.token_key)
        mock_get_status.assert_called_once_with(self.user.id)

    @mock.patch('api.clients.ManagerAPI.get_user_status')
    def test_authenticate_drycc_token_cache_hit(self, mock_get_status):
        """Test authentication with a valid drycc token, hitting the cache"""
        mock_get_status.return_value = (True, "User acts normally")

        # Set user in cache to simulate cache hit
        cache.set(self.token_key, self.user, timeout=300)

        request = self.factory.get('/', HTTP_AUTHORIZATION=f'token {self.token_key}')
        user, token = self.auth.authenticate(request)

        self.assertEqual(user, self.user)
        self.assertEqual(token, self.token_key)
        # Should still verify through ManagerAPI
        mock_get_status.assert_called_once_with(self.user.id)

    @mock.patch('api.clients.ManagerAPI.get_user_status')
    def test_authenticate_drycc_token_inactive(self, mock_get_status):
        """Test authentication with a valid drycc token, but user is inactive"""
        mock_get_status.return_value = (False, "Workspace inactive")

        request = self.factory.get('/', HTTP_AUTHORIZATION=f'token {self.token_key}')
        with self.assertRaisesMessage(AuthenticationFailed, "Workspace inactive"):
            self.auth.authenticate(request)

    def test_authenticate_invalid_drycc_token(self):
        """Test authentication with an invalid drycc token"""
        request = self.factory.get('/', HTTP_AUTHORIZATION='token invalid_token_abc123')
        with self.assertRaisesMessage(AuthenticationFailed, "Invalid token."):
            self.auth.authenticate(request)
