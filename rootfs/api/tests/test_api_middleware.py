"""
Unit tests for the Drycc api app.

Run the tests with "./manage.py test api"
"""

from django.contrib.auth import get_user_model
from rest_framework.authtoken.models import Token
from api.tests import DryccTestCase

from api import __version__

User = get_user_model()


class APIMiddlewareTest(DryccTestCase):

    """Tests middleware.py's business logic"""

    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = Token.objects.get(user=self.user).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

    def test_drycc_version_header_good(self):
        """
        Test that when the version header is sent.
        """
        response = self.client.get('/v2/apps')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.has_header('DRYCC_API_VERSION'), True)
        self.assertEqual(response['DRYCC_API_VERSION'], __version__.rsplit('.', 1)[0])
