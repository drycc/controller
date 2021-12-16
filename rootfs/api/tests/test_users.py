from django.contrib.auth import get_user_model
from rest_framework.authtoken.models import Token
from api.tests import DryccTestCase

User = get_user_model()


class TestUsers(DryccTestCase):
    """ Tests users endpoint"""

    fixtures = ['tests.json']

    def test_super_user_can_list(self):
        user = User.objects.get(username='autotest')
        token = Token.objects.get(user=user)

        for url in ['/v2/users', '/v2/users/']:
            response = self.client.get(url,
                                       HTTP_AUTHORIZATION='token {}'.format(token))
            self.assertEqual(response.status_code, 200, response.data)
            self.assertEqual(len(response.data['results']), 4)

    def test_enable(self):
        user = User.objects.get(username='autotest')
        token = Token.objects.get(user=user)
        response = self.client.patch("/v2/users/autotest2/enable/",
                                     HTTP_AUTHORIZATION='token {}'.format(token))
        self.assertEqual(response.status_code, 204)
        user = User.objects.get(username='autotest2')
        self.assertEqual(user.is_active, True)

    def test_disable(self):
        user = User.objects.get(username='autotest')
        token = Token.objects.get(user=user)
        response = self.client.patch("/v2/users/autotest2/disable/",
                                     HTTP_AUTHORIZATION='token {}'.format(token))
        self.assertEqual(response.status_code, 204)
        user = User.objects.get(username='autotest2')
        self.assertEqual(user.is_active, False)

    def test_non_super_user_cannot_list(self):
        user = User.objects.get(username='autotest2')
        token = Token.objects.get(user=user)

        for url in ['/v2/users', '/v2/users/']:
            response = self.client.get(url,
                                       HTTP_AUTHORIZATION='token {}'.format(token))
            self.assertEqual(response.status_code, 403)
