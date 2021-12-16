from django.contrib.auth import get_user_model
from django.core.cache import cache
from rest_framework.authtoken.models import Token


from api.tests import DryccTransactionTestCase

User = get_user_model()


class TestServices(DryccTransactionTestCase):

    """Tests push notification from build system"""

    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = Token.objects.get(user=self.user).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

    def tearDown(self):
        # make sure every test has a clean slate for k8s mocking
        cache.clear()

    def test_service_basic_ops(self):
        """Test basic service operations."""
        app_id = self.create_app()

        # list non-existing services
        response = self.client.get('/v2/apps/{}/services'.format(app_id))
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['services']), 0)
        # create 1st service
        response = self.client.post(
            '/v2/apps/{}/services'.format(app_id),
            {'procfile_type': 'test', 'path_pattern': '/testep/notify'}
        )
        self.assertEqual(response.status_code, 201, response.data)
        # list 1st service
        response = self.client.get('/v2/apps/{}/services'.format(app_id))
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['services']), 1)
        expected1 = {
            'procfile_type': 'test',
            'path_pattern': '/testep/notify'
        }
        self.assertDictContainsSubset(expected1, response.data['services'][0])
        # update 1st service
        response = self.client.post(
            '/v2/apps/{}/services'.format(app_id),
            {'procfile_type': 'test', 'path_pattern': '/testep/notify_new'}
        )
        self.assertEqual(response.status_code, 201, response.data)
        # list 1st service and get new value
        response = self.client.get('/v2/apps/{}/services'.format(app_id))
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['services']), 1)
        expected1 = {
            'procfile_type': 'test',
            'path_pattern': '/testep/notify_new'
        }
        self.assertDictContainsSubset(expected1, response.data['services'][0])
        # create 2nd service
        response = self.client.post(
            '/v2/apps/{}/services'.format(app_id),
            {'procfile_type': 'test2', 'path_pattern': '/testep2/notify'}
        )
        self.assertEqual(response.status_code, 201, response.data)
        # list two services
        response = self.client.get('/v2/apps/{}/services'.format(app_id))
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['services']), 2)
        expected2 = {
            'procfile_type': 'test2',
            'path_pattern': '/testep2/notify'
        }
        self.assertDictContainsSubset(expected2, response.data['services'][0])
        self.assertDictContainsSubset(expected1, response.data['services'][1])
        # delete 1st
        response = self.client.delete(
            '/v2/apps/{}/services'.format(app_id),
            {'procfile_type': 'test'}
        )
        self.assertEqual(response.status_code, 204, response.data)
        # delete 2nd
        response = self.client.delete(
            '/v2/apps/{}/services'.format(app_id),
            {'procfile_type': 'test2'}
        )
        self.assertEqual(response.status_code, 204, response.data)
        # delete non-existing (1st again)
        response = self.client.delete(
            '/v2/apps/{}/services'.format(app_id),
            {'procfile_type': 'test'}
        )
        self.assertEqual(response.status_code, 404, response.data)
