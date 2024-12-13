import requests_mock

from django.core.cache import cache
from django.contrib.auth import get_user_model

from api.models.app import App
from api.tests import adapter, DryccTransactionTestCase

User = get_user_model()


@requests_mock.Mocker(real_http=True, adapter=adapter)
class TestAppSettings(DryccTransactionTestCase):
    """Tests setting and updating config values"""

    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = self.get_or_create_token(self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

    def tearDown(self):
        # make sure every test has a clean slate for k8s mocking
        cache.clear()

    def test_settings_bool(self, mock_requests):
        """
        Create an application with the routable flag turned on or off
        """
        # create app, expecting routable to be true
        app_id = self.create_app()
        app = App.objects.get(id=app_id)
        self.assertTrue(app.appsettings_set.latest().routable)
        self.assertTrue(app.appsettings_set.latest().autodeploy)
        self.assertTrue(app.appsettings_set.latest().autorollback)
        # Set routable to false
        response = self.client.post(
            f'/v2/apps/{app.id}/settings',
            {'routable': False}
        )
        self.assertEqual(response.status_code, 201, response.data)
        self.assertFalse(app.appsettings_set.latest().routable)
        self.assertTrue(app.appsettings_set.latest().autodeploy)
        self.assertTrue(app.appsettings_set.latest().autorollback)

        # Set autodeploy to false
        response = self.client.post(
            f'/v2/apps/{app.id}/settings',
            {'autodeploy': False}
        )
        self.assertEqual(response.status_code, 201, response.data)
        self.assertFalse(app.appsettings_set.latest().routable)
        self.assertFalse(app.appsettings_set.latest().autodeploy)
        self.assertTrue(app.appsettings_set.latest().autorollback)

        # Set autorollback to false
        response = self.client.post(
            f'/v2/apps/{app.id}/settings',
            {'autorollback': False}
        )
        self.assertEqual(response.status_code, 201, response.data)
        self.assertFalse(app.appsettings_set.latest().routable)
        self.assertFalse(app.appsettings_set.latest().autodeploy)
        self.assertFalse(app.appsettings_set.latest().autorollback)

        # Set autorollback to true
        response = self.client.post(
            f'/v2/apps/{app.id}/settings',
            {'autorollback': True}
        )
        self.assertEqual(response.status_code, 201, response.data)
        self.assertFalse(app.appsettings_set.latest().routable)
        self.assertFalse(app.appsettings_set.latest().autodeploy)
        self.assertTrue(app.appsettings_set.latest().autorollback)

        # Set autodeploy to true
        response = self.client.post(
            f'/v2/apps/{app.id}/settings',
            {'autodeploy': True}
        )
        self.assertEqual(response.status_code, 201, response.data)
        self.assertFalse(app.appsettings_set.latest().routable)
        self.assertTrue(app.appsettings_set.latest().autodeploy)
        self.assertTrue(app.appsettings_set.latest().autorollback)

        # Set routable to false
        response = self.client.post(
            f'/v2/apps/{app.id}/settings',
            {'routable': True}
        )
        self.assertEqual(response.status_code, 201, response.data)
        self.assertTrue(app.appsettings_set.latest().routable)
        self.assertTrue(app.appsettings_set.latest().autodeploy)
        self.assertTrue(app.appsettings_set.latest().autorollback)

    def test_autoscale(self, mock_requests):
        """
        Test that autoscale can be applied
        """
        app_id = self.create_app()

        # create an autoscaling rule
        scale = {'autoscale': {'cmd': {'min': 2, 'max': 5, 'cpu_percent': 45}}}
        response = self.client.post(
            f'/v2/apps/{app_id}/settings',
            scale
        )
        self.assertEqual(response.status_code, 201, response.data)
        self.assertIn('cmd', response.data['autoscale'])
        self.assertEqual(response.data['autoscale'], scale['autoscale'])

        # update
        scale = {'autoscale': {'cmd': {'min': 2, 'max': 8, 'cpu_percent': 45}}}
        response = self.client.post(
            f'/v2/apps/{app_id}/settings',
            scale
        )
        self.assertEqual(response.status_code, 201, response.data)
        self.assertIn('cmd', response.data['autoscale'])
        self.assertEqual(response.data['autoscale'], scale['autoscale'])

        # create
        scale = {'autoscale': {'worker': {'min': 2, 'max': 5, 'cpu_percent': 45}}}
        response = self.client.post(
            f'/v2/apps/{app_id}/settings',
            scale
        )
        self.assertEqual(response.status_code, 201, response.data)
        self.assertIn('worker', response.data['autoscale'])
        self.assertEqual(response.data['autoscale']['worker'], scale['autoscale']['worker'])

        # check that the cmd proc type is still there
        self.assertIn('cmd', response.data['autoscale'])

        # check that config fails if trying to unset non-existing proc type
        response = self.client.post(
            f'/v2/apps/{app_id}/settings',
            {'autoscale': {'invalid-proctype': None}})
        self.assertEqual(response.status_code, 422, response.data)
        response = self.client.post(
            f'/v2/apps/{app_id}/settings',
            {'autoscale': {'invalid_proctype': None}})
        self.assertEqual(response.status_code, 400, response.data)

        # remove a proc type
        response = self.client.post(
            f'/v2/apps/{app_id}/settings',
            {'autoscale': {'worker': None}})
        self.assertEqual(response.status_code, 201, response.data)
        self.assertNotIn('worker', response.data['autoscale'])
        self.assertIn('cmd', response.data['autoscale'])

        # remove another proc type
        response = self.client.post(
            f'/v2/apps/{app_id}/settings',
            {'autoscale': {'cmd': None}})
        self.assertEqual(response.status_code, 201, response.data)
        self.assertNotIn('cmd', response.data['autoscale'])

    def test_autoscale_validations(self, mock_requests):
        """
        Test that autoscale validations work
        """
        app_id = self.create_app()

        # Set one of the values that require a numeric value to a string
        response = self.client.post(
            f'/v2/apps/{app_id}/settings',
            {'autoscale': {'cmd': {'min': 4, 'max': 5, 'cpu_percent': "t"}}}
        )
        self.assertEqual(response.status_code, 400, response.data)

        # Don't set one of the mandatory value
        response = self.client.post(
            f'/v2/apps/{app_id}/settings',
            {'autoscale': {'cmd': {'min': 4, 'cpu_percent': 45}}}
        )
        self.assertEqual(response.status_code, 400, response.data)

    def test_settings_labels(self, mock_requests):
        """
        Test that labels can be applied
        """
        app_id = self.create_app()

        # create
        base_labels = {
            'label':
                {
                    'git_repo': 'https://github.com/drycc/controller',
                    'team': 'frontend',
                    'empty': ''
                }
        }
        response = self.client.post(
            f'/v2/apps/{app_id}/settings',
            base_labels
        )
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data['label'], base_labels['label'])

        # update
        labels = {'label': {'team': 'backend'}}
        response = self.client.post(
            f'/v2/apps/{app_id}/settings',
            labels
        )
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data['label']['team'], labels['label']['team'])
        self.assertEqual(response.data['label']['git_repo'], base_labels['label']['git_repo'])
        self.assertEqual(response.data['label']['empty'], base_labels['label']['empty'])

        # remove
        labels = {'label': {'git_repo': None}}
        response = self.client.post(
            f'/v2/apps/{app_id}/settings',
            labels
        )
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data['label']['team'], 'backend')
        self.assertFalse('git_repo' in response.data['label'])
        self.assertEqual(response.data['label']['empty'], base_labels['label']['empty'])

        # error on remove non-exist label
        labels = {'label': {'git_repo': None}}
        response = self.client.post(
            f'/v2/apps/{app_id}/settings',
            labels
        )
        self.assertEqual(response.status_code, 422, response.data)
