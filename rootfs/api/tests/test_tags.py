import json
import requests_mock

from django.core.cache import cache
from django.contrib.auth import get_user_model

from api.tests import adapter, DryccTransactionTestCase

User = get_user_model()


@requests_mock.Mocker(real_http=True, adapter=adapter)
class TestTags(DryccTransactionTestCase):
    """Tests setting and updating config values"""

    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = self.get_or_create_token(self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

    def tearDown(self):
        # make sure every test has a clean slate for k8s mocking
        cache.clear()

    def test_tags(self, mock_requests):
        """
        Test that tags can be set on an application
        """
        app_id = self.create_app()

        # check default
        url = f'/v2/apps/{app_id}/config'
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertIn('tags', response.data)
        self.assertEqual(response.data['tags'], {})

        # set some tags
        body = {'tags': json.dumps({'web': {'environ': 'dev'}})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        tags1 = response.data

        # check tags again
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertIn('tags', response.data)
        tags = response.data['tags']
        self.assertIn('web', tags)
        self.assertEqual(tags['web']['environ'], 'dev')

        # set an additional value
        body = {'tags': json.dumps({'web': {'rack': '1'}})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        tags2 = response.data
        self.assertNotEqual(tags1['uuid'], tags2['uuid'])
        tags = response.data['tags']
        self.assertIn('web', tags)
        self.assertEqual(tags['web']['rack'], '1')
        self.assertEqual(tags['web']['environ'], 'dev')

        # read the limit again
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        tags3 = response.data
        self.assertEqual(tags2, tags3)
        tags = response.data['tags']
        self.assertIn('web', tags)
        self.assertEqual(tags['web']['rack'], '1')
        self.assertEqual(tags['web']['environ'], 'dev')

        # unset a value
        body = {'tags': json.dumps({'web': {'rack': None}})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        tags4 = response.data
        self.assertNotEqual(tags3['uuid'], tags4['uuid'])
        self.assertNotIn('rack', json.dumps(response.data['tags']))

        # set valid values
        body = {'tags': json.dumps({'web': {'kubernetes.io/hostname': '172.17.8.100'}})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        body = {'tags': json.dumps({'web': {'is.valid': 'is-also_valid'}})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        body = {'tags': json.dumps({'web': {'host.the-name.com/is.valid': 'valid'}})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        body = {'tags': json.dumps({'web': {'host.the-name.com/does.no.exist': 'valid'}})}
        response = self.client.post(url, body)
        self.assertContains(
            response,
            'Addition of host.the-name.com/does.no.exist=valid is the cause',
            status_code=400
        )

        # set invalid values
        body = {'tags': json.dumps({'web': {'valid': 'in\nvalid'}})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 400, response.data)
        body = {'tags': json.dumps({'web': {'host.name.com/notvalid-': 'valid'}})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 400, response.data)
        body = {'tags': json.dumps({'web': {'valid': 'invalid.'}})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 400, response.data)
        body = {'tags': json.dumps({'web': {'host.name.com/,not.valid': 'valid'}})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 400, response.data)
        long_tag = 'a' * 300
        body = {'tags': json.dumps({'web': {'{}/not.valid'.format(long_tag): 'valid'}})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 400, response.data)
        body = {'tags': json.dumps({'web': {'this&foo.com/not.valid': 'valid'}})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 400, response.data)

        # disallow put/patch/delete
        response = self.client.put(url)
        self.assertEqual(response.status_code, 405, response.data)
        response = self.client.patch(url)
        self.assertEqual(response.status_code, 405, response.data)
