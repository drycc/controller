# -*- coding: utf-8 -*-
"""
Unit tests for the Drycc api app.

Run the tests with "./manage.py test api"
"""
import json
from io import StringIO
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.management import call_command

from unittest import mock

from api.models.app import App
from api.models.base import PROCFILE_TYPE_RUN, PROCFILE_TYPE_WEB
from api.models.config import Config
from api.serializers import CONFIG_LIMITS_MISMATCH_MSG
from api.models.build import Build
from api.models.release import Release

from api.tests import adapter, DryccTransactionTestCase
import requests_mock

User = get_user_model()


@requests_mock.Mocker(real_http=True, adapter=adapter)
class ConfigTest(DryccTransactionTestCase):
    """Tests setting and updating config values"""

    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = self.get_or_create_token(self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

        url = '/v2/apps'
        response = self.client.post(url, HTTP_AUTHORIZATION='token {}'.format(self.token))
        self.assertEqual(response.status_code, 201, response.data)
        self.app = App.objects.all()[0]

    def tearDown(self):
        # make sure every test has a clean slate for k8s mocking
        cache.clear()

    def test_config(self, mock_requests):
        """
        Test that config is auto-created for a new app and that
        config can be updated using a PATCH
        """
        app_id = self.create_app()

        # check to see that an initial/empty config was created
        url = f"/v2/apps/{app_id}/config"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertIn('values', response.data)
        self.assertEqual(response.data['values'], {})
        config1 = response.data

        # set an initial config value
        body = {'values': json.dumps({'NEW_URL1': 'http://localhost:8080/'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        config2 = response.data
        self.assertNotEqual(config1['uuid'], config2['uuid'])
        self.assertIn('NEW_URL1', response.data['values'])

        # read the config
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        config3 = response.data
        self.assertEqual(config2, config3)
        self.assertIn('NEW_URL1', response.data['values'])

        # set an additional config value
        body = {'values': json.dumps({'NEW_URL2': 'http://localhost:8080/'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        config3 = response.data
        self.assertNotEqual(config2['uuid'], config3['uuid'])
        self.assertIn('NEW_URL1', response.data['values'])
        self.assertIn('NEW_URL2', response.data['values'])

        # read the config again
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        config4 = response.data
        self.assertEqual(config3, config4)
        self.assertIn('NEW_URL1', response.data['values'])
        self.assertIn('NEW_URL2', response.data['values'])

        # unset a config value
        body = {'values': json.dumps({'NEW_URL2': None})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        config5 = response.data
        self.assertNotEqual(config4['uuid'], config5['uuid'])
        self.assertNotIn('NEW_URL2', json.dumps(response.data['values']))

        # unset all config values
        body = {'values': json.dumps({'NEW_URL1': None})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertNotIn('NEW_URL1', json.dumps(response.data['values']))

        # set a port and then unset it to make sure validation ignores the unset
        body = {'values': json.dumps({'PORT': '5000'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertIn('PORT', response.data['values'])

        body = {'values': json.dumps({'PORT': None})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertNotIn('PORT', response.data['values'])

        # disallow put/patch/delete
        response = self.client.put(url)
        self.assertEqual(response.status_code, 405, response.data)
        response = self.client.patch(url)
        self.assertEqual(response.status_code, 405, response.data)
        response = self.client.delete(url)
        self.assertEqual(response.status_code, 405, response.data)
        return config5

    def test_response_data(self, mock_requests):
        """Test that the serialized response contains only relevant data."""
        app_id = self.create_app()

        url = f"/v2/apps/{app_id}/config"

        # set an initial config value
        body = {'values': json.dumps({'PORT': '5000'})}
        response = self.client.post(url, body)
        for key in response.data:
            self.assertIn(key, ['uuid', 'owner', 'created', 'updated', 'app', 'values',
                                'typed_values', 'limits', 'tags', 'registry', 'healthcheck',
                                'lifecycle_post_start', 'lifecycle_pre_stop',
                                'termination_grace_period'])
        expected = {
            'owner': self.user.username,
            'app': app_id,
            'values': {'PORT': '5000'},
            'limits': {
                PROCFILE_TYPE_RUN: 'std1.large.c1m1',
                PROCFILE_TYPE_WEB: 'std1.large.c1m1'
            },
            'tags': {},
            'registry': {}
        }
        self.assertEqual(response.data, response.data | expected)

    def test_response_data_types_converted(self, mock_requests):
        """Test that config data is converted into the correct type."""
        app_id = self.create_app()

        url = f"/v2/apps/{app_id}/config"

        body = {
            'values': json.dumps({'PORT': 5000}),
            'limits': {
                PROCFILE_TYPE_WEB: 'std1.large.c1m2',
            }
        }
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        for key in response.data:
            self.assertIn(key, ['uuid', 'owner', 'created', 'updated', 'app', 'values', 'limits',
                                'typed_values', 'tags', 'registry', 'healthcheck',
                                'lifecycle_post_start', 'lifecycle_pre_stop',
                                'termination_grace_period'])
        expected = {
            'owner': self.user.username,
            'app': app_id,
            'values': {'PORT': '5000'},
            'limits': {
                PROCFILE_TYPE_RUN: 'std1.large.c1m1',
                PROCFILE_TYPE_WEB: 'std1.large.c1m2'
            },
            'tags': {},
            'registry': {}
        }
        self.assertEqual(response.data, expected | response.data)

        body = {'limits': {PROCFILE_TYPE_WEB: "not-exist"}}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 400, response.data)
        self.assertEqual(
            str(response.data["limits"][0]),
            CONFIG_LIMITS_MISMATCH_MSG.format("not-exist")
        )

    def test_config_set_same_key(self, mock_requests):
        """
        Test that config sets on the same key function properly
        """
        app_id = self.create_app()
        url = f"/v2/apps/{app_id}/config"

        # set an initial config value
        body = {'values': json.dumps({'PORT': '5000'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertIn('PORT', response.data['values'])

        # reset same config value
        body = {'values': json.dumps({'PORT': '5001'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertIn('PORT', response.data['values'])
        self.assertEqual(response.data['values']['PORT'], '5001')

    def test_config_set_unicode(self, mock_requests):
        """
        Test that config sets with unicode values are accepted.
        """
        app_id = self.create_app()
        url = f"/v2/apps/{app_id}/config"

        # set an initial config value
        body = {'values': json.dumps({'POWERED_BY': 'Деис'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertIn('POWERED_BY', response.data['values'])
        # reset same config value
        body = {'values': json.dumps({'POWERED_BY': 'Кроликов'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertIn('POWERED_BY', response.data['values'])
        self.assertEqual(response.data['values']['POWERED_BY'], 'Кроликов')

        # set an integer to test unicode regression
        body = {'values': json.dumps({'INTEGER': 1})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertIn('INTEGER', response.data['values'])
        self.assertEqual(response.data['values']['INTEGER'], '1')

    def test_config_str(self, mock_requests):
        """Test the text representation of a node."""
        config5 = self.test_config()
        config = Config.objects.get(uuid=config5['uuid'])
        self.assertEqual(str(config), "{}-{}".format(config5['app'], str(config5['uuid'])[:7]))

    def test_valid_config_keys(self, mock_requests):
        """Test that valid config keys are accepted.
        """
        keys = ("FOO", "_foo", "f001", "FOO_BAR_BAZ_")
        app_id = self.create_app()
        url = f'/v2/apps/{app_id}/config'
        for k in keys:
            body = {'values': json.dumps({k: "testvalue"})}
            response = self.client.post(url, body)
            self.assertEqual(response.status_code, 201)
            self.assertIn(k, response.data['values'])

    def test_config_deploy_failure(self, mock_requests):
        """
        Cause an Exception in app.deploy to cause a release.delete
        """
        app_id = self.create_app()

        # deploy app to get a build
        url = "/v2/apps/{}/builds".format(app_id)
        body = {'image': 'autotest/example', 'stack': 'container'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data['image'], body['image'])

        with mock.patch('api.models.app.App.deploy') as mock_deploy:
            mock_deploy.side_effect = Exception('Boom!')
            url = f'/v2/apps/{app_id}/config'
            body = {'values': json.dumps({'test': "testvalue"})}
            response = self.client.post(url, body)
            self.assertEqual(response.status_code, 201)
            app = App.objects.get(id=app_id)
            release = app.release_set.latest()
            self.assertEqual(release.failed, True)
            self.assertEqual(release.exception, "error: Boom!")

    def test_invalid_config_keys(self, mock_requests):
        """Test that invalid config keys are rejected.
        """
        keys = ("$123", "../../foo", "FOO/", "*FOO-BAR")
        app_id = self.create_app()
        url = f'/v2/apps/{app_id}/config'
        for k in keys:
            body = {'values': json.dumps({k: "testvalue"})}
            response = self.client.post(url, body)
            self.assertEqual(response.status_code, 400)

    def test_invalid_config_values(self, mock_requests):
        """
        Test that invalid config values are rejected.
        Right now only PORT is checked
        """
        data = [
            {'field': 'PORT', 'value': 'dog'},
            {'field': 'PORT', 'value': 99999}
        ]
        app_id = self.create_app()
        url = f'/v2/apps/{app_id}/config'
        for row in data:
            body = {'values': json.dumps({row['field']: row['value']})}
            response = self.client.post(url, body)
            self.assertEqual(response.status_code, 400, response.data)

    def test_admin_can_create_config_on_other_apps(self, mock_requests):
        """If a non-admin creates an app, an administrator should be able to set config
        values for that app.
        """
        user = User.objects.get(username='autotest2')
        token = self.get_or_create_token(user)

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token)
        app_id = self.create_app()
        url = f"/v2/apps/{app_id}/config"

        # set an initial config value
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)
        body = {'values': json.dumps({'PORT': '5000'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertIn('PORT', response.data['values'])
        return response

    def test_config_owner_is_requesting_user(self, mock_requests):
        """
        Ensure that setting the config value is owned by the requesting user
        See https://github.com/drycc/drycc/issues/2650
        """
        response = self.test_admin_can_create_config_on_other_apps()
        self.assertEqual(response.data['owner'], self.user.username)

    def test_unauthorized_user_cannot_modify_config(self, mock_requests):
        """
        An unauthorized user should not be able to modify other config.

        Since an unauthorized user can't access the application, these
        requests should return a 403.
        """
        app_id = self.create_app()

        unauthorized_user = User.objects.get(username='autotest2')
        unauthorized_token = self.get_or_create_token(unauthorized_user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + unauthorized_token)
        url = '/v2/apps/{}/config'.format(app_id)
        body = {'values': {'FOO': 'bar'}}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 403)

    def test_config_app_not_exists(self, mock_requests):
        url = '/v2/apps/{}/config'.format('fake')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.data, 'No App matches the given query.')

    def test_config_failures(self, mock_requests):
        app_id = self.create_app()
        app = App.objects.get(id=app_id)

        # deploy app to get a build
        url = "/v2/apps/{}/builds".format(app_id)
        body = {'image': 'autotest/example', 'stack': 'container'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data['image'], body['image'])

        # set an initial config value
        url = f"/v2/apps/{app_id}/config"
        body = {'values': json.dumps({'NEW_URL1': 'http://localhost:8080/'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertIn('NEW_URL1', response.data['values'])
        success_config = app.release_set.latest().config

        # create a failed config to check that failed release is created
        with mock.patch('api.models.app.App.deploy') as mock_deploy:
            mock_deploy.side_effect = Exception('Boom!')
            url = f'/v2/apps/{app_id}/config'
            body = {'values': json.dumps({'test': "testvalue"})}
            response = self.client.post(url, body)
            self.assertEqual(response.status_code, 201)
            self.assertEqual(app.release_set.latest().version, 4)
            self.assertEqual(app.release_set.latest().failed, True)
            self.assertEqual(app.release_set.latest().exception, "error: Boom!")
            self.assertEqual(app.release_set.filter(failed=False).latest().version, 3)

        # create a build to see that the new release is created with the last successful config
        url = "/v2/apps/{}/builds".format(app_id)
        body = {'image': 'autotest/example', 'stack': 'container'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(app.release_set.latest().version, 5)
        self.assertEqual(app.release_set.latest().config, success_config)
        self.assertEqual(app.config_set.count(), 3)

    def test_unset_limits(self, mock_requests):
        app_id = self.create_app()
        url = f"/v2/apps/{app_id}/config"
        body = {
            'values': json.dumps({'PORT': 5000}),
            'limits': {
                "task": 'std1.large.c2m4',
                PROCFILE_TYPE_RUN: 'std1.large.c2m4',
                PROCFILE_TYPE_WEB: 'std1.large.c2m4',
            },
        }
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["limits"], body["limits"])
        # unset ok
        body = {
            'limits': {
                  "task": None,
            },
        }
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201)
        response = self.client.get(url)
        self.assertEqual(
            response.data["limits"],
            {PROCFILE_TYPE_RUN: 'std1.large.c2m4', PROCFILE_TYPE_WEB: 'std1.large.c2m4'},
        )

    def test_unset_limits_error(self, mock_requests):
        app_id = self.create_app()
        url = f"/v2/apps/{app_id}/config"
        body = {
            'values': json.dumps({'PORT': 5000}),
            'limits': {
                "task": 'std1.large.c2m4',
                PROCFILE_TYPE_RUN: 'std1.large.c2m4',
                PROCFILE_TYPE_WEB: 'std1.large.c2m4',
            },
        }
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201)
        # dockerfile + procfile worflow
        app = App.objects.get(id=app_id)
        user = User.objects.get(username='autotest')
        build = Build.objects.create(
            owner=user,
            app=app,
            image="qwerty",
            procfile={
                'web': 'node server.js',
                'worker': 'node worker.js'
            },
            dockerfile='foo',
            sha='somereallylongsha'
        )
        # create an initial release
        release = Release.objects.create(
            version=3,
            owner=user,
            app=app,
            config=app.config_set.latest(),
            build=build
        )
        # deploy
        app.pipeline(release)
        # unset error
        body = {
            'limits': {
                  "no-exists": None,
            },
        }
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 422)
        self.assertEqual(str(response.data["detail"]), "no-exists does not exist under limits")
        # scale up
        body = {'web': 3}
        response = self.client.post(f"/v2/apps/{app_id}/ptypes/scale", body)
        self.assertEqual(response.status_code, 204, response.data)

        body = {
            'limits': {
                  PROCFILE_TYPE_WEB: None,
            },
        }
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 422)
        self.assertEqual(
            str(response.data["detail"]), "the web has already been used and cannot be deleted")

    def call_command(self, *args, **kwargs):
        out = StringIO()
        call_command(
            "measure_apps",
            *args,
            stdout=out,
            stderr=StringIO(),
            **kwargs,
        )
        return out.getvalue()

    def test_measure_config(self, *args, **kwargs):
        # create
        app_id = self.create_app()
        url = f"/v2/apps/{app_id}/config"
        body = {
            'values': json.dumps({'PORT': 5000}),
            'limits': {
                  PROCFILE_TYPE_RUN: 'std1.large.c2m4',
                  PROCFILE_TYPE_WEB: 'std1.large.c2m4',
            },
        }
        response = self.client.post(url, body)
        out = self.call_command()
        self.assertIn(out, "done\n")
        self.assertEqual(response.status_code, 201)

    def test_set_config_limits_run(self, *args, **kwargs):
        # create
        app_id = self.create_app()
        # dockerfile + procfile worflow
        app = App.objects.get(id=app_id)
        user = User.objects.get(username='autotest')
        build = Build.objects.create(
            owner=user,
            app=app,
            image="qwerty",
            procfile={
                'web': 'node server.js',
                'worker': 'node worker.js'
            },
            dockerfile='foo',
            sha='somereallylongsha'
        )
        # create an initial release
        release = Release.objects.create(
            version=3,
            owner=user,
            app=app,
            config=app.config_set.latest(),
            build=build
        )
        # deploy
        app.pipeline(release)
        body = {
            'values': json.dumps({'PORT': 5000}),
            'limits': {
                  PROCFILE_TYPE_RUN: 'std1.large.c2m4',
                  PROCFILE_TYPE_WEB: 'std1.large.c2m4',
            },
        }
        url = f"/v2/apps/{app_id}/config"
        response = self.client.post(url, body)
        url = f"/v2/apps/{app_id}/config"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        expect = {'run': 'std1.large.c2m4', 'web': 'std1.large.c2m4', 'worker': 'std1.large.c1m1'}
        self.assertEqual(expect, response.json()["limits"], response.data)

    def test_config_set_typed_values(self, mock_requests):
        """
        Test that config sets on the same key function properly
        """
        app_id = self.create_app()
        url = f"/v2/apps/{app_id}/config"

        # set an initial config value
        body = {'typed_values': {'web': {'PORT': '5000'}}}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertIn('PORT', response.data['typed_values']['web'])

        # reset same config value
        body = {'typed_values': {'web': {'PORT': '5001'}}}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertIn('PORT', response.data['typed_values']['web'])
        self.assertEqual(response.data['typed_values']['web']['PORT'], '5001')
        # unset PORT
        body = {'typed_values': {'web': {'PORT': None}}}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data['typed_values']['web'], {}, response.data)
        # unset web
        body = {'typed_values': {'web': None}}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data['typed_values'], {}, response.data)
