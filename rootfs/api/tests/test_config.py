# -*- coding: utf-8 -*-
"""
Unit tests for the Drycc api app.

Run the tests with "./manage.py test api"
"""
from io import StringIO
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.management import call_command

from unittest import mock

from api.models.app import App
from api.models.base import PTYPE_RUN, PTYPE_WEB
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
        self.assertEqual(response.data['values'], [])
        config1 = response.data

        # set an initial config value
        value1 = {"name": "NEW_URL1", "value": "http://localhost:8080/", "group": "global"}
        body = {'values': [value1]}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        config2 = response.data
        self.assertNotEqual(config1['uuid'], config2['uuid'])
        self.assertEqual(body['values'], response.data['values'])

        # read the config
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        config3 = response.data
        self.assertEqual(config2, config3)
        self.assertEqual(body['values'], response.data['values'])

        # set an additional config value
        value2 = {"name": "NEW_URL2", "value": "http://localhost:8080/", "group": "global"}
        body = {'values': [value2]}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        config3 = response.data
        self.assertNotEqual(config2['uuid'], config3['uuid'])
        self.assertEqual([value1, value2], response.data['values'])

        # read the config again
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        config4 = response.data
        self.assertEqual(config3, config4)
        self.assertEqual([value1, value2], response.data['values'])

        # unset a config value
        value2['value'] = None
        body = {'values': [value2]}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        config5 = response.data
        self.assertNotEqual(config4['uuid'], config5['uuid'])
        self.assertEqual([value1], response.data['values'])

        # unset all config values
        value1['value'] = None
        body = {'values': [value1]}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual([], response.data['values'])

        # set a port and then unset it to make sure validation ignores the unset
        value3 = {"name": "PORT", "value": "5000", "group": "global"}
        body = {'values': [value3]}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual([value3], response.data['values'])

        value3['value'] = None
        body = {'values': [value3]}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual([], response.data['values'])

        # disallow put/patch
        response = self.client.put(url)
        self.assertEqual(response.status_code, 405, response.data)
        response = self.client.patch(url)
        self.assertEqual(response.status_code, 405, response.data)
        return config5

    def test_registry_set(self, mock_requests):
        app_id = self.create_app()
        # set an initial config value
        url = f"/v2/apps/{app_id}/config"
        web_registry = {'web': {'username': 'admin', 'password': 'admin'}}
        body = {'registry': web_registry}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)

        url = '/v2/apps/{}/config'.format(app_id)
        response = self.client.get(url)
        self.assertEqual(response.data['registry'], web_registry, response.data)

        task_registry = {'task': {'username': 'admin', 'password': 'admin'}}
        body = {'registry': task_registry}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)

        url = '/v2/apps/{}/config'.format(app_id)
        response = self.client.get(url)
        all_registry = {}
        all_registry.update(web_registry)
        all_registry.update(task_registry)
        self.assertEqual(response.data['registry'], all_registry, response.data)

        # delete task username
        task_registry = {'task': {'username': None, 'password': 'admin'}}
        body = {'registry': task_registry}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        url = '/v2/apps/{}/config'.format(app_id)
        response = self.client.get(url)
        all_registry = {}
        all_registry.update(web_registry)
        all_registry.update(task_registry)
        del all_registry['task']['username']
        self.assertEqual(response.data['registry'], all_registry, response.data)

        # delete task registry
        task_registry = {'task': None}
        body = {'registry': task_registry}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        url = '/v2/apps/{}/config'.format(app_id)
        response = self.client.get(url)
        self.assertEqual(response.data['registry'], web_registry, response.data)

    def test_values_refs(self, mock_requests):
        app_id = self.create_app()
        url = f"/v2/apps/{app_id}/config"
        values = [{"name": "DEBUG", "value": "true", "group": "global"}]
        body = {'values': values}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        uuid = response.data["uuid"]
        config = Config.objects.get(uuid=uuid)
        self.assertEqual(config.envs("web"), {'DEBUG': 'true'})
        self.assertEqual(config.envs("task"), {'DEBUG': 'true'})

        # add test error, changed nothing
        values = [
            {"name": "DEBUG", "value": "true", "group": "global"},
        ]
        body = {'values': values}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 409, response.data)

        # add values ok
        values = [
            {"name": "DEBUG", "value": "true", "group": "mytask1"},
            {"name": "APP", "value": "task2", "group": "mytask2"},
            {"name": "DEBUG", "value": "false", "group": "global"},
        ]
        body = {'values': values}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        uuid = response.data["uuid"]
        config = Config.objects.get(uuid=uuid)
        self.assertEqual(config.envs("web"), {'DEBUG': 'false'})
        self.assertEqual(config.envs("task"), {'DEBUG': 'false'})

        # add values_refs
        body = {'values_refs': {"task": ["mytask1", "mytask2"]}}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        uuid = response.data["uuid"]
        config = Config.objects.get(uuid=uuid)
        self.assertEqual(config.envs("web"), {'DEBUG': 'false'})
        self.assertEqual(config.envs("task"), {'DEBUG': 'true', 'APP': 'task2'})

        # add new item for mytask
        values = [
            {"name": "VERSION", "value": "1.0.1", "group": "mytask1"},
        ]
        body = {'values': values}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        uuid = response.data["uuid"]
        config = Config.objects.get(uuid=uuid)
        self.assertEqual(config.envs("web"), {'DEBUG': 'false'})
        self.assertEqual(
            config.envs("task"), {'DEBUG': 'true', 'VERSION': '1.0.1', 'APP': 'task2'})

        # remove tas values_refs
        body = {'values_refs': {'task': ['mytask1']}}
        response = self.client.delete(url, body)
        self.assertEqual(response.status_code, 200, response.data)
        url = '/v2/apps/{}/config'.format(app_id)
        response = self.client.get(url)
        self.assertEqual(response.data['values_refs'], {"task": ["mytask2"]}, response.data)

    def test_response_data(self, mock_requests):
        """Test that the serialized response contains only relevant data."""
        app_id = self.create_app()

        url = f"/v2/apps/{app_id}/config"

        # set an initial config value
        value1 = {"name": "PORT", "value": "5000", "group": "global"}
        body = {'values': [value1]}
        response = self.client.post(url, body)
        for key in response.data:
            self.assertIn(key, ['uuid', 'owner', 'created', 'updated', 'app', 'values',
                                'values_refs', 'limits', 'tags', 'registry', 'healthcheck',
                                'lifecycle_post_start', 'lifecycle_pre_stop',
                                'termination_grace_period'])
        expected = {
            'owner': self.user.username,
            'app': app_id,
            'values': [value1],
            'limits': {
                PTYPE_RUN: 'std1.large.c1m1',
                PTYPE_WEB: 'std1.large.c1m1'
            },
            'tags': {},
            'registry': {}
        }
        self.assertEqual(response.data, response.data | expected)

    def test_response_data_types_converted(self, mock_requests):
        """Test that config data is converted into the correct type."""
        app_id = self.create_app()

        url = f"/v2/apps/{app_id}/config"
        value1 = {"name": "PORT", "value": "5000", "group": "global"}
        body = {
            'values': [value1],
            'limits': {
                PTYPE_WEB: 'std1.large.c1m2',
            }
        }
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        for key in response.data:
            self.assertIn(key, ['uuid', 'owner', 'created', 'updated', 'app', 'values', 'limits',
                                'values_refs', 'tags', 'registry', 'healthcheck',
                                'lifecycle_post_start', 'lifecycle_pre_stop',
                                'termination_grace_period'])
        expected = {
            'owner': self.user.username,
            'app': app_id,
            'values': [value1],
            'limits': {
                PTYPE_RUN: 'std1.large.c1m1',
                PTYPE_WEB: 'std1.large.c1m2'
            },
            'tags': {},
            'registry': {}
        }
        self.assertEqual(response.data, expected | response.data)

        body = {'limits': {PTYPE_WEB: "not-exist"}}
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
        value1 = {"name": "PORT", "value": "5000", "group": "global"}
        body = {'values': [value1]}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual([value1], response.data['values'])

        # reset same config value
        value1['value'] = '5001'
        body = {'values': [value1]}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual([value1], response.data['values'])

    def test_config_set_unicode(self, mock_requests):
        """
        Test that config sets with unicode values are accepted.
        """
        app_id = self.create_app()
        url = f"/v2/apps/{app_id}/config"

        # set an initial config value
        value1 = {"name": "POWERED_BY", "value": "Деис", "group": "global"}
        body = {'values': [value1]}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual([value1], response.data['values'])
        # reset same config value
        value1['value'] = 'Кроликов'
        body = {'values': [value1]}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual([value1], response.data['values'])

        # set an integer to test unicode regression
        value2 = {"name": "INTEGER", "value": "1", "group": "global"}
        body = {'values': [value2]}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual([value1, value2], response.data['values'])

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
        values = []
        for k in keys:
            value1 = {"name": k, "value": "testvalue", "group": "global"}
            values.append(value1)
            body = {'values': [value1]}
            response = self.client.post(url, body)
            self.assertEqual(response.status_code, 201)
            self.assertEqual(values, response.data['values'])

    def test_config_deploy_failure(self, mock_requests):
        """
        Cause an Exception in app.deploy to cause a release.delete
        """
        app_id = self.create_app()

        # deploy app to get a build
        url = "/v2/apps/{}/build".format(app_id)
        body = {'image': 'autotest/example', 'stack': 'container'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data['image'], body['image'])

        with mock.patch('api.models.app.App.deploy') as mock_deploy:
            mock_deploy.side_effect = Exception('Boom!')
            url = f'/v2/apps/{app_id}/config'
            value1 = {"name": "test", "value": "testvalue", "group": "global"}
            body = {'values': [value1]}
            response = self.client.post(url, body)
            self.assertEqual(response.status_code, 201)
            app = App.objects.get(id=app_id)
            release = app.release_set.latest()
            self.assertEqual(release.failed, True)
            self.assertEqual(release.conditions[0]['exception'], "Boom!")

    def test_invalid_config_keys(self, mock_requests):
        """Test that invalid config keys are rejected.
        """
        keys = ("$123", "../../foo", "FOO/", "*FOO-BAR")
        app_id = self.create_app()
        url = f'/v2/apps/{app_id}/config'
        for k in keys:
            value1 = {"name": k, "value": "testvalue", "group": "global"}
            body = {'values': [value1]}
            response = self.client.post(url, body)
            self.assertEqual(response.status_code, 400)

    def test_invalid_config_values(self, mock_requests):
        """
        Test that invalid config values are rejected.
        Right now only PORT is checked
        """
        data = [
            {"name": "PORT", "value": "dog", "group": "global"},
            {"name": "PORT", "value": "99999", "group": "global"}
        ]
        app_id = self.create_app()
        url = f'/v2/apps/{app_id}/config'
        for row in data:
            body = {'values': [row]}
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
        value1 = {"name": "PORT", "value": "5000", "group": "global"}
        body = {'values': [value1]}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual([value1], response.data['values'])
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
        value1 = {"name": "FOO", "value": "bar", "group": "global"}
        body = {'values': [value1]}
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
        url = "/v2/apps/{}/build".format(app_id)
        body = {'image': 'autotest/example', 'stack': 'container'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data['image'], body['image'])

        # set an initial config value
        url = f"/v2/apps/{app_id}/config"
        value1 = {"name": "NEW_URL1", "value": "http://localhost:8080/", "group": "global"}
        body = {'values': [value1]}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual([value1], response.data['values'])
        success_config = app.release_set.latest().config

        # create a failed config to check that failed release is created
        with mock.patch('api.models.app.App.deploy') as mock_deploy:
            mock_deploy.side_effect = Exception('Boom!')
            url = f'/v2/apps/{app_id}/config'
            value1 = {"name": "test", "value": "testvalue", "group": "global"}
            body = {'values': [value1]}
            response = self.client.post(url, body)
            self.assertEqual(response.status_code, 201)
            self.assertEqual(app.release_set.latest().version, 4)
            self.assertEqual(app.release_set.latest().failed, True)
            self.assertEqual(app.release_set.latest().conditions[0]['exception'], "Boom!")
            self.assertEqual(app.release_set.filter(failed=False).latest().version, 3)

        # create a build to see that the new release is created with the last successful config
        url = "/v2/apps/{}/build".format(app_id)
        body = {'image': 'autotest/example', 'stack': 'container'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(app.release_set.latest().version, 5)
        self.assertEqual(app.release_set.latest().config, success_config)
        self.assertEqual(app.config_set.count(), 3)

    def test_unset_limits(self, mock_requests):
        app_id = self.create_app()
        url = f"/v2/apps/{app_id}/config"
        value1 = {"name": "PORT", "value": "5000", "group": "global"}
        body = {
            'values': [value1],
            'limits': {
                "task": 'std1.large.c2m4',
                PTYPE_RUN: 'std1.large.c2m4',
                PTYPE_WEB: 'std1.large.c2m4',
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
            {PTYPE_RUN: 'std1.large.c2m4', PTYPE_WEB: 'std1.large.c2m4'},
        )

    def test_unset_limits_error(self, mock_requests):
        app_id = self.create_app()
        url = f"/v2/apps/{app_id}/config"
        value1 = {"name": "PORT", "value": "5000", "group": "global"}
        body = {
            'values': [value1],
            'limits': {
                "task": 'std1.large.c2m4',
                PTYPE_RUN: 'std1.large.c2m4',
                PTYPE_WEB: 'std1.large.c2m4',
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
        release.deploy()
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
                  PTYPE_WEB: None,
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
        value1 = {"name": "PORT", "value": "5000", "group": "global"}
        body = {
            'values': [value1],
            'limits': {
                  PTYPE_RUN: 'std1.large.c2m4',
                  PTYPE_WEB: 'std1.large.c2m4',
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
        release.deploy()
        value1 = {"name": "PORT", "value": "5000", "group": "global"}
        body = {
            'values': [value1],
            'limits': {
                  PTYPE_RUN: 'std1.large.c2m4',
                  PTYPE_WEB: 'std1.large.c2m4',
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
        body = {'values': [{"name": "PORT", "value": "5000", "ptype": "web"}]}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertIn({"name": "PORT", "value": "5000", "ptype": "web"}, response.data['values'])

        # reset same config value
        body = {'values': [{"name": "PORT", "value": "5001", "ptype": "web"}]}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertIn({"name": "PORT", "value": "5001", "ptype": "web"}, response.data['values'])
        # unset PORT
        body = {'values': [{"name": "PORT", "value": None, "ptype": "web"}]}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data['values'], [], response.data)

    def test_config_version(self, mock_requests):
        """
        Test that config sets on the same key function properly
        """
        app_id = self.create_app()
        url = f"/v2/apps/{app_id}/config"

        # set an initial config value
        value1 = {"name": "PORT", "value": "5000", "group": "global"}
        body = {'values': [value1]}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual([value1], response.data['values'])
        url = f"/v2/apps/{app_id}/config"

        # set config NAME
        value2 = {"name": "NAME", "value": "drycc", "group": "global"}
        body = {'values': [value2]}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual([value1, value2], response.data['values'])

        # set config WEBSITE
        value3 = {"name": "WEBSITE", "value": "www.drycc.cc", "group": "global"}
        body = {'values': [value3]}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual([value1, value2, value3], response.data['values'])

        url = f"/v2/apps/{app_id}/config/?version=v2"
        response = self.client.get(url)
        self.assertEqual(response.data['values'], [value1], response.data)

        url = f"/v2/apps/{app_id}/config/?version=v3"
        response = self.client.get(url)
        self.assertEqual(
            response.data['values'], [value1, value2], response.data)

        url = f"/v2/apps/{app_id}/config/?version=v4"
        response = self.client.get(url)
        self.assertEqual(
            response.data['values'],
            [value1, value2, value3], response.data)

    def test_diff_ptypes(self, mock_requests):
        app_id = self.create_app()
        value1 = {"name": "WEBSITE", "value": "www.drycc.cc", "group": "global"}
        body = {'values': [value1]}
        url = f"/v2/apps/{app_id}/config"
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        uuid = response.data["uuid"]
        config = Config.objects.get(uuid=uuid)
        old_config = config.previous()
        self.assertEqual(config.diff_ptypes(old_config, ["web", "task"]), {"web", "task"})

        # add value
        value1 = {"name": "DEBUG", "value": "true", "group": "mygroup"}
        body = {'values': [value1]}
        url = f"/v2/apps/{app_id}/config"
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        uuid = response.data["uuid"]
        config = Config.objects.get(uuid=uuid)
        old_config = config.previous()
        self.assertEqual(config.diff_ptypes(old_config, ["web", "task"]), set())

        # add group ref
        body = {'values_refs': {"task": ["mygroup"]}}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        uuid = response.data["uuid"]
        config = Config.objects.get(uuid=uuid)
        old_config = config.previous()
        self.assertEqual(config.diff_ptypes(old_config, ["web", "task"]), {"task"})
        # add new group
        value1 = {"name": "DEBUG", "value": "true", "group": "mygroup1"}
        body = {'values': [value1]}
        url = f"/v2/apps/{app_id}/config"
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)

        body = {'values_refs': {"task": ["mygroup1"]}}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        uuid = response.data["uuid"]
        config = Config.objects.get(uuid=uuid)
        old_config = config.previous()
        self.assertEqual(config.diff_ptypes(old_config, ["web", "task"]), {"task"})
        self.assertEqual(config.envs("task"), {'WEBSITE': 'www.drycc.cc', 'DEBUG': 'true'})

    def test_config_from_dryccfile(self, mock_requests):
        app_id = self.create_app()
        app = App.objects.get(id=app_id)
        build_body = {
            'image': 'autotest/example',
            'stack': 'heroku-18',
            'sha': 'a'*40,
            'dryccfile': {
                "build": {
                    "docker": {"web": "Dockerfile", "worker": "worker/Dockerfile"},
                    "config": {"RAILS_ENV": "development", "FOO": "bar"}
                },
                'deploy': {
                    'web': {
                        'image': "127.0.0.1/cat/cat"
                    }
                }
            },
        }
        with mock.patch('scheduler.resources.pod.Pod.watch') as mock_kube:
            mock_kube.return_value = ['up', 'down']
            url = f"/v2/apps/{app_id}/build"
            response = self.client.post(url, build_body)
            self.assertEqual(response.status_code, 201, response.data)
        value1 = {"name": "WEBSITE", "value": "www.drycc.cc", "group": "global"}
        body = {'values': [value1]}
        url = f"/v2/apps/{app_id}/config"
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        release = app.release_set.latest()
        self.assertEqual(release.failed, False)
        self.assertEqual(release.config.envs("web"), {"WEBSITE": "www.drycc.cc"})
        # set env by dryccfile
        build_body['dryccfile']['config'] = {
            "mygroup1": [
                {"name": "GROUP", "value": "g1"},
                {"name": "DEBUG", "value": "tr"},
            ],
            "mygroup2": [
                {"name": "TEST1", "value": "g1"},
                {"name": "TEST2", "value": "tr"},
            ],
        }
        build_body['dryccfile']['deploy']['web']['config'] = {
            'env': [
                {'name': "PENV1", 'value': 'web'},
                {'name': "PENV2", 'value': 'web'},
            ],
            'ref': ['mygroup1', 'mygroup2']
        }
        with mock.patch('scheduler.resources.pod.Pod.watch') as mock_kube:
            mock_kube.return_value = ['up', 'down']
            url = f"/v2/apps/{app_id}/build"
            response = self.client.post(url, build_body)
            self.assertEqual(response.status_code, 201, response.data)

        release = app.release_set.latest()
        self.assertEqual(release.failed, False)
        self.assertEqual(
            release.config.envs("web"),
            {
                'GROUP': 'g1', 'DEBUG': 'tr', 'TEST1': 'g1', 'TEST2': 'tr', 'PENV1': 'web',
                'PENV2': 'web'
            }
        )
        build_body['dryccfile']['deploy']['web']['healthcheck'] = {
            'livenessProbe': {
                'httpGet': {
                    'path': '/healthz',
                    'port': 8080,
                },
                'initialDelaySeconds': 3,
                'periodSeconds': 3,
            }
        }
        with mock.patch('scheduler.resources.pod.Pod.watch') as mock_kube:
            mock_kube.return_value = ['up', 'down']
            url = f"/v2/apps/{app_id}/build"
            response = self.client.post(url, build_body)
            self.assertEqual(response.status_code, 201, response.data)

        release = app.release_set.latest()
        self.assertEqual(release.failed, False)
        self.assertEqual(
            release.config.healthcheck['web'],
            build_body['dryccfile']['deploy']['web']['healthcheck'],
        )
