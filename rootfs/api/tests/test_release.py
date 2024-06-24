import hashlib
import hmac
import json
import logging
import requests
import uuid

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test.utils import override_settings
from unittest import mock

from api.models.app import App
from api.models.base import PROCFILE_TYPE_WEB
from api.models.build import Build
from api.models.release import Release
from scheduler import KubeHTTPException
from api.tests import adapter, DryccTransactionTestCase
import requests_mock

User = get_user_model()


@requests_mock.Mocker(real_http=True, adapter=adapter)
class ReleaseTest(DryccTransactionTestCase):

    """Tests push notification from build system"""

    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = self.get_or_create_token(self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

    def tearDown(self):
        # make sure every test has a clean slate for k8s mocking
        cache.clear()

    def test_release(self, mock_requests):
        """
        Test that a release is created when an app is created, and
        that updating config or build or triggers a new release
        """
        app_id = self.create_app()
        # check that updating config rolls a new release
        url = f'/v2/apps/{app_id}/config'
        body = {'values': json.dumps({'NEW_URL1': 'http://localhost:8080/'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertIn('NEW_URL1', response.data['values'])
        # check to see that an initial release was created
        url = f'/v2/apps/{app_id}/releases'
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        # account for the config release as well
        self.assertEqual(response.data['count'], 2)
        url = f'/v2/apps/{app_id}/releases/v1'
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        release1 = response.data
        self.assertIn('config', response.data)
        self.assertIn('build', response.data)
        self.assertEqual(release1['version'], 1)
        # check to see that a new release was created
        url = f'/v2/apps/{app_id}/releases/v2'
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        release2 = response.data
        self.assertNotEqual(release1['uuid'], release2['uuid'])
        self.assertNotEqual(release1['config'], release2['config'])
        self.assertEqual(release1['build'], release2['build'])
        self.assertEqual(release2['version'], 2)
        # check that updating the build rolls a new release
        url = f'/v2/apps/{app_id}/builds'
        body = {'image': 'autotest/example', 'stack': 'container'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data['image'], body['image'])
        # check to see that a new release was created
        url = f'/v2/apps/{app_id}/releases/v3'
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        release3 = response.data
        self.assertNotEqual(release2['uuid'], release3['uuid'])
        self.assertNotEqual(release2['build'], release3['build'])
        self.assertEqual(release3['version'], 3)
        # check that we can fetch a previous release
        url = f'/v2/apps/{app_id}/releases/v2'
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        release2 = response.data
        self.assertNotEqual(release2['uuid'], release3['uuid'])
        self.assertNotEqual(release2['build'], release3['build'])
        self.assertEqual(release2['version'], 2)
        # disallow post/put/patch/delete
        url = f'/v2/apps/{app_id}/releases'
        response = self.client.post(url)
        self.assertEqual(response.status_code, 405, response.content)
        response = self.client.put(url)
        self.assertEqual(response.status_code, 405, response.content)
        response = self.client.patch(url)
        self.assertEqual(response.status_code, 405, response.content)
        response = self.client.delete(url)
        self.assertEqual(response.status_code, 405, response.content)
        return release3

    def test_get_image(self, mock_requests):
        app_id = self.create_app()
        url = f"/v2/apps/{app_id}/builds"
        body = {
            'image': '127.0.0.1:5555/autotest/example:git-fadf1231',
            'stack': 'heroku-18',
            'sha': 'a'*40,
            'dryccfile': {
                "build": {
                    "docker": {"web": "Dockerfile", "worker": "worker/Dockerfile"},
                    "config": {"RAILS_ENV": "development", "FOO": "bar"}
                },
                "run": {
                    "command": ["./deployment-tasks.sh"],
                    "image": "worker",
                },
                "deploy": {
                    "web": {
                        "command": ["bash", "-c"],
                        "args": ["bundle exec puma -C config/puma.rb"],
                    },
                    "worker": {
                        "command": ["bash", "-c"],
                        "args": ["python myworker.py"],
                    },
                    "worker-1": {
                        "image": "worker"
                    },
                    "worker-2": {},
                    "worker-3": {
                        "command": ["bash", "-c"],
                        "args": ["bundle exec puma -C config/puma.rb"],
                        "image": "web"
                    },
                    "worker-4": {
                        "command": ["bash", "-c"],
                        "args": ["bundle exec puma -C config/puma.rb"],
                        "image": "127.0.0.1:7070/myapp/web:git-123fsa1"
                    }
                }
            }
        }
        default_image = '127.0.0.1:5555/autotest/example:git-fadf1231'
        worker_image = "127.0.0.1:5555/autotest/example:git-fadf1231-worker"
        worker_4_image = "127.0.0.1:7070/myapp/web:git-123fsa1"

        with mock.patch('scheduler.resources.pod.Pod.watch') as mock_kube:
            mock_kube.return_value = ['up', 'down']
            response = self.client.post(url, body)
            self.assertEqual(response.status_code, 201, response.data)
            app = App.objects.get(id=app_id)
            release_obj = app.release_set.filter(version=2)[0]
            self.assertEqual(
                release_obj.get_run_image(),
                worker_image, release_obj.build.dryccfile)
            self.assertEqual(
                release_obj.get_deploy_image("web"),
                default_image, release_obj.build.dryccfile)
            self.assertEqual(
                release_obj.get_deploy_image("worker"),
                worker_image, release_obj.build.dryccfile)
            self.assertEqual(
                release_obj.get_deploy_image("worker-1"),
                worker_image, release_obj.build.dryccfile)
            self.assertEqual(
                release_obj.get_deploy_image("worker-2"),
                default_image, release_obj.build.dryccfile)
            self.assertEqual(
                release_obj.get_deploy_image("worker-3"),
                default_image, release_obj.build.dryccfile)
            self.assertEqual(
                release_obj.get_deploy_image("worker-4"),
                worker_4_image, release_obj.build.dryccfile)

    def test_response_data(self, mock_requests):
        app_id = self.create_app()
        body = {'values': json.dumps({'NEW_URL': 'http://localhost:8080/'})}
        url = '/v2/apps/{}/config'.format(app_id)
        config_response = self.client.post(url, body)
        url = '/v2/apps/{}/releases/v2'.format(app_id)
        response = self.client.get(url)
        for key in response.data.keys():
            self.assertIn(key, ['uuid', 'owner', 'created', 'updated', 'app', 'build', 'config',
                                'summary', 'canary', 'version', 'state', 'failed', 'exception'])
        expected = {
            'owner': self.user.username,
            'app': app_id,
            'build': None,
            'config': uuid.UUID(config_response.data['uuid']),
            'summary': '{} added values NEW_URL'.format(self.user.username),
            'version': 2
        }
        self.assertEqual(response.data, response.data | expected)

    def test_release_rollback(self, mock_requests):
        app_id = self.create_app()
        app = App.objects.get(id=app_id)
        # try to rollback with only 1 release extant, expecting 400
        url = f"/v2/apps/{app_id}/releases/rollback/"
        response = self.client.post(url)
        self.assertEqual(response.status_code, 400, response.data)
        self.assertEqual(response.data, {'detail': 'version cannot be below 0'})
        self.assertEqual(response.get('content-type'), 'application/json')
        # update the build to roll a new release
        url = f'/v2/apps/{app_id}/builds'
        body = {'image': 'autotest/example', 'stack': 'container'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        # update config to roll another release
        url = f'/v2/apps/{app_id}/config'
        body = {'values': json.dumps({'NEW_URL1': 'http://localhost:8080/'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        # create another release with a different build
        url = f'/v2/apps/{app_id}/builds'
        body = {'image': 'autotest/example:canary', 'stack': 'container'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        # rollback and check to see that a 5th release was created
        # with the build and config of release #3
        url = f"/v2/apps/{app_id}/releases/rollback/"
        response = self.client.post(url)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(Release.objects.count(), 5)
        Release.objects.get(app=app, version=1)
        Release.objects.get(app=app, version=2)
        release3 = Release.objects.get(app=app, version=3)
        release4 = Release.objects.get(app=app, version=4)
        release5 = Release.objects.get(app=app, version=5)
        # verify the rollback to v3
        self.assertNotEqual(release5.uuid, release3.uuid)
        self.assertNotEqual(release5.build, release4.build)
        self.assertEqual(release5.build, release3.build)
        self.assertEqual(release5.config.values, release3.config.values)
        # double-check to see that the current build and config is the same as v3
        self.assertEqual(release5.get_deploy_image(PROCFILE_TYPE_WEB), 'autotest/example')
        self.assertEqual(release5.config.values, {'NEW_URL1': 'http://localhost:8080/'})
        # try to rollback to v1 and verify that the rollback failed
        # (v1 is an initial release with no build)
        url = f"/v2/apps/{app_id}/releases/rollback/"
        body = {'version': 1}
        response = self.client.post(url, body)
        self.assertContains(response, 'Cannot roll back to initial release.', status_code=400)
        # roll back to v2 so we can verify config gets rolled back too
        url = f"/v2/apps/{app_id}/releases/rollback/"
        body = {'version': 2}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(Release.objects.count(), 6)
        release6 = Release.objects.get(app=app, version=6)
        self.assertEqual(release6.get_deploy_image(PROCFILE_TYPE_WEB), 'autotest/example')
        self.assertEqual(release6.config.values, {})

    def test_release_str(self, mock_requests):
        """Test the text representation of a release."""
        release3 = self.test_release()
        release = Release.objects.get(uuid=release3['uuid'])
        self.assertEqual(str(release), "{}-v3".format(release3['app']))

    def test_release_summary(self, mock_requests):
        """Test the text summary of a release."""
        release = self.test_release()
        app = App.objects.get(id=release['app'])
        release = app.release_set.latest()
        # check that the release has push and env change messages
        self.assertIn('autotest deployed ', release.summary)
        # add config, confirm that config objects are in the summary
        url = f'/v2/apps/{app.id}/config'
        body = {
            'values': json.dumps({'FOO': 'bar'}),
        }
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(
            'autotest added values FOO',
            app.release_set.latest().summary)

    def test_admin_can_create_release(self, mock_requests):
        """If a non-user creates an app, an admin should be able to create releases."""
        user = User.objects.get(username='autotest2')
        token = self.get_or_create_token(user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token)
        app_id = self.create_app()
        # check that updating config rolls a new release
        url = f'/v2/apps/{app_id}/config'
        body = {'values': json.dumps({'NEW_URL1': 'http://localhost:8080/'})}
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertIn('NEW_URL1', response.data['values'])
        # check to see that an initial release was created
        url = f'/v2/apps/{app_id}/releases'
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        # account for the config release as well
        self.assertEqual(response.data['count'], 2)

    def test_unauthorized_user_cannot_modify_release(self, mock_requests):
        """
        An unauthorized user should not be able to modify other releases.

        Since an unauthorized user should not know about the application at all, these
        requests should return a 404.
        """
        app_id = self.create_app()

        # push a new build
        url = f'/v2/apps/{app_id}/builds'
        body = {'image': 'test', 'stack': 'container'}
        response = self.client.post(url, body)

        # update config to roll a new release
        url = f'/v2/apps/{app_id}/config'
        body = {'values': json.dumps({'NEW_URL1': 'http://localhost:8080/'})}
        response = self.client.post(url, body)
        unauthorized_user = User.objects.get(username='autotest2')
        unauthorized_token = self.get_or_create_token(unauthorized_user)

        # try to rollback
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + unauthorized_token)
        url = f'/v2/apps/{app_id}/releases/rollback/'
        response = self.client.post(url)
        self.assertEqual(response.status_code, 403)

    def test_release_rollback_failure(self, mock_requests):
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

        # update config to roll a new release
        url = '/v2/apps/{}/config'.format(app_id)
        body = {'values': json.dumps({'NEW_URL1': 'http://localhost:8080/'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)

        # app.deploy exception
        with mock.patch('api.models.app.App.deploy') as mock_deploy:
            mock_deploy.side_effect = Exception('Boom!')
            url = "/v2/apps/{}/releases/rollback/".format(app_id)
            body = {'version': 2}
            response = self.client.post(url, body)
            self.assertEqual(response.status_code, 201, response.data)
            data = self.client.get(f"/v2/apps/{app_id}/releases/", body).json()
            self.assertEqual(data["results"][0]["state"], "crashed", data)

        # update config to roll a new release
        url = '/v2/apps/{}/config'.format(app_id)
        body = {'values': json.dumps({'NEW_URL2': 'http://localhost:8080/'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)

        # try to rollback to v4 and verify that the rollback failed
        # (v4 is a failed release)
        url = f"/v2/apps/{app_id}/releases/rollback/"
        body = {'version': 4}
        response = self.client.post(url, body)
        self.assertContains(response, 'Cannot roll back to failed release.', status_code=400)

        # app.deploy exception followed by a KubeHTTPException of 404
        with mock.patch('api.models.app.App.deploy') as mock_deploy:
            mock_deploy.side_effect = Exception('Boom!')
            with mock.patch(
                    'api.models.release.Release._delete_release_in_scheduler') as mock_kube:
                # instead of full request mocking, fake it out in a simple way
                class Response(object):
                    def json(self):
                        return '{}'

                response = Response()
                response.status_code = 404
                response.reason = "Not Found"
                kube_exception = KubeHTTPException(response, 'big boom')
                mock_kube.side_effect = kube_exception

                url = "/v2/apps/{}/releases/rollback/".format(app_id)
                body = {'version': 2}
                response = self.client.post(url, body)
                self.assertEqual(response.status_code, 201, response.data)
                data = self.client.get(f"/v2/apps/{app_id}/releases/", body).json()
                self.assertEqual(data["results"][0]["state"], "crashed", data)

    def test_release_unset_config(self, mock_requests):
        """
        Test that a release is created when an app is created, a config can be
        set and then unset without causing a 409 (conflict)
        """
        app_id = self.create_app()

        # check that updating config rolls a new release
        url = f'/v2/apps/{app_id}/config'
        body = {'limits': json.dumps({'cmd': None})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 422, response.data)

    def test_release_no_change(self, mock_requests):
        """
        Test that a release is created when an app is created, and
        then has 2 identical config set, causing a 409 as there was
        no change
        """
        app_id = self.create_app()

        # check that updating config rolls a new release
        url = f'/v2/apps/{app_id}/config'
        body = {'values': json.dumps({'NEW_URL1': 'http://localhost:8080/'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertIn('NEW_URL1', response.data['values'])

        # trigger identical release
        url = f'/v2/apps/{app_id}/config'
        body = {'values': json.dumps({'NEW_URL1': 'http://localhost:8080/'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 409, response.data)

    def test_release_get_port(self, mock_requests):
        """
        Test that get_port always returns the proper value.
        """
        app_id = self.create_app()
        app = App.objects.get(id=app_id)

        url = f'/v2/apps/{app_id}/builds'
        body = {'sha': '123456', 'image': 'autotest/example', 'stack': 'heroku-18'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        release = app.release_set.latest()

        # when app is not routable, then it still return 5000
        self.assertEqual(release.get_port('web'), 5000)

        # switch to a dockerfile app or else it'll automatically default to 5000
        url = f'/v2/apps/{app_id}/builds'
        body = {'image': 'autotest/example', 'stack': 'container'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)

        url = f'/v2/apps/{app_id}/config'
        body = {'values': json.dumps({'PORT': '8080'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        release = app.release_set.latest()
        self.assertEqual(release.get_port('web'), 8080)

        url = f'/v2/apps/{app_id}/config'
        body = {'typed_values': json.dumps({"web": {'PORT': '9000'}})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        release = app.release_set.latest()
        self.assertEqual(release.get_port('web'), 9000)

        # not web procfile
        self.assertEqual(release.get_port('task'), 8080)
        url = f'/v2/apps/{app_id}/config'
        body = {'values': json.dumps({'PORT': '9000'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        release = app.release_set.latest()
        self.assertEqual(release.get_port('task'), 9000)
        # set typed_values port
        body = {'typed_values': json.dumps({"task": {'PORT': '9001'}})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        release = app.release_set.latest()
        self.assertEqual(release.get_port('task'), 9001)

    @override_settings(DRYCC_DEPLOY_HOOK_URLS=['http://drycc.rocks'])
    @mock.patch('api.models.release.logger')
    def test_deploy_hooks_logged(self, mock_requests, mock_logger):
        """
        Verifies that a configured deploy hook is dumped into the logs when a release is created.
        """
        app_id = 'foo'
        body = {'sha': '123456', 'image': 'autotest/example', 'stack': 'heroku-18'}

        mr_rocks = mock_requests.post(f'http://drycc.rocks?app={app_id}&user={self.user.username}&sha=&release=v1&release_summary={self.user.username}+created+initial+release')  # noqa
        self.create_app(app_id)
        # check app logs
        exp_msg = f"[{app_id}]: Sent deploy hook to http://drycc.rocks"
        mock_logger.log.assert_any_call(logging.INFO, exp_msg)
        self.assertTrue(mr_rocks.called)
        self.assertEqual(mr_rocks.call_count, 1)

        # override DRYCC_DEPLOY_HOOK_URLS again, ensuring that the new deploy hooks get the same
        # treatment
        url = f'/v2/apps/{app_id}/builds'
        with self.settings(DRYCC_DEPLOY_HOOK_URLS=['http://drycc.ninja', 'http://cat.dog']):
            mr_ninja = mock_requests.post(f"http://drycc.ninja?app={app_id}&user={self.user.username}&sha=123456&release=v2&release_summary={self.user.username}+deployed+123456")  # noqa
            mr_catdog = mock_requests.post(f"http://cat.dog?app={app_id}&user={self.user.username}&sha=123456&release=v2&release_summary={self.user.username}+deployed+123456")  # noqa
            response = self.client.post(url, body)
            self.assertEqual(response.status_code, 201, response.data)

            # check app logs
            exp_msg = f"[{app_id}]: Sent deploy hook to http://drycc.ninja"
            mock_logger.log.assert_any_call(logging.INFO, exp_msg)
            self.assertTrue(mr_ninja.called)
            self.assertEqual(mr_ninja.call_count, 1)
            exp_msg = f"[{app_id}]: Sent deploy hook to http://cat.dog"
            mock_logger.log.assert_any_call(logging.INFO, exp_msg)
            self.assertTrue(mr_catdog.called)
            self.assertEqual(mr_catdog.call_count, 1)
        sha = '2345678'
        body['sha'] = sha
        # Ensure that when requests.Exception is raised, the error is noted and life carries on.
        with self.settings(DRYCC_DEPLOY_HOOK_URLS=['http://cat.ninja', 'http://drycc.dog']):
            def raise_callback(request, context):
                raise requests.ConnectionError('poop')
            mr_ninja = mock_requests.post(f"http://cat.ninja?app={app_id}&user={self.user.username}&sha={sha}&release=v3&release_summary={self.user.username}+deployed+{sha}", text=raise_callback)  # noqa
            mr_catdog = mock_requests.post(f"http://drycc.dog?app={app_id}&user={self.user.username}&sha={sha}&release=v3&release_summary={self.user.username}+deployed+{sha}")  # noqa
            response = self.client.post(url, body)
            self.assertEqual(response.status_code, 201, response.data)

            # check app logs
            exp_msg = f"[{app_id}]: An error occurred while sending the deploy hook to http://cat.ninja: poop"  # noqa
            mock_logger.log.assert_any_call(logging.ERROR, exp_msg)
            self.assertTrue(mr_ninja.called)
            self.assertEqual(mr_ninja.call_count, 1)
            exp_msg = f"[{app_id}]: Sent deploy hook to http://drycc.dog"
            mock_logger.log.assert_any_call(logging.INFO, exp_msg)
            self.assertTrue(mr_catdog.called)
            self.assertEqual(mr_catdog.call_count, 1)

        # ensure that when a secret key is used, a Drycc-Signature header is present
        # which was generated by using HMAC-SHA1 against the target URL
        secret = 'Hasta la vista, baby.'
        hook_url = 'http://drycc.com'
        sha = '3456789'
        body['sha'] = sha
        # target URL MUST be in the exact alphabetized order when calculating the HMAC signature.
        target_url = '{}?app={}&release=v4&release_summary={}+deployed+{}&sha={}&user={}'.format(
            hook_url,
            app_id,
            self.user.username,
            sha,
            sha,
            self.user.username,
        )
        signature = hmac.new(
            secret.encode('utf-8'),
            target_url.encode('utf-8'),
            hashlib.sha1,
        ).hexdigest()
        request_headers = {'Authorization': signature}

        with self.settings(DRYCC_DEPLOY_HOOK_SECRET_KEY=secret, DRYCC_DEPLOY_HOOK_URLS=[hook_url]):
            mr_terminator = mock_requests.post(
                target_url,
                request_headers=request_headers,
            )
            response = self.client.post(url, body)
            self.assertEqual(response.status_code, 201, response.data)

            # check app logs
            exp_msg = f"[{app_id}]: Sent deploy hook to {hook_url}"
            mock_logger.log.assert_any_call(logging.INFO, exp_msg)
            self.assertTrue(mr_terminator.called)
            self.assertEqual(mr_terminator.call_count, 1)

    @override_settings(REGISTRY_LOCATION="off-cluster")
    def test_release_external_registry(self, mock_requests):
        """
        Test that get_port always returns the proper value.
        """
        app_id = self.create_app()

        # set the required port for external registries
        body = {'values': json.dumps({'PORT': '3000'})}
        config_response = self.client.post('/v2/apps/{}/config'.format(app_id), body)
        self.assertEqual(config_response.status_code, 201, config_response.data)

        app = App.objects.get(id=app_id)
        url = f'/v2/apps/{app_id}/builds'
        body = {'image': 'test/autotest/example', 'stack': 'container'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        release = app.release_set.latest()
        self.assertEqual(release.get_port('web'), 3000)
        self.assertEqual(release.get_deploy_image(PROCFILE_TYPE_WEB), 'test/autotest/example')

        url = f'/v2/apps/{app_id}/config'
        body = {'typed_values': json.dumps({"web": {'PORT': '9000'}})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        release = app.release_set.latest()
        self.assertEqual(release.get_port('web'), 9000)

    def test_diff_procfile_types(self, mock_requests):
        app_id = self.create_app()
        app = App.objects.get(id=app_id)
        user = User.objects.get(username='autotest')

        # CNCF Buildpack app
        build = Build.objects.create(
            owner=user,
            app=app,
            image="qwerty",
            procfile={},
            sha='african-swallow',
            dockerfile={},
            dryccfile={
                "build": {
                    "docker": {
                        "web": "Dockerfile",
                        "worker": "worker/Dockerfile",
                    }
                },
                "deploy": {
                    "web": {
                        "command": ["bash", "-ec"],
                        "args": ["bundle exec puma -C config/puma.rb"]
                    },
                    "worker": {
                        "command": ["bash", "-ec"],
                        "args": ["python myworker.py"]
                    }
                }
            },
        )

        # create an initial release
        release = Release.objects.create(
            version=2,
            owner=user,
            app=app,
            config=app.config_set.latest(),
            build=build,
            state="succeed"
        )
        self.assertIsNone(release.diff_procfile_types())
        # test has image
        build = Build.objects.create(
            owner=user,
            app=app,
            image="qwerty",
            procfile={},
            sha='african-swallow',
            dockerfile={},
            dryccfile={
                "deploy": {
                    "web": {
                        "image": "docker.io/test/test:v1",
                        "command": ["bash", "-ec"],
                        "args": ["bundle exec puma -C config/puma.rb"]
                    },
                    "worker": {
                        "image": "docker.io/test/test:v1",
                        "command": ["bash", "-ec"],
                        "args": ["python myworker.py"]
                    }
                }
            },
        )
        release = Release.objects.create(
            version=3,
            owner=user,
            app=app,
            config=app.config_set.latest(),
            build=build,
            state="succeed"
        )
        self.assertEqual(release.diff_procfile_types(), {'web', 'worker'})
        # test has image
        build = Build.objects.create(
            owner=user,
            app=app,
            image="qwerty",
            procfile={},
            sha='african-swallow',
            dockerfile={},
            dryccfile={
                "deploy": {
                    "web": {
                        "image": "docker.io/test/test:v2",
                        "command": ["bash", "-ec"],
                        "args": ["bundle exec puma -C config/puma.rb"]
                    },
                    "worker": {
                        "image": "docker.io/test/test:v1",
                        "command": ["bash", "-ec"],
                        "args": ["python myworker.py"]
                    }
                }
            },
        )
        release = Release.objects.create(
            version=4,
            owner=user,
            app=app,
            config=app.config_set.latest(),
            build=build,
            state="succeed"
        )
        self.assertEqual(release.diff_procfile_types(), {'web'})
        # test has image
        build = Build.objects.create(
            owner=user,
            app=app,
            image="qwerty",
            procfile={},
            sha='african-swallow',
            dockerfile={},
            dryccfile={
                "deploy": {
                    "web": {
                        "image": "docker.io/test/test:v2",
                        "command": ["bash", "-ec"],
                        "args": ["bundle exec puma -C config/puma.rb"]
                    },
                    "worker": {
                        "image": "docker.io/test/test:v2",
                        "command": ["bash", "-ec"],
                        "args": ["python myworker.py"]
                    }
                }
            },
        )
        release = Release.objects.create(
            version=5,
            owner=user,
            app=app,
            config=app.config_set.latest(),
            build=build,
            state="succeed"
        )
        self.assertEqual(release.diff_procfile_types(), {'worker'})
        # test no image
        build = Build.objects.create(
            owner=user,
            app=app,
            image="qwerty",
            procfile={},
            sha='african-swallow',
            dockerfile={},
            dryccfile={
                "build": {
                    "docker": {
                        "web": "Dockerfile",
                        "worker": "worker/Dockerfile",
                    }
                },
                "deploy": {
                    "web": {
                        "command": ["bash", "-ec"],
                        "args": ["bundle exec puma -C config/puma.rb"]
                    },
                    "worker": {
                        "command": ["bash", "-ec"],
                        "args": ["python myworker.py"]
                    },
                    "worker-sync": {
                        "image": "web",
                        "command": ["bash", "-ec"],
                        "args": ["python myworker.py sync"]
                    },
                }
            },
        )
        release = Release.objects.create(
            version=6,
            owner=user,
            app=app,
            config=app.config_set.latest(),
            build=build,
            state="succeed"
        )
        self.assertEqual(release.diff_procfile_types(), {'web', 'worker', 'worker-sync'})
        # test has image
        build = Build.objects.create(
            owner=user,
            app=app,
            image="qwerty",
            procfile={},
            sha='african-swallow',
            dockerfile={},
            dryccfile={
                "run": {
                    "args": ["sleep", "60s"],
                    "image": "registry.drycc.cc/drycc/base:bookworm"
                },
                "deploy": {
                    "web": {
                        "image": "registry.drycc.cc/drycc/python-dev",
                        "args": ["python", "-m", "http.server", "5000"]
                    },
                    "task": {
                        "image": "docker.io/library/nginx",
                        "command": ["sleep"],
                        "args": ["infinity"]
                    }
                }
            },
        )
        release = Release.objects.create(
            version=7,
            owner=user,
            app=app,
            config=app.config_set.latest(),
            build=build,
            state="succeed"
        )
        self.assertEqual(release.diff_procfile_types(), {'worker', 'task', 'worker-sync', 'web'})
        # test has image
        build = Build.objects.create(
            owner=user,
            app=app,
            image="qwerty",
            procfile={},
            sha='african-swallow',
            dockerfile={},
            dryccfile={
                "run": {
                    "args": ["sleep", "60s"],
                    "image": "registry.drycc.cc/drycc/base:bookworm"
                },
                "deploy": {
                    "web": {
                        "image": "registry.drycc.cc/drycc/python-dev",
                        "args": ["python", "-m", "http.server", "5000"]
                    },
                    "task": {
                        "image": "docker.io/library/nginx:mainline-bookworm-perl",
                        "command": ["sleep"],
                        "args": ["infinity"]
                    }
                }
            },
        )
        release = Release.objects.create(
            version=8,
            owner=user,
            app=app,
            config=app.config_set.latest(),
            build=build,
            state="succeed"
        )
        self.assertEqual(release.diff_procfile_types(), {'task'})
        # test has image
        build = Build.objects.create(
            owner=user,
            app=app,
            image="qwerty",
            procfile={},
            sha='african-swallow',
            dockerfile={},
            dryccfile={
                "run": {
                    "args": ["sleep", "60s"],
                    "image": "registry.drycc.cc/drycc/base:bookworm"
                },
                "deploy": {
                    "web": {
                        "image": "registry.drycc.cc/drycc/python-dev",
                        "args": ["python", "-m", "http.server", "5000"]
                    },
                    "task": {
                        "image": "docker.io/library/nginx:mainline-bookworm-perl",
                        "command": ["sleep"],
                        "args": ["infinity"]
                    }
                }
            },
        )
        release = Release.objects.create(
            version=9,
            owner=user,
            app=app,
            config=app.config_set.latest(),
            build=build,
            state="succeed"
        )
        self.assertEqual(release.diff_procfile_types(), set())
        with mock.patch('scheduler.resources.pod.Pod.watch') as mock_kube:
            with mock.patch('api.models.app.logger') as mock_logger:
                mock_kube.return_value = ['up', 'down']
                app.pipeline(release, False, True)
                self.assertEqual(release.state, "succeed")
                prefix = f"[{release.app.id}]: [pipeline] release v{release.version}"
                exp_msg = f"{prefix} no changes, skip executing pipeline.deploy"
                mock_logger.log.assert_any_call(logging.INFO, exp_msg)
