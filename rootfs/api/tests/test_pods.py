"""
Unit tests for the Drycc api app.

Run the tests with "./manage.py test api"
"""
import os

from django.contrib.auth import get_user_model
from django.core.cache import cache
from unittest import mock

from api.models.app import App
from api.models.build import Build
from api.models.release import Release
from scheduler import KubeException

from api.tests import adapter, DryccTransactionTestCase
import requests_mock

User = get_user_model()


@requests_mock.Mocker(real_http=True, adapter=adapter)
class PodTest(DryccTransactionTestCase):
    """Tests creation of pods on nodes"""

    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = self.get_or_create_token(self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

    def tearDown(self):
        # make sure every test has a clean slate for k8s mocking
        cache.clear()

    def test_container_api_heroku(self, mock_requests):
        app_id = self.create_app()

        # should start with zero
        url = f"/v2/apps/{app_id}/pods"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 0)

        # post a new build
        url = f"/v2/apps/{app_id}/build"
        body = {
            'image': 'autotest/example',
            'stack': 'heroku-18',
            'sha': 'a'*40,
            'procfile': {
                'web': 'node server.js',
                'worker': 'node worker.js'
            }
        }
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)

        # scale up
        url = f"/v2/apps/{app_id}/ptypes/scale"
        # test setting one proc type at a time
        body = {'web': 4}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)

        body = {'worker': 2}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)

        url = f"/v2/apps/{app_id}/pods"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 6)

        url = f"/v2/apps/{app_id}"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        # ensure the structure field is up-to-date
        self.assertEqual(response.data['structure']['web'], 4)
        self.assertEqual(response.data['structure']['worker'], 2)

        # scale down
        url = f"/v2/apps/{app_id}/ptypes/scale"
        # test setting two proc types at a time
        body = {'web': 2, 'worker': 1}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)

        url = f"/v2/apps/{app_id}/pods"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 3)

        url = f"/v2/apps/{app_id}"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        # ensure the structure field is up-to-date
        self.assertEqual(response.data['structure']['web'], 2)
        self.assertEqual(response.data['structure']['worker'], 1)

        # scale down to 0
        url = f"/v2/apps/{app_id}/ptypes/scale"
        body = {'web': 0, 'worker': 0}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)

        url = f"/v2/apps/{app_id}/pods"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 0)

        url = f"/v2/apps/{app_id}"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)

    def test_container_api(self, mock_requests):
        app_id = self.create_app()

        # should start with zero
        url = f"/v2/apps/{app_id}/pods"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 0)

        # post a new build
        url = f"/v2/apps/{app_id}/build"
        body = {
            'image': 'autotest/example',
            'stack': 'container',
            'dockerfile': "FROM busybox\nCMD /bin/true"
        }
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)

        # scale up
        url = f"/v2/apps/{app_id}/ptypes/scale"
        body = {'web': 6}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)

        url = f"/v2/apps/{app_id}/pods"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 6)

        url = f"/v2/apps/{app_id}"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)

        # scale down
        url = f"/v2/apps/{app_id}/ptypes/scale"
        body = {'web': 3}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)

        url = f"/v2/apps/{app_id}/pods"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 3)

        url = f"/v2/apps/{app_id}"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)

        # scale down to 0
        url = f"/v2/apps/{app_id}/ptypes/scale"
        body = {'web': 0}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)

        url = f"/v2/apps/{app_id}/pods"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 0)

        url = f"/v2/apps/{app_id}"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)

    def test_release(self, mock_requests):
        app_id = self.create_app()

        # should start with zero
        url = f"/v2/apps/{app_id}/pods"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 0)

        # post a new build
        url = f"/v2/apps/{app_id}/build"
        body = {
            'image': 'autotest/example',
            'stack': 'heroku-18',
            'sha': 'a'*40,
            'procfile': {
                'web': 'node server.js',
                'worker': 'node worker.js'
            }
        }
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)

        # scale up
        url = f"/v2/apps/{app_id}/ptypes/scale"
        body = {'web': 1}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)

        url = f"/v2/apps/{app_id}/pods"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertPodContains(response.data['results'], app_id, "web", "v2")

        # post a new build
        url = f"/v2/apps/{app_id}/build"
        # a web proctype must exist on the second build or else the container will be removed
        body = {
            'image': 'autotest/example',
            'stack': 'heroku-18',
            'procfile': {
                'web': 'echo hi'
            }
        }
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data['image'], body['image'])

        url = f"/v2/apps/{app_id}/pods"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertPodContains(response.data['results'], app_id, 'web', 'v3')

        # post new config
        url = f"/v2/apps/{app_id}/config"
        body = {'values': [{'name': 'KEY', 'value': 'value', 'group': 'global'}]}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)

        url = f"/v2/apps/{app_id}/pods"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertPodContains(response.data['results'], app_id, "web", 'v4')

        # describe pod
        pod_name = response.data['results'][0]["name"]
        response = self.client.get(f"/v2/apps/{app_id}/pods/{pod_name}/describe/")
        self.assertEqual(response.status_code, 200, response.data)

        # delete pods
        response = self.client.delete(
            f"/v2/apps/{app_id}/pods/",
            {'pod_ids': pod_name}
        )
        self.assertEqual(response.status_code, 200, response.data)

        # describe no exists pod
        pod_name = "no-exists-pod-name"
        response = self.client.get(f"/v2/apps/{app_id}/pods/{pod_name}/describe/")
        self.assertEqual(response.status_code, 400, response.data)

    def test_container_errors(self, mock_requests):
        app_id = self.create_app()

        # create a release so we can scale
        app = App.objects.get(id=app_id)
        user = User.objects.get(username='autotest')
        build = Build.objects.create(owner=user, app=app, image="qwerty")

        # create an initial release
        release = Release.objects.create(
            version=2,
            owner=user,
            app=app,
            config=app.config_set.latest(),
            build=build
        )
        # deploy
        release.deploy()
        url = f"/v2/apps/{app_id}/ptypes/scale"
        body = {'web': 'not_an_int'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)
        app = App.objects.get(id=app_id)
        self.assertEqual(app.structure, {'web': 1})

        body = {'invalid': 1}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)
        app = App.objects.get(id=app_id)
        self.assertEqual(app.structure, {'web': 1})

    def test_container_str(self, mock_requests):
        """Test the text representation of a container."""
        app_id = self.create_app()

        # post a new build
        url = f"/v2/apps/{app_id}/build"
        body = {
            'image': 'autotest/example',
            'stack': 'heroku-18',
            'sha': 'a'*40,
            'procfile': {
                'web': 'node server.js',
                'worker': 'node worker.js'
            }
        }
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)

        # scale up
        url = f"/v2/apps/{app_id}/ptypes/scale"
        body = {'web': 4, 'worker': 2}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)

        # should start with zero
        url = f"/v2/apps/{app_id}/pods"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 6)
        pods = response.data['results']
        for pod in pods:
            if pod['state'] != 'up':
                continue
            self.assertIn(pod['type'], ['web', 'worker'])
            self.assertEqual(pod['release'], 'v2')
            # pod name is auto generated so use regex
            self.assertRegex(pod['name'], app_id + '-(worker|web)-[0-9]{7,10}-[a-z0-9]{5}')

    def test_pod_command_format(self, mock_requests):
        # regression test for https://github.com/drycc/drycc/pull/1285
        app_id = self.create_app()

        # post a new build
        url = f"/v2/apps/{app_id}/build"
        body = {
            'image': 'autotest/example',
            'stack': 'heroku-18',
            'sha': 'a'*40,
            'procfile': {
                'web': 'node server.js',
                'worker': 'node worker.js'
            }
        }
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)

        # scale up
        url = f"/v2/apps/{app_id}/ptypes/scale"
        body = {'web': 1}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)
        url = f"/v2/apps/{app_id}/pods"
        response = self.client.get(url)

        # verify that the release.get_deploy_args property got formatted
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 1)

        pod = response.data['results'][0]
        self.assertEqual(pod['type'], 'web')
        self.assertEqual(pod['release'], 'v2')
        # pod name is auto generated so use regex
        self.assertRegex(pod['name'], app_id + '-web-[0-9]{8,10}-[a-z0-9]{5}')

        # verify commands
        release = App.objects.get(id=app_id).release_set.latest()

        self.assertNotIn('{c_type}', release.get_deploy_args('web'))

    def test_scale_errors(self, mock_requests):
        app_id = self.create_app()

        # should start with zero
        url = f"/v2/apps/{app_id}/pods"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 0)

        # post a new build
        url = f"/v2/apps/{app_id}/build"
        body = {
            'image': 'autotest/example',
            'stack': 'heroku-18',
            'sha': 'a'*40,
            'procfile': {
                'web': 'node server.js',
                'worker': 'node worker.js'
            }
        }
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)

        # scale to a negative number
        url = f"/v2/apps/{app_id}/ptypes/scale"
        body = {'web': -1}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)
        app = App.objects.get(id=app_id)
        self.assertEqual(app.structure["web"], 1)

        # scale to something other than a number
        url = f"/v2/apps/{app_id}/ptypes/scale"
        body = {'web': 'one'}
        response = self.client.post(url, body)
        app = App.objects.get(id=app_id)
        self.assertEqual(response.status_code, 204, response.data)
        self.assertEqual(app.structure["web"], 1)

        # scale to something other than a number
        url = f"/v2/apps/{app_id}/ptypes/scale"
        body = {'web': [1]}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)
        app = App.objects.get(id=app_id)
        self.assertEqual(app.structure["web"], 1)

        # scale with a non-existent proc type
        url = f"/v2/apps/{app_id}/ptypes/scale"
        body = {'foo': 1}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)
        app = App.objects.get(id=app_id)
        self.assertEqual("foo" in app.structure, False)

        # scale up to an integer as a sanity check
        url = f"/v2/apps/{app_id}/ptypes/scale"
        body = {'web': 1}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)
        app = App.objects.get(id=app_id)
        self.assertEqual(app.structure["web"], 1)

        with mock.patch('scheduler.KubeHTTPClient.scale') as mock_kube:
            mock_kube.side_effect = KubeException('Boom!')
            url = f"/v2/apps/{app_id}/ptypes/scale"
            response = self.client.post(url, {'web': 10})
            self.assertEqual(response.status_code, 204, response.data)
            app = App.objects.get(id=app_id)
            self.assertEqual(app.structure["web"], 1)

    def test_admin_can_manage_other_pods(self, mock_requests):
        """If a non-admin user creates a container, an administrator should be able to
        manage it.
        """
        user = User.objects.get(username='autotest2')
        token = self.get_or_create_token(user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token)

        app_id = self.create_app()

        # post a new build
        url = f"/v2/apps/{app_id}/build"
        body = {
            'image': 'autotest/example',
            'stack': 'heroku-18',
            'sha': 'a'*40,
            'procfile': {
                'web': 'node server.js',
                'worker': 'node worker.js'
            }
        }
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)

        # login as admin, scale up
        url = f"/v2/apps/{app_id}/ptypes/scale"
        body = {'web': 4, 'worker': 2}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)

    def test_scale_without_build_should_error(self, mock_requests):
        """A user should not be able to scale processes unless a build is present."""
        app_id = 'autotest'
        url = '/v2/apps'
        body = {'cluster': 'autotest', 'id': app_id}
        response = self.client.post(url, body)

        url = f'/v2/apps/{app_id}/ptypes/scale'
        body = {'web': '1'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)
        app = App.objects.get(id=app_id)
        self.assertEqual("web" in app.structure, False)

    def test_command_good(self, mock_requests):
        """Test the default command for each container workflow"""
        app_id = self.create_app()
        app = App.objects.get(id=app_id)
        user = User.objects.get(username='autotest')

        # CNCF Buildpack app
        build = Build.objects.create(
            owner=user,
            app=app,
            image="qwerty",
            procfile={
                'web': 'node server.js',
                'worker': 'node worker.js'
            },
            sha='african-swallow',
            dockerfile=''
        )

        # create an initial release
        release = Release.objects.create(
            version=2,
            owner=user,
            app=app,
            config=app.config_set.latest(),
            build=build
        )
        # deploy
        release.deploy()

        # use `start web` for backwards compatibility with buildpacks
        self.assertEqual(release.get_deploy_args('web'), [])
        self.assertEqual(release.get_deploy_args('worker'), [])

        # switch to container image app
        build.sha = ''
        build.save()
        self.assertEqual(release.get_deploy_args('web'), ['node', 'server.js'])

        # switch to dockerfile app
        build.sha = 'european-swallow'
        build.dockerfile = 'dockerdockerdocker'
        build.save()
        self.assertEqual(release.get_deploy_args('web'), ['node', 'server.js'])
        self.assertEqual(release.get_deploy_args('cmd'), [])

        # ensure we can override the cmd process type in a Procfile
        build.procfile['cmd'] = 'node server.js'
        build.save()
        self.assertEqual(release.get_deploy_command('cmd'), [])
        self.assertEqual(release.get_deploy_args('cmd'), ['node', 'server.js'])
        self.assertEqual(release.get_deploy_command('worker'), [])
        self.assertEqual(release.get_deploy_args('worker'), ['node', 'worker.js'])

        # for backwards compatibility if no Procfile is supplied
        build.procfile = {}
        build.save()
        self.assertEqual(release.get_deploy_args('worker'), [])

    def test_run_command_good(self, mock_requests):
        """Test the run command for each container workflow"""
        app_id = self.create_app()
        app = App.objects.get(id=app_id)

        # dockerfile + procfile worflow
        build = Build.objects.create(
            owner=self.user,
            app=app,
            image="qwerty",
            stack="heroku-18",
            procfile={
                'web': 'node server.js',
                'worker': 'node worker.js'
            },
            dockerfile='foo',
            sha='somereallylongsha'
        )

        # create an initial release
        release = Release.objects.create(
            version=2,
            owner=self.user,
            app=app,
            config=app.config_set.latest(),
            build=build
        )
        # deploy
        release.deploy()

        # create a run pod
        url = f"/v2/apps/{app_id}/run"
        body = {'command': 'echo hi'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)
        app = App.objects.get(id=app_id)
        self.assertEqual(release.get_deploy_command('web'), [])

        # docker image workflow
        build.dockerfile = ''
        build.sha = ''
        build.save()
        url = f"/v2/apps/{app_id}/run"
        body = {'command': 'echo hi'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)
        app = App.objects.get(id=app_id)
        self.assertEqual(release.get_deploy_command('cmd'), [])
        self.assertEqual(release.get_deploy_command('run'), [])

        # procfile workflow
        build.sha = 'somereallylongsha'
        build.save()
        url = f"/v2/apps/{app_id}/run"
        body = {'command': 'echo hi'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)

    def test_run_not_fail_on_debug(self, mock_requests):
        """
        do a run with DRYCC_DEBUG on - https://github.com/drycc/controller/issues/583
        """
        os.environ['DRYCC_DEBUG'] = 'true'

        app_id = self.create_app()
        app = App.objects.get(id=app_id)

        # dockerfile + procfile worflow
        build = Build.objects.create(
            owner=self.user,
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
            version=2,
            owner=self.user,
            app=app,
            config=app.config_set.latest(),
            build=build
        )
        # deploy
        release.deploy()

        # create a run pod
        url = f"/v2/apps/{app_id}/run"
        body = {'command': 'echo hi'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)
        self.assertEqual(release.get_deploy_command('web'), [])

    def test_scaling_does_not_add_run_proctypes_to_structure(self, mock_requests):
        """Test that app info doesn't show transient "run" proctypes."""
        app_id = self.create_app()
        app = App.objects.get(id=app_id)
        user = User.objects.get(username='autotest')

        # dockerfile + procfile worflow
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
            version=2,
            owner=user,
            app=app,
            config=app.config_set.latest(),
            build=build
        )
        # deploy
        release.deploy()

        # create a run pod
        url = f"/v2/apps/{app_id}/run"
        body = {'command': 'echo hi'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)

        # scale up
        url = f"/v2/apps/{app_id}/ptypes/scale"
        body = {'web': 3}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)

        # test that "run" proctype isn't in the app info returned
        url = f"/v2/apps/{app_id}"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertNotIn('run', response.data['structure'])

    def test_scale_with_unauthorized_user_returns_403(self, mock_requests):
        """An unauthorized user should not be able to access an app's resources.

        If an unauthorized user is trying to scale an app he or she does not have access to, it
        should return a 403.
        """
        app_id = self.create_app()

        # post a new build
        url = f"/v2/apps/{app_id}/build"
        body = {
            'image': 'autotest/example',
            'sha': 'a'*40,
            'procfile': {'web': 'node server.js', 'worker': 'node worker.js'}
        }
        response = self.client.post(url, body)
        unauthorized_user = User.objects.get(username='autotest2')
        unauthorized_token = self.get_or_create_token(unauthorized_user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + unauthorized_token)

        # scale up with unauthorized user
        url = f"/v2/apps/{app_id}/ptypes/scale"
        body = {'web': 4}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 403)

    def test_modified_procfile_from_build_removes_pods(self, mock_requests):
        """
        When a new procfile is posted which removes a certain process type, drycc should stop the
        existing pods.
        """
        app_id = self.create_app()

        # post a new build
        build_url = f"/v2/apps/{app_id}/build"
        body = {
            'image': 'autotest/example',
            'stack': 'heroku-18',
            'sha': 'a'*40,
            'procfile': {
                'web': 'node server.js',
                'worker': 'node worker.js'
            }
        }
        response = self.client.post(build_url, body)

        url = f"/v2/apps/{app_id}/ptypes/scale"
        body = {'web': 4}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)

        body = {
            'image': 'autotest/example',
            'stack': 'heroku-18',
            'sha': 'a'*40,
            'procfile': {
                'worker': 'node worker.js'
            }
        }
        response = self.client.post(build_url, body)
        self.assertEqual(response.status_code, 201, response.data)
        # check web pods
        application = App.objects.get(id=app_id)
        pods = application.list_pods(type='web')
        self.assertEqual(len(pods), 0)
        pods = application.list_pods(type='worker')
        self.assertEqual(len(pods), 0)

    def test_list_pods_failure(self, mock_requests):
        """
        Listing all available pods exceptions
        """

        app_id = self.create_app()

        with mock.patch('scheduler.resources.pod.Pod.get') as kube_pod:
            with mock.patch('scheduler.resources.pod.Pod.get') as kube_pods:
                kube_pod.side_effect = KubeException('boom!')
                kube_pods.side_effect = KubeException('boom!')
                url = f"/v2/apps/{app_id}/pods"
                response = self.client.get(url)
                self.assertEqual(response.status_code, 503, response.data)
