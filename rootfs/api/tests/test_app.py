"""
Unit tests for the Drycc api app.

Run the tests with "./manage.py test api"
"""
import base64
import json
import logging
from unittest import mock
import random
import requests

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test.utils import override_settings

from api.models.app import App
from api.models.base import PTYPE_WEB
from api.models.workspace import Workspace, WorkspaceMember
from scheduler import KubeException, KubeHTTPException

from api.exceptions import DryccException
from api.tests import adapter, DryccTestCase, DryccTransactionTestCase
import requests_mock

User = get_user_model()


def mock_none(*args, **kwargs):
    return None


def _mock_run(*args, **kwargs):
    return [0, 'mock']


@requests_mock.Mocker(real_http=True, adapter=adapter)
class AppTest(DryccTestCase):
    """Tests creation of applications"""

    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = self.get_or_create_token(self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)
        self.workspace_name = self._ensure_workspace_admin(self._default_workspace_name())

        original_post = self.client.post

        def _post_with_workspace(path, data=None, *args, **kwargs):
            if path == '/v2/apps':
                payload = {} if data is None else dict(data)
                payload.setdefault('workspace', self.workspace_name)
                data = payload
            return original_post(path, data, *args, **kwargs)

        self.client.post = _post_with_workspace

    def tearDown(self):
        # make sure every test has a clean slate for k8s mocking
        cache.clear()

    def test_app(self, mock_requests):
        """
        Test that a user can create, read, update and delete an application
        """
        app_id = self.create_app()

        response = self.client.get('/v2/apps')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 1)

        url = f'/v2/apps/{app_id}'
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)

        body = {'id': 'new'}
        response = self.client.patch(url, body)
        self.assertEqual(response.status_code, 400, response.data)
        self.assertIn('workspace is required', str(response.data))

        response = self.client.delete(url)
        self.assertEqual(response.status_code, 204, response.data)

    def test_app_name_length(self, mock_requests):
        """
        Test that the app name length cannot be longer than the maximum length dictated by
        Kubernetes' maximum service name length.
        """
        name = 'a' * 64
        body = {'id': name}
        response = self.client.post('/v2/apps', body)
        self.assertEqual(
            response.data,
            {'id': ['Ensure this field has no more than 63 characters.']}
        )
        self.assertEqual(response.status_code, 400)

    def test_response_data(self, mock_requests):
        """Test that the serialized response contains only relevant data."""
        body = {'id': 'app-{}'.format(random.randrange(1000, 10000))}
        response = self.client.post('/v2/apps', body)
        for key in response.data:
            self.assertIn(key, ['uuid', 'created', 'updated', 'id', 'workspace', 'structure'])
        expected = {
            'id': body['id'],
            'workspace': self.user.username,
            'structure': {}
        }
        self.assertEqual(response.data, expected | response.data)

    def test_app_override_id(self, mock_requests):
        app_id = self.create_app()

        response = self.client.post('/v2/apps', {'id': app_id})
        self.assertContains(response, 'Application with this id already exists.', status_code=400)

    @mock.patch('api.models.app.logger')
    def test_app_release_notes_in_logs(self, mock_requests, mock_logger):
        """Verifies that an app's release summary is dumped into the logs."""
        with mock.patch('api.models.release.logger') as release_logger:
            app_id = self.create_app()
            app = App.objects.get(id=app_id)
            # check release logs
            exp_msg = "[{app_id}]: {self.user.username} created initial release".format(
                **locals())
            release_logger.log.assert_any_call(logging.INFO, exp_msg)
            app.log('hello world')
            exp_msg = f"[{app_id}]: hello world"
            mock_logger.log.assert_any_call(logging.INFO, exp_msg)
            app.log('goodbye world', logging.WARNING)
            # assert logging with a different log level
            exp_msg = f"[{app_id}]: goodbye world"
            mock_logger.log.assert_any_call(logging.WARNING, exp_msg)

    def test_app_errors(self, mock_requests):
        response = self.client.post('/v2/apps', {'id': 'camelCase'})
        self.assertContains(
            response,
            'App name must start with an alphabetic character, cannot end with a hyphen and can '
            + 'only contain a-z (lowercase), 0-9 and hyphens.',
            status_code=400
        )

        response = self.client.post('/v2/apps', {'id': '123name-starts-with-numbers'})
        self.assertContains(
            response,
            'App name must start with an alphabetic character, cannot end with a hyphen and can '
            + 'only contain a-z (lowercase), 0-9 and hyphens.',
            status_code=400
        )

        response = self.client.post('/v2/apps', {'id': 'name-ends-with-hyphen-'})
        self.assertContains(
            response,
            'App name must start with an alphabetic character, cannot end with a hyphen and can '
            + 'only contain a-z (lowercase), 0-9 and hyphens.',
            status_code=400
        )

        app_id = self.create_app()
        url = f'/v2/apps/{app_id}'
        response = self.client.delete(url)
        self.assertEqual(response.status_code, 204, response.data)
        for endpoint in ('containers', 'config', 'releases', 'builds'):
            url = f'/v2/apps/{app_id}/{endpoint}'
            response = self.client.get(url)
            self.assertEqual(response.status_code, 404)

    def test_app_reserved_names(self, mock_requests):
        """Nobody should be able to create applications with names which are reserved."""
        reserved_names = ['fooooo', 'barrrrrr']
        with self.settings(RESERVED_NAME_PATTERNS=reserved_names):
            for name in reserved_names:
                response = self.client.post('/v2/apps', {'id': name})
                self.assertContains(
                    response,
                    '{} is a reserved name.'.format(name),
                    status_code=400)

    def test_app_structure_is_valid_json(self, mock_requests):
        """Application structures should be valid JSON objects."""
        response = self.client.post('/v2/apps')
        self.assertEqual(response.status_code, 201, response.data)
        self.assertIn('id', response.data)
        self.assertIn('structure', response.data)
        self.assertEqual(response.data['structure'], {})
        app_id = response.data['id']
        app = App.objects.get(id=app_id)
        app.structure = {'web': 1}
        app.save()

        response = self.client.get('/v2/apps/{}'.format(app_id))
        self.assertIn('structure', response.data)
        self.assertEqual(response.data['structure'], {"web": 1})

    @mock.patch('api.models.release.logger')
    def test_admin_can_manage_other_apps(self, mock_requests, mock_logger):
        """Administrators of Drycc should be able to manage all applications.
        """
        # log in as non-admin user and create an app
        username = 'autotest2'
        user = User.objects.get(username=username)
        token = self.get_or_create_token(user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token)
        app_id = self.create_app()

        app = App.objects.get(id=app_id)
        WorkspaceMember.objects.get_or_create(
            workspace=app.workspace,
            user=self.user,
            defaults={'role': 'admin'},
        )

        # log in as admin, check to see if they have access
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)
        url = '/v2/apps/{}'.format(app_id)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        # check app logs
        exp_msg = "[%s]: %s created initial release" % (app_id, username)
        mock_logger.log.assert_any_call(logging.INFO, exp_msg)
        # TODO: test run needs an initial build
        # delete the app
        url = '/v2/apps/{}'.format(app_id)
        response = self.client.delete(url)
        self.assertEqual(response.status_code, 204, response.data)

    def test_admin_can_see_other_apps(self, mock_requests):
        """If a user creates an application, the administrator should be able
        to see it.
        """
        # log in as non-admin user and create an app
        user = User.objects.get(username='autotest2')
        token = self.get_or_create_token(user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token)
        app_id = self.create_app()

        app = App.objects.get(id=app_id)
        WorkspaceMember.objects.get_or_create(
            workspace=app.workspace,
            user=self.user,
            defaults={'role': 'viewer'},
        )

        # log in as admin
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)
        response = self.client.get('/v2/apps')
        self.assertIn('count', response.data)
        self.assertEqual(response.data['count'], 1, response.data)

    def test_run_without_release_should_error(self, mock_requests):
        """
        A user should not be able to run a one-off command unless a release
        is present.
        """
        app_id = self.create_app()
        url = '/v2/apps/{}/run'.format(app_id)
        body = {'command': 'ls -al'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 400, response.data)
        self.assertEqual(
            str(response.data["detail"]), 'no build available, please deploy a release')

    @mock.patch('api.models.app.App.run', _mock_run)
    @mock.patch('api.models.app.App.deploy', mock_none)
    def test_run(self, mock_requests):
        """
        A user should be able to run a one off command
        """
        app_id = self.create_app()

        # create build
        body = {'image': 'autotest/example', 'stack': 'container'}
        url = f'/v2/apps/{app_id}/build'
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)

        # cannot run command without body
        url = '/v2/apps/{}/run'.format(app_id)
        response = self.client.post(url, {})
        self.assertEqual(response.status_code, 400, response.data)
        self.assertEqual(
            response.data,
            {'detail': 'command is a required field, or it can be defined in Procfile'}
        )

        # run command
        body = {'command': 'ls -al'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)

    def test_run_failure(self, mock_requests):
        """Raise a KubeException via scheduler.run"""
        app_id = self.create_app()

        # create build
        body = {'image': 'autotest/example', 'stack': 'container'}
        url = f'/v2/apps/{app_id}/build'
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)

        with mock.patch('scheduler.KubeHTTPClient.http_post') as kube_run:
            kube_run.side_effect = KubeException('boom!')
            # run command
            url = '/v2/apps/{}/run'.format(app_id)
            body = {'command': 'ls -al'}
            response = self.client.post(url, body)
            self.assertEqual(response.status_code, 503, response.data)

    def test_unauthorized_user_cannot_see_app(self, mock_requests):
        """
        An unauthorized user should not be able to access an app's resources.

        Since an unauthorized user can't access the application, these
        tests return 404 when app is filtered out from queryset.
        """
        app_id = self.create_app()
        unauthorized_user = User.objects.get(username='autotest2')
        unauthorized_token = self.get_or_create_token(unauthorized_user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + unauthorized_token)

        url = '/v2/apps/{}/run'.format(app_id)
        body = {'command': 'foo'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 404)

        url = '/v2/apps/{}'.format(app_id)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 404)

        response = self.client.delete(url)
        self.assertEqual(response.status_code, 404)

    def test_app_info_not_showing_wrong_app(self, mock_requests):
        self.create_app()
        response = self.client.get('/v2/apps/foo')
        self.assertEqual(response.status_code, 404)

    def test_app_transfer(self, mock_requests):
        owner = User.objects.get(username='autotest2')
        owner_token = self.get_or_create_token(owner)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + owner_token)

        collaborator = User.objects.get(username='autotest3')
        collab_token = self.get_or_create_token(collaborator)

        # create a workspace and app under owner
        response = self.client.post('/v2/workspaces', {
            'name': 'wstransfer1',
            'email': 'ws-owner@example.com',
        })
        self.assertEqual(response.status_code, 201, response.data)

        response = self.client.post('/v2/apps', {
            'id': 'app-transfer01',
            'workspace': 'wstransfer1',
        })
        self.assertEqual(response.status_code, 201, response.data)

        app = App.objects.get(id='app-transfer01')
        workspace = Workspace.objects.get(name='wstransfer1')
        url = '/v2/apps/{}'.format(app.id)

        # collaborator cannot access app before joining workspace
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + collab_token)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 404, response.data)

        # owner adds collaborator to workspace
        WorkspaceMember.objects.get_or_create(
            workspace=workspace,
            user=collaborator,
            defaults={'role': 'member'},
        )

        # collaborator can access app after membership
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)

        # collaborator cannot manage workspace members
        response = self.client.patch(
            f'/v2/workspaces/{workspace.name}/members/{owner.username}',
            {'role': 'viewer'},
        )
        self.assertEqual(response.status_code, 403, response.data)

    def test_transfer_api_success(self, mock_requests):
        app_id = self.create_app(name='appxferok')
        response = self.client.post('/v2/workspaces', {
            'name': 'wstarget',
            'email': 'target@example.com',
        })
        self.assertEqual(response.status_code, 201, response.data)

        response = self.client.patch(
            f'/v2/apps/{app_id}',
            {'workspace': 'wstarget'},
        )
        self.assertEqual(response.status_code, 204, response.data)

        app = App.objects.get(id=app_id)
        self.assertEqual(app.workspace.name, 'wstarget')

    def test_transfer_api_requires_workspace(self, mock_requests):
        app_id = self.create_app(name='appxferreqws')
        response = self.client.patch(f'/v2/apps/{app_id}', {})
        self.assertEqual(response.status_code, 400, response.data)
        self.assertIn('workspace is required', str(response.data))

    def test_transfer_api_non_admin_forbidden(self, mock_requests):
        """Non-admin members of a workspace should not be able to transfer apps."""
        # owner creates workspace and app
        owner = User.objects.get(username='autotest2')
        owner_token = self.get_or_create_token(owner)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + owner_token)

        response = self.client.post('/v2/workspaces', {
            'name': 'wsxferadmin',
            'email': 'xferadmin@example.com',
        })
        self.assertEqual(response.status_code, 201, response.data)

        response = self.client.post('/v2/apps', {
            'id': 'app-xferadmin',
            'workspace': 'wsxferadmin',
        })
        self.assertEqual(response.status_code, 201, response.data)

        # add a non-admin member to the workspace
        member = User.objects.get(username='autotest3')
        workspace = Workspace.objects.get(name='wsxferadmin')
        WorkspaceMember.objects.create(user=member, workspace=workspace, role='member')

        # create a target workspace for the member
        member_token = self.get_or_create_token(member)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + member_token)

        response = self.client.post('/v2/workspaces', {
            'name': 'wsxfertarget',
            'email': 'xfertarget@example.com',
        })
        self.assertEqual(response.status_code, 201, response.data)

        # non-admin member cannot transfer the app → 403
        response = self.client.patch(
            '/v2/apps/app-xferadmin',
            {'workspace': 'wsxfertarget'},
        )
        self.assertEqual(response.status_code, 403, response.data)

    def test_transfer_api_target_workspace_not_found(self, mock_requests):
        app_id = self.create_app(name='appxfer404')
        response = self.client.patch(
            f'/v2/apps/{app_id}',
            {'workspace': 'workspace-not-exists'},
        )
        self.assertEqual(response.status_code, 404, response.data)

    def test_app_exists_in_kubernetes(self, mock_requests):
        """
        Create an app that has the same namespace as an existing kubernetes namespace
        """
        body = {'id': 'duplicate'}
        response = self.client.post('/v2/apps', body)
        self.assertContains(
            response,
            'duplicate already exists as a namespace in this kuberenetes setup',
            status_code=409
        )

    def test_app_delete_failure_kubernetes_destroy(self, mock_requests):
        """
        Create an app and then delete but have scheduler.ns.delete
        fail with an exception
        """
        # create
        app_id = self.create_app()

        with mock.patch('scheduler.resources.namespace.Namespace.delete') as mock_kube:
            # delete
            mock_kube.side_effect = KubeException('Boom!')
            response = self.client.delete('/v2/apps/{}'.format(app_id))
            self.assertEqual(response.status_code, 503, response.data)

    def test_app_delete_missing_namespace(self, mock_requests):
        """
        Create an app and then delete but have namespace missing
        Should still succeed
        """
        # create
        app_id = self.create_app()

        with mock.patch('scheduler.resources.namespace.Namespace.get') as mock_kube:
            # instead of full request mocking, fake it out in a simple way
            class Response(object):
                def json(self):
                    return '{}'

            response = Response()
            response.status_code = 404
            response.reason = "Not Found"
            kube_exception = KubeHTTPException(response, 'big boom')
            mock_kube.side_effect = kube_exception

            response = self.client.delete('/v2/apps/{}'.format(app_id))
            self.assertEqual(response.status_code, 204, response.data)

        # verify that app is gone
        response = self.client.get('/v2/apps/{}'.format(app_id))
        self.assertEqual(response.status_code, 404, response.data)

    def test_app_verify_application_health_success(self, mock_requests):
        """
        Create an application which in turn causes a health check to run against
        the router. Make it succeed on the 6th try
        """
        responses = [
            {'text': 'Not Found', 'status_code': 404},
            {'text': 'Not Found', 'status_code': 404},
            {'text': 'Not Found', 'status_code': 404},
            {'text': 'Not Found', 'status_code': 404},
            {'text': 'Not Found', 'status_code': 404},
            {'text': 'OK', 'status_code': 200}
        ]

        # create app
        app_id = self.create_app()
        hostname = 'http://{}.{}.svc:80/'.format(app_id, app_id)
        mr = mock_requests.register_uri('GET', hostname, responses)

        # deploy app to get verification
        url = "/v2/apps/{}/build".format(app_id)
        body = {'image': 'autotest/example', 'stack': 'container'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data['image'], body['image'])

        self.assertEqual(mr.called, True)
        self.assertEqual(mr.call_count, 6)

    def test_app_verify_application_health_failure_404(self, mock_requests):
        """
        Create an application which in turn causes a health check to run against
        the router. Make it fail with a 404 after 10 tries
        """
        # function tries to hit router 10 times
        responses = [
            {'text': 'Not Found', 'status_code': 404},
            {'text': 'Not Found', 'status_code': 404},
            {'text': 'Not Found', 'status_code': 404},
            {'text': 'Not Found', 'status_code': 404},
            {'text': 'Not Found', 'status_code': 404},
            {'text': 'Not Found', 'status_code': 404},
            {'text': 'Not Found', 'status_code': 404},
            {'text': 'Not Found', 'status_code': 404},
            {'text': 'Not Found', 'status_code': 404},
            {'text': 'Not Found', 'status_code': 404},
        ]

        # create app
        app_id = self.create_app()

        hostname = 'http://{}.{}.svc:80/'.format(app_id, app_id)
        mr = mock_requests.register_uri('GET', hostname, responses)
        # deploy app to get verification
        url = "/v2/apps/{}/build".format(app_id)
        body = {'image': 'autotest/example', 'stack': 'container'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data['image'], body['image'])

        self.assertEqual(mr.called, True)
        self.assertEqual(mr.call_count, 10)

    def test_app_verify_application_health_failure_exceptions(self, mock_requests):
        """
        Create an application which in turn causes a health check to run against
        the router. Make it fail with a python-requets exception
        """
        def _raise_exception(request, ctx):
            raise requests.exceptions.RequestException('Boom!')

        # create app
        app_id = self.create_app()
        # function tries to hit router 10 times
        hostname = 'http://{}.{}.svc:80/'.format(app_id, app_id)
        mr = mock_requests.register_uri('GET', hostname, text=_raise_exception)

        # deploy app to get verification
        url = "/v2/apps/{}/build".format(app_id)
        body = {'image': 'autotest/example', 'stack': 'container'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data['image'], body['image'])

        # Called 10 times due to the exception
        self.assertEqual(mr.called, True)
        self.assertEqual(mr.call_count, 10)

    def test_list_ordering(self, mock_requests):
        """
        Test that a list of apps is sorted by name
        """
        for name in ['zulua', 'tango', 'alpha', 'foxtrot']:
            response = self.client.post('/v2/apps', {'id': name})
            self.assertEqual(response.status_code, 201, response.data)

        response = self.client.get('/v2/apps')
        apps = response.data['results']
        self.assertEqual(apps[0]['id'], 'alpha')
        self.assertEqual(apps[1]['id'], 'foxtrot')
        self.assertEqual(apps[2]['id'], 'tango')
        self.assertEqual(apps[3]['id'], 'zulua')

    def test_get_private_registry_config(self, mock_requests):
        registry = {"web": {'username': 'test', 'password': 'test'}}
        auth = bytes('{}:{}'.format("test", "test"), 'UTF-8')
        encAuth = base64.b64encode(auth).decode(encoding='UTF-8')
        image = 'test/test'

        docker_config, name, create = App()._get_private_registry_config("web", image, registry.get("web", {}))  # noqa
        dockerConfig = json.loads(docker_config)
        expected = {"https://index.docker.io/v1/": {"auth": encAuth}}
        self.assertEqual(dockerConfig.get('auths'), expected)
        self.assertEqual(name, "private-registry-web")
        self.assertEqual(create, True)

        image = "quay.io/test/test"
        docker_config, name, create = App()._get_private_registry_config("web", image, registry.get("web", {}))  # noqa
        dockerConfig = json.loads(docker_config)
        expected = {"quay.io": {"auth": encAuth}}
        self.assertEqual(dockerConfig.get('auths'), expected)
        self.assertEqual(name, "private-registry-web")
        self.assertEqual(create, True)

    @override_settings(REGISTRY_LOCATION="off-cluster")
    def test_get_private_registry_config_off_cluster(self, mock_requests):
        registry = {}
        auth = bytes('{}:{}'.format("test", "test"), 'UTF-8')
        encAuth = base64.b64encode(auth).decode(encoding='UTF-8')
        image = "test.com/test/test"
        docker_config, name, create = App()._get_private_registry_config("web", image, registry.get("web", {}))  # noqa
        dockerConfig = json.loads(docker_config)
        expected = {"https://index.docker.io/v1/": {
            "auth": encAuth
        }}
        self.assertEqual(dockerConfig.get('auths'), expected)
        self.assertEqual(name, "private-registry-web-off-cluster")
        self.assertEqual(create, True)

    @override_settings(REGISTRY_LOCATION="ecra")
    def test_get_private_registry_config_bad_registry_location(self, mock_requests):
        registry = {}
        image = "test.com/test/test"
        docker_config, name, create = App()._get_private_registry_config("web", image, registry)
        self.assertEqual(docker_config, None)
        self.assertEqual(name, None)
        self.assertEqual(create, None)

    def test_build_env_vars(self, mock_requests):
        app = App.objects.create(workspace=Workspace.objects.get(name=self.workspace_name))
        # Make sure an exception is raised when calling without a build available
        with self.assertRaises(DryccException):
            app._build_env_vars(app.release_set.latest(), PTYPE_WEB)
        data = {'image': 'autotest/example', 'stack': 'heroku-18'}
        url = f"/v2/apps/{app.id}/build"
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, 201, response.data)
        time_created = app.release_set.latest().created
        self.assertEqual(
            app._build_env_vars(app.release_set.latest(), PTYPE_WEB),
            {
                'DRYCC_APP': app.id,
                'WORKFLOW_RELEASE': 'v2',
                'PORT': 5000,
                'SOURCE_VERSION': '',
                'WORKFLOW_RELEASE_SUMMARY': 'autotest deployed autotest/example',
                'WORKFLOW_RELEASE_CREATED_AT': str(time_created.strftime(
                    settings.DRYCC_DATETIME_FORMAT))
            })
        data['sha'] = 'abc1234'
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, 201, response.data)
        time_created = app.release_set.latest().created
        self.assertEqual(
            app._build_env_vars(app.release_set.latest(), PTYPE_WEB),
            {
                'DRYCC_APP': app.id,
                'WORKFLOW_RELEASE': 'v3',
                'PORT': 5000,
                'SOURCE_VERSION': 'abc1234',
                'WORKFLOW_RELEASE_SUMMARY': 'autotest deployed abc1234',
                'WORKFLOW_RELEASE_CREATED_AT': str(time_created.strftime(
                    settings.DRYCC_DATETIME_FORMAT))
            })

    def test_gather_app_settings(self, mock_requests):
        app = App.objects.create(workspace=Workspace.objects.get(name=self.workspace_name))
        app.save()
        data = {'image': 'autotest/example', 'stack': 'container'}
        url = f"/v2/apps/{app.id}/build"
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, 201, response.data)
        # Set some app settings
        url = f"/v2/apps/{app.id}/config"
        body = {
            'values': [
                {"name": "DRYCC_DEPLOY_TIMEOUT", "value": "60", "group": "global"},
                {"name": "DRYCC_DEPLOY_BATCHES", "value": "3", "group": "global"},
                {
                    "name": "KUBERNETES_POD_TERMINATION_GRACE_PERIOD_SECONDS",
                    "value": "90", "group": "global"
                },
            ],
        }
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        # Gather app settings
        s = app._gather_app_settings(app.release_set.latest(),
                                     app.appsettings_set.latest(),
                                     'web',
                                     3)
        self.assertEqual(s['deploy_batches'], 3)
        self.assertEqual(s['deploy_timeout'], 60)
        self.assertEqual(s['termination_grace_period_seconds'], 90)

    def test_app_name_bad_regex(self, mock_requests):
        """
        Create a normal app and then try to do a build on it but include
        extra chars (equal for example) in the name and make sure no new
        apps are created and that the operation errors out
        """
        # create app
        app_id = self.create_app()

        # verify that there is only 1 app and it is the one expected
        response = self.client.get("/v2/apps")
        self.assertEqual(response.status_code, 200, response)
        self.assertEqual(response.data['count'], 1, response.data)
        self.assertEqual(response.data['results'][0]['id'], app_id, response.data)

        # deploy to an app that doesn't exist should fail with 404
        url = "/v2/apps/{}/build".format('={}'.format(app_id))
        body = {'image': 'autotest/example', 'stack': 'container'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 404, response)

        # verify again that there is only 1 app
        response = self.client.get("/v2/apps")
        self.assertEqual(response.status_code, 200, response)
        self.assertEqual(response.data['count'], 1, response.data)

    def test_app_workspace_isolation(self, mock_requests):
        """
        Apps in different workspaces should be isolated.
        A user who is not a member of a workspace should not see its apps.
        """
        # user1 creates workspace and app
        response = self.client.post('/v2/workspaces', {
            'name': 'wsisolate1',
            'email': 'isolate1@example.com',
        })
        self.assertEqual(response.status_code, 201, response.data)

        response = self.client.post('/v2/apps', {
            'id': 'app-isolate01',
            'workspace': 'wsisolate1',
        })
        self.assertEqual(response.status_code, 201, response.data)

        # user2 creates a different workspace and app
        user2 = User.objects.get(username='autotest2')
        token2 = self.get_or_create_token(user2)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token2)

        response = self.client.post('/v2/workspaces', {
            'name': 'wsisolate2',
            'email': 'isolate2@example.com',
        })
        self.assertEqual(response.status_code, 201, response.data)

        response = self.client.post('/v2/apps', {
            'id': 'app-isolate02',
            'workspace': 'wsisolate2',
        })
        self.assertEqual(response.status_code, 201, response.data)

        # user2 cannot see user1's app
        response = self.client.get('/v2/apps/app-isolate01')
        self.assertEqual(response.status_code, 404, response.data)

        # user2 can see their own app
        response = self.client.get('/v2/apps/app-isolate02')
        self.assertEqual(response.status_code, 200, response.data)

        # user2's app list should only contain their own app
        response = self.client.get('/v2/apps')
        self.assertEqual(response.status_code, 200, response.data)
        app_ids = [app['id'] for app in response.data['results']]
        self.assertIn('app-isolate02', app_ids)
        self.assertNotIn('app-isolate01', app_ids)

    def test_app_workspace_member_can_see_app(self, mock_requests):
        """
        When a user is added as a member to a workspace,
        they should be able to see apps in that workspace.
        """
        # user1 creates workspace and app
        response = self.client.post('/v2/workspaces', {
            'name': 'wsmember1',
            'email': 'member1@example.com',
        })
        self.assertEqual(response.status_code, 201, response.data)

        response = self.client.post('/v2/apps', {
            'id': 'app-member01',
            'workspace': 'wsmember1',
        })
        self.assertEqual(response.status_code, 201, response.data)

        # user2 cannot see the app initially
        user2 = User.objects.get(username='autotest2')
        token2 = self.get_or_create_token(user2)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token2)

        response = self.client.get('/v2/apps/app-member01')
        self.assertEqual(response.status_code, 404, response.data)

        # add user2 as a viewer to the workspace
        workspace = Workspace.objects.get(name='wsmember1')
        WorkspaceMember.objects.create(user=user2, workspace=workspace, role='viewer')

        # now user2 can see the app
        response = self.client.get('/v2/apps/app-member01')
        self.assertEqual(response.status_code, 200, response.data)

    def test_app_response_has_workspace_not_owner(self, mock_requests):
        """
        App API response should contain 'workspace' field, not 'owner'.
        """
        app_id = self.create_app()

        response = self.client.get(f'/v2/apps/{app_id}')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertIn('workspace', response.data)
        self.assertNotIn('owner', response.data)

        # app list should also have workspace, not owner
        response = self.client.get('/v2/apps')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertGreater(len(response.data['results']), 0)
        app_data = response.data['results'][0]
        self.assertIn('workspace', app_data)
        self.assertNotIn('owner', app_data)

    def test_app_subresources_have_no_owner_field(self, mock_requests):
        """
        App sub-resources (build, config, release, domain, etc.) should
        not contain an 'owner' field in their API responses since the
        owner field has been removed from these models.
        """
        app_id = self.create_app()

        # Create a build to generate a release
        url = f'/v2/apps/{app_id}/build'
        body = {'image': 'autotest/example', 'stack': 'container'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)

        # Build should not have 'owner'
        self.assertNotIn('owner', response.data)

        # Config should not have 'owner'
        url = f'/v2/apps/{app_id}/config'
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertNotIn('owner', response.data)

        # Releases should not have 'owner'
        url = f'/v2/apps/{app_id}/releases'
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        for release in response.data['results']:
            self.assertNotIn('owner', release)

    def test_key_and_token_still_have_owner(self, mock_requests):
        """
        Key and Token models should still contain 'owner' field
        since they are user personal assets, not workspace resources.
        """
        # Key should have 'owner'
        body = {'id': str(self.user), 'public': (
            'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCfQkkUUoxpvcNMkvv7jqnfodgs37M2eBO'
            'APgLK+KNBMaZaaKB4GF1QhTCMfFhoiTW3rqa0J75bHJcdkoobtTHlK8XUrFqsquWyg3XhsT'
            'Yr/3RQQXvO86e2sF7SVDJqVtpnbQGc5SgNrHCeHJmf5HTbXSIjCO/AJSvIjnituT/SIAMGe'
            'Bw0Nq/iSltwYAek1hiKO7wSmLcIQ8U4A00KEUtalaumf2aHOcfjgPfzlbZGP0S0cuBwSqLr'
            '8b5XGPmkASNdUiuJY4MJOce7bFU14B7oMAy2xacODUs1momUeYtGI9T7X2WMowJaO7tP3Gl'
            'sgBMP81VfYTfYChAyJpKp2yoP autotest@autotesting'
        )}
        response = self.client.post('/v2/keys', body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertIn('owner', response.data)

        # Token should have 'owner'
        response = self.client.get('/v2/tokens')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertGreater(len(response.data['results']), 0)
        self.assertIn('owner', response.data['results'][0])

    def test_app_list_filters_by_workspace_membership(self, mock_requests):
        """
        App list API should only return apps in workspaces where the
        authenticated user is a member.
        """
        # user1 creates workspace1 with app1
        response = self.client.post('/v2/workspaces', {
            'name': 'wslist01',
            'email': 'wslist1@example.com',
        })
        self.assertEqual(response.status_code, 201, response.data)

        response = self.client.post('/v2/apps', {
            'id': 'app-list01',
            'workspace': 'wslist01',
        })
        self.assertEqual(response.status_code, 201, response.data)

        # user2 creates workspace2 with app2
        user2 = User.objects.get(username='autotest2')
        token2 = self.get_or_create_token(user2)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token2)

        response = self.client.post('/v2/workspaces', {
            'name': 'wslist02',
            'email': 'wslist2@example.com',
        })
        self.assertEqual(response.status_code, 201, response.data)

        response = self.client.post('/v2/apps', {
            'id': 'app-list02',
            'workspace': 'wslist02',
        })
        self.assertEqual(response.status_code, 201, response.data)

        # user2 should only see their own app
        response = self.client.get('/v2/apps')
        self.assertEqual(response.status_code, 200, response.data)
        app_ids = [app['id'] for app in response.data['results']]
        self.assertIn('app-list02', app_ids)
        self.assertNotIn('app-list01', app_ids)

        # Switch back to user1
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

        # user1 should only see their own app
        response = self.client.get('/v2/apps')
        self.assertEqual(response.status_code, 200, response.data)
        app_ids = [app['id'] for app in response.data['results']]
        self.assertIn('app-list01', app_ids)
        self.assertNotIn('app-list02', app_ids)

    def test_app_list_filter_by_workspace_param(self, mock_requests):
        """
        App list API should support filtering by ?workspace=xxx query parameter.
        """
        # user1 creates workspace1 with app1
        response = self.client.post('/v2/workspaces', {
            'name': 'wsfilter01',
            'email': 'wsfilter1@example.com',
        })
        self.assertEqual(response.status_code, 201, response.data)

        response = self.client.post('/v2/apps', {
            'id': 'app-filter01',
            'workspace': 'wsfilter01',
        })
        self.assertEqual(response.status_code, 201, response.data)

        # user1 creates workspace2 with app2
        response = self.client.post('/v2/workspaces', {
            'name': 'wsfilter02',
            'email': 'wsfilter2@example.com',
        })
        self.assertEqual(response.status_code, 201, response.data)

        response = self.client.post('/v2/apps', {
            'id': 'app-filter02',
            'workspace': 'wsfilter02',
        })
        self.assertEqual(response.status_code, 201, response.data)

        # list all apps (no filter)
        response = self.client.get('/v2/apps')
        self.assertEqual(response.status_code, 200, response.data)
        app_ids = [app['id'] for app in response.data['results']]
        self.assertIn('app-filter01', app_ids)
        self.assertIn('app-filter02', app_ids)

        # filter by workspace1 - should only see app1
        response = self.client.get('/v2/apps?workspace=wsfilter01')
        self.assertEqual(response.status_code, 200, response.data)
        app_ids = [app['id'] for app in response.data['results']]
        self.assertIn('app-filter01', app_ids)
        self.assertNotIn('app-filter02', app_ids)

        # filter by workspace2 - should only see app2
        response = self.client.get('/v2/apps?workspace=wsfilter02')
        self.assertEqual(response.status_code, 200, response.data)
        app_ids = [app['id'] for app in response.data['results']]
        self.assertIn('app-filter02', app_ids)
        self.assertNotIn('app-filter01', app_ids)

        # filter by non-existent workspace - should return 404
        response = self.client.get('/v2/apps?workspace=nonexistent')
        self.assertEqual(response.status_code, 404, response.data)

    def test_app_list_workspace_not_member(self, mock_requests):
        """
        App list API should return 403 when filtering by a workspace
        the user is not a member of.
        """
        # user1 creates workspace with app
        response = self.client.post('/v2/workspaces', {
            'name': 'wsnotmember01',
            'email': 'notmember1@example.com',
        })
        self.assertEqual(response.status_code, 201, response.data)

        response = self.client.post('/v2/apps', {
            'id': 'app-notmember01',
            'workspace': 'wsnotmember01',
        })
        self.assertEqual(response.status_code, 201, response.data)

        # user2 creates their own workspace (but is NOT a member of wsnotmember01)
        user2 = User.objects.get(username='autotest2')
        token2 = self.get_or_create_token(user2)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token2)

        response = self.client.post('/v2/workspaces', {
            'name': 'wsnotmember02',
            'email': 'notmember2@example.com',
        })
        self.assertEqual(response.status_code, 201, response.data)

        # user2 filters by wsnotmember01 (which they are not a member of) → 403
        response = self.client.get('/v2/apps?workspace=wsnotmember01')
        self.assertEqual(response.status_code, 403, response.data)

        # user2 can still list their own apps without workspace filter
        response = self.client.get('/v2/apps')
        self.assertEqual(response.status_code, 200, response.data)

        # user2 can filter by their own workspace
        response = self.client.get('/v2/apps?workspace=wsnotmember02')
        self.assertEqual(response.status_code, 200, response.data)

    def test_app_retrieve_ignores_workspace_param(self, mock_requests):
        """
        App retrieve API should ignore the ?workspace= query parameter.
        The workspace filter only applies to the list action.
        """
        # user1 creates workspace and app
        response = self.client.post('/v2/workspaces', {
            'name': 'wsretrieve01',
            'email': 'retrieve1@example.com',
        })
        self.assertEqual(response.status_code, 201, response.data)

        response = self.client.post('/v2/apps', {
            'id': 'app-retrieve01',
            'workspace': 'wsretrieve01',
        })
        self.assertEqual(response.status_code, 201, response.data)

        # retrieve with a different workspace param should still work
        # (workspace param is only used in list, not retrieve)
        response = self.client.get('/v2/apps/app-retrieve01?workspace=other-workspace')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data['id'], 'app-retrieve01')

    def test_app_list_search_still_works(self, mock_requests):
        """
        App list API should still support ?search=xxx fuzzy search
        alongside the workspace filter.
        """
        # create workspace and app
        response = self.client.post('/v2/workspaces', {
            'name': 'wssearch01',
            'email': 'wssearch1@example.com',
        })
        self.assertEqual(response.status_code, 201, response.data)

        response = self.client.post('/v2/apps', {
            'id': 'app-search01',
            'workspace': 'wssearch01',
        })
        self.assertEqual(response.status_code, 201, response.data)

        response = self.client.post('/v2/apps', {
            'id': 'app-search02',
            'workspace': 'wssearch01',
        })
        self.assertEqual(response.status_code, 201, response.data)

        # search by prefix
        response = self.client.get('/v2/apps?search=app-search')
        self.assertEqual(response.status_code, 200, response.data)
        app_ids = [app['id'] for app in response.data['results']]
        self.assertIn('app-search01', app_ids)
        self.assertIn('app-search02', app_ids)

        # search + workspace filter combined
        response = self.client.get('/v2/apps?workspace=wssearch01&search=app-search01')
        self.assertEqual(response.status_code, 200, response.data)
        app_ids = [app['id'] for app in response.data['results']]
        self.assertIn('app-search01', app_ids)
        self.assertNotIn('app-search02', app_ids)


class AppWorkspaceModelTest(DryccTransactionTestCase):
    """
    Test App model workspace-related behavior without K8s dependency.

    These tests verify the workspace-based permission model at the ORM level,
    bypassing App.save() which requires K8s API access.
    Uses bulk_create to insert App records directly into the database.
    """

    fixtures = ['tests.json']

    def setUp(self):
        self.user1 = User.objects.get(username='autotest')
        self.token1 = self.get_or_create_token(self.user1)
        self.user2 = User.objects.get(username='autotest2')
        self.token2 = self.get_or_create_token(self.user2)

    def tearDown(self):
        cache.clear()

    def test_app_model_has_workspace_no_owner(self):
        """
        App model should have a 'workspace' field and no 'owner' field.
        """
        # App has workspace field
        self.assertTrue(hasattr(App, 'workspace'))
        # App does NOT have owner field
        self.assertFalse(hasattr(App, 'owner'))

    def test_app_queryset_filters_by_workspace_membership(self):
        """
        App.objects.filter(workspace__workspacemember__user__username=...)
        should return only apps in workspaces where the user is a member.
        """
        # Create workspace1 with user1 as admin
        ws1 = Workspace.objects.create(name='wsamodel01', email='ws1@example.com')
        WorkspaceMember.objects.create(workspace=ws1, user=self.user1, role='admin')

        # Create workspace2 with user2 as admin
        ws2 = Workspace.objects.create(name='wsamodel02', email='ws2@example.com')
        WorkspaceMember.objects.create(workspace=ws2, user=self.user2, role='admin')

        # Create apps directly in DB (bypass K8s)
        App.objects.bulk_create([
            App(id='app-model01', workspace=ws1),
            App(id='app-model02', workspace=ws2),
        ])

        # user1 should only see app-model01
        user1_apps = list(
            App.objects.filter(
                workspace__workspacemember__user__username=self.user1.username
            ).values_list('id', flat=True)
        )
        self.assertIn('app-model01', user1_apps)
        self.assertNotIn('app-model02', user1_apps)

        # user2 should only see app-model02
        user2_apps = list(
            App.objects.filter(
                workspace__workspacemember__user__username=self.user2.username
            ).values_list('id', flat=True)
        )
        self.assertIn('app-model02', user2_apps)
        self.assertNotIn('app-model01', user2_apps)

    def test_key_model_still_has_owner(self):
        """
        Key model should still have 'owner' field since it's a user personal asset.
        """
        from api.models.key import Key
        self.assertTrue(hasattr(Key, 'owner'))

    def test_token_model_still_has_owner(self):
        """
        Token model should still have 'owner' field since it's a user personal asset.
        """
        from api.models.base import Token
        self.assertTrue(hasattr(Token, 'owner'))
