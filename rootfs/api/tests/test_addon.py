# -*- coding: utf-8 -*-
"""
Unit tests for addon management.

Run the tests with "./manage.py test api"
"""
import copy
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.cache import cache

from api import models
from api.models.addon import AddonInstance
from api.tests import DryccTransactionTestCase
from scheduler import KubeHTTPException

User = get_user_model()

ADDONCLASS_DATA = {
    'metadata': {'name': 'valkey'},
    'spec': {
        'description': 'Valkey in-memory data store',
        'storageModel': 'bundle',
        'visiblePaths': ['name', 'description', 'allowCreate', 'allowUpdate'],
        'targetResource': {'kind': 'Valkey'},
        'plans': [
            {
                'name': 'micro',
                'description': '1 GB, Standalone',
                'defaults': {},
                'overrides': {
                    'shards': 1, 'replicas': 0, 'workloadType': 'StatefulSet',
                    'resources': {
                        'limits': {'cpu': '500m', 'memory': '1Gi'},
                        'requests': {'cpu': '250m', 'memory': '512Mi'},
                    },
                    'persistence': {
                        'enabled': True, 'size': '2Gi', 'storageClassName': '',
                    },
                    'exporter': {'enabled': True},
                },
                'allowCreate': ['users', 'config', 'tls.enabled'],
                'allowUpdate': ['users', 'config', 'tls.enabled'],
            },
            {
                'name': 'small',
                'description': '2 GB, 1 Master + 1 Replica',
                'defaults': {},
                'overrides': {
                    'shards': 1, 'replicas': 1, 'workloadType': 'StatefulSet',
                    'resources': {
                        'limits': {'cpu': '500m', 'memory': '2Gi'},
                        'requests': {'cpu': '250m', 'memory': '1Gi'},
                    },
                    'persistence': {
                        'enabled': True, 'size': '4Gi', 'storageClassName': '',
                    },
                    'exporter': {'enabled': True},
                },
                'allowCreate': ['users', 'config', 'tls.enabled'],
                'allowUpdate': ['users', 'config', 'tls.enabled'],
            },
        ],
    },
}

GENERIC_ADDONCLASS_DATA = {
    'metadata': {'name': 'generic'},
    'spec': {
        'description': 'Generic application workload',
        'storageModel': 'custom',
        'multiplierFrom': 'replicas',
        'visiblePaths': ['name', 'description', 'allowCreate', 'allowUpdate'],
        'targetResource': {'kind': 'Generic'},
        'plans': [
            {
                'name': 'micro',
                'description': '250m CPU / 512Mi memory',
                'defaults': {
                    'imagePullPolicy': 'IfNotPresent',
                    'replicas': 1,
                    'persistence': {'enabled': False},
                },
                'overrides': {
                    'resources': {
                        'limits': {'cpu': '250m', 'memory': '512Mi'},
                        'requests': {'cpu': '125m', 'memory': '256Mi'},
                    },
                    'service': {'enabled': True, 'type': 'ClusterIP'},
                },
                'allowCreate': [
                    'image.repository', 'image.tag', 'replicas',
                    'persistence.enabled', 'persistence.size',
                ],
                'allowUpdate': ['image.tag', 'replicas'],
            },
            {
                'name': 'medium',
                'description': '1 CPU / 2Gi memory',
                'defaults': {
                    'imagePullPolicy': 'IfNotPresent',
                    'replicas': 2,
                    'persistence': {'enabled': True, 'size': '8Gi'},
                },
                'overrides': {
                    'resources': {
                        'limits': {'cpu': 1, 'memory': '2Gi'},
                        'requests': {'cpu': '500m', 'memory': '1Gi'},
                    },
                    'service': {'enabled': True, 'type': 'ClusterIP'},
                },
                'allowCreate': [
                    'image.repository', 'image.tag', 'replicas',
                    'persistence.enabled', 'persistence.size',
                ],
                'allowUpdate': ['image.tag', 'replicas'],
            },
        ],
    },
}


def _ok_mock(json_data=None, status_code=200):
    r = mock.Mock()
    r.status_code = status_code
    r.json.return_value = json_data if json_data is not None else {}
    return r


def _notfound_mock():
    r = mock.Mock()
    r.status_code = 404
    r.json.return_value = {'message': 'not found'}
    return r


def _mock_connection_scheduler(data=None, secret_name='valkey-abc123-connection'):
    s = _mock_scheduler()
    cr = mock.Mock()
    cr.status_code = 200
    cr.json.return_value = {
        'status': {'connectionSecretName': secret_name},
    }
    s.addonresources.get = mock.Mock(return_value=cr)

    secret = mock.Mock()
    secret.status_code = 200
    secret.json.return_value = {
        'data': data if data is not None else {'host': 'localhost', 'port': '6379'},
    }
    s.secret.get = mock.Mock(return_value=secret)
    return s


def _mock_scheduler():
    s = mock.Mock()
    m = mock.Mock()
    m.status_code = 200
    m.json.return_value = {'items': [ADDONCLASS_DATA, GENERIC_ADDONCLASS_DATA]}
    vm = mock.Mock()
    vm.status_code = 200
    vm.json.return_value = ADDONCLASS_DATA
    gm = mock.Mock()
    gm.status_code = 200
    gm.json.return_value = GENERIC_ADDONCLASS_DATA
    s.addonclasses.get = mock.Mock(
        side_effect=lambda name=None, ignore_exception=True: (
            vm if name == 'valkey' else gm if name == 'generic' else m
        )
    )
    created_xrs = {}

    def get_xr(namespace, name=None, ignore_exception=True, **kwargs):
        if name in created_xrs:
            r = mock.Mock()
            r.status_code = 200
            r.json.return_value = created_xrs[name]
            return r
        r = mock.Mock()
        r.status_code = 404
        return r
    s.addonresources.get = mock.Mock(side_effect=get_xr)

    def create_xr(namespace, name, ignore_exception=True, **kwargs):
        manifest = kwargs.get('manifest', {})
        created_xrs[name] = manifest
        r = mock.Mock()
        r.status_code = 201
        r.json.return_value = {'metadata': {'name': name}}
        return r
    s.addonresources.create = mock.Mock(side_effect=create_xr)

    def put_xr(namespace, name, ignore_exception=True, **kwargs):
        manifest = kwargs.get('manifest', {})
        created_xrs[name] = manifest
        r = mock.Mock()
        r.status_code = 200
        return r
    s.addonresources.put = mock.Mock(side_effect=put_xr)

    dr = mock.Mock()
    dr.status_code = 200
    s.addonresources.delete = mock.Mock(return_value=dr)

    # App lifecycle (namespace / networkpolicy / tls / issuer) mocks.
    # ns.get returns 404 so App.create() enters the ns.create branch;
    # all write ops return successful 2xx responses.
    s.ns.get = mock.Mock(return_value=_notfound_mock())
    s.ns.create = mock.Mock(return_value=_ok_mock({'metadata': {'name': 'ns'}}))
    s.networkpolicy.get = mock.Mock(return_value=_notfound_mock())
    s.networkpolicy.create = mock.Mock(return_value=_ok_mock())
    s.networkpolicy.patch = mock.Mock(return_value=_ok_mock())
    s.issuer.get = mock.Mock(side_effect=KubeHTTPException(_notfound_mock(), 'get issuer'))
    s.issuer.create = mock.Mock(return_value=_ok_mock({'metadata': {'name': 'issuer'}}))
    s.issuer.put = mock.Mock(return_value=_ok_mock())
    s.certificate.get = mock.Mock(return_value=_notfound_mock())
    s.certificate.create = mock.Mock(return_value=_ok_mock())
    s.certificate.put = mock.Mock(return_value=_ok_mock())
    s.certificate.delete = mock.Mock(return_value=_ok_mock())
    s.certificaterequest.get = mock.Mock(return_value=_notfound_mock())
    s.secret.get = mock.Mock(return_value=_notfound_mock())
    s.secret.create = mock.Mock(return_value=_ok_mock())
    s.secret.update = mock.Mock(return_value=_ok_mock())
    s.secret.patch = mock.Mock(return_value=_ok_mock())
    s.unhealthy = staticmethod(lambda code: code not in (200, 201, 204))
    return s


class AddonClassTest(DryccTransactionTestCase):
    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = self.get_or_create_token(self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

    def tearDown(self):
        cache.clear()

    @mock.patch('api.views.addon.get_scheduler')
    def test_list_addonclasses(self, mock_gs):
        mock_gs.return_value = _mock_scheduler()
        response = self.client.get('/v2/addon-classes')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data['count'], 2)
        self.assertEqual(response.data['results'][0]['name'], 'valkey')
        self.assertEqual(response.data['results'][0]['kind'], 'Valkey')
        for plan in response.data['results'][0]['plans']:
            self.assertNotIn('defaults', plan)
            self.assertNotIn('overrides', plan)
            self.assertIn('allowCreate', plan)
            self.assertIn('allowUpdate', plan)

    @mock.patch('api.views.addon.get_scheduler')
    def test_retrieve_addonclass(self, mock_gs):
        mock_gs.return_value = _mock_scheduler()
        response = self.client.get('/v2/addon-classes/valkey')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data['name'], 'valkey')
        for plan in response.data['plans']:
            self.assertNotIn('defaults', plan)
            self.assertNotIn('overrides', plan)
            self.assertIn('name', plan)
            self.assertIn('description', plan)

    @mock.patch('api.views.addon.get_scheduler')
    def test_addonclass_visible_paths_fallback(self, mock_gs):
        """When visiblePaths is absent, the default visible set applies."""
        data = copy.deepcopy(ADDONCLASS_DATA)
        del data['spec']['visiblePaths']
        s = mock.Mock()
        single = mock.Mock()
        single.status_code = 200
        single.json.return_value = data
        s.addonclasses.get = mock.Mock(return_value=single)
        mock_gs.return_value = s

        response = self.client.get('/v2/addon-classes/valkey')
        self.assertEqual(response.status_code, 200, response.data)
        for plan in response.data['plans']:
            self.assertNotIn('defaults', plan)
            self.assertNotIn('overrides', plan)
            self.assertIn('allowCreate', plan)

    @mock.patch('api.views.addon.get_scheduler')
    def test_addonclass_visible_paths_nested_jsonpath(self, mock_gs):
        """Nested jsonpaths expose only the named leaf, not its siblings."""
        data = copy.deepcopy(GENERIC_ADDONCLASS_DATA)
        data['spec']['visiblePaths'] = ['name', 'defaults.imagePullPolicy']
        s = mock.Mock()
        single = mock.Mock()
        single.status_code = 200
        single.json.return_value = data
        s.addonclasses.get = mock.Mock(return_value=single)
        mock_gs.return_value = s

        response = self.client.get('/v2/addon-classes/generic')
        self.assertEqual(response.status_code, 200, response.data)
        plan = response.data['plans'][0]
        self.assertEqual(plan['name'], 'micro')
        self.assertEqual(plan['defaults'], {'imagePullPolicy': 'IfNotPresent'})
        self.assertNotIn('replicas', plan.get('defaults', {}))
        self.assertNotIn('persistence', plan.get('defaults', {}))
        self.assertNotIn('overrides', plan)
        self.assertNotIn('allowCreate', plan)

    @mock.patch('api.views.addon.get_scheduler')
    def test_retrieve_nonexistent_addonclass(self, mock_gs):
        s = _mock_scheduler()

        def get_addonclass(name=None, ignore_exception=True):
            if name == 'missing':
                resp = mock.Mock()
                resp.status_code = 404
                resp.reason = 'Not Found'
                resp.json.return_value = {'message': 'not found'}
                raise KubeHTTPException(resp, 'get AddonClass missing')
            items_resp = mock.Mock()
            items_resp.status_code = 200
            items_resp.json.return_value = {'items': [ADDONCLASS_DATA]}
            return items_resp

        s.addonclasses.get = mock.Mock(side_effect=get_addonclass)
        mock_gs.return_value = s
        response = self.client.get('/v2/addon-classes/missing')
        self.assertEqual(response.status_code, 404, response.data)

    def test_jsonpath_get_set_del(self):
        from api.utils import jsonpath

        data = {'a': {'b': {'c': 1}}}
        # get (default action)
        self.assertEqual(jsonpath(data, 'a.b.c'), 1)
        self.assertEqual(jsonpath(data, 'a.x', default='miss'), 'miss')
        # set (creates intermediate dicts)
        jsonpath(data, 'a.b.d', action='set', value=2)
        self.assertEqual(data, {'a': {'b': {'c': 1, 'd': 2}}})
        jsonpath(data, 'x.y', action='set', value=3)
        self.assertEqual(data['x'], {'y': 3})
        # del (returns default, removes the leaf)
        self.assertIsNone(jsonpath(data, 'a.b.c', action='del'))
        self.assertEqual(data['a']['b'], {'d': 2})
        # del on a missing path is a no-op (returns default)
        self.assertEqual(jsonpath(data, 'a.b.z', action='del', default='gone'), 'gone')


class AddonInstanceTest(DryccTransactionTestCase):
    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = self.get_or_create_token(self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)
        self.workspace_id = self._ensure_workspace_admin(
            self._default_workspace_id())
        self._patch()
        self.app_id = self.create_app()

    def tearDown(self):
        AddonInstance.objects.all().delete()
        cache.clear()
        mock.patch.stopall()

    def _patch(self):
        s = _mock_scheduler()
        mock.patch('api.views.addon.get_scheduler', return_value=s).start()
        mock.patch('api.models.base.get_scheduler', return_value=s).start()

    def _upsert(self, name, params=None):
        data = {
            'kind': 'Valkey',
            'plan': 'micro',
            'parameters': params if params is not None else {},
        }
        return self.client.put(
            '/v2/apps/{}/addons/{}/'.format(self.app_id, name), data, format='json')

    def _upsert_generic(self, name, plan='micro', params=None):
        data = {
            'kind': 'Generic',
            'plan': plan,
            'parameters': params if params is not None else {},
        }
        return self.client.put(
            '/v2/apps/{}/addons/{}/'.format(self.app_id, name), data, format='json')

    def test_create_addon_instance(self):
        response = self._upsert('valkey-abc123')
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data['name'], 'valkey-abc123')
        self.assertEqual(response.data['plan'], 'micro')
        self.assertEqual(response.data['app'], self.app_id)
        instance = AddonInstance.objects.get(name='valkey-abc123')
        self.assertEqual(instance.kind, 'Valkey')
        self.assertEqual(instance.app.id, self.app_id)

    def test_create_missing_app(self):
        # an addon under a non-existent app yields 404
        response = self.client.put(
            '/v2/apps/nonexistent-app/addons/test-name/',
            data={'kind': 'Valkey', 'plan': 'micro', 'parameters': {}},
            format='json')
        self.assertEqual(response.status_code, 404, response.data)

    def test_create_missing_addon(self):
        s = _mock_scheduler()
        notfound = mock.Mock()
        notfound.status_code = 404
        notfound.json.return_value = {'message': 'not found'}
        s.addonclasses.get = mock.Mock(return_value=notfound)
        mock.patch('api.views.addon.get_scheduler', return_value=s).start()
        mock.patch('api.models.base.get_scheduler', return_value=s).start()
        response = self.client.put(
            '/v2/apps/{}/addons/test-name/'.format(self.app_id),
            data={'kind': 'Nonexistent', 'plan': 'micro', 'parameters': {}},
            format='json')
        self.assertEqual(response.status_code, 400, response.data)

    def test_create_plan_not_found(self):
        response = self.client.put(
            '/v2/apps/{}/addons/test-name/'.format(self.app_id),
            data={
                'kind': 'Valkey',
                'plan': 'nonexistent',
                'parameters': {},
            },
            format='json')
        self.assertEqual(response.status_code, 400, response.data)

    def test_create_invalid_parameter(self):
        response = self._upsert('test-name', params={'shards': 5})
        self.assertEqual(response.status_code, 400, response.data)

    def test_list_addon_instances(self):
        self._upsert('valkey-abc123')
        response = self.client.get('/v2/apps/{}/addons/'.format(self.app_id))
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data['count'], 1)

    def test_retrieve_addon_instance(self):
        self._upsert('valkey-abc123')
        response = self.client.get('/v2/apps/{}/addons/valkey-abc123'.format(self.app_id))
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data['name'], 'valkey-abc123')

    def test_update_addon_instance(self):
        self._upsert('valkey-abc123', params={'users': []})
        response = self.client.put(
            '/v2/apps/{}/addons/valkey-abc123/'.format(self.app_id),
            data={
                'kind': 'Valkey',
                'plan': 'micro',
                'parameters': {'users': [{'name': 'admin'}]},
            },
            format='json')
        self.assertEqual(response.status_code, 200, response.data)

    def test_update_disallowed_field(self):
        self._upsert('valkey-abc123')
        response = self.client.put(
            '/v2/apps/{}/addons/valkey-abc123/'.format(self.app_id),
            data={
                'kind': 'Valkey',
                'plan': 'micro',
                'parameters': {'shards': 5},
            },
            format='json')
        self.assertEqual(response.status_code, 400, response.data)

    def test_update_kind_not_allowed(self):
        self._upsert('valkey-abc123')
        response = self.client.put(
            '/v2/apps/{}/addons/valkey-abc123/'.format(self.app_id),
            data={
                'kind': 'Generic',
                'plan': 'micro',
                'parameters': {},
            },
            format='json')
        self.assertEqual(response.status_code, 400, response.data)

    def test_destroy_addon_instance(self):
        self._upsert('valkey-abc123')
        response = self.client.delete('/v2/apps/{}/addons/valkey-abc123/'.format(self.app_id))
        self.assertEqual(response.status_code, 204, response.data)
        self.assertFalse(
            AddonInstance.objects.filter(name='valkey-abc123').exists())

    def test_delete_app_with_addons_blocked(self):
        # An app with addons attached must not be deletable until the
        # addons are removed first.
        self._upsert('valkey-abc123')
        response = self.client.delete('/v2/apps/{}'.format(self.app_id))
        self.assertEqual(response.status_code, 400, response.data)
        # app should still exist
        self.assertTrue(models.app.App.objects.filter(id=self.app_id).exists())
        # remove the addon, then app deletion must succeed
        self.client.delete('/v2/apps/{}/addons/valkey-abc123/'.format(self.app_id))
        response = self.client.delete('/v2/apps/{}'.format(self.app_id))
        self.assertEqual(response.status_code, 204, response.data)

    def test_app_isolation(self):
        # Addons are only reachable via an app the user belongs to.
        self._upsert('valkey-abc123', params={'users': []})
        response = self.client.get('/v2/apps/{}/addons/'.format(self.app_id))
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data['count'], 1)

    def test_generic_multiplier_from_params(self):
        response = self._upsert_generic('generic-abc123', params={'replicas': 3})
        self.assertEqual(response.status_code, 201, response.data)
        instance = AddonInstance.objects.get(name='generic-abc123')
        self.assertEqual(instance.multiplier, 3)

    def test_generic_multiplier_from_defaults(self):
        response = self._upsert_generic('generic-abc123')
        self.assertEqual(response.status_code, 201, response.data)
        instance = AddonInstance.objects.get(name='generic-abc123')
        self.assertEqual(instance.multiplier, 1)

    def test_generic_multiplier_update(self):
        self._upsert_generic('generic-abc123', params={'replicas': 2})
        instance = AddonInstance.objects.get(name='generic-abc123')
        self.assertEqual(instance.multiplier, 2)
        response = self._upsert_generic('generic-abc123', params={'replicas': 5})
        self.assertEqual(response.status_code, 200, response.data)
        instance = AddonInstance.objects.get(name='generic-abc123')
        self.assertEqual(instance.multiplier, 5)

    def test_valkey_multiplier_no_multiplierFrom(self):
        response = self._upsert('valkey-abc123')
        self.assertEqual(response.status_code, 201, response.data)
        instance = AddonInstance.objects.get(name='valkey-abc123')
        self.assertEqual(instance.multiplier, 1)

    def test_generic_nested_params_allowed(self):
        response = self._upsert_generic('generic-abc123', params={
            'replicas': 2,
            'persistence': {'enabled': True, 'size': '4Gi'},
        })
        self.assertEqual(response.status_code, 201, response.data)

    def test_generic_nested_params_disallowed(self):
        response = self._upsert_generic('generic-abc123', params={
            'persistence': {'enabled': True, 'storageClassName': 'fast'},
        })
        self.assertEqual(response.status_code, 400, response.data)

    def test_generic_nested_params_immutable_on_update(self):
        self._upsert_generic('generic-abc123', params={
            'replicas': 2,
            'persistence': {'enabled': True, 'size': '4Gi'},
        })
        response = self._upsert_generic('generic-abc123', params={
            'replicas': 3,
            'persistence': {'enabled': False, 'size': '4Gi'},
        })
        self.assertEqual(response.status_code, 400, response.data)

    def test_valkey_config_as_whole_object(self):
        response = self._upsert('valkey-abc123', params={
            'config': {'maxmemory': '100mb', 'maxmemory-policy': 'allkeys-lru'},
        })
        self.assertEqual(response.status_code, 201, response.data)

    def test_get_conn(self):
        self._upsert('valkey-abc123')
        s = _mock_connection_scheduler()
        with mock.patch('api.models.base.get_scheduler', return_value=s):
            instance = AddonInstance.objects.get(name='valkey-abc123')
            data = instance.get_conn()
        self.assertEqual(data, {'host': 'localhost', 'port': '6379'})

    def test_retrieve_addon_connection(self):
        self._upsert('valkey-abc123')
        s = _mock_connection_scheduler()
        with mock.patch('api.models.base.get_scheduler', return_value=s):
            response = self.client.get(
                '/v2/apps/{}/addons/valkey-abc123/connection'.format(self.app_id))
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data, {'host': 'localhost', 'port': '6379'})

    def test_retrieve_addon_connection_not_ready(self):
        self._upsert('valkey-abc123')
        s = _mock_connection_scheduler()
        cr = mock.Mock()
        cr.status_code = 200
        cr.json.return_value = {'status': {}}
        s.addonresources.get = mock.Mock(return_value=cr)
        with mock.patch('api.models.base.get_scheduler', return_value=s):
            response = self.client.get(
                '/v2/apps/{}/addons/valkey-abc123/connection'.format(self.app_id))
        self.assertEqual(response.status_code, 400, response.data)
        self.assertEqual(
            response.data['detail'],
            "Addon 'valkey-abc123' connection secret is not ready")

    def test_retrieve_addon_connection_resource_missing(self):
        self._upsert('valkey-abc123')
        s = _mock_connection_scheduler()
        cr = mock.Mock()
        cr.status_code = 404
        s.addonresources.get = mock.Mock(return_value=cr)
        with mock.patch('api.models.base.get_scheduler', return_value=s):
            response = self.client.get(
                '/v2/apps/{}/addons/valkey-abc123/connection'.format(self.app_id))
        self.assertEqual(response.status_code, 400, response.data)
        self.assertEqual(
            response.data['detail'],
            "Addon 'valkey-abc123' resource not found in namespace '{}'".format(self.app_id))

    def test_get_conn_secret_missing(self):
        self._upsert('valkey-abc123')
        s = _mock_connection_scheduler()
        resp = mock.Mock()
        resp.status_code = 404
        resp.reason = 'Not Found'
        resp.json.return_value = {'message': 'not found'}
        s.secret.get = mock.Mock(side_effect=KubeHTTPException(resp, 'get Secret missing'))
        with mock.patch('api.models.base.get_scheduler', return_value=s):
            instance = AddonInstance.objects.get(name='valkey-abc123')
            with self.assertRaises(KubeHTTPException):
                instance.get_conn()
