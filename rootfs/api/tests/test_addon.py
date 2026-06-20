# -*- coding: utf-8 -*-
"""
Unit tests for addon management.

Run the tests with "./manage.py test api"
"""
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.cache import cache

from api import models
from api.models.addon import AddonInstance
from api.tests import DryccTransactionTestCase

User = get_user_model()

ADDONCLASS_DATA = {
    'metadata': {'name': 'valkey'},
    'spec': {
        'description': 'Valkey in-memory data store',
        'storageModel': 'bundle',
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
    from scheduler import KubeHTTPException
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

    @mock.patch('api.views.addon.get_scheduler')
    def test_retrieve_addonclass(self, mock_gs):
        mock_gs.return_value = _mock_scheduler()
        response = self.client.get('/v2/addon-classes/valkey')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data['name'], 'valkey')

    @mock.patch('api.views.addon.get_scheduler')
    def test_retrieve_nonexistent_addonclass(self, mock_gs):
        from scheduler import KubeHTTPException
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
        self.assertEqual(response.status_code, 200, response.data)
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
        self.assertEqual(response.status_code, 200, response.data)
        instance = AddonInstance.objects.get(name='generic-abc123')
        self.assertEqual(instance.multiplier, 3)

    def test_generic_multiplier_from_defaults(self):
        response = self._upsert_generic('generic-abc123')
        self.assertEqual(response.status_code, 200, response.data)
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
        self.assertEqual(response.status_code, 200, response.data)
        instance = AddonInstance.objects.get(name='valkey-abc123')
        self.assertEqual(instance.multiplier, 1)

    def test_generic_nested_params_allowed(self):
        response = self._upsert_generic('generic-abc123', params={
            'replicas': 2,
            'persistence': {'enabled': True, 'size': '4Gi'},
        })
        self.assertEqual(response.status_code, 200, response.data)

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
        self.assertEqual(response.status_code, 200, response.data)
