import importlib
from types import SimpleNamespace
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.cache import cache

from api.exceptions import DryccException
from api.models.app import App
from api.models.build import Build
from api.models.gateway import Route
from api.models.release import Release
from api.models.service import Service
from api.tests import DryccTransactionTestCase
from scheduler import KubeException

User = get_user_model()


class ServiceTest(DryccTransactionTestCase):

    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = self.get_or_create_token(self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

    def tearDown(self):
        # make sure every test has a clean slate for k8s mocking
        cache.clear()

    def apply_service(self, app_id, name, ports, ptype='test', body_name=None,
                      body_ptype=None):
        return self.client.put(
            f'/v2/apps/{app_id}/services/{name}/',
            {
                'name': body_name or name,
                'ptype': body_ptype or ptype,
                'ports': ports,
            },
            format='json',
        )

    def assert_status(self, response, expected):
        self.assertEqual(response.status_code, expected, getattr(response, 'data', None))

    def assert_service_ports(self, service, expected):
        self.assertEqual(service.ports, expected)
        response = service.scheduler.svc.get(service.app.id, service.name)
        self.assertEqual(response.status_code, 200, response.json())
        self.assertEqual(response.json()['spec']['ports'], expected)

    def create_http_service_routes(self, app_id):
        ports = [{'port': 5000, 'protocol': 'TCP', 'target_port': 5000}]
        response = self.apply_service(app_id, 'shared-service', ports, ptype='task')
        self.assert_status(response, 201)
        response = self.apply_service(app_id, 'other-service', ports, ptype='task')
        self.assert_status(response, 201)
        for domain, ptype in (
                ('task.example.com', 'task'), ('worker.example.com', 'worker')):
            response = self.client.post(
                f'/v2/apps/{app_id}/domains/',
                {'domain': domain, 'ptype': ptype},
            )
            self.assert_status(response, 201)
        response = self.client.put(
            f'/v2/apps/{app_id}/gateways/shared-gateway/',
            {'name': 'shared-gateway', 'ports': [{'port': 5000, 'protocol': 'HTTP'}]},
            format='json',
        )
        self.assert_status(response, 201)
        app = App.objects.get(id=app_id)
        for name, backend in (('shared-route', 'shared-service'),
                              ('other-route', 'other-service')):
            route = Route(
                app=app,
                name=name,
                kind='HTTPRoute',
                rules=[{
                    'backendRefs': [{
                        'kind': 'Service',
                        'name': backend,
                        'port': 5000,
                    }],
                }],
                parent_refs=(
                    [{'name': 'shared-gateway', 'port': 5000}]
                    if name == 'shared-route' else []
                ),
            )
            route.save()
        return Service.objects.get(app__id=app_id, name='shared-service')

    def assert_route_domain(self, service, route_name, domain):
        response = service.scheduler.httproute.get(service.app.id, route_name)
        self.assertEqual(response.status_code, 200, response.json())
        parent_refs = response.json()['spec']['parentRefs']
        self.assertEqual(len(parent_refs), 1)
        self.assertEqual(parent_refs[0]['kind'], 'ListenerSet')
        self.assertEqual(parent_refs[0]['sectionName'], domain.replace('.', '-'))

    def test_service_basic_ops(self):
        app_id = self.create_app()
        collection_url = f'/v2/apps/{app_id}/services/'
        detail_url = f'/v2/apps/{app_id}/services/test-service/'
        ports = [
            {'port': 5000, 'protocol': 'UDP', 'target_port': 5000},
            {'port': 6000, 'protocol': 'TCP', 'target_port': 6000},
        ]

        response = self.client.get(collection_url)
        self.assert_status(response, 200)
        self.assertEqual(response.data.get('count'), 0)
        self.assertEqual(response.data['results'], [])

        response = self.client.post(collection_url, {}, format='json')
        self.assert_status(response, 405)
        response = self.client.delete(collection_url, {}, format='json')
        self.assert_status(response, 405)

        response = self.apply_service(app_id, 'test-service', ports)
        self.assert_status(response, 201)
        self.assertEqual(response.data['app'], app_id)
        self.assertEqual(response.data['name'], 'test-service')
        self.assertEqual(response.data['ptype'], 'test')
        self.assertEqual(response.data['domain'], f'test-service.{app_id}.svc')
        self.assertEqual(response.data['ports'], [
            {'name': 'udp-5000', 'port': 5000, 'protocol': 'UDP', 'target_port': 5000},
            {'name': 'tcp-6000', 'port': 6000, 'protocol': 'TCP', 'target_port': 6000},
        ])
        self.assertIsInstance(response.data['ports'][0]['port'], int)
        self.assertIsInstance(response.data['ports'][0]['target_port'], int)

        service = Service.objects.get(app__id=app_id, name='test-service')
        self.assert_service_ports(service, [
            {'name': 'udp-5000', 'port': 5000, 'protocol': 'UDP', 'targetPort': 5000},
            {'name': 'tcp-6000', 'port': 6000, 'protocol': 'TCP', 'targetPort': 6000},
        ])

        response = self.client.get(detail_url)
        self.assert_status(response, 200)
        self.assertEqual(response.data['name'], 'test-service')
        self.assertEqual(response.data['domain'], f'test-service.{app_id}.svc')
        response = self.client.get(collection_url)
        self.assertEqual(response.data.get('count'), 1)
        self.assertEqual(len(response.data['results']), 1)

        ports = [
            {'port': 5000, 'protocol': 'UDP', 'target_port': 5001},
            {'port': 7000, 'protocol': 'TCP', 'target_port': 7000},
        ]
        response = self.apply_service(app_id, 'test-service', ports)
        self.assert_status(response, 200)
        response = self.apply_service(app_id, 'test-service', ports)
        self.assert_status(response, 200)
        self.assertEqual(response.data['ports'], [
            {'name': 'udp-5000', 'port': 5000, 'protocol': 'UDP', 'target_port': 5001},
            {'name': 'tcp-7000', 'port': 7000, 'protocol': 'TCP', 'target_port': 7000},
        ])
        service.refresh_from_db()
        self.assert_service_ports(service, [
            {'name': 'udp-5000', 'port': 5000, 'protocol': 'UDP', 'targetPort': 5001},
            {'name': 'tcp-7000', 'port': 7000, 'protocol': 'TCP', 'targetPort': 7000},
        ])

        response = self.client.delete(detail_url)
        self.assert_status(response, 204)
        response = self.client.get(detail_url)
        self.assert_status(response, 404)
        response = self.client.delete(detail_url)
        self.assert_status(response, 404)
        response = self.client.get(collection_url)
        self.assertEqual(response.data.get('count'), 0)

    def test_service_allows_multiple_names_for_same_ptype(self):
        app_id = self.create_app()
        ports = [{'port': 5000, 'protocol': 'TCP', 'target_port': 5000}]

        response = self.apply_service(app_id, 'first-service', ports)
        self.assert_status(response, 201)
        response = self.apply_service(app_id, 'second-service', ports)
        self.assert_status(response, 201)

        services = Service.objects.filter(app__id=app_id, ptype='test')
        self.assertEqual(services.count(), 2)
        self.assertEqual(
            set(services.values_list('name', flat=True)),
            {'first-service', 'second-service'},
        )
        for service in services:
            k8s_service = service.scheduler.svc.get(app_id, service.name).json()
            self.assertEqual(k8s_service['spec']['selector']['type'], 'test')

    def test_service_same_name_can_exist_in_different_apps(self):
        first_app = self.create_app()
        second_app = self.create_app()
        ports = [{'port': 5000, 'protocol': 'TCP', 'target_port': 5000}]

        self.assert_status(self.apply_service(first_app, 'shared-name', ports), 201)
        self.assert_status(self.apply_service(second_app, 'shared-name', ports), 201)
        self.assertEqual(Service.objects.filter(name='shared-name').count(), 2)

    def test_service_same_port_allows_different_protocols(self):
        app_id = self.create_app()
        response = self.apply_service(app_id, 'test-service', [
            {'port': 80, 'protocol': 'TCP', 'target_port': 5000},
            {'port': 80, 'protocol': 'UDP', 'target_port': 5000},
        ])
        self.assert_status(response, 201)
        self.assertEqual(response.data['ports'], [
            {'name': 'tcp-80', 'port': 80, 'protocol': 'TCP', 'target_port': 5000},
            {'name': 'udp-80', 'port': 80, 'protocol': 'UDP', 'target_port': 5000},
        ])

        response = self.apply_service(app_id, 'test-service', [
            {'port': 80, 'protocol': 'TCP', 'target_port': 5000},
            {'port': 80, 'protocol': 'TCP', 'target_port': 5001},
        ])
        self.assert_status(response, 400)

    def test_service_ports_schema_validation(self):
        app_id = self.create_app()
        invalid_ports = [
            [],
            {},
            [{'port': 80, 'protocol': 'TCP'}],
            [{'port': 0, 'protocol': 'TCP', 'target_port': 80}],
            [{'port': 80, 'protocol': 'TLS', 'target_port': 80}],
            [{'name': 'tcp-80', 'port': 80, 'protocol': 'TCP', 'target_port': 80}],
            [{'port': 80, 'protocol': 'TCP', 'target_port': 80, 'node_port': 30080}],
        ]
        for ports in invalid_ports:
            with self.subTest(ports=ports):
                response = self.apply_service(app_id, 'test-service', ports)
                self.assert_status(response, 400)
        self.assertFalse(Service.objects.filter(app__id=app_id, name='test-service').exists())

    def test_service_name_is_required_and_url_name_is_authoritative(self):
        app_id = self.create_app()
        ports = [{'port': 80, 'protocol': 'TCP', 'target_port': 5000}]

        response = self.client.put(
            f'/v2/apps/{app_id}/services/test-service/',
            {'ptype': 'test', 'ports': ports},
            format='json',
        )
        self.assert_status(response, 400)

        response = self.apply_service(app_id, 'test-service', ports, body_name='other-service')
        self.assert_status(response, 201)
        self.assertEqual(response.data['name'], 'test-service')
        self.assertTrue(Service.objects.filter(app__id=app_id, name='test-service').exists())
        self.assertFalse(Service.objects.filter(app__id=app_id, name='other-service').exists())

    def test_service_url_name_is_validated(self):
        app_id = self.create_app()
        ports = [{'port': 80, 'protocol': 'TCP', 'target_port': 5000}]

        with mock.patch.object(Service, 'refresh_k8s_svc') as refresh:
            for name in ('default', 'drycc-system', 'x', 'a' * 64):
                with self.subTest(name=name):
                    response = self.apply_service(
                        app_id, name, ports, body_name='valid-name')
                    self.assert_status(response, 400)
            self.assertEqual(refresh.call_count, 0)
        self.assertFalse(Service.objects.filter(app__id=app_id).exists())

    def test_service_ptype_update_keeps_name_and_refreshes_routes(self):
        app_id = self.create_app()
        ports = [{'port': 5000, 'protocol': 'TCP', 'target_port': 5000}]
        response = self.apply_service(app_id, 'shared-service', ports, ptype='task')
        self.assert_status(response, 201)
        response = self.client.put(
            f'/v2/apps/{app_id}/routes/shared-route/',
            {
                'name': 'shared-route',
                'kind': 'TCPRoute',
                'rules': [{
                    'backend_refs': [{
                        'kind': 'Service',
                        'name': 'shared-service',
                        'port': 5000,
                    }],
                }],
                'parent_refs': [],
            },
            format='json',
        )
        self.assert_status(response, 201)

        with mock.patch.object(Route, 'refresh_to_k8s', autospec=True) as refresh:
            response = self.apply_service(app_id, 'shared-service', ports, ptype='worker')
        self.assert_status(response, 200)
        self.assertEqual(refresh.call_count, 1)
        service = Service.objects.get(app__id=app_id, name='shared-service')
        self.assertEqual(service.ptype, 'worker')
        k8s_service = service.scheduler.svc.get(app_id, service.name).json()
        self.assertEqual(k8s_service['spec']['selector']['type'], 'worker')

    def test_service_ptype_update_refreshes_domain_parent_refs(self):
        app_id = self.create_app()
        service = self.create_http_service_routes(app_id)
        self.assert_route_domain(service, 'shared-route', 'task.example.com')
        original_refresh = Route.refresh_to_k8s
        refreshed = []

        def record_refresh(route):
            refreshed.append(route.name)
            return original_refresh(route)

        with mock.patch.object(
                Route, 'refresh_to_k8s', autospec=True, side_effect=record_refresh):
            service.ptype = 'worker'
            service.save()

        self.assertEqual(refreshed, ['shared-route'])
        self.assert_route_domain(service, 'shared-route', 'worker.example.com')

    def test_route_refresh_failure_restores_previous_ptype(self):
        app_id = self.create_app()
        service = self.create_http_service_routes(app_id)
        original_refresh = Route.refresh_to_k8s
        calls = []

        def fail_first_refresh(route):
            calls.append(route.name)
            if len(calls) == 1:
                raise KubeException('route refresh failed')
            return original_refresh(route)

        service.ptype = 'worker'
        with mock.patch.object(
                Route, 'refresh_to_k8s', autospec=True, side_effect=fail_first_refresh):
            with self.assertRaises(KubeException):
                service.save()

        service.refresh_from_db()
        self.assertEqual(service.ptype, 'task')
        k8s_service = service.scheduler.svc.get(app_id, service.name).json()
        self.assertEqual(k8s_service['spec']['selector']['type'], 'task')
        self.assert_route_domain(service, 'shared-route', 'task.example.com')
        self.assertEqual(calls, ['shared-route', 'shared-route'])

    def test_default_ingress_rejects_conflicting_service_name(self):
        app_id = self.create_app()
        ports = [{'port': 5000, 'protocol': 'TCP', 'target_port': 5000}]
        response = self.apply_service(app_id, app_id, ports, ptype='task')
        self.assert_status(response, 201)
        app = App.objects.get(id=app_id)

        with self.assertRaises(DryccException):
            app._create_default_ingress(5000)

    def test_deploy_preflights_default_service_conflict(self):
        app_id = self.create_app()
        ports = [{'port': 5000, 'protocol': 'TCP', 'target_port': 5000}]
        response = self.apply_service(app_id, app_id, ports, ptype='task')
        self.assert_status(response, 201)
        app = App.objects.get(id=app_id)
        build = Build.objects.create(app=app, image='qwerty')
        release = Release.objects.create(
            version=2,
            app=app,
            config=app.config_set.latest(),
            build=build,
        )

        with mock.patch('api.models.app.apply_tasks') as apply_tasks:
            release.deploy()

        apply_tasks.assert_not_called()
        release.refresh_from_db()
        self.assertTrue(release.failed)
        self.assertIn(app_id, release.conditions[-1]['exception'])
        self.assertIn('task', release.conditions[-1]['exception'])

    def test_deploy_checks_every_service_for_ptype(self):
        app_id = self.create_app()
        app = App.objects.get(id=app_id)
        build = Build.objects.create(app=app, image='qwerty')
        release = Release.objects.create(
            version=2,
            app=app,
            config=app.config_set.latest(),
            build=build,
        )
        ports = [{'port': 5000, 'protocol': 'TCP', 'target_port': 5000}]
        for name in ('custom-web-a', 'custom-web-b'):
            response = self.apply_service(app_id, name, ports, ptype='web')
            self.assert_status(response, 201)

        with mock.patch.object(App, 'verify_http_health', autospec=True) as health:
            release.deploy()

        self.assertEqual(health.call_count, 3)
        self.assertEqual(
            {call.args[1].name for call in health.call_args_list},
            {app_id, 'custom-web-a', 'custom-web-b'},
        )


class ServiceMigrationTest(DryccTransactionTestCase):

    def test_backfill_service_names_uses_legacy_rules(self):
        migration = importlib.import_module('api.migrations.0034_service_name')

        class HistoricalServiceInstance:
            def __init__(self, app_id, ptype):
                self.app_id = f'{app_id}-uuid'
                self.app = SimpleNamespace(id=app_id)
                self.ptype = ptype
                self.name = None
                self.saved = False

            def save(self, update_fields):
                self.saved = update_fields == ['name']

        services = [
            HistoricalServiceInstance('example-app', 'web'),
            HistoricalServiceInstance('example-app', 'worker'),
        ]

        class Objects:
            def all(self):
                return services

        class HistoricalService:
            objects = Objects()

        class Apps:
            @staticmethod
            def get_model(app_label, model_name):
                return HistoricalService

        migration.backfill_service_names(Apps(), None)

        self.assertEqual([service.name for service in services], [
            'example-app',
            'example-app-worker',
        ])
        self.assertTrue(all(service.saved for service in services))
