import os
import json
import string
import random
from django.contrib.auth import get_user_model
from django.core.cache import cache
from jsonschema.exceptions import ValidationError

from api.models.app import App
from api.models.base import PTYPE_WEB
from api.models.build import Build
from api.models.gateway import Gateway, Route
from api.models.release import Release
from api.utils import validate_json
from api.tests import TEST_ROOT, DryccTransactionTestCase
from api.serializers.schemas.rules import SCHEMA as RULES_SCHEMA

User = get_user_model()


class BaseGatewayTest(DryccTransactionTestCase):
    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = self.get_or_create_token(self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

    def tearDown(self):
        # make sure every test has a clean slate for k8s mocking
        cache.clear()

    def create_app_with_domain_and_deploy(self):
        app_id = self.create_app()
        response = self.client.post(
            '/v2/apps/{}/domains'.format(app_id),
            {'domain': 'test-domain.example.com', 'ptype': PTYPE_WEB}
        )
        self.assertEqual(response.status_code, 201, response.data)
        # check default gateway route
        response = self.client.get('/v2/apps/{}/gateways/'.format(app_id))
        self.assertEqual(len(response.data["results"]), 0, response.data)
        response = self.client.get('/v2/apps/{}/routes/'.format(app_id))
        self.assertEqual(len(response.data["results"]), 0, response.data)
        # create a release so we can scale
        app = App.objects.get(id=app_id)
        build = Build.objects.create(app=app, image="qwerty")

        # create an initial release
        release = Release.objects.create(
            version=2,
            app=app,
            config=app.config_set.latest(),
            build=build
        )
        # deploy
        release.deploy()
        return app_id

    def change_certs_auto(self, app_id, enabled):
        data = {'certs_auto_enabled': enabled}
        response = self.client.post(f'/v2/apps/{app_id}/tls', data)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data.get('certs_auto_enabled'), enabled, response.data)

    def create_gateway(self, app_id, name, port, protocol):
        response = self.client.put(
            '/v2/apps/{}/gateways/{}/'.format(app_id, name),
            {'app': app_id, 'name': name, 'ports': [{'port': port, 'protocol': protocol}]},
            format='json'
        )
        self.assertEqual(response.status_code, 201)

    def create_gateway_name(self):
        app_id = self.create_app()
        name1 = 'gatway_'
        response = self.client.put(
            f'/v2/apps/{app_id}/gateways/{name1}/',
            {'app': app_id, 'name': name1, 'ports': [{'port': 80, 'protocol': 'HTTP'}]}
        )
        self.assertEqual(response.status_code, 400)
        name2 = '-gatway'
        response = self.client.put(
            f'/v2/apps/{app_id}/gateways/{name2}/',
            {'app': app_id, 'name': name2, 'ports': [{'port': 80, 'protocol': 'HTTP'}]}
        )
        self.assertEqual(response.status_code, 400)
        name3 = 'test.gatway'
        response = self.client.put(
            f'/v2/apps/{app_id}/gateways/{name3}/',
            {'app': app_id, 'name': name3, 'ports': [{'port': 80, 'protocol': 'HTTP'}]}
        )
        self.assertEqual(response.status_code, 400)

    def create_tls_domain(self, app_id):
        cert_url = f'/v2/apps/{app_id}/certs'
        secret_name = ''.join(random.choice(string.ascii_lowercase) for _ in range(23))
        domain = 'autotest.example.com'

        with open('{}/certs/{}.key'.format(TEST_ROOT, domain)) as f:
            key = f.read()

        with open('{}/certs/{}.cert'.format(TEST_ROOT, domain)) as f:
            cert = f.read()
        response = self.client.post(
            cert_url,
            {
                'name': secret_name,
                'certificate': cert,
                'key': key
            }
        )
        self.assertEqual(response.status_code, 201)

        response = self.client.post(
            '/v2/apps/{}/domains'.format(app_id),
            {'domain': domain, 'ptype': PTYPE_WEB}
        )
        self.assertEqual(response.status_code, 201)
        response = self.client.post(
            '{}/{}/domain/'.format(cert_url, secret_name),
            {'domain': domain}
        )
        self.assertEqual(response.status_code, 201)
        return domain, secret_name


class GatewayTest(BaseGatewayTest):

    """Tests push notification from build system"""

    def test_create_gateway(self):
        app_id = self.create_app()
        self.create_gateway(app_id, 'bing-gateway', 8000, "HTTP")
        response = self.client.get('/v2/apps/{}/gateways/'.format(app_id))
        self.assertEqual(response.data["count"], 1, response.data)

    def test_add_gateway_port(self):
        app_id = self.create_app()
        gateway_name = 'bing-gateway'
        self.create_gateway(app_id, gateway_name, 8000, "HTTP")
        response = self.client.put(
            '/v2/apps/{}/gateways/{}/'.format(app_id, gateway_name),
            {'app': app_id, 'name': gateway_name, 'ports': [
                {'port': 8000, 'protocol': "HTTP"},
                {'port': 443, 'protocol': "HTTP"},
            ]},
            format='json'
        )
        self.assertEqual(response.status_code, 200)
        response = self.client.get('/v2/apps/{}/gateways/'.format(app_id))
        actual = None
        for result in response.data["results"]:
            if result["name"] == gateway_name:
                actual = json.loads(json.dumps(result))
                break
        self.assertEqual(actual["app"], app_id)
        self.assertEqual(actual["name"], gateway_name)
        self.assertEqual(actual["ports"], [
            {"port": 8000, "protocol": "HTTP"},
            {"port": 443, "protocol": "HTTP"},
        ])
        self.assertEqual(actual["addresses"], [{
            "type": "IPAddress",
            "value": "172.22.108.207"
        }])

    def add_gateway_port(self, app_id, name, protocol, port):
        # get existing gateway ports, then append the new one
        response = self.client.get('/v2/apps/{}/gateways/'.format(app_id))
        existing_ports = []
        for gw in response.data.get("results", []):
            if gw["name"] == name:
                existing_ports = [
                    {"port": p["port"], "protocol": p["protocol"]}
                    for p in gw.get("ports", [])
                ]
                break
        ports = existing_ports + [{"port": port, "protocol": protocol}]
        response = self.client.put(
            '/v2/apps/{}/gateways/{}/'.format(app_id, name),
            {'app': app_id, 'name': name, 'ports': ports},
            format='json'
        )
        self.assertEqual(response.status_code, 201)
        response = self.client.get('/v2/apps/{}/gateways/'.format(app_id))
        return app_id, response.data["results"]

    def add_tls_gateway_port(self, name, protocol, port):
        app_id = self.create_app(name)
        domain, secret_name = self.create_tls_domain(app_id)
        app_id, results = self.add_gateway_port(app_id, name, protocol, port)
        return app_id, domain, secret_name, results

    def test_add_gateway_tls_port(self):
        port = 443
        name = "tls-gateway"
        _, _, _, results = self.add_tls_gateway_port(name, "TLS", port)
        self.assertEqual(results[0]['app'], name)
        self.assertEqual(results[0]['name'], name)
        self.assertEqual(results[0]['ports'], [{'port': 443, 'protocol': 'TLS'}])
        self.assertEqual(
            results[0]['addresses'], [{'type': 'IPAddress', 'value': '172.22.108.207'}])

    def test_add_gateway_https_port(self):
        port = 443
        name = "bingo-gateway"
        _, _, _, results = self.add_tls_gateway_port(name, "HTTPS", port)
        self.assertEqual(results[0]['app'], name)
        self.assertEqual(results[0]['name'], name)
        self.assertEqual(results[0]['ports'], [{'port': port, 'protocol': 'HTTPS'}])
        self.assertEqual(
            results[0]['addresses'], [{'type': 'IPAddress', 'value': '172.22.108.207'}])

    def test_add_gateway_http_port(self):
        port = 80
        name = "bingo-gateway"
        _, _, _, results = self.add_tls_gateway_port(name, "HTTP", port)
        self.assertEqual(results[0]['app'], 'bingo-gateway')
        self.assertEqual(results[0]['name'], 'bingo-gateway')
        self.assertEqual(results[0]['ports'], [
            {'port': 80, 'protocol': 'HTTP'},
            {'port': 443, 'protocol': 'HTTPS'},
        ])
        self.assertEqual(
            results[0]['addresses'], [{'type': 'IPAddress', 'value': '172.22.108.207'}])

    def test_add_gateway_udp_port(self):
        port = 999
        name = "bingo-gateway"
        app_id = self.create_app(name)
        _, results = self.add_gateway_port(app_id, name, "UDP", port)
        self.assertEqual(results[0]['app'], 'bingo-gateway')
        self.assertEqual(results[0]['name'], 'bingo-gateway')
        self.assertEqual(results[0]['ports'], [{'port': 999, 'protocol': 'UDP'}])
        self.assertEqual(
            results[0]['addresses'], [{'type': 'IPAddress', 'value': '172.22.108.207'}])

    def test_remove_domain_cleans_gateway_ports(self):
        app_id, domain, _, _ = self.add_tls_gateway_port("bingo-gateway", "HTTPS", 443)
        url = '/v2/apps/{app_id}/domains/{domain}'.format(domain=domain,
                                                          app_id=app_id)
        response = self.client.delete(url)
        self.assertEqual(response.status_code, 204)

        response = self.client.get('/v2/apps/{}/gateways/'.format(app_id))
        self.assertEqual(response.data["results"][0]["ports"], [])

    def test_remove_certificate_cleans_gateway_ports(self):
        app_id, domain, secret_name, _ = self.add_tls_gateway_port("bingo-gateway", "HTTPS", 443)
        response = self.client.get('/v2/apps/{}/gateways/'.format(app_id))
        self.assertEqual(len(response.data["results"][0]["ports"]), 1)
        response = self.client.delete(
            '{}/{}/domain/{}/'.format(f'/v2/apps/{app_id}/certs', secret_name, domain)
        )
        self.assertEqual(response.status_code, 204)
        response = self.client.get('/v2/apps/{}/gateways/'.format(app_id))
        self.assertEqual(response.data["results"][0]["ports"], [])
        return app_id

    def test_enable_auto_certs_restores_gateway_https_port(self):
        app_id = self.test_remove_certificate_cleans_gateway_ports()
        data = {'certs_auto_enabled': True}
        response = self.client.post(
            '/v2/apps/{}/tls'.format(app_id),
            data)
        self.assertEqual(response.status_code, 201, response.data)
        response = self.client.get('/v2/apps/{}/gateways/'.format(app_id))
        self.assertEqual(len(response.data["results"][0]["ports"]), 1)

    def test_remove_gateway_port(self):
        app_id = self.create_app()
        self.create_gateway(app_id, 'bing-gateway', 8000, "HTTP")
        response = self.client.get('/v2/apps/{}/gateways/'.format(app_id))
        self.assertEqual(response.data["count"], 1, response.data)
        # delete
        response = self.client.delete(
            '/v2/apps/{}/gateways/{}/'.format(app_id, 'bing-gateway')
        )
        self.assertEqual(response.status_code, 204)
        response = self.client.get('/v2/apps/{}/gateways/'.format(app_id))
        self.assertEqual(response.data["count"], 0, response.data)

    def test_gateway_tls_changes_default_ports(self):
        app_id = self.create_app_with_domain_and_deploy()
        response = self.client.get('/v2/apps/{}/gateways/'.format(app_id))
        expect = [{
            "port": 80,
            "protocol": "HTTP"
        }]
        self.assertEqual(response.data["count"], 1, response.data)
        self.assertEqual(response.data["results"][0]["ports"], expect, response.data)

        self.change_certs_auto(app_id, True)
        response = self.client.get('/v2/apps/{}/gateways/'.format(app_id))
        self.assertEqual(response.data["count"], 1, response.data)
        gw = response.data["results"][0]
        self.assertEqual(gw['app'], app_id)
        self.assertEqual(gw['name'], app_id)
        self.assertEqual(gw['ports'], [
            {'port': 80, 'protocol': 'HTTP'},
            {'port': 443, 'protocol': 'HTTPS'},
        ])
        self.assertEqual(gw['addresses'], [{'type': 'IPAddress', 'value': '172.22.108.207'}])

        self.change_certs_auto(app_id, False)
        response = self.client.get('/v2/apps/{}/gateways/'.format(app_id))
        expect = [{
            "port": 80,
            "protocol": "HTTP"
        }]
        self.assertEqual(response.data["count"], 1, response.data)
        self.assertEqual(response.json()["results"][0]["ports"], expect, response.data)


class RouteTest(BaseGatewayTest):

    def create_route(self, app_id, route_name="test-route",
                     ptype="task", kind="HTTPRoute"):
        # create service
        port = 5000
        response = self.client.post(
            '/v2/apps/{}/services'.format(app_id),
            {
                'port': port,
                'protocol': 'TCP',
                'target_port': port,
                'ptype': ptype
            }
        )
        self.assertEqual(response.status_code, 201, response.data)
        # create route
        response = self.client.put(
            '/v2/apps/{}/routes/{}/'.format(app_id, route_name),
            {
                "app": app_id,
                "kind": kind,
                "name": route_name,
                "rules": [{
                    "backendRefs": [{
                        "kind": "Service",
                        "name": f"{app_id}-{ptype}",
                        "port": 5000,
                        "weight": 100,
                    }],
                }],
                "parent_refs": [],
            }
        )
        self.assertEqual(response.status_code, 201, response.data)
        return ptype, port, route_name

    def test_create_route(self):
        app_id = self.create_app()
        self.create_route(app_id)
        # create route error - missing required fields
        response = self.client.put(
            '/v2/apps/{}/routes/test-route-1/'.format(app_id),
            {
                "app": app_id,
                "port": 5000,
                "ptype": "no-exists",
                "kind": "HTTPRoute",
                "name": "test-route-1",
            }
        )
        self.assertEqual(response.status_code, 400)
        response = self.client.get('/v2/apps/{}/routes/'.format(app_id))
        self.assertEqual(response.data["count"], 1)
        self.assertEqual(len(response.data["results"][0]["rules"]), 1)

        # name regex format
        name1 = "test-route-a"
        response = self.client.put(
            '/v2/apps/{}/routes/{}/'.format(app_id, name1),
            {
                "app": app_id,
                "port": 5000,
                "ptype": "no-exists",
                "kind": "HTTPRoute",
                "name": name1,
            }
        )
        self.assertEqual(response.status_code, 400)
        # name regex format - invalid names no longer tested via URL since regex handles it
        # test missing required fields instead
        name2 = "test-route-missing-rules"
        response = self.client.put(
            '/v2/apps/{}/routes/{}/'.format(app_id, name2),
            {
                "app": app_id,
                "kind": "HTTPRoute",
                "name": name2,
                "parent_refs": [],
            }
        )
        self.assertEqual(response.status_code, 400)
        name3 = "test-route-missing-kind"
        response = self.client.put(
            '/v2/apps/{}/routes/{}/'.format(app_id, name3),
            {
                "app": app_id,
                "name": name3,
                "rules": [],
                "parent_refs": [],
            }
        )
        self.assertEqual(response.status_code, 400)

    def test_route_upsert_parent_refs(self):
        app_id = self.create_app()
        ptype, port, route_name = self.create_route(app_id)
        gateway_name_1 = 'bing-gateway-1'
        self.create_gateway(app_id, gateway_name_1, 5000, "HTTP")
        response = self.client.put(
            '/v2/apps/{}/routes/{}/'.format(app_id, route_name),
            {
                "app": app_id,
                "name": route_name,
                "kind": "HTTPRoute",
                "rules": [{
                    "backendRefs": [{
                        "kind": "Service",
                        "name": f"{app_id}-{ptype}",
                        "port": port,
                        "weight": 100,
                    }],
                }],
                "parent_refs": [{
                    "name": gateway_name_1,
                    "port": port,
                }],
            },
            format='json'
        )
        self.assertEqual(response.status_code, 200, response.data)
        response = self.client.get('/v2/apps/{}/routes/'.format(app_id))
        self.assertEqual(len(response.data["results"][0]["parent_refs"]), 1)
        gateway_name_2 = 'bing-gateway-2'
        self.create_gateway(app_id, gateway_name_2, 5000, "HTTP")
        response = self.client.put(
            '/v2/apps/{}/routes/{}/'.format(app_id, route_name),
            {
                "app": app_id,
                "name": route_name,
                "kind": "HTTPRoute",
                "rules": [{
                    "backendRefs": [{
                        "kind": "Service",
                        "name": f"{app_id}-{ptype}",
                        "port": port,
                        "weight": 100,
                    }],
                }],
                "parent_refs": [
                    {
                        "name": gateway_name_1,
                        "port": port,
                    },
                    {
                        "name": gateway_name_2,
                        "port": port,
                    },
                ],
            },
            format='json'
        )
        self.assertEqual(response.status_code, 200, response.data)
        response = self.client.get('/v2/apps/{}/routes/'.format(app_id))
        self.assertEqual(len(response.data["results"][0]["parent_refs"]), 2)
        return ptype, app_id, gateway_name_1, gateway_name_2, port, route_name

    def test_route_upsert_accepts_valid_parent_refs(self):
        app_id = self.create_app()
        _, port, route_name = self.create_route(app_id, "myroute1", "test")
        gateway_name_1 = 'bing-gateway-1'
        self.create_gateway(app_id, gateway_name_1, 5000, "HTTP")
        response = self.client.put(
            '/v2/apps/{}/routes/{}/'.format(app_id, route_name),
            {
                "app": app_id,
                "name": route_name,
                "kind": "HTTPRoute",
                "rules": [{
                    "backendRefs": [{
                        "kind": "Service",
                        "name": f"{app_id}-test",
                        "port": port,
                        "weight": 100,
                    }],
                }],
                "parent_refs": [{
                    "name": gateway_name_1,
                    "port": port,
                }],
            },
            format='json'
        )
        self.assertEqual(response.status_code, 200, response.data)
        response = self.client.get('/v2/apps/{}/routes/'.format(app_id))
        self.assertEqual(len(response.data["results"][0]["parent_refs"]), 1)
        # create other route
        _, port, route_name = self.create_route(app_id, "myroute2", "mytest")
        response = self.client.put(
            '/v2/apps/{}/routes/{}/'.format(app_id, route_name),
            {
                "app": app_id,
                "name": route_name,
                "kind": "HTTPRoute",
                "rules": [{
                    "backendRefs": [{
                        "kind": "Service",
                        "name": f"{app_id}-mytest",
                        "port": port,
                        "weight": 100,
                    }],
                }],
                "parent_refs": [{
                    "name": gateway_name_1,
                    "port": port,
                }],
            },
            format='json'
        )
        self.assertEqual(response.status_code, 200, response.data)

    def test_route_upsert_rejects_conflicting_parent_refs(self):
        app_id = self.create_app()
        _, port, route_name = self.create_route(app_id, "myroute1", "test", "TCPRoute")
        gateway_name_1 = 'bing-gateway-1'
        self.create_gateway(app_id, gateway_name_1, 5000, "TCP")
        response = self.client.put(
            '/v2/apps/{}/routes/{}/'.format(app_id, route_name),
            {
                "app": app_id,
                "name": route_name,
                "kind": "TCPRoute",
                "rules": [{
                    "backendRefs": [{
                        "kind": "Service",
                        "name": f"{app_id}-test",
                        "port": port,
                        "weight": 100,
                    }],
                }],
                "parent_refs": [{
                    "name": gateway_name_1,
                    "port": port,
                }],
            },
            format='json'
        )
        self.assertEqual(response.status_code, 200, response.data)
        response = self.client.get('/v2/apps/{}/routes/'.format(app_id))
        self.assertEqual(len(response.data["results"][0]["parent_refs"]), 1)
        # create other route
        _, port, route_name = self.create_route(app_id, "myroute2", "mytest", "TCPRoute")
        response = self.client.put(
            '/v2/apps/{}/routes/{}/'.format(app_id, route_name),
            {
                "app": app_id,
                "name": route_name,
                "kind": "TCPRoute",
                "rules": [{
                    "backendRefs": [{
                        "kind": "Service",
                        "name": f"{app_id}-mytest",
                        "port": port,
                        "weight": 100,
                    }],
                }],
                "parent_refs": [{
                    "name": gateway_name_1,
                    "port": port,
                }],
            },
            format='json'
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.data['non_field_errors'][0], 'this listener has already been referenced')

    def test_route_upsert_remove_parent_refs(self):
        ptype, app_id, _, gateway_name_2, port, route_name = self.test_route_upsert_parent_refs()
        response = self.client.put(
            '/v2/apps/{}/routes/{}/'.format(app_id, route_name),
            {
                "app": app_id,
                "name": route_name,
                "kind": "HTTPRoute",
                "rules": [{
                    "backendRefs": [{
                        "kind": "Service",
                        "name": f"{app_id}-{ptype}",
                        "port": port,
                        "weight": 100,
                    }],
                }],
                "parent_refs": [{
                    "name": gateway_name_2,
                    "port": port,
                }],
            },
            format='json'
        )
        self.assertEqual(response.status_code, 200, response.data)
        response = self.client.get('/v2/apps/{}/routes/'.format(app_id))
        self.assertEqual(len(response.data["results"][0]["parent_refs"]), 1)

        response = self.client.put(
            '/v2/apps/{}/routes/{}/'.format(app_id, route_name),
            {
                "app": app_id,
                "name": route_name,
                "kind": "HTTPRoute",
                "rules": [{
                    "backendRefs": [{
                        "kind": "Service",
                        "name": f"{app_id}-{ptype}",
                        "port": port,
                        "weight": 100,
                    }],
                }],
                "parent_refs": [],
            },
            format='json'
        )
        self.assertEqual(response.status_code, 200, response.data)
        response = self.client.get('/v2/apps/{}/routes/'.format(app_id))
        self.assertEqual(len(response.data["results"][0]["parent_refs"]), 0)

    def test_app_settings_change_routable(self):
        _, app_id, _, _, _, route_name = self.test_route_upsert_parent_refs()
        # Set routable to false
        response = self.client.post(
            f'/v2/apps/{app_id}/settings',
            {'routable': False}
        )
        self.assertEqual(response.status_code, 201, response.data)
        app = App.objects.get(id=app_id)
        response = app.scheduler.httproute.get(app_id, route_name, ignore_exception=True)
        self.assertEqual(response.status_code, 404)
        # Set routable to false
        response = self.client.post(
            f'/v2/apps/{app_id}/settings',
            {'routable': True}
        )
        response = app.scheduler.httproute.get(app_id, route_name, ignore_exception=True)
        self.assertEqual(response.status_code, 200)

    def test_route_delete(self):
        app_id = self.create_app()
        _, _, route_name = self.create_route(app_id)
        response = self.client.get('/v2/apps/{}/routes/'.format(app_id))
        self.assertEqual(len(response.data["results"]), 1)
        response = self.client.delete(
            '/v2/apps/{}/routes/{}/'.format(app_id, route_name),
        )
        self.assertEqual(response.status_code, 204)
        response = self.client.get('/v2/apps/{}/routes/'.format(app_id))
        self.assertEqual(len(response.data["results"]), 0)

    def test_route_rules_get_returns_backendRefs_for_api(self):
        app_id = self.create_app()
        ptype, _, route_name = self.create_route(app_id)
        response = self.client.get(
            '/v2/apps/{}/routes/{}/'.format(app_id, route_name),
        )
        expect = [{
            'backendRefs': [{
                'kind': 'Service',
                'name': '%s-%s' % (app_id, ptype),
                'port': 5000,
                'weight': 100
            }]
        }]
        self.assertEqual(response.data["rules"], expect)

    def test_route_rule_schemas(self):
        for rule in os.listdir("{}/rules/".format(TEST_ROOT)):
            with open("{}/rules/{}".format(TEST_ROOT, rule)) as f:
                data = f.read()
                try:
                    validate_json(json.loads(data), RULES_SCHEMA)
                except Exception as e:
                    raise self.failureException("validate %s rule error: %s" % (rule, str(e)))

    def test_route_rules_set_accepts_backendRefs_for_storage(self):
        app_id = self.create_app()
        ptype, _, route_name = self.create_route(app_id)
        expect = [{
            "backendRefs": [{
                "kind": "Service",
                "name": "%s-%s" % (app_id, ptype),
                "port": 5000,
                "weight": 100
            }]
        }]
        response = self.client.put(
            '/v2/apps/{}/routes/{}/'.format(app_id, route_name),
            {
                "app": app_id,
                "name": route_name,
                "kind": "HTTPRoute",
                "rules": expect,
                "parent_refs": [],
            },
            format='json',
        )
        self.assertEqual(response.status_code, 200)
        response = self.client.get(
            '/v2/apps/{}/routes/{}/'.format(app_id, route_name),
        )
        self.assertEqual(response.data["rules"], expect)
        expect_invalid = [{
            "backendRefs": [{
                "kind": "Service",
                "name": "%s-%s-noexits" % (app_id, ptype),
                "port": 5000,
                "weight": 100
            }]
        }]
        response = self.client.put(
            '/v2/apps/{}/routes/{}/'.format(app_id, route_name),
            {
                "app": app_id,
                "name": route_name,
                "kind": "HTTPRoute",
                "rules": expect_invalid,
                "parent_refs": [],
            },
            format='json',
        )
        self.assertEqual(response.status_code, 400)

    def test_route_serializer_accepts_backendRefs_input(self):
        app_id = self.create_app()
        ptype, port, route_name = self.create_route(app_id)
        gateway_name = 'bing-gateway-1'
        self.create_gateway(app_id, gateway_name, port, "HTTP")
        response = self.client.put(
            '/v2/apps/{}/routes/{}/'.format(app_id, route_name),
            {
                "app": app_id,
                "name": route_name,
                "kind": "HTTPRoute",
                "rules": [{
                    "backendRefs": [{
                        "kind": "Service",
                        "name": f"{app_id}-{ptype}",
                        "port": port,
                        "weight": 10,
                    }],
                }],
                "parent_refs": [{
                    "name": gateway_name,
                    "port": port,
                }],
            },
            format='json'
        )
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(
            response.data["rules"],
            [{
                "backendRefs": [{
                    "kind": "Service",
                    "name": f"{app_id}-{ptype}",
                    "port": port,
                    "weight": 10,
                }],
            }],
            response.data,
        )

    def test_route_tls_changes_default_parent_refs(self):
        app_id = self.create_app_with_domain_and_deploy()
        response = self.client.get('/v2/apps/{}/routes/'.format(app_id))
        self.assertEqual(len(response.data["results"]), 1, response.data)
        expect = [{
            'name': f'{app_id}',
            'port': 80
        }]
        # enable tls
        self.change_certs_auto(app_id, True)
        self.assertEqual(response.data["results"][0]["parent_refs"], expect, response.data)
        response = self.client.get('/v2/apps/{}/routes/'.format(app_id))
        self.assertEqual(len(response.data["results"]), 1, response.data)
        expect = [{
            'name': f'{app_id}',
            'port': 80
        }, {
            'name': f'{app_id}',
            'port': 443
        }]
        self.assertEqual(len(response.data["results"]), 1, response.data)
        self.assertEqual(response.data["results"][0]["parent_refs"], expect, response.data)
        # disable tls
        self.change_certs_auto(app_id, False)
        response = self.client.get('/v2/apps/{}/routes/'.format(app_id))
        self.assertEqual(len(response.data["results"]), 1, response.data)
        expect = [{
            'name': f'{app_id}',
            'port': 80
        }]
        self.assertEqual(len(response.data["results"]), 1, response.data)
        self.assertEqual(response.data["results"][0]["parent_refs"], expect, response.data)

    def test_route_parent_refs_with_listener_sets(self):
        app_id = self.create_app_with_domain_and_deploy()
        response = self.client.get('/v2/apps/{}/routes/'.format(app_id))
        self.assertEqual(len(response.data["results"]), 1, response.data)
        expect = [{
            'name': f'{app_id}',
            'port': 80
        }]
        # enable tls
        self.change_certs_auto(app_id, True)
        self.assertEqual(response.data["results"][0]["parent_refs"], expect, response.data)
        response = self.client.get('/v2/apps/{}/routes/'.format(app_id))
        self.assertEqual(len(response.data["results"]), 1, response.data)
        expect = [{
            'name': f'{app_id}',
            'port': 80
        }, {
            'name': f'{app_id}',
            'port': 443
        }]
        self.assertEqual(len(response.data["results"]), 1, response.data)
        self.assertEqual(response.data["results"][0]["parent_refs"], expect, response.data)
        # add new domain
        ptype, kind, route_name, domain = (
            'gateway', "HTTPRoute", "myroute-1", 'test-domain-gateway.example.com')
        response = self.client.post(
            '/v2/apps/{}/domains'.format(app_id),
            {'domain': domain, 'ptype': ptype}
        )
        self.assertEqual(response.status_code, 201, response.data)
        # add new services
        response = self.client.post(
            '/v2/apps/{}/services'.format(app_id),
            {
                'port': 9999,
                'protocol': 'TCP',
                'target_port': 9999,
                'ptype': 'gateway'
            }
        )
        self.assertEqual(response.status_code, 201, response.data)
        # add new router
        response = self.client.put(
            '/v2/apps/{}/routes/{}/'.format(app_id, route_name),
            {
                "app": app_id,
                "kind": kind,
                "name": route_name,
                "rules": [{
                    "backendRefs": [{
                        "kind": "Service",
                        "name": f"{app_id}-{ptype}",
                        "port": 9999,
                        "weight": 100,
                    }],
                }],
                "parent_refs": [],
            },
            format='json'
        )
        self.assertEqual(response.status_code, 201, response.data)
        response = self.client.put(
            '/v2/apps/{}/routes/{}/'.format(app_id, route_name),
            {
                "app": app_id,
                "name": route_name,
                "kind": kind,
                "rules": [{
                    "backendRefs": [{
                        "kind": "Service",
                        "name": f"{app_id}-{ptype}",
                        "port": 9999,
                        "weight": 100,
                    }],
                }],
                "parent_refs": [{
                    "name": app_id,
                    "port": 443,
                }],
            },
            format='json'
        )
        self.assertEqual(response.status_code, 200, response.data)
        route = Route.objects.get(name=route_name)
        response = route.scheduler.httproutes.get(app_id, route_name)
        self.assertEqual(response.status_code, 200, response.json())
        self.assertEqual(len(response.json()['spec']['parentRefs']), 1)
        # get gateway
        response = route.scheduler.gateways.get(app_id, app_id)
        listeners = [
            listener for listener in response.json()['spec']['listeners']
            if listener['port'] == 443
        ]
        self.assertEqual(len(listeners), 1)
        self.assertNotIn('hostname', listeners[0])
        ls_name = f"{app_id}-https-443"
        ls_response = route.scheduler.listenersets.get(app_id, ls_name)
        self.assertEqual(ls_response.status_code, 200)
        ls_hostnames = [
            entry['hostname'] for entry in ls_response.json()['spec']['listeners']
        ]
        self.assertIn(domain, ls_hostnames)

    def test_refresh_listener_sets(self):
        app_id = self.create_app_with_domain_and_deploy()
        self.change_certs_auto(app_id, True)
        gateway = Gateway.objects.get(app__id=app_id, name=app_id)
        gateway.refresh_to_k8s()
        ls_name = f"{app_id}-https-443"
        response = gateway.scheduler.listenersets.get(app_id, ls_name)
        self.assertEqual(response.status_code, 200)
        body = response.json()
        listeners = body["spec"]["listeners"]
        hostnames = [item["hostname"] for item in listeners]
        self.assertIn("test-domain.example.com", hostnames)
        for item in listeners:
            self.assertEqual(item["protocol"], "HTTPS")
            self.assertEqual(item["port"], 443)
            self.assertEqual(item["name"], "test-domain-example-com")
        self.assertEqual(body["spec"]["parentRef"]["name"], app_id)
        self.assertEqual(body["spec"]["parentRef"]["kind"], "Gateway")

        http_ls_name = f"{app_id}-http-80"
        http_response = gateway.scheduler.listenersets.get(app_id, http_ls_name)
        self.assertEqual(http_response.status_code, 200)
        http_listeners = http_response.json()["spec"]["listeners"]
        self.assertIn(
            "test-domain.example.com",
            [item["hostname"] for item in http_listeners],
        )

        tcp_response = gateway.scheduler.listenersets.get(
            app_id, f"{app_id}-tcp-80", ignore_exception=True)
        self.assertEqual(tcp_response.status_code, 404)

    def test_get_all_parent_refs_http_uses_listener_set(self):
        app_id = self.create_app_with_domain_and_deploy()
        self.change_certs_auto(app_id, True)
        route = Route.objects.get(app__id=app_id)
        parent_refs, http_parent_refs = route._get_all_parent_refs()
        domain = "test-domain.example.com"
        sanitized = domain.replace(".", "-")
        http_ref = next(
            (r for r in http_parent_refs if r["name"] == f"{app_id}-http-80"), None)
        self.assertIsNotNone(http_ref)
        self.assertEqual(http_ref["kind"], "ListenerSet")
        self.assertEqual(http_ref["sectionName"], sanitized)
        https_ref = next(
            (r for r in parent_refs if r["name"] == f"{app_id}-https-443"), None)
        self.assertIsNotNone(https_ref)
        self.assertEqual(https_ref["kind"], "ListenerSet")
        self.assertEqual(https_ref["sectionName"], sanitized)
        for ref in parent_refs + http_parent_refs:
            self.assertEqual(ref["group"], "gateway.networking.k8s.io")

    def test_get_all_parent_refs_tcp_uses_gateway(self):
        app_id = self.create_app()
        port = 6000
        gateway_name = "tcp-gw"
        self.create_gateway(app_id, gateway_name, port, "TCP")
        response = self.client.post(
            '/v2/apps/{}/services'.format(app_id),
            {
                'port': port,
                'protocol': 'TCP',
                'target_port': port,
                'ptype': 'task',
            }
        )
        self.assertEqual(response.status_code, 201, response.data)
        response = self.client.post(
            '/v2/apps/{}/domains'.format(app_id),
            {'domain': "tcp-domain.example.com", 'ptype': 'task'}
        )
        self.assertEqual(response.status_code, 201, response.data)
        route_name = "tcp-route"
        response = self.client.put(
            '/v2/apps/{}/routes/{}/'.format(app_id, route_name),
            {
                "app": app_id,
                "kind": "TCPRoute",
                "name": route_name,
                "rules": [{
                    "backendRefs": [{
                        "kind": "Service",
                        "name": f"{app_id}-task",
                        "port": port,
                        "weight": 100,
                    }],
                }],
                "parent_refs": [],
            },
            format='json'
        )
        self.assertEqual(response.status_code, 201, response.data)
        response = self.client.put(
            '/v2/apps/{}/routes/{}/'.format(app_id, route_name),
            {
                "app": app_id,
                "name": route_name,
                "kind": "TCPRoute",
                "rules": [{
                    "backendRefs": [{
                        "kind": "Service",
                        "name": f"{app_id}-task",
                        "port": port,
                        "weight": 100,
                    }],
                }],
                "parent_refs": [{"name": gateway_name, "port": port}],
            },
            format='json'
        )
        self.assertEqual(response.status_code, 200, response.data)
        route = Route.objects.get(app__id=app_id, name=route_name)
        parent_refs, http_parent_refs = route._get_all_parent_refs()
        self.assertEqual(http_parent_refs, [])
        self.assertEqual(len(parent_refs), 1)
        ref = parent_refs[0]
        self.assertEqual(ref["kind"], "Gateway")
        self.assertEqual(ref["name"], gateway_name)
        self.assertEqual(ref["sectionName"], f"tcp-{port}")


class GatewayRouteModelValidationTest(BaseGatewayTest):

    def test_gateway_model_ports_schema_validation(self):
        app_id = self.create_app()
        app = App.objects.get(id=app_id)
        gateway = Gateway(
            app=app,
            name='schema-gateway',
            ports=[{"port": 80}],
        )
        with self.assertRaises(ValidationError):
            gateway.full_clean()

    def test_route_model_rules_schema_validation(self):
        app_id = self.create_app()
        response = self.client.put(
            '/v2/apps/{}/routes/schema-route/'.format(app_id),
            {
                "app": app_id,
                "kind": "HTTPRoute",
                "name": "schema-route",
                "rules": [{"backendRefs": [{"name": 123, "port": 80}]}],
                "parent_refs": [],
            },
            format='json'
        )
        self.assertEqual(response.status_code, 400)

    def test_route_model_parent_refs_schema_validation(self):
        app_id = self.create_app()
        response = self.client.put(
            '/v2/apps/{}/routes/schema-route/'.format(app_id),
            {
                "app": app_id,
                "kind": "HTTPRoute",
                "name": "schema-route",
                "rules": [{"backendRefs": [{"name": "svc", "port": 80}]}],
                "parent_refs": [{"name": "gw"}],
            },
            format='json'
        )
        self.assertEqual(response.status_code, 400)
