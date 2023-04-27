import json
import string
import random
from django.contrib.auth import get_user_model
from django.core.cache import cache
from rest_framework.authtoken.models import Token

from api.tests import TEST_ROOT, DryccTransactionTestCase

User = get_user_model()


class BaseGatewayTest(DryccTransactionTestCase):
    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = Token.objects.get(user=self.user).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

    def tearDown(self):
        # make sure every test has a clean slate for k8s mocking
        cache.clear()

    def create_gateway(self, app_id, name, port, protocol):
        response = self.client.post(
            '/v2/apps/{}/gateways/'.format(app_id),
            {'name': name, 'port': port, 'protocol': protocol}
        )
        self.assertEqual(response.status_code, 201)

    def create_tls_domain(self, app_id):
        cert_url = '/v2/certs'
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
            {'domain': domain}
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

    def test_add_listener(self):
        app_id = self.create_app()
        self.create_gateway(app_id, 'bing-gateway', 8000, "HTTP")
        response = self.client.post(
            '/v2/apps/{}/gateways/'.format(app_id),
            {'name': 'bing-gateway', 'port': 443, 'protocol': "HTTP"}
        )
        self.assertEqual(response.status_code, 201)
        response = self.client.get('/v2/apps/{}/gateways/'.format(app_id))
        results = [{
            "app": app_id,
            "owner": "autotest",
            "name": "bing-gateway",
            "listeners": [
                {
                    "name": "%s-8000-tcp" % app_id,
                    "port": 8000,
                    "protocol": "HTTP",
                    "allowedRoutes": {"namespaces": {"from": "All"}}
                },
                {
                    "name": "%s-443-tcp" % app_id,
                    "port": 443,
                    "protocol": "HTTP",
                    "allowedRoutes": {"namespaces": {"from": "All"}}
                }]
        }]
        self.assertEqual(results, json.loads(json.dumps(response.data["results"])))

    def add_tls_listener(self, name, protocol):
        app_id = self.create_app()
        domain, secret_name = self.create_tls_domain(app_id)
        response = self.client.post(
            '/v2/apps/{}/gateways/'.format(app_id),
            {'name': name, 'port': 443, 'protocol': protocol}
        )
        self.assertEqual(response.status_code, 201)
        response = self.client.get('/v2/apps/{}/gateways/'.format(app_id))
        if protocol == "HTTPS":
            listener_name = "%s-443-mix-%s" % (app_id, domain)
        else:
            listener_name = "%s-443-tcp-%s" % (app_id, domain)
        results = [{
            "app": app_id,
            "owner": "autotest",
            "name": name,
            "listeners": [{
                "tls": {
                    "certificateRefs": [{
                        "kind": "Secret",
                        "name": secret_name
                    }]
                },
                "name": listener_name,
                "port": 443,
                "hostname": domain,
                "protocol": protocol,
                "allowedRoutes": {
                    "namespaces": {
                        "from": "All"
                    }
                }
            }]
        }]
        self.assertEqual(results, json.loads(json.dumps(response.data["results"])))
        return app_id, domain, secret_name

    def test_add_tls_listener(self):
        self.add_tls_listener("tls-gateway", "TLS")

    def test_add_https_listener(self):
        self.add_tls_listener("bingo-gateway", "HTTPS")

    def test_remove_domain(self):
        app_id, domain, _ = self.add_tls_listener("bingo-gateway", "HTTPS")
        url = '/v2/apps/{app_id}/domains/{domain}'.format(domain=domain,
                                                          app_id=app_id)
        response = self.client.delete(url)
        self.assertEqual(response.status_code, 204)

        response = self.client.get('/v2/apps/{}/gateways/'.format(app_id))
        self.assertEqual(response.data["results"][0]["listeners"], [])

    def test_remove_tls(self):
        app_id, domain, secret_name = self.add_tls_listener("bingo-gateway", "HTTPS")
        response = self.client.get('/v2/apps/{}/gateways/'.format(app_id))
        self.assertEqual(len(response.data["results"][0]["listeners"]), 1)
        response = self.client.delete(
            '{}/{}/domain/{}/'.format('/v2/certs', secret_name, domain)
        )
        self.assertEqual(response.status_code, 204)

        response = self.client.get('/v2/apps/{}/gateways/'.format(app_id))
        self.assertEqual(response.data["results"][0]["listeners"], [])
        return app_id

    def test_certs_auto_enabled(self):
        app_id = self.test_remove_tls()
        data = {'certs_auto_enabled': True}
        response = self.client.post(
            '/v2/apps/{}/tls'.format(app_id),
            data)
        self.assertEqual(response.status_code, 201, response.data)
        response = self.client.get('/v2/apps/{}/gateways/'.format(app_id))
        self.assertEqual(len(response.data["results"][0]["listeners"]), 1)

    def test_remove_listener(self):
        app_id = self.create_app()
        self.create_gateway(app_id, 'bing-gateway', 8000, "HTTP")
        response = self.client.get('/v2/apps/{}/gateways/'.format(app_id))
        self.assertEqual(response.data["count"], 1, response.data)
        # delete
        response = self.client.delete(
            '/v2/apps/{}/gateways/'.format(app_id),
            {'name': 'bing-gateway', 'port': 8000, 'protocol': "HTTP"}
        )
        self.assertEqual(response.status_code, 204)
        response = self.client.get('/v2/apps/{}/gateways/'.format(app_id))
        self.assertEqual(response.data["count"], 0, response.data)


class RouteTest(BaseGatewayTest):

    def create_route(self, app_id):
        # create service
        port = 5000
        procfile_type = "task"
        response = self.client.post(
            '/v2/apps/{}/services'.format(app_id),
            {
                'port': port,
                'protocol': 'TCP',
                'target_port': port,
                'procfile_type': procfile_type
            }
        )
        self.assertEqual(response.status_code, 201, response.data)
        # create route
        route_name = "test-route"
        response = self.client.post(
            '/v2/apps/{}/routes/'.format(app_id),
            {
                "port": 5000,
                "procfile_type": procfile_type,
                "kind": "HTTPRoute",
                "name": route_name,
            }
        )
        self.assertEqual(response.status_code, 201)
        return procfile_type, port, route_name

    def test_create_route(self):
        app_id = self.create_app()
        self.create_route(app_id)
        # create route error
        response = self.client.post(
            '/v2/apps/{}/routes/'.format(app_id),
            {
                "port": 5000,
                "procfile_type": "no-exists",
                "kind": "HTTPRoute",
                "name": "test-route-1",
            }
        )
        self.assertEqual(response.status_code, 404)

    def test_route_attach(self):
        app_id = self.create_app()
        _, port, route_name = self.create_route(app_id)
        gateway_name_1 = 'bing-gateway-1'
        self.create_gateway(app_id, gateway_name_1, 8000, "HTTP")
        self.client.patch(
            '/v2/apps/{}/routes/{}/attach/'.format(app_id, route_name),
            {
                "gateway": gateway_name_1,
                "port": port
            }
        )
        response = self.client.get('/v2/apps/{}/routes/'.format(app_id))
        self.assertEqual(len(response.data["results"][0]["parent_refs"]), 1)
        gateway_name_2 = 'bing-gateway-2'
        self.create_gateway(app_id, gateway_name_2, 8000, "HTTP")
        self.client.patch(
            '/v2/apps/{}/routes/{}/attach/'.format(app_id, route_name),
            {
                "gateway": gateway_name_2,
                "port": port
            }
        )
        response = self.client.get('/v2/apps/{}/routes/'.format(app_id))
        self.assertEqual(len(response.data["results"][0]["parent_refs"]), 2)
        return app_id, gateway_name_1, gateway_name_2, port, route_name

    def test_route_detach(self):
        app_id, gateway_name_1, gateway_name_2, port, route_name = self.test_route_attach()
        self.client.patch(
            '/v2/apps/{}/routes/{}/detach/'.format(app_id, route_name),
            {
                "gateway": gateway_name_1,
                "port": port
            }
        )
        response = self.client.get('/v2/apps/{}/routes/'.format(app_id))
        self.assertEqual(len(response.data["results"][0]["parent_refs"]), 1)

        self.client.patch(
            '/v2/apps/{}/routes/{}/detach/'.format(app_id, route_name),
            {
                "gateway": gateway_name_2,
                "port": port
            }
        )
        response = self.client.get('/v2/apps/{}/routes/'.format(app_id))
        self.assertEqual(len(response.data["results"][0]["parent_refs"]), 0)

        response = self.client.patch(
            '/v2/apps/{}/routes/{}/detach/'.format(app_id, route_name),
            {
                "gateway": gateway_name_2,
                "port": port
            }
        )
        self.assertEqual(response.status_code, 400)

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

    def test_rule_get(self):
        app_id = self.create_app()
        procfile_type, _, route_name = self.create_route(app_id)
        response = self.client.get(
            '/v2/apps/{}/routes/{}/rules/'.format(app_id, route_name),
        )
        expect = [{
            'backendRefs': [{
                'kind': 'Service',
                'name': "%s-%s" % (app_id, procfile_type),
                'port': 5000
            }]
        }]
        self.assertEqual(response.data, expect)

    def test_rule_set(self):
        app_id = self.create_app()
        procfile_type, _, route_name = self.create_route(app_id)
        expect = [{
            'backendRefs': [
                {
                    'kind': 'Service',
                    'name': "%s-%s" % (app_id, procfile_type),
                    'port': 5000
                }
            ],
            "matches": [
                {
                    "path": {
                        "type": "PathPrefix",
                        "value": "/get"
                    }
                }
            ]
        }]
        response = self.client.put(
            '/v2/apps/{}/routes/{}/rules/'.format(app_id, route_name),
            json.dumps(expect),
            content_type="application/json",
        )
        response = self.client.get(
            '/v2/apps/{}/routes/{}/rules/'.format(app_id, route_name),
        )
        self.assertEqual(response.data, expect)

        expect = [{
            'backendRefs': [
                {
                    'kind': 'Service',
                    'name': "%s-%s-noexists" % (app_id, procfile_type),
                    'port': 5000
                }
            ],
            "matches": [
                {
                    "path": {
                        "type": "PathPrefix",
                        "value": "/get"
                    }
                }
            ]
        }]
        response = self.client.put(
            '/v2/apps/{}/routes/{}/rules/'.format(app_id, route_name),
            json.dumps(expect),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
