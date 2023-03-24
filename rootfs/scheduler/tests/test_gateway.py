"""
Unit tests for the Drycc gateway module.
"""
from scheduler.tests import TestCase


class GatewayTest(TestCase):
    """Tests scheduler gateway calls"""

    def create_gateway(self, namespace, name):
        self.scheduler.ns.create("test-gateway")
        listener = {
            "name": "test-gateway-web",
            "protocol": "TCP",
            "port": 31400,
            "allowedRoutes": {
                "kinds": [
                    {
                        "kind": "TCPRoute"
                    }
                ]
            }
        }
        return self.scheduler.gateways.create(
            "test-gateway",
            "test-gateway",
            gateway_class="istio",
            listeners=[listener, ]
        )

    def test_create_gateway(self):
        response = self.create_gateway("test-gateway", "test-gateway")
        listeners = response.json()["spec"]["listeners"]
        self.assertEqual(listeners[0]["name"], "test-gateway-web")

    def test_patch_gateway(self):
        self.create_gateway("test-gateway", "test-gateway")
        response = self.scheduler.gateways.patch(
            "test-gateway",
            "test-gateway",
            version=1,
            gateway_class="istio",
            listeners=[
                {
                    "name": "test-gateway-web",
                    "protocol": "TCP",
                    "port": 8080,
                    "allowedRoutes": {
                        "kinds": [
                            {
                                "kind": "TCPRoute"
                            }
                        ]
                    }
                }
            ],
        )
        listeners = response.json()["spec"]["listeners"]
        self.assertEqual(listeners[0]["port"], 8080)

    def test_delete_gateway(self):
        self.create_gateway("test-gateway", "test-gateway")
        self.scheduler.gateways.delete("test-gateway", "test-gateway")
        response = self.scheduler.gateways.get(
            "test-gateway", "test-gateway", ignore_exception=True)
        self.assertEqual(response.status_code, 404)


class HTTPRouteTest(TestCase):
    """Tests scheduler gateway calls"""

    def create_http_route(self, name="test-gateway", weight=0.0):
        self.scheduler.ns.create(name)
        return self.scheduler.httproutes.create(
            name,
            name,
            port=5000,
            procfile_type="web",
            weight=weight
        )

    def test_create_http_route_1(self):
        response = self.create_http_route(weight=0.9)
        for backend in response.json()['spec']['rules'][0]['backendRefs']:
            if backend["name"].endswith("canary"):
                self.assertEqual(backend["weight"], 9)
            else:
                self.assertEqual(backend["weight"], 991)

    def test_create_http_route_2(self):
        response = self.create_http_route(name="test-gateway1", weight=0.0)
        self.assertEqual(
            len(response.json()["spec"]["rules"][0]["backendRefs"]),
            1
        )

    def test_patch_http_route(self):
        self.create_http_route()
        rules = [
            {
                "backendRefs": [
                    {
                        "name": "tcp-echo-v1",
                        "port": 9000,
                        "weight": 10,
                    },
                    {
                        "name": "tcp-echo-v1-canary",
                        "port": 9000,
                        "weight": 90,
                    }
                ]
            }
        ]
        response = self.scheduler.httproutes.patch(
            "test-gateway",
            "test-gateway",
            port=8000,
            procfile_type="cmd",
            version=1,
            rules=rules
        )
        self.assertEqual(response.json()["spec"]["rules"], rules)

    def test_delete_http_route(self):
        self.test_create_http_route_2()
        self.scheduler.httproutes.delete("test-gateway", "test-gateway")
        response = self.scheduler.httproutes.get(
            "test-gateway",
            "test-gateway",
            ignore_exception=True
        )
        self.assertEqual(response.status_code, 404)


class TCPRouteTest(TestCase):
    """Tests scheduler gateway calls"""

    def create_tcp_route(self, name="test-tcp-route", weight=0.0):
        self.scheduler.ns.create(name)
        return self.scheduler.tcproutes.create(
            name,
            name,
            port=5000,
            procfile_type="celery",
            weight=weight
        )

    def test_create_tcp_route_1(self):
        response = self.create_tcp_route(weight=0.9)
        for backend in response.json()['spec']['rules'][0]['backendRefs']:
            if backend["name"].endswith("canary"):
                self.assertEqual(backend["weight"], 9)
            else:
                self.assertEqual(backend["weight"], 991)

    def test_create_tcp_route_2(self):
        response = self.create_tcp_route(name="test-tcp-route1", weight=0.0)
        self.assertEqual(
            len(response.json()["spec"]["rules"][0]["backendRefs"]),
            1
        )

    def test_patch_tcp_route(self):
        self.create_tcp_route()
        rules = [
            {
                "backendRefs": [
                    {
                        "name": "tcp-echo-v1",
                        "port": 9000,
                        "weight": 10,
                    },
                    {
                        "name": "tcp-echo-v1-canary",
                        "port": 9000,
                        "weight": 90,
                    }
                ]
            }
        ]
        response = self.scheduler.tcproutes.patch(
            "test-tcp-route",
            "test-tcp-route",
            port=8000,
            procfile_type="cmd",
            version=1,
            rules=rules
        )
        self.assertEqual(response.json()["spec"]["rules"], rules)

    def test_delete_tcp_route(self):
        self.test_create_tcp_route_2()
        self.scheduler.tcproutes.delete("test-tcp-route", "test-tcp-route")
        response = self.scheduler.tcproutes.get(
            "test-tcp-route",
            "test-tcp-route",
            ignore_exception=True
        )
        self.assertEqual(response.status_code, 404)


class UDPRouteTest(TestCase):
    """Tests scheduler gateway calls"""

    def create_udp_route(self, name="test-udp-route", weight=0.0):
        self.scheduler.ns.create(name)
        return self.scheduler.udproutes.create(
            name,
            name,
            port=5000,
            procfile_type="celery",
            weight=weight
        )

    def test_create_udp_route_1(self):
        response = self.create_udp_route(weight=0.9)
        for backend in response.json()['spec']['rules'][0]['backendRefs']:
            if backend["name"].endswith("canary"):
                self.assertEqual(backend["weight"], 9)
            else:
                self.assertEqual(backend["weight"], 991)

    def test_create_udp_route_2(self):
        response = self.create_udp_route(name="test-udp-route1", weight=0.0)
        self.assertEqual(
            len(response.json()["spec"]["rules"][0]["backendRefs"]),
            1
        )

    def test_patch_udp_route(self):
        self.create_udp_route()
        rules = [
            {
                "backendRefs": [
                    {
                        "name": "udp-echo-v1",
                        "port": 9000,
                        "weight": 10,
                    },
                    {
                        "name": "udp-echo-v1-canary",
                        "port": 9000,
                        "weight": 90,
                    }
                ]
            }
        ]
        response = self.scheduler.udproutes.patch(
            "test-udp-route",
            "test-udp-route",
            port=8000,
            procfile_type="cmd",
            version=1,
            rules=rules
        )
        self.assertEqual(response.json()["spec"]["rules"], rules)

    def test_delete_udp_route(self):
        self.test_create_udp_route_2()
        self.scheduler.udproutes.delete("test-udp-route", "test-udp-route")
        response = self.scheduler.udproutes.get(
            "test-udp-route",
            "test-udp-route",
            ignore_exception=True
        )
        self.assertEqual(response.status_code, 404)
