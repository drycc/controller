"""
Unit tests for the Drycc gateway module.
"""
from scheduler.tests import TestCase


class IssuerTest(TestCase):
    """Tests scheduler gateway calls"""

    def create_issuer(self, namespace, name):
        self.scheduler.ns.create(namespace)
        data = {
            "parent_refs": [{
                "group": "gateway.networking.k8s.io",
                "kind": "Gateway",
                "name": "gateway_name",
            }],
            "server": "https://acme-v02.api.letsencrypt.org/directory",
            "key_id": "key_id",
            "key_secret": "key_secret",
        }
        return self.scheduler.issuer.create(namespace, name, **data)

    def test_issuer_get(self):
        response = self.create_issuer("test-issuer", "test-issuer")
        self.assertEqual(response.status_code, 201)
        response = self.scheduler.issuer.get("test-issuer", "test-issuer")
        self.assertEqual(
            response.json()["spec"]["acme"]["server"],
            "https://acme-v02.api.letsencrypt.org/directory"
        )

    def test_issuer_put(self):
        response = self.create_issuer("test-issuer", "test-issuer")
        self.assertEqual(response.status_code, 201)
        data1 = {
            "parent_refs": [{
                "group": "gateway.networking.k8s.io",
                "kind": "Gateway",
                "name": "gateway_name",
            }],
            "server": "https://test.test.com/directory",
            "key_id": "key_id",
            "key_secret": "key_secret",
        }
        self.scheduler.issuer.put("test-issuer", "test-issuer", **data1)
        response = self.scheduler.issuer.get("test-issuer", "test-issuer", ignore_exception=True)
        self.assertEqual(
            response.json()["spec"]["acme"]["server"], "https://test.test.com/directory")

    def test_issuer_delete(self):
        response = self.create_issuer("test-issuer", "test-issuer")
        self.assertEqual(response.status_code, 201)
        response = self.scheduler.issuer.delete("test-issuer", "test-issuer")
        self.assertEqual(response.status_code, 200)
        response = self.scheduler.issuer.get("test-issuer", "test-issuer", ignore_exception=True)
        self.assertEqual(response.status_code, 404)
