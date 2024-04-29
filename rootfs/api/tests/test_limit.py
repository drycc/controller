import json
import requests_mock

from django.core.cache import cache
from django.contrib.auth import get_user_model

from api.tests import adapter, DryccTransactionTestCase

User = get_user_model()


@requests_mock.Mocker(real_http=True, adapter=adapter)
class TestLimit(DryccTransactionTestCase):
    """Tests setting and updating config values"""

    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = self.get_or_create_token(self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

    def tearDown(self):
        # make sure every test has a clean slate for k8s mocking
        cache.clear()

    def test_get_limits_specs(self, mock_requests):
        results = {
            "id": "std1",
            "cpu": {
                "name": "Universal CPU",
                "boost": "3700MHZ",
                "clock": "3100MHZ",
                "cores": 32,
                "threads": 64
            },
            "memory": {
                "size": "64GB",
                "type": "DDR4-ECC"
            },
            "features": {
                "gpu": {
                    "name": "Integrated GPU",
                    "rops": 1,
                    "tmus": 1,
                    "cores": 128,
                    "memory": {
                        "size": "shared",
                        "type": "shared"
                    }
                },
                "network": "10G"
            },
            "disabled": False
        }
        response = self.client.get(
            '/v2/limits/specs/',
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 1)
        self.assertEqual(json.loads(json.dumps(response.data["results"][0])), results)
        response = self.client.get(
            '/v2/limits/specs/?keywords=unknown',
        )
        self.assertEqual(response.data["count"], 1)
        response = self.client.get(
            '/v2/limits/specs/?keywords=intel amd unknown',
        )
        self.assertEqual(response.data["count"], 1)
        response = self.client.get(
            '/v2/limits/specs/?keywords=noexists',
        )
        self.assertEqual(response.data["count"], 0)

    def test_get_limits_plans(self, mock_requests):
        response = self.client.get(
            '/v2/limits/plans/',
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 6, response.data)
        response = self.client.get(
            '/v2/limits/plans/?cpu=1',
        )
        self.assertEqual(response.data["count"], 3, response.data)
        response = self.client.get(
            '/v2/limits/plans/?cpu=1&memory=1',
        )
        self.assertEqual(response.data["count"], 1, response.data)
        response = self.client.get(
            '/v2/limits/plans/?cpu=1&memory=1GB',
        )
        self.assertEqual(response.data["count"], 1, response.data)
        response = self.client.get(
            '/v2/limits/plans/?spec-id=std1',
        )
        self.assertEqual(response.data["count"], 6, response.data)
        response = self.client.get(
            '/v2/limits/plans/?spec-id=std2',
        )
        self.assertEqual(response.data["count"], 0, response.data)
        # get one plan
        response = self.client.get(
            '/v2/limits/plans/std1.large.c1m1/',
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["id"], "std1.large.c1m1")
