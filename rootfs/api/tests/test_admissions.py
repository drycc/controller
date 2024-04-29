import os
import json
from django.contrib.auth import get_user_model
from django.core.cache import cache
from api.models.app import App
from api.models.resource import Resource
from api import admissions
from api.tests import adapter, TEST_ROOT, DryccTransactionTestCase
import requests_mock

User = get_user_model()

SCALE_TEST_CASES = (
    ("deployment_scale.json", (admissions.DeploymentsScaleHandler, "web", 2)),
    ("job_status_create_ok.json", (admissions.JobsStatusHandler, "run", 1)),
    ("job_status_succeeded.json", (admissions.JobsStatusHandler, "run", 0)),
    ("job_status_create_ok.json", (admissions.JobsStatusHandler, "run", 1)),
    ("job_status_failed.json", (admissions.JobsStatusHandler, "run", 0)),
)

RESOURCE_TEST_CASES = (
    (
        "service_instance_provisioning.json",
        (admissions.ServiceInstancesStatusHandler, "Provisioning", None),
    ),
    (
        "service_instance_ready.json",
        (admissions.ServiceInstancesStatusHandler, "Ready", None),
    ),
    (
        "service_binding_binding_request_in_flight.json",
        (admissions.ServicebindingsStatusHandler, "Ready", "BindingRequestInFlight"),
    ),
    (
        "service_binding_ready.json",
        (admissions.ServicebindingsStatusHandler, "Ready", "Ready"),
    ),
)


@requests_mock.Mocker(real_http=True, adapter=adapter)
class AdmissionsTest(DryccTransactionTestCase):
    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = self.get_or_create_token(self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

    def tearDown(self):
        # make sure every test has a clean slate for k8s mocking
        cache.clear()

    def test_admissions_scale(self, requests_mock):
        app_id = self.create_app("myapp")
        for case, (admission_class, procfile_type, scale) in SCALE_TEST_CASES:
            with open(os.path.join(TEST_ROOT, "admissions", case)) as f:
                request = json.loads(f.read())["request"]
                handler = admission_class()
                self.assertEqual(handler.detect(request), True)
                self.assertEqual(handler.handle(request), True)
                app = App.objects.get(id=app_id)
                self.assertEqual(app.structure.get(procfile_type, 0), scale)

    def test_admissions_service_catalog(self, requests_mock):
        app_id = self.create_app("myapp")
        resource_name = 'redis-t2'
        response = self.client.post(
            '/v2/apps/{}/resources'.format(app_id),
            data={'name': resource_name, 'plan': 'redis:standard-128'}
        )
        self.assertEqual(response.status_code, 201, response.data)

        for case, (admission_class, status, ready) in RESOURCE_TEST_CASES:
            with open(os.path.join(TEST_ROOT, "admissions", case)) as f:
                request = json.loads(f.read())["request"]
                handler = admission_class()
                data = (handler, f)
                self.assertEqual(handler.detect(request), True, data)
                self.assertEqual(handler.handle(request), True, data)
                resource = Resource.objects.get(name=resource_name)
                self.assertEqual(resource.status, status, data)
                self.assertEqual(resource.binding, ready, data)
