import os
import json
from django.contrib.auth import get_user_model
from django.core.cache import cache
from api.models.app import App
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
        for case, (admission_class, ptype, scale) in SCALE_TEST_CASES:
            with open(os.path.join(TEST_ROOT, "admissions", case)) as f:
                request = json.loads(f.read())["request"]
                handler = admission_class()
                self.assertEqual(handler.detect(request), True)
                self.assertEqual(handler.handle(request), True)
                app = App.objects.get(id=app_id)
                self.assertEqual(app.structure.get(ptype, 0), scale)
