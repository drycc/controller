import os
import json
from django.contrib.auth import get_user_model
from django.core.cache import cache
from rest_framework.authtoken.models import Token
from api.models.app import App
from api.tests import TEST_ROOT, DryccTransactionTestCase
from api.admissions import JobsStatusHandler, DeploymentsScaleHandler

User = get_user_model()

TEST_CASES = (
    ("deployment_scale.json", (DeploymentsScaleHandler, "web", 2)),
    ("job_status_create_ok.json", (JobsStatusHandler, "run", 1)),
    ("job_status_succeeded.json", (JobsStatusHandler, "run", 0)),
    ("job_status_create_ok.json", (JobsStatusHandler, "run", 1)),
    ("job_status_failed.json", (JobsStatusHandler, "run", 0)),
)


class AdmissionsTest(DryccTransactionTestCase):
    fixtures = ['tests.json']
    admission_classes = (JobsStatusHandler, DeploymentsScaleHandler)

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = Token.objects.get(user=self.user).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

    def tearDown(self):
        # make sure every test has a clean slate for k8s mocking
        cache.clear()

    def test_admissions(self):
        app_id = self.create_app("myapp")
        for case, (admission_class, ptype, scale) in TEST_CASES:
            with open(os.path.join(TEST_ROOT, "admissions", case)) as f:
                request = json.loads(f.read())["request"]
                handler = admission_class()
                self.assertEqual(handler.detect(request), True)
                self.assertEqual(handler.handle(request), True)
                app = App.objects.get(id=app_id)
                self.assertEqual(app.structure.get(ptype, 0), scale)
