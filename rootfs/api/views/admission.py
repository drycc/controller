"""
Admission webhook views.
"""
import json
from django.conf import settings
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet

from api import admissions


class AdmissionWebhookViewSet(GenericViewSet):

    admission_classes = (
        admissions.JobsStatusHandler,
        admissions.DeploymentsScaleHandler,
    )
    permission_classes = (AllowAny, )

    def handle(self, request, **kwargs):
        key = kwargs['key']
        data = json.loads(request.body.decode("utf8"))["request"]
        if settings.CERT_KEY == key:
            allowed = True
            for admission_class in self.admission_classes:
                admission = admission_class()
                if admission.detect(data):
                    allowed = admission.handle(data)
                    break
        else:
            allowed = False
        return Response({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": {
                "uid": data["uid"],
                "allowed": allowed,
            }
        })
