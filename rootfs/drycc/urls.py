"""
URL routing patterns for the Drycc project.

This is the "main" urls.py which then includes the urls.py files of
installed apps.
"""


from django.urls import include, re_path
from api.views import LivenessCheckView
from api.views import ReadinessCheckView

urlpatterns = [
    re_path(r'^healthz$', LivenessCheckView.as_view()),
    re_path(r'^readiness$', ReadinessCheckView.as_view()),
    re_path(r'^v2/', include('api.urls')),
]
