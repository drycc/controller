import uuid
import morph
import importlib
from django.db import models
from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _
from scheduler.exceptions import KubeException
from api.exceptions import ServiceUnavailable
from api.utils import dict_merge


def get_anonymous_user_instance(user): return user(id=-1)


class AuditedModel(models.Model):
    """Add created and updated fields to a model."""

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    class Meta:
        """Mark :class:`AuditedModel` as abstract."""
        abstract = True

    @classmethod
    @property
    def _scheduler(cls):
        mod = importlib.import_module(settings.SCHEDULER_MODULE)
        return mod.SchedulerClient(settings.SCHEDULER_URL, settings.K8S_API_VERIFY_TLS)

    def _fetch_service_config(self, app, svc_name=None):
        try:
            # Get the service from k8s to attach the domain correctly
            if svc_name is None:
                svc_name = app
            svc = self._scheduler.svc.get(app, svc_name).json()
        except KubeException as e:
            raise ServiceUnavailable('Could not fetch Kubernetes Service {}'.format(app)) from e

        # Get minimum structure going if it is missing on the service
        if 'metadata' not in svc or 'annotations' not in svc['metadata']:
            default = {'metadata': {'annotations': {}}}
            svc = dict_merge(svc, default)

        if 'labels' not in svc['metadata']:
            default = {'metadata': {'labels': {}}}
            svc = dict_merge(svc, default)

        return svc

    def _load_service_config(self, app, component, svc_name=None):
        # fetch setvice definition with minimum structure
        svc = self._fetch_service_config(app, svc_name)

        # always assume a .drycc.cc/ ending
        component = "%s.drycc.cc/" % component

        # Filter to only include values for the component and strip component out of it
        # Processes dots into a nested structure
        config = morph.unflatten(morph.pick(svc['metadata']['annotations'], prefix=component))

        return config

    def _save_service_config(self, app, component, data, svc_name=None):
        if svc_name is None:
            svc_name = app
        # fetch setvice definition with minimum structure
        svc = self._fetch_service_config(app, svc_name)

        # always assume a .drycc.cc ending
        component = "%s.drycc.cc/" % component

        # add component to data and flatten
        data = {"%s%s" % (component, key): value for key, value in list(data.items()) if value}
        svc['metadata']['annotations'].update(morph.flatten(data))

        # Update the k8s service for the application with new service information
        try:
            self._scheduler.svc.update(app, svc_name, svc)
        except KubeException as e:
            raise ServiceUnavailable('Could not update Kubernetes Service {}'.format(app)) from e


class UuidAuditedModel(AuditedModel):
    """Add a UUID primary key to an :class:`AuditedModel`."""

    uuid = models.UUIDField('UUID',
                            default=uuid.uuid4,
                            primary_key=True,
                            editable=False,
                            auto_created=True,
                            unique=True)

    class Meta:
        """Mark :class:`UuidAuditedModel` as abstract."""
        abstract = True


class User(AbstractUser):
    id = models.BigIntegerField(_('id'), primary_key=True)
    email = models.EmailField(_('email address'), unique=True)
