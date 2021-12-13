# -*- coding: utf-8 -*-

"""
Data models for the Drycc API.
"""
import time
import hashlib
import hmac
import importlib
import logging
import morph
import re
import urllib.parse
import uuid
import requests
from datetime import timedelta
from django.conf import settings
from django.db import models
from django.db.models.signals import post_delete, post_save
from django.utils.timezone import now
from django.dispatch import receiver
from rest_framework.exceptions import ValidationError
from rest_framework.authtoken.models import Token
from requests_toolbelt import user_agent
from scheduler.exceptions import KubeException
from .. import __version__ as drycc_version
from ..exceptions import DryccException, AlreadyExists, ServiceUnavailable, UnprocessableEntity  # noqa

logger = logging.getLogger(__name__)
session = None


def get_session():
    global session
    if session is None:
        session = requests.Session()
        session.headers = {
            # https://toolbelt.readthedocs.org/en/latest/user-agent.html#user-agent-constructor
            'User-Agent': user_agent('Drycc Controller', drycc_version),
        }
        # `mount` a custom adapter that retries failed connections for HTTP and HTTPS requests.
        # http://docs.python-requests.org/en/latest/api/#requests.adapters.HTTPAdapter
        session.mount('http://', requests.adapters.HTTPAdapter(max_retries=10))
        session.mount('https://', requests.adapters.HTTPAdapter(max_retries=10))
    return session


def validate_label(value):
    """
    Check that the value follows the kubernetes name constraints
    http://kubernetes.io/v1.1/docs/design/identifiers.html
    """
    match = re.match(r'^[a-z0-9-]+$', value)
    if not match:
        raise ValidationError("Can only contain a-z (lowercase), 0-9 and hyphens")


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


from .app import App, validate_app_id, validate_reserved_names, validate_app_structure  # noqa
from .appsettings import AppSettings  # noqa
from .blocklist import Blocklist  # noqa
from .build import Build  # noqa
from .certificate import Certificate, validate_certificate  # noqa
from .config import Config  # noqa
from .domain import Domain  # noqa
from .service import Service  # noqa
from .key import Key, validate_base64  # noqa
from .release import Release  # noqa
from .tls import TLS  # noqa
from .volume import Volume  # noqa
from .resource import Resource  # noqa
from ..tasks import retrieve_resource, send_measurements # noqa
from ..utils import dict_merge  # noqa

# define update/delete callbacks for synchronizing
# models with the configuration management backend


def _log_instance_created(**kwargs):
    if kwargs.get('created'):
        instance = kwargs['instance']
        message = '{} {} created'.format(instance.__class__.__name__.lower(), instance)
        if hasattr(instance, 'app'):
            instance.app.log(message)
        else:
            logger.info(message)


def _log_instance_added(**kwargs):
    if kwargs.get('created'):
        instance = kwargs['instance']
        message = '{} {} added'.format(instance.__class__.__name__.lower(), instance)
        if hasattr(instance, 'app'):
            instance.app.log(message)
        else:
            logger.info(message)


def _log_instance_updated(**kwargs):
    instance = kwargs['instance']
    message = '{} {} updated'.format(instance.__class__.__name__.lower(), instance)
    if hasattr(instance, 'app'):
        instance.app.log(message)
    else:
        logger.info(message)


def _log_instance_removed(**kwargs):
    instance = kwargs['instance']
    message = '{} {} removed'.format(instance.__class__.__name__.lower(), instance)
    if hasattr(instance, 'app'):
        instance.app.log(message)
    else:
        logger.info(message)


# special case: log the release summary and send release info to each deploy hook
def _hook_release_created(**kwargs):
    if kwargs.get('created'):
        release = kwargs['instance']
        # append release lifecycle logs to the app
        release.app.log(release.summary)

        for deploy_hook in settings.DRYCC_DEPLOY_HOOK_URLS:
            url = deploy_hook
            params = {
                'app': release.app,
                'release': 'v{}'.format(release.version),
                'release_summary': release.summary,
                'sha': '',
                'user': release.owner,
            }
            if release.build is not None:
                params['sha'] = release.build.sha

            # order of the query arguments is important when computing the HMAC auth secret
            params = sorted(params.items())
            url += '?{}'.format(urllib.parse.urlencode(params))

            headers = {}
            if settings.DRYCC_DEPLOY_HOOK_SECRET_KEY is not None:
                headers['Authorization'] = hmac.new(
                    settings.DRYCC_DEPLOY_HOOK_SECRET_KEY.encode('utf-8'),
                    url.encode('utf-8'),
                    hashlib.sha1
                ).hexdigest()

            try:
                get_session().post(url, headers=headers)
                # just notify with the base URL, disregard the added URL query
                release.app.log('Deploy hook sent to {}'.format(deploy_hook))
            except requests.RequestException as e:
                release.app.log('An error occurred while sending the deploy hook to {}: {}'.format(
                    deploy_hook, e), logging.ERROR)


# Log significant app-related events
post_save.connect(_hook_release_created, sender=Release, dispatch_uid='api.models.log')

post_save.connect(_log_instance_created, sender=Build, dispatch_uid='api.models.log')
post_save.connect(_log_instance_added, sender=Certificate, dispatch_uid='api.models.log')
post_save.connect(_log_instance_added, sender=Domain, dispatch_uid='api.models.log')

post_save.connect(_log_instance_updated, sender=AppSettings, dispatch_uid='api.models.log')
post_save.connect(_log_instance_updated, sender=Config, dispatch_uid='api.models.log')

post_delete.connect(_log_instance_removed, sender=Certificate, dispatch_uid='api.models.log')
post_delete.connect(_log_instance_removed, sender=Domain, dispatch_uid='api.models.log')
post_delete.connect(_log_instance_removed, sender=TLS, dispatch_uid='api.models.log')
post_delete.connect(_log_instance_removed, sender=Volume, dispatch_uid='api.models.log')
post_delete.connect(_log_instance_removed, sender=Resource, dispatch_uid='api.models.log')


# automatically generate a new token on creation
@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_auth_token_handle(sender, instance=None, created=False, **kwargs):
    if created:
        Token.objects.create(user=instance)


@receiver(post_save, sender=App)
def app_changed_handle(sender, instance=None, created=False, update_fields=None, **kwargs):
    # measure limits to workflow manager
    if settings.WORKFLOW_MANAGER_URL is not None and (
        created or (
            update_fields is not None and "structure" in update_fields)):
        timestamp = time.time()
        send_measurements.apply_async(
            args=[instance.to_measurements(timestamp), ],
            queue="priority.middle",
        )


@receiver(post_save, sender=Config)
def config_changed_handle(sender, instance=None, created=False, update_fields=None, **kwargs):
    # measure limits to workflow manager
    if settings.WORKFLOW_MANAGER_URL is not None and (
        created or (
            update_fields is not None and (
                "cpu" in update_fields or "memory" in update_fields))):
        timestamp = time.time()
        send_measurements.apply_async(
            args=[instance.app.to_measurements(timestamp), ],
            queue="priority.middle",
        )


@receiver(post_save, sender=Volume)
def volume_changed_handle(sender, instance=None, created=False, update_fields=None, **kwargs):
    # measure volumes to workflow manager
    if settings.WORKFLOW_MANAGER_URL is not None and created:
        timestamp = time.time()
        send_measurements.apply_async(
            args=[instance.to_measurements(timestamp), ],
            queue="priority.middle",
        )


@receiver(post_save, sender=Resource)
def resource_changed_handle(sender, instance=None, created=False, update_fields=None, **kwargs):
    # retrieve_resource
    if created or instance.binding == "Binding" or (
            update_fields is not None and "plan" in update_fields):
        retrieve_resource.apply_async(
            args=(instance, ),
            eta=now() + timedelta(seconds=30)
        )
    # measure resources to workflow manager
    if settings.WORKFLOW_MANAGER_URL is not None and (
        created or (
            update_fields is not None and (
                "plan" in update_fields
            ))):
        timestamp = time.time()
        send_measurements.apply_async(
            args=[instance.to_measurements(timestamp), ],
            queue="priority.middle",
        )
