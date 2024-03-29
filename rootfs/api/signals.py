# -*- coding: utf-8 -*-

"""
Data models for the Drycc API.
"""
import time
import hashlib
import hmac
import logging
import urllib.parse
import requests
from django.conf import settings
from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from rest_framework.authtoken.models import Token
from api.utils import get_session
from api.tasks import send_measurements
from api.models.app import App
from api.models.service import Service
from api.models.gateway import Gateway, DEFAULT_HTTPS_PORT
from api.models.appsettings import AppSettings
from api.models.build import Build
from api.models.certificate import Certificate
from api.models.config import Config
from api.models.domain import Domain
from api.models.release import Release
from api.models.tls import TLS
from api.models.volume import Volume
from api.models.resource import Resource


User = get_user_model()
logger = logging.getLogger(__name__)


def _log_instance_created(**kwargs):
    if kwargs.get('created'):
        instance = kwargs['instance']
        message = '{} {} created'.format(instance.__class__.__name__.lower(), instance)
        if hasattr(instance, 'log'):
            instance.log(message)
        elif hasattr(instance, 'app'):
            instance.app.log(message)
        else:
            logger.info(message)


def _log_instance_added(**kwargs):
    if kwargs.get('created'):
        instance = kwargs['instance']
        message = '{} {} added'.format(instance.__class__.__name__.lower(), instance)
        if hasattr(instance, 'log'):
            instance.log(message)
        elif hasattr(instance, 'app'):
            instance.app.log(message)
        else:
            logger.info(message)


def _log_instance_updated(**kwargs):
    instance = kwargs['instance']
    message = '{} {} updated'.format(instance.__class__.__name__.lower(), instance)
    if hasattr(instance, 'log'):
        instance.log(message)
    elif hasattr(instance, 'app'):
        instance.app.log(message)
    else:
        logger.info(message)


def _log_instance_removed(**kwargs):
    instance = kwargs['instance']
    message = '{} {} removed'.format(instance.__class__.__name__.lower(), instance)
    if hasattr(instance, 'log'):
        instance.log(message)
    elif hasattr(instance, 'app'):
        instance.app.log(message)
    else:
        logger.info(message)


# special case: log the release summary and send release info to each deploy hook
def _hook_release_created(**kwargs):
    if kwargs.get('created'):
        release = kwargs['instance']
        # append release lifecycle logs to the app
        release.log(release.summary)

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
                release.log('Sent deploy hook to {}'.format(deploy_hook))
            except requests.RequestException as e:
                release.log('An error occurred while sending the deploy hook to {}: {}'.format(
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
@receiver(post_save, sender=User)
def create_auth_token_handle(sender, instance, created=False, **kwargs):
    if created:
        Token.objects.create(user=instance)


@receiver(post_save, sender=App)
def app_changed_handle(sender, instance: App, created=False, update_fields=None, **kwargs):
    # measure limits to workflow manager
    if settings.WORKFLOW_MANAGER_URL and not created and (
            update_fields is not None and "structure" in update_fields):
        timestamp = time.time()
        send_measurements.apply_async(
            args=[instance.to_measurements(timestamp), ],
        )


@receiver(post_save, sender=TLS)
def tls_changed_handle(sender, instance: TLS, created=False, update_fields=None, **kwargs):
    if (update_fields and "issuer" in update_fields) or created:
        instance.refresh_issuer_to_k8s()
    if (update_fields and "https_enforced" in update_fields) or created:
        for route in instance.app.route_set.all():
            route.refresh_to_k8s()
    if (update_fields and "certs_auto_enabled" in update_fields) or created:
        instance.refresh_certificate_to_k8s()
        for gateway in instance.app.gateway_set.all():
            if (instance.certs_auto_enabled and gateway.name == instance.app.id
                    and gateway.add(DEFAULT_HTTPS_PORT, "HTTPS")[0]):
                gateway.save()
            else:
                gateway.refresh_to_k8s()
        for route in instance.app.route_set.all():
            route.refresh_to_k8s()


@receiver(post_save, sender=Gateway)
def gateway_changed_handle(
        sender, instance: Gateway, created=False, update_fields=None, **kwargs):
    if created or (not created and update_fields is None):  # create or delete
        for tls in instance.app.tls_set.all():
            tls.refresh_certificate_to_k8s()
        for route in instance.app.route_set.all():
            route.refresh_to_k8s()


@receiver(signal=[post_save, post_delete], sender=Service)
def service_changed_handle(
        sender, instance: Service, created=False, update_fields=None, **kwargs):
    if kwargs['signal'] == post_delete:
        instance.app.route_set.filter(procfile_type=instance.procfile_type).delete()


@receiver(signal=[post_save, post_delete], sender=Domain)
def domain_changed_handle(
        sender, instance: Domain, created=False, update_fields=None, **kwargs):
    for gateway in instance.app.gateway_set.all():
        gateway.refresh_to_k8s()
    for route in instance.app.route_set.all():
        route.refresh_to_k8s()


@receiver(signal=[post_save, post_delete], sender=AppSettings)
def appsettings_changed_handle(
        sender, instance: AppSettings, created=False, update_fields=None, **kwargs):
    prev_settings, action, canaries = instance.diff_canaries()
    if prev_settings is not None:
        release = instance.app.release_set.filter(failed=False).latest()
        if release.canary:
            if action == "append":
                instance.app.deploy(release)
            elif action == "remove":
                instance.app.cleanup_old()
        for procfile_type in canaries:
            canary = (action == "append")
            service = instance.app.service_set.filter(procfile_type=procfile_type).first()
            if service is not None and service.canary != canary:
                service.canary = canary
                service.save()
        if prev_settings.routable != instance.routable:
            for route in instance.app.route_set.all():
                if route.routable != instance.routable:
                    route.routable = instance.routable
                    route.save()


@receiver(post_save, sender=Config)
def config_changed_handle(sender, instance: Config, created=False, update_fields=None, **kwargs):
    # measure limits to workflow manager
    if settings.WORKFLOW_MANAGER_URL and (
            created or (update_fields is not None and "limits" in update_fields)):
        timestamp = time.time()
        send_measurements.apply_async(
            args=[instance.app.to_measurements(timestamp), ],
        )


@receiver(post_save, sender=Volume)
def volume_changed_handle(sender, instance: Volume, created=False, update_fields=None, **kwargs):
    # measure volumes to workflow manager
    if settings.WORKFLOW_MANAGER_URL and created:
        timestamp = time.time()
        send_measurements.apply_async(
            args=[instance.to_measurements(timestamp), ],
        )


@receiver(post_save, sender=Resource)
def resource_changed_handle(
        sender, instance: Resource, created=False, update_fields=None, **kwargs):
    # measure resources to workflow manager
    if settings.WORKFLOW_MANAGER_URL and (
        created or (
            update_fields is not None and (
                "plan" in update_fields
            ))):
        timestamp = time.time()
        send_measurements.apply_async(
            args=[instance.to_measurements(timestamp), ],
        )
