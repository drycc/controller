# -*- coding: utf-8 -*-

"""
Data models for the Drycc API.
"""
import os
import time
import hashlib
import hmac
import logging
import urllib.parse
import pkgutil
import inspect
import requests
from datetime import timedelta
from django.conf import settings
from django.db import models
from django.db.models.signals import post_delete, post_save
from django.utils.timezone import now
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from rest_framework.authtoken.models import Token
from api.utils import get_session
from api.tasks import retrieve_resource, send_measurements
from .app import App
from .appsettings import AppSettings
from .build import Build
from .certificate import Certificate
from .config import Config
from .domain import Domain
from .release import Release
from .tls import TLS
from .volume import Volume
from .resource import Resource


User = get_user_model()
logger = logging.getLogger(__name__)


# In order to comply with the Django specification, all models need to be imported
def import_all_models():
    for _, modname, ispkg in pkgutil.iter_modules([os.path.dirname(__file__)]):
        if not ispkg:
            exec(f"from api.models.{modname} import *")
    for key, value in locals().items():
        if inspect.isclass(value) and issubclass(value, models.Model):
            globals()[key] = value


import_all_models()


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
@receiver(post_save, sender=User)
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
