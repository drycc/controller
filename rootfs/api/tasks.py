# Create your tasks here
import time
import uuid
import logging
from datetime import timedelta
from typing import List, Dict
from django.core import signals
from django.utils.timezone import now
from celery import shared_task

from api import manager
from api.models.resource import Resource
logger = logging.getLogger(__name__)


@shared_task(bind=True)
def retrieve_resource(self, resource):
    task_id = uuid.uuid4().hex
    signals.request_started.send(sender=task_id)
    try:
        if not resource.retrieve():
            t = time.time() - resource.created.timestamp()
            if t < 3600:
                raise self.retry(exc=None, countdown=30)
            elif t < 3600 * 12:
                raise self.retry(exc=None, countdown=1800)
            else:
                resource.detach_resource()
    except Resource.DoesNotExist:
        logger.exception(
            "retrieve task not found resource: {}".format(resource.id))
    finally:
        signals.request_finished.send(sender=task_id)


@shared_task(
    autoretry_for=(Exception, ),
    retry_backoff=8,
    retry_jitter=True,
    retry_backoff_max=3600,
    retry_kwargs={'max_retries': None}
)
def measure_config(config: List[Dict[str, str]]):
    task_id = uuid.uuid4().hex
    signals.request_started.send(sender=task_id)
    try:
        measurement = manager.Measurement()
        measurement.post_config(config)
    finally:
        signals.request_finished.send(sender=task_id)


@shared_task(
    autoretry_for=(Exception, ),
    retry_backoff=8,
    retry_jitter=True,
    retry_backoff_max=3600,
    retry_kwargs={'max_retries': None}
)
def measure_volumes(volumes: List[Dict[str, str]]):
    task_id = uuid.uuid4().hex
    signals.request_started.send(sender=task_id)
    try:
        measurement = manager.Measurement()
        measurement.post_volumes(volumes)
    finally:
        signals.request_finished.send(sender=task_id)


@shared_task(
    autoretry_for=(Exception, ),
    retry_backoff=8,
    retry_jitter=True,
    retry_backoff_max=3600,
    retry_kwargs={'max_retries': None}
)
def measure_networks(networks: List[Dict[str, str]]):
    task_id = uuid.uuid4().hex
    signals.request_started.send(sender=task_id)
    try:
        measurement = manager.Measurement()
        measurement.post_networks(networks)
    finally:
        signals.request_finished.send(sender=task_id)


@shared_task(
    autoretry_for=(Exception, ),
    retry_backoff=8,
    retry_jitter=True,
    retry_backoff_max=3600,
    retry_kwargs={'max_retries': None}
)
def measure_instances(instances: List[Dict[str, str]]):
    task_id = uuid.uuid4().hex
    signals.request_started.send(sender=task_id)
    try:
        measurement = manager.Measurement()
        measurement.post_instances(instances)
    finally:
        signals.request_finished.send(sender=task_id)


@shared_task(
    autoretry_for=(Exception, ),
    retry_backoff=8,
    retry_jitter=True,
    retry_backoff_max=3600,
    retry_kwargs={'max_retries': None}
)
def measure_resources(resources: List[Dict[str, str]]):
    task_id = uuid.uuid4().hex
    signals.request_started.send(sender=task_id)
    try:
        measurement = manager.Measurement()
        measurement.post_resources(resources)
    finally:
        signals.request_finished.send(sender=task_id)
