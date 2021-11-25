# Create your tasks here
import time
import uuid
import logging
from typing import List, Dict
from django.core import signals
from celery import shared_task

from api import manager
from api.models import ServiceUnavailable
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
def send_measurements(measurements: List[Dict[str, str]]):
    task_id = uuid.uuid4().hex
    signals.request_started.send(sender=task_id)
    try:
        measurement = manager.Measurement()
        measurement.post(measurements)
    finally:
        signals.request_finished.send(sender=task_id)


@shared_task(
    autoretry_for=(ServiceUnavailable, ),
    retry_jitter=True,
    retry_kwargs={'max_retries': 3}
)
def scale_app(app, user, structure):
    task_id = uuid.uuid4().hex
    signals.request_started.send(sender=task_id)
    try:
        app.scale(user, structure)
    finally:
        signals.request_finished.send(sender=task_id)


@shared_task(
    autoretry_for=(ServiceUnavailable, ),
    retry_jitter=True,
    retry_kwargs={'max_retries': 3}
)
def restart_app(app, **kwargs):
    task_id = uuid.uuid4().hex
    signals.request_started.send(sender=task_id)
    try:
        app.restart(**kwargs)
    finally:
        signals.request_finished.send(sender=task_id)
