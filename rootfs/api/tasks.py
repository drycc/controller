# Create your tasks here
import time
import logging
from django.core import signals
from datetime import timedelta
from django.utils.timezone import now
from celery import shared_task

from .models.resource import Resource


logger = logging.getLogger(__name__)


@shared_task
def retrieve_resource(data):
    signals.request_started.send(sender=data['task_id'])
    try:
        resource = Resource.objects.get(uuid=data['resource_id'])
        if not resource.retrieve():
            t = time.time() - resource.created.timestamp()
            if t < 3600:
                retrieve_resource.apply_async(
                    args=(data, ),
                    eta=now() + timedelta(seconds=30))
            elif t < 3600 * 12:
                retrieve_resource.apply_async(
                    args=(data, ),
                    eta=now() + timedelta(seconds=1800))
            else:
                resource.detach_resource()
    except Resource.DoesNotExist:
        logger.info("retrieve task not found resource: {}".format(data['resource_id']))  # noqa
    finally:
        signals.request_finished.send(sender=data['task_id'])
