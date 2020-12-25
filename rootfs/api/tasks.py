# Create your tasks here
import time
import logging
from datetime import timedelta

from django.core import signals
from django.utils.timezone import now
from django.conf import settings
from celery import shared_task
from influxdb_client import Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

from api.models.resource import Resource
from api.utils import get_influxdb_client

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


@shared_task
def write_point(data):
    signals.request_started.send(sender=data['task_id'])
    try:
        client = get_influxdb_client()
        write_api = client.write_api(write_options=SYNCHRONOUS)
        ps = []
        for r in data["records"]:
            p = Point(data["measurement"])
            for k, v in r["tag"].items():
                p.tag(k, v)
            for k, v in r["field"].items():
                p.field(k, v)
            p.time(now(), WritePrecision.MS)
            ps.append(p)
        write_api.write(bucket=settings.INFLUXDB_BUCKET, record=ps)
    except Exception as e:
        logger.info("write influxdb point fail: {}".format(e))
    finally:
        signals.request_finished.send(sender=data['task_id'])
