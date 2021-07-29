# Create your tasks here
import time
import uuid
import json
import logging
import requests
from datetime import timedelta
from typing import List, Dict
from django.core import signals
from django.conf import settings
from django.utils.timezone import now
from celery import shared_task
from requests_toolbelt import user_agent
from api.models.resource import Resource
from api import __version__ as drycc_version
logger = logging.getLogger(__name__)


@shared_task
def retrieve_resource(resource):
    task_id = uuid.uuid4().hex
    signals.request_started.send(sender=task_id)
    try:
        if not resource.retrieve():
            t = time.time() - resource.created.timestamp()
            if t < 3600:
                retrieve_resource.apply_async(
                    args=(resource, ),
                    eta=now() + timedelta(seconds=30))
            elif t < 3600 * 12:
                retrieve_resource.apply_async(
                    args=(resource, ),
                    eta=now() + timedelta(seconds=1800))
            else:
                resource.detach_resource()
    except Resource.DoesNotExist:
        logger.exception("retrieve task not found resource: {}".format(resource.id))  # noqa
    finally:
        signals.request_finished.send(sender=task_id)


@shared_task
def measure_config(config: List[Dict[str, str]]):
    """
    [
        {
            "app_id":  "test",
            "owner_id": "test",
            "container_type": web,
            "cpu": "1",
            "memory": "2G",
            "timestamp": 1609231998.9103732
        }
    ]
    """
    task_id = uuid.uuid4().hex
    signals.request_started.send(sender=task_id)
    try:
        requests.post(
            url="%s/measurements/config/" % settings.WORKFLOW_MANAGER_URL,
            headers={
                'Content-Type': 'application/json',
                'Authorization': 'token %s' % settings.WORKFLOW_MANAGER_TOKEN,
                'User-Agent': user_agent('Drycc Controller ', drycc_version)
            },
            data=json.dumps(config)
        )
    except Exception as e:
        logger.exception("write influxdb point fail: {}".format(e))
    finally:
        signals.request_finished.send(sender=task_id)


@shared_task
def measure_volumes(volumes: List[Dict[str, str]]):
    """
    [
        {
            "name": "disk",
            "app_id": "test",
            "owner_id": "test",
            "size": "100G",
            "timestamp": "1609231998.9103732"
        }
    ]
    """
    task_id = uuid.uuid4().hex
    signals.request_started.send(sender=task_id)
    try:
        requests.post(
            url="%s/measurements/volumes/" % settings.WORKFLOW_MANAGER_URL,
            headers={
                'Content-Type': 'application/json',
                'Authorization': 'token %s' % settings.WORKFLOW_MANAGER_TOKEN,
                'User-Agent': user_agent('Drycc Controller ', drycc_version)
            },
            data=json.dumps(volumes)
        )
    except Exception as e:
        logger.exception("write influxdb point fail: {}".format(e))
    finally:
        signals.request_finished.send(sender=task_id)


@shared_task
def measure_networks(networks: List[Dict[str, str]]):
    """
    [
        {
            "app_id": "test",
            "owner_id": "test",
            "pod_name": "django2test-web-xxxxxx",
            "rx_bytes": "10000",
            "tx_bytes": "200000",
            "timestamp": "1609231998.9103732"
        }
    ]
    """
    task_id = uuid.uuid4().hex
    signals.request_started.send(sender=task_id)
    try:
        requests.post(
            url="%s/measurements/networks/" % settings.WORKFLOW_MANAGER_URL,
            headers={
                'Content-Type': 'application/json',
                'Authorization': 'token %s' % settings.WORKFLOW_MANAGER_TOKEN,
                'User-Agent': user_agent('Drycc Controller ', drycc_version)
            },
            data=json.dumps(networks)
        )
    except Exception as e:
        logger.exception("write influxdb point fail: {}".format(e))
    finally:
        signals.request_finished.send(sender=task_id)


@shared_task
def measure_instances(instances: List[Dict[str, str]]):
    """
    [
        {
            "app_id": "test",
            "owner_id":  "test",
            "container_type": "web",
            "container_count": 1,
            "timestamp": "1609231998.9103732"
        }
    ]
    """
    task_id = uuid.uuid4().hex
    signals.request_started.send(sender=task_id)
    try:
        requests.post(
            url="%s/measurements/instances/" % settings.WORKFLOW_MANAGER_URL,
            headers={
                'Content-Type': 'application/json',
                'Authorization': 'token %s' % settings.WORKFLOW_MANAGER_TOKEN,
                'User-Agent': user_agent('Drycc Controller ', drycc_version)
            },
            data=json.dumps(instances)
        )
    except Exception as e:
        logger.exception("write influxdb point fail: {}".format(e))
    finally:
        signals.request_finished.send(sender=task_id)


@shared_task
def measure_resources(resources: List[Dict[str, str]]):
    """
    [
        {
            "name": "test1",
            "app_id": "redis",
            "owener_id": "test",
            "plan": "redis:small",
            "timestamp": "1609231998.9103732"
        }
    ]
    """
    task_id = uuid.uuid4().hex
    signals.request_started.send(sender=task_id)
    try:
        requests.post(
            url="%s/measurements/resources/" % settings.WORKFLOW_MANAGER_URL,
            headers={
                'Content-Type': 'application/json',
                'Authorization': 'token %s' % settings.WORKFLOW_MANAGER_TOKEN,
                'User-Agent': user_agent('Drycc Controller ', drycc_version)
            },
            data=json.dumps(resources)
        )
    except Exception as e:
        logger.exception("write influxdb point fail: {}".format(e))
    finally:
        signals.request_finished.send(sender=task_id)
