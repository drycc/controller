import uuid
import hashlib
import logging
import random
from datetime import timedelta
from asgiref.sync import async_to_sync
from django.utils import timezone
from django.core.management.base import BaseCommand
from django.conf import settings
from api import monitor
from api.models.app import App
from api.tasks import send_usage

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """Management command for push data to manager"""

    def _upload_network_usage(self, start_time, app_map, timestamp):
        stop = timestamp - (timestamp % 3600)
        start = stop - 3600
        networks = []
        for item in async_to_sync(monitor.query_network_usage)(app_map.keys(), start, stop):
            metric = item["metric"]
            _, value = item["value"]
            pod_name = metric['pod']
            networks.append({
                "app_id":  str(app_map[metric['namespace']].uuid),
                "owner": app_map[metric['namespace']].owner_id,
                "type": "network",
                "unit": "bytes",
                "name": metric['direction'],
                "usage": value,
                "kwargs": {
                    "pod": pod_name,
                },
                "timestamp": start,
                "identifier": hashlib.md5(pod_name.encode("utf-8")).hexdigest(),
            })
        logger.info(f"bulk sent: {len(networks)}")
        send_usage.apply_async(
            args=(networks,), eta=start_time + timedelta(seconds=random.randint(1, 3600))
        )

    def handle(self, *args, **options):
        if settings.WORKFLOW_MANAGER_URL:
            now = timezone.now()
            start_time, timestamp, task_id = now, int(now.timestamp()), uuid.uuid4().hex
            logger.info(f"pushing {task_id} networks to workflow_manager when {now}")
            app_map = {}
            for app in App.objects.all():
                app_map[app.id] = app
                if len(app_map) % 1000 == 0:
                    self._upload_network_usage(start_time, app_map, timestamp)
                    app_map = {}
            if len(app_map) > 0:
                self._upload_network_usage(start_time, app_map, timestamp)
            logger.info(f"pushed {task_id} networks to workflow_manager when {timezone.now()}")
            self.stdout.write("done")
