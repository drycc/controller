import uuid
import time
import logging
from asgiref.sync import async_to_sync
from django.utils import timezone
from django.core.management.base import BaseCommand
from django.conf import settings
from api import monitor
from api.models.app import App
from api.tasks import send_measurements

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """Management command for push data to manager"""

    def _measure_networks(self, app_map, timestamp):
        stop = timestamp - (timestamp % 3600)
        start = stop - 3600
        networks = []
        for metric, (_, value) in async_to_sync(monitor.query_network_receive_flow(
                app_map.keys(), start, stop)):
            networks.append({
                "app_id":  str(app_map[metric['namespace']].uuid),
                "owner": app_map[metric['namespace']].owner_id,
                "type": "network",
                "unit": "bytes",
                "name": "rx",
                "usage": value,
                "kwargs": {
                    "pod": metric['pod'],
                },
                "timestamp": start
            })
        for metric, (_, value) in async_to_sync(monitor.query_network_transmit_flow(
                app_map.keys(), start, stop)):
            networks.append({
                "app_id":  str(app_map[metric['namespace']].uuid),
                "owner": app_map[metric['namespace']].owner_id,
                "type": "network",
                "unit": "bytes",
                "name": "tx",
                "usage": value,
                "kwargs": {
                    "pod": metric['pod'],
                },
                "timestamp": start
            })
        send_measurements.delay(networks)

    def handle(self, *args, **options):
        if settings.WORKFLOW_MANAGER_URL:
            timestamp = int(time.time())
            task_id = uuid.uuid4().hex
            logger.info(f"pushing {task_id} limits to workflow_manager when {timezone.now()}")
            app_map = {}
            for app in App.objects.all():
                app_map[app.id] = app
                if len(app_map) % 1000 == 0:
                    self._measure_networks(app_map, timestamp)
                    app_map = {}
            if len(app_map) > 0:
                self._measure_networks(app_map, timestamp)
            logger.info(f"pushed {task_id} limits to workflow_manager when {timezone.now()}")
            self.stdout.write("done")
