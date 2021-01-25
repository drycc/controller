import uuid
import time
import logging
from django.utils import timezone
from django.core.management.base import BaseCommand
from django.conf import settings
from api import influxdb
from api.tasks import measure_networks, measure_instances
from api.models import App

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """Management command for push data to manager"""

    def _measure_networks(self, app_map, timestamp):
        stop = timestamp - (timestamp % 3600)
        start = stop - 3600
        networks = []
        for record in influxdb.query_network_flow(app_map.keys(), start, stop):
            app_id = record["namespace"]
            owner_id = app_map[app_id].owner_id
            networks.append({
                "app_id": app_id,
                "user_id":  owner_id,
                "pod_name": record["pod_name"],
                "rx_bytes": record["rx_bytes"],
                "tx_bytes": record["tx_bytes"],
                "timestamp": timestamp
            })
        measure_networks.delay(networks)

    def _measure_instances(self, app_map, timestamp):
        stop = timestamp - (timestamp % 3600)
        start = stop - 3600
        instances = []
        for record in influxdb.query_container_count(app_map.keys(), start, stop):
            app_id = record["namespace"]
            owner_id = app_map[app_id].owner_id
            container_type = record["container_name"].replace(f"{app_id}-", "", 1)
            instances.append({
                "app_id": app_id,
                "user_id":  owner_id,
                "container_type": container_type,
                "container_count": record["_value"],
                "timestamp": timestamp
            })
        measure_instances.delay(instances)

    def handle(self, *args, **options):
        if settings.WORKFLOW_MANAGER_URL is not None:
            timestamp = int(time.time())
            task_id = uuid.uuid4().hex
            logger.info(f"pushing {task_id} networks to workflow_manager when {timezone.now()}")
            app_map = {}
            for app in App.objects.all():
                app_map[app.id] = app
                if len(app_map) % 300 == 0:
                    self._measure_networks(app_map, timestamp)
                    self._measure_instances(app_map, timestamp)
                    app_map = {}
            if len(app_map) > 0:
                self._measure_networks(app_map, timestamp)
                self._measure_instances(app_map, timestamp)
            logger.info(f"pushed {task_id} networks to workflow_manager when {timezone.now()}")
            self.stdout.write("done")
