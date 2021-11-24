import uuid
import time
import logging
from django.utils import timezone
from django.core.management.base import BaseCommand
from django.conf import settings
from api import influxdb
from api.models import Config
from api.tasks import send_measurements

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """Management command for push data to manager"""

    def _measure_networks(self, config_map, timestamp):
        stop = timestamp - (timestamp % 3600)
        start = stop - 3600
        networks = []
        for record in influxdb.query_network_flow(config_map.keys(), start, stop):
            app_id = record["namespace"]
            owner_id = config_map[app_id].owner_id
            networks.append({
                "app_id":  app_id,
                "owner_id": owner_id,
                "name": record["pod_name"],
                "type": "NETWORK",
                "unit": "BYTES",
                "usage": record["rx_bytes"] + record["tx_bytes"],
                "timestamp": "%d" % start
            })
        send_measurements.delay(networks)

    def handle(self, *args, **options):
        if settings.WORKFLOW_MANAGER_URL is not None:
            timestamp = int(time.time())
            task_id = uuid.uuid4().hex
            logger.info(f"pushing {task_id} limits to workflow_manager when {timezone.now()}")
            config_map = {}
            for config in Config.objects.all():
                config_map[config.app_d] = config
                if len(config_map) % 1000 == 0:
                    send_measurements.delay(self._measure_networks(config_map, timestamp))
                    config_map = {}
            if len(config_map) > 0:
                send_measurements.delay(self._measure_networks(config_map, timestamp))
            logger.info(f"pushed {task_id} limits to workflow_manager when {timezone.now()}")
            self.stdout.write("done")
