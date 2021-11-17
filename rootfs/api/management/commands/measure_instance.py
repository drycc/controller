import uuid
import time
import logging
from django.utils import timezone
from django.core.management.base import BaseCommand
from django.conf import settings
from api import influxdb
from api.models import Config
from api.tasks import send_measurements
from api.utils import unit_to_bytes, unit_to_millicpu

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """Management command for push data to manager"""

    def _to_cpu_measurement(self, config, record, timestamp):
        app_id = record["namespace"]
        owner_id = config.owner_id
        container_type = record["container_name"].replace(f"{app_id}-", "", 1)
        return {
            "app_id": app_id,
            "user_id": owner_id,
            "name": container_type,
            "type": "CPU",
            "unit": "MILLI",
            "usage": unit_to_millicpu(unit_to_millicpu(config.cpu.get(container_type))),
            "timestamp": "%f" % timestamp
        }

    def _to_memory_measurement(self, config, record, timestamp):
        app_id = record["namespace"]
        owner_id = config.owner_id
        container_type = record["container_name"].replace(f"{app_id}-", "", 1)
        return {
            "app_id": app_id,
            "user_id": owner_id,
            "name": container_type,
            "type": "CPU",
            "unit": "MILLI",
            "usage": unit_to_bytes(self.memory.get(container_type)),
            "timestamp": "%f" % timestamp
        }

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
                "timestamp": "%f" % timestamp
            })
        send_measurements.delay(networks)

    def _measure_config(self, config_map, timestamp):
        stop = timestamp - (timestamp % 3600)
        start = stop - 3600
        measurement_map = {}
        for record in influxdb.query_container_count(config_map.keys(), start, stop):
            app_id = record["namespace"]
            cpu = self._to_cpu_measurement(config_map[app_id], record, timestamp)
            memory = self._to_memory_measurement(config_map[app_id], record, timestamp)
            key = f"{app_id}:cpu:{cpu['name']}"
            if key in measurement_map:
                measurement_map[key]["usage"] += cpu["usage"]
            else:
                measurement_map[key] = cpu
            key = f"{app_id}:memory:{cpu['name']}"
            if key in measurement_map:
                measurement_map[key]["usage"] += memory["usage"]
            else:
                measurement_map[key] = memory
        return measurement_map.values()

    def handle(self, *args, **options):
        if settings.WORKFLOW_MANAGER_URL is not None:
            timestamp = time.time()
            task_id = uuid.uuid4().hex
            logger.info(f"pushing {task_id} limits to workflow_manager when {timezone.now()}")
            config_map = {}
            for config in Config.objects.all():
                config_map[config.app_d] = config
                if len(config_map) % 1000 == 0:
                    send_measurements.delay(self._measure_config(config_map, timestamp))
                    send_measurements.delay(self._measure_networks(config_map, timestamp))
                    config_map = {}
            if len(config_map) > 0:
                send_measurements.delay(self._measure_config(config_map, timestamp))
                send_measurements.delay(self._measure_networks(config_map, timestamp))
            logger.info(f"pushed {task_id} limits to workflow_manager when {timezone.now()}")
            self.stdout.write("done")
