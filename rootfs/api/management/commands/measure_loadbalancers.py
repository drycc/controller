import uuid
import time
import logging
import ipaddress
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

    def _get_measure_name(self, ip):
        address = ipaddress.ip_address(ip)
        prefix = "intranet" if address.is_private else "internet"
        return f"{prefix}:{address.version}"

    def _measure_loadbalancers(self, app_map, timestamp):
        stop = timestamp - (timestamp % 3600)
        start = stop - 3600
        loadbalancers = []
        for metric, (_, value) in async_to_sync(monitor.query_loadbalancer(
                app_map.keys(), start, stop)):
            ip = metric["ip"]
            namespace = metric["namespace"]
            owner_id = app_map[namespace].owner_id
            loadbalancers.append({
                "app_id":  str(app_map[namespace].uuid),
                "owner": owner_id,
                "name": self._get_measure_name(ip),
                "type": "loadbalancer",
                "unit": "number",
                "usage": value,
                "kwargs": {
                    "ip": ip,
                    "node": metric["node"],
                    "service": metric["service"],
                    "instance": metric["instance"],
                },
                "timestamp": start
            })
        send_measurements.delay(loadbalancers)

    def handle(self, *args, **options):
        if settings.WORKFLOW_MANAGER_URL and settings.DRYCC_VICTORIAMETRICS_URL:
            timestamp = int(time.time())
            task_id = uuid.uuid4().hex
            logger.info(f"pushing {task_id} limits to workflow_manager when {timezone.now()}")
            app_map = {}
            for app in App.objects.all():
                app_map[app.id] = app
                if len(app_map) % 1000 == 0:
                    self._measure_loadbalancers(app_map, timestamp)
                    app_map = {}
            if len(app_map) > 0:
                self._measure_loadbalancers(app_map, timestamp)
            logger.info(f"pushed {task_id} limits to workflow_manager when {timezone.now()}")
            self.stdout.write("done")
