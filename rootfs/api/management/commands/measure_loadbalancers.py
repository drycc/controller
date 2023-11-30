import uuid
import time
import logging
from django.utils import timezone
from django.core.management.base import BaseCommand
from django.conf import settings
from api import monitor
from api.models.app import App
from api.tasks import send_measurements

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """Management command for push data to manager"""

    def _measure_loadbalancers(self, app_map, timestamp):
        stop = timestamp - (timestamp % 3600)
        start = stop - 3600
        loadbalancers = []
        for item in monitor.query_loadbalancer(app_map.keys(), start, stop):
            name = item["ip"]
            namespace = item["namespace"]
            owner_id = app_map[namespace].owner_id
            loadbalancers.append({
                "app_id":  str(app_map[namespace].uuid),
                "owner": owner_id,
                "name": name,
                "type": "loadbalancer",
                "unit": "number",
                "usage": 1,
                "timestamp": start
            })
        send_measurements.delay(loadbalancers)

    def handle(self, *args, **options):
        if settings.WORKFLOW_MANAGER_URL and settings.DRYCC_PROMETHEUS_URL:
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
