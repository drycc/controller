import uuid
import time
from contextlib import closing
from django.utils import timezone
from django.core.management.base import BaseCommand
from django.conf import settings
from api.tasks import measure_networks, measure_instances
from api.models import App
from api.utils import get_influxdb_client


class Command(BaseCommand):
    """Management command for push data to influxdb"""

    def _build_query_networks_flux(self, app_map, timestamp):
        timestamp = int(timestamp)
        stop = timestamp - (timestamp % 3600)
        start = stop - 3600
        namespace_range = ' or '.join(
                ['r["namespace"] == \"{app_id}\"' for app_id in app_map.keys()])
        return f'''
            from(bucket: "kubernetes")
            |> range(start: {start}, stop: {stop})
            |> filter(fn: (r) => r["_measurement"] == "kubernetes_pod_network"
                and ({namespace_range}))
            |> pivot(
                rowKey:["_time"],
                columnKey: ["_field"],
                valueColumn: "_value"
            )
            |> increase(columns: ["rx_bytes", "tx_bytes", "tx_errors", "rx_errors"])
            |> last(column: "_time")
            '''

    def _build_query_instances_flux(self, app_map, timestamp):
        timestamp = int(timestamp)
        stop = timestamp - (timestamp % 3600)
        start = stop - 3600
        namespace_range = ' or '.join(
                ['r["namespace"] == \"{app_id}\"' for app_id in app_map.keys()])
        return f'''
            from(bucket: "kubernetes")
            |> range(start: {start}, stop: {stop})
            |> filter(fn: (r) => r["_measurement"] == "kubernetes_pod_container"
                and r["_field"]=="cpu_usage_core_nanoseconds"
                and ({namespace_range}))
            |> group(columns: ["_time", "namespace", "container_name"])
            |> count(column: "_value")
            |> group(columns: ["namespace", "container_name"])
            |> top(n: 3)
            |> min(column: "_value")
            '''

    def _measure_networks(self, app_map, timestamp):
        networks = []
        with closing(get_influxdb_client()) as client:
            with closing(client.query_api()) as query_api:
                with closing(query_api.query_stream(
                        self._build_query_networks_flux(app_map, timestamp))
                        ) as records:
                    for record in records:
                        app_id = record["namespace"]
                        user_id = app_map[app_id].user_id
                        networks.append({
                            "app_id": app_id,
                            "user_id":  user_id,
                            "pod_name": record["pod_name"],
                            "rx_bytes": record["rx_bytes"],
                            "tx_bytes": record["tx_bytes"],
                            "timestamp": timestamp
                        })
        measure_networks.delay(networks)

    def _measure_instances(self, app_map, timestamp):
        instances = []
        with closing(get_influxdb_client()) as client:
            with closing(client.query_api()) as query_api:
                with closing(query_api.query_stream(
                        self._build_query_instances_flux(app_map, timestamp))
                        ) as records:
                    for record in records:
                        app_id = record["namespace"]
                        user_id = app_map[app_id].user_id
                        container_type = record["container_name"].replace(f"-{app_id}", "", 1)
                        instances.append({
                            "app_id": app_id,
                            "user_id":  user_id,
                            "container_type": container_type,
                            "container_count": record["_value"],
                            "timestamp": timestamp
                        })
        measure_instances.delay(instances)

    def handle(self, *args, **options):
        if settings.WORKFLOW_MANAGER_URL is not None:
            timestamp = time.time()
            task_id = uuid.uuid4().hex
            print(f"pushing {task_id} networks to workflow_manager when {timezone.now()}")
            app_map = {}
            for app in App.objects.all():
                app_map[app.pk] = app
                if len(app_map) % 1000 == 0:
                    self._measure_networks(app_map, timestamp)
                    self._measure_instances(app_map, timestamp)
                    app_map = {}
            if len(app_map) > 0:
                self._measure_networks(app_map, timestamp)
                self._measure_instances(app_map, timestamp)
            print(f"pushed {task_id} networks to workflow_manager when {timezone.now()}")
