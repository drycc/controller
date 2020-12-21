import json

from django.utils import timezone
from django.core.management.base import BaseCommand
from django.conf import settings

from influxdb_client import Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS
from api.utils import get_influxdb_client, unit_to_byte

from api.models import App


class Command(BaseCommand):
    """Management command for push data to influxdb"""

    def handle(self, *args, **options):
        print(f"push data to influxdb when {timezone.now()}")
        client = get_influxdb_client()
        write_api = client.write_api(write_options=SYNCHRONOUS)

        apps = App.objects.all()
        records = []
        for app in apps:
            config = app.config_set.latest()
            limits = json.loads(
                settings.KUBERNETES_NAMESPACE_DEFAULT_LIMIT_RANGES_SPEC)
            limits_default = limits.get('limits')[0].get('default')
            p = [Point("drycc_limit").tag("type", _).tag("namespace", config.app)
                     .field("cpu", int(config.cpu.get(type, limits_default.get('cpu'))[:-1]))  # noqa
                     .field("memory", unit_to_byte(config.memory.get(type, limits_default.get('memory'))))  # noqa
                     .time(timezone.now(), WritePrecision.MS) for _ in app.types]  # noqa
            records.extend(p)

            for resource in app.resource_set.all():
                p = Point("drycc_resource") \
                    .tag("name", resource.name) \
                    .tag("namespace", resource.app) \
                    .field("plan", resource.plan) \
                    .time(timezone.now(), WritePrecision.MS)
                records.append(p)

            for volume in app.volume_set.all():
                p = Point("drycc_volume") \
                    .tag("name", volume.name) \
                    .tag("namespace", volume.app) \
                    .field("size", unit_to_byte(volume.size)) \
                    .time(timezone.now(), WritePrecision.MS)
                records.append(p)

        write_api.write(bucket=settings.INFLUXDB_BUCKET, record=records)
