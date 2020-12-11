from django.core.management.base import BaseCommand

from api.models import App


class Command(BaseCommand):
    """Management command for push data to influxdb"""
    def handle(self, *args, **options):
        print("push data to influxdb")
        apps = App.objects.all()
        for app in apps:
            for volume in app.volume_set():
                volume.to_influx()
            for resource in app.resource_set():
                resource.to_influx()
            for config in app.config_set().latest():
                config.to_influx()
