import uuid
import time
from django.utils import timezone
from django.core.management.base import BaseCommand
from django.conf import settings
from api.models import Config
from api.tasks import measure_config


class Command(BaseCommand):
    """Management command for push data to influxdb"""

    def handle(self, *args, **options):
        if settings.WORKFLOW_MANAGER_URL is not None:
            timestamp = time.time()
            task_id = uuid.uuid4().hex
            print(f"pushing {task_id} limits to workflow_manager when {timezone.now()}")
            config_list = []
            for config in Config.objects.all():
                config_list.extend(config.to_measurements(timestamp))
                if len(config_list) % 1000 == 0:
                    measure_config.delay(config_list)
                    config_list = []
            if len(config_list) > 0:
                measure_config.delay(*config_list)
            print(f"pushed {task_id} limits to workflow_manager when {timezone.now()}")
