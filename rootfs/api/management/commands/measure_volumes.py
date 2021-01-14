import uuid
import time
from django.utils import timezone
from django.core.management.base import BaseCommand
from django.conf import settings
from api.models import Volume
from api.tasks import measure_volumes


class Command(BaseCommand):
    """Management command for push data to influxdb"""

    def handle(self, *args, **options):
        if settings.WORKFLOW_MANAGER_URL is not None:
            timestamp = time.time()
            task_id = uuid.uuid4().hex
            print(f"pushing {task_id} volumes to workflow_manager when {timezone.now()}")
            volume_list = []
            for volume in Volume.objects.all():
                volume_list.extend(volume.to_measurements(timestamp))
                if len(volume_list) % 1000 == 0:
                    measure_volumes.delay(volume_list)
                    volume_list = []
            if len(volume_list) > 0:
                measure_volumes.delay(*volume_list)
            print(f"pushed {task_id} volumes to workflow_manager when {timezone.now()}")
