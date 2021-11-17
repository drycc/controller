import uuid
import time
import logging
from django.utils import timezone
from django.core.management.base import BaseCommand
from django.conf import settings
from api.models import Volume
from api.tasks import send_measurements

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """Management command for push data to manager"""

    def handle(self, *args, **options):
        if settings.WORKFLOW_MANAGER_URL is not None:
            timestamp = time.time()
            task_id = uuid.uuid4().hex
            logger.info(f"pushing {task_id} volumes to workflow_manager when {timezone.now()}")
            volume_list = []
            for volume in Volume.objects.all():
                volume_list.extend(volume.to_measurements(timestamp))
                if len(volume_list) % 1000 == 0:
                    send_measurements.delay(volume_list)
                    volume_list = []
            if len(volume_list) > 0:
                send_measurements.delay(volume_list)
            logger.info(f"pushed {task_id} volumes to workflow_manager when {timezone.now()}")
            self.stdout.write("done")
