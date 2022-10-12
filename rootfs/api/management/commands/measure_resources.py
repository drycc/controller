import uuid
import time
import logging
from django.utils import timezone
from django.core.management.base import BaseCommand
from django.conf import settings
from api.models.resource import Resource
from api.tasks import send_measurements

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """Management command for push data to manager"""

    def handle(self, *args, **options):
        if settings.WORKFLOW_MANAGER_URL:
            timestamp = time.time()
            task_id = uuid.uuid4().hex
            logger.info(f"pushing {task_id} resources to workflow_manager when {timezone.now()}")
            resource_list = []
            for resource in Resource.objects.all():
                resource_list.extend(resource.to_measurements(timestamp))
                if len(resource_list) % 1000 == 0:
                    send_measurements.delay(resource_list)
                    resource_list = []
            if len(resource_list) > 0:
                send_measurements.delay(resource_list)
            logger.info(f"pushed {task_id} resources to workflow_manager when {timezone.now()}")
            self.stdout.write("done")
