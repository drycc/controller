import uuid
import time
import logging
import random
from datetime import timedelta
from django.utils import timezone
from django.core.management.base import BaseCommand
from django.conf import settings
from api.models.resource import Resource
from api.tasks import send_usage

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """Management command for push data to manager"""

    def handle(self, *args, **options):
        if settings.WORKFLOW_MANAGER_URL:
            start_time, timestamp, task_id = timezone.now(), time.time(), uuid.uuid4().hex
            logger.info(f"pushing {task_id} resources to workflow_manager when {timezone.now()}")
            resource_list = []
            for resource in Resource.objects.filter(status="Ready"):
                resource_list.extend(resource.to_usages(timestamp))
                if len(resource_list) % 1000 == 0:
                    send_usage.apply_async(
                        args=(resource_list,),
                        eta=start_time + timedelta(seconds=random.randint(1, 1800))
                    )
                    resource_list = []
            if len(resource_list) > 0:
                send_usage.apply_async(
                    args=(resource_list,),
                    eta=start_time + timedelta(seconds=random.randint(1, 1800))
                )
            logger.info(f"pushed {task_id} resources to workflow_manager when {timezone.now()}")
            self.stdout.write("done")
