import uuid
import time
import logging
import random
from datetime import timedelta
from django.utils import timezone
from django.core.management.base import BaseCommand
from django.conf import settings
from api.models.gateway import Gateway
from api.tasks import send_usage

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """Management command for push data to manager"""

    def handle(self, *args, **options):
        if settings.WORKFLOW_MANAGER_URL:
            start_time, timestamp, task_id = timezone.now(), int(time.time()), uuid.uuid4().hex
            logger.info(f"pushing {task_id} gateways to workflow_manager when {timezone.now()}")
            gateway_list = []
            for gateway in Gateway.objects.all():
                gateway_list.extend(gateway.to_usages(timestamp))
                if len(gateway_list) % 1000 == 0:
                    send_usage.apply_async(
                        args=(gateway_list,),
                        eta=start_time + timedelta(seconds=random.randint(1, 1800))
                    )
                    gateway_list = []
            if len(gateway_list) > 0:
                send_usage.apply_async(
                    args=(gateway_list,),
                    eta=start_time + timedelta(seconds=random.randint(1, 1800))
                )
            logger.info(f"pushed {task_id} gateways to workflow_manager when {timezone.now()}")
            self.stdout.write("done")
