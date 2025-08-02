import uuid
import time
import logging
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
            timestamp = time.time()
            task_id = uuid.uuid4().hex
            logger.info(f"pushing {task_id} gateways to workflow_manager when {timezone.now()}")
            gateway_list = []
            for gateway in Gateway.objects.all():
                gateway_list.extend(gateway.to_usages(timestamp))
                if len(gateway_list) % 1000 == 0:
                    send_usage.delay(gateway_list)
                    gateway_list = []
            if len(gateway_list) > 0:
                send_usage.delay(gateway_list)
            logger.info(f"pushed {task_id} gateways to workflow_manager when {timezone.now()}")
            self.stdout.write("done")
