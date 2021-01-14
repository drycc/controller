import uuid
import time
from django.utils import timezone
from django.core.management.base import BaseCommand
from django.conf import settings
from api.models import Resource
from api.tasks import measure_resources


class Command(BaseCommand):
    """Management command for push data to influxdb"""

    def handle(self, *args, **options):
        if settings.WORKFLOW_MANAGER_URL is not None:
            timestamp = time.time()
            task_id = uuid.uuid4().hex
            print(f"pushing {task_id} resources to workflow_manager when {timezone.now()}")
            resource_list = []
            for resource in Resource.objects.all():
                resource_list.extend(resource.to_to_measurements(timestamp))
                if len(resource_list) % 1000 == 0:
                    measure_resources.delay(resource_list)
                    resource_list = []
            if len(resource_list) > 0:
                measure_resources.delay(*resource_list)
            print(f"pushed {task_id} resources to workflow_manager when {timezone.now()}")
