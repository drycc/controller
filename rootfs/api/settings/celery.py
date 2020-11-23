import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'api.settings.production')
app = Celery('drycc')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.conf.update(
    task_routes={
        'api.tasks.retrieve_resource': {'queue': 'priority.high'},
    },
)
app.autodiscover_tasks()
