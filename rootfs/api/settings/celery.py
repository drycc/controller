import os
from celery import Celery, platforms


class Config:
    # Celery Configuration Options
    timezone = "Asia/Shanghai"
    enable_utc = True
    task_serializer = 'pickle'
    accept_content = frozenset([
        'application/data',
        'application/text',
        'application/json',
        'application/x-python-serialize',
    ])
    task_track_started = True
    task_time_limit = 30 * 60
    worker_max_tasks_per_child = 200
    result_expires = 24 * 60 * 60
    broker_url = os.environ.get('DRYCC_RABBITMQ_URL', 'amqp://guest:guest@127.0.0.1:5672/')  # noqa
    cache_backend = 'django-cache'
    task_default_queue = 'controller'
    task_default_exchange = 'priority'
    task_default_routing_key = 'controller.priority.low'
    worker_cancel_long_running_tasks_on_connection_loss = True


app = Celery('drycc')
app.config_from_object(Config)
app.conf.update(
    task_routes={
        'api.tasks.scale_app': {
            'queue': 'priority',
            'exchange': 'controller',
            'routing_key': 'controller.priority.high',
        },
        'api.tasks.restart_app': {
            'queue': 'priority',
            'exchange': 'controller',
            'routing_key': 'controller.priority.high',
        },
        'api.tasks.retrieve_resource': {
            'queue': 'priority',
            'exchange': 'controller',
            'routing_key': 'controller.priority.high',
        },
        'api.tasks.send_measurements': {
            'queue': 'priority',
            'exchange': 'controller',
            'routing_key': 'controller.priority.middle',
        },
    },
)
app.autodiscover_tasks()
platforms.C_FORCE_ROOT = True
