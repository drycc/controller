import os
from kombu import Exchange, Queue
from celery import Celery


class Config(object):
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
    task_default_queue = 'low'
    task_default_exchange = 'controller.priority'
    task_default_routing_key = 'controller.priority.low'
    broker_connection_retry_on_startup = True
    worker_cancel_long_running_tasks_on_connection_loss = True


app = Celery('drycc')
app.config_from_object(Config())
app.conf.update(
    task_routes={
        'api.tasks.scale_app': {
            'queue': 'high',
            'exchange': 'controller.priority',
            'routing_key': 'controller.priority.high',
        },
        'api.tasks.restart_app': {
            'queue': 'high',
            'exchange': 'controller.priority',
            'routing_key': 'controller.priority.high',
        },
        'api.tasks.retrieve_resource': {
            'queue': 'high',
            'exchange': 'controller.priority',
            'routing_key': 'controller.priority.high',
        },
        'api.tasks.send_measurements': {
            'queue': 'middle',
            'exchange': 'controller.priority',
            'routing_key': 'controller.priority.middle',
        },
    },
    task_queues=(
        Queue(
            'low',
            exchange=Exchange('controller.priority', type="direct"),
            routing_key='controller.priority.low',
            queue_arguments={'x-max-priority': 16},
        ),
        Queue(
            'high',
            exchange=Exchange('controller.priority', type="direct"),
            routing_key='controller.priority.high',
            queue_arguments={'x-max-priority': 64},
        ),
        Queue(
            'middle',
            exchange=Exchange('controller.priority', type="direct"),
            routing_key='controller.priority.middle',
            queue_arguments={'x-max-priority': 32},
        ),
    ),
)
app.autodiscover_tasks()
