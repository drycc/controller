import random
import string
import os
import multiprocessing
from django.core import signals
from api.settings.celery import app
from api.settings.production import DATABASES
from api.settings.production import *  # noqa

# Fix Django test error.
# https://github.com/django/django/blob/main/django/test/runner.py#L455
# This code was removed in Django > 5.2, so it is safe to remove this when we upgrade.
multiprocessing.set_start_method('fork')
# Monkey patch celery
app.conf.update(task_always_eager=True)
signals.request_started.send = lambda sender, **named: []
signals.request_finished.send = lambda sender, **named: []
signals.got_request_exception.send = lambda sender, **named: []

# A boolean that turns on/off debug mode.
# https://docs.djangoproject.com/en/1.11/ref/settings/#debug
DEBUG = True

# If set to True, Django's normal exception handling of view functions
# will be suppressed, and exceptions will propagate upwards
# https://docs.djangoproject.com/en/1.11/ref/settings/#debug-propagate-exceptions
DEBUG_PROPAGATE_EXCEPTIONS = True

# scheduler for testing
SCHEDULER_MODULE = 'scheduler.mock'
SCHEDULER_URL = 'http://test-scheduler.example.com'

# randomize test database name so we can run multiple unit tests simultaneously
DATABASES['default']['NAME'] = "unittest-{}".format(''.join(
    random.choice(string.ascii_letters + string.digits) for _ in range(8)))
DATABASES['default']['USER'] = 'postgres'

# use DB name to isolate the data for each test run
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': DATABASES['default']['NAME'],
        'KEY_PREFIX': DATABASES['default']['NAME'],
    }
}

# How long k8s waits for a pod to finish work after a SIGTERM before sending SIGKILL
KUBERNETES_POD_TERMINATION_GRACE_PERIOD_SECONDS = int(
    os.environ.get('KUBERNETES_POD_TERMINATION_GRACE_PERIOD_SECONDS', 2))

DRYCC_APP_STORAGE_CLASS = os.environ.get('DRYCC_APP_STORAGE_CLASS', '')


class DisableMigrations(object):

    def __contains__(self, item):
        return True

    def __getitem__(self, item):
        return None


MIGRATION_MODULES = DisableMigrations()

# WORKFLOW_MANAGER_URL = "http://127.0.0.1:8000"
WORKFLOW_MANAGER_ACCESS_KEY = "1234567890"
WORKFLOW_MANAGER_SECRET_KEY = "1234567890"

DRYCC_VOLUME_CLAIM_TEMPLATE = """
{% if type == 'csi' %}
{
  "metadata": {
    "annotations": {
      "billing.drycc.cc/type": "usage"
    }
  },
  "spec": {
    "accessModes": [
      "ReadWriteMany"
    ],
    "storageClassName": "{{storage_class}}",
    "resources": {
      "requests": {
        "storage": "{{size}}"
      }
    },
    "volumeMode": "Filesystem"
  }
}
{% elif type == 'nfs' %}
{
  "metadata": {
    "annotations": {
      "billing.drycc.cc/type": "basic"
    }
  },
  "spec": {
    "accessModes": [
      "ReadWriteMany"
    ],
    "storageClassName": "",
    "resources": {
      "requests": {
        "storage": "{{size}}"
      }
    },
    "volumeName": "{{volume_name}}"
  }
}
{% elif type == 'nfs' %}
{
  "metadata": {
    "annotations": {
      "billing.drycc.cc/type": "basic"
    }
  },
  "spec": {
    "accessModes": [
      "ReadWriteMany"
    ],
    "storageClassName": "",
    "resources": {
      "requests": {
        "storage": "{{size}}"
      }
    },
    "volumeName": "{{volume_name}}"
  }
}
{% endif %}
"""
