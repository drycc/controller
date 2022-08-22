import os
from os.path import dirname, realpath

import faulthandler
faulthandler.enable()

# If there is a mutating admission webhook configuration, start webhook
if os.path.exists("/etc/controller/webhook/cert"):
    bind = '0.0.0.0:8443'
    keyfile = "/etc/controller/webhook/cert/tls.key"
    certfile = "/etc/controller/webhook/cert/tls.crt"
else:
    bind = '0.0.0.0:8000'

workers = int(os.environ.get('GUNICORN_WORKERS', 2))
worker_class = "uvicorn.workers.UvicornWorker"
pythonpath = dirname(dirname(dirname(realpath(__file__))))
timeout = 1200
pidfile = '/tmp/gunicorn.pid'
logger_class = 'drycc.gunicorn.logging.Logging'
loglevel = 'info'
errorlog = '-'
accesslog = '-'
access_log_format = '%(h)s "%(r)s" %(s)s %(b)s "%(a)s"'


def worker_int(worker):
    """Print a stack trace when a worker receives a SIGINT or SIGQUIT signal."""
    worker.log.warning('worker terminated')
    import traceback
    traceback.print_stack()


def worker_abort(worker):
    """Print a stack trace when a worker receives a SIGABRT signal, generally on timeout."""
    worker.log.warning('worker aborted')
    import traceback
    traceback.print_stack()
