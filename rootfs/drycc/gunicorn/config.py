import os
from os.path import dirname, realpath, exists

import faulthandler
faulthandler.enable()

bind = '0.0.0.0:8000'

# If there is a mutating admission mutate configuration, start mutate
MUTATE_KEY_PATH = os.environ.get(
    'DRYCC_MUTATE_KEY_PATH', '/etc/controller/mutate/cert/key')
MUTATE_TLS_KEY_PATH = os.environ.get(
    'DRYCC_MUTATE_TLS_KEY_PATH', '/etc/controller/mutate/cert/tls.key')
MUTATE_TLS_CRT_PATH = os.environ.get(
    'DRYCC_MUTATE_TLS_CRT_PATH', '/etc/controller/mutate/cert/tls.crt')
if exists(MUTATE_KEY_PATH) and exists(MUTATE_TLS_KEY_PATH) and exists(MUTATE_TLS_CRT_PATH):
    bind = '0.0.0.0:8443'
    keyfile = MUTATE_TLS_KEY_PATH
    certfile = MUTATE_TLS_CRT_PATH
    reload_extra_files = [MUTATE_KEY_PATH, MUTATE_TLS_KEY_PATH, MUTATE_TLS_CRT_PATH]
else:
    bind = '0.0.0.0:8000'

workers = int(os.environ.get('GUNICORN_WORKERS', 4))
timeout = int(os.environ.get('GUNICORN_TIMEOUT', 30))
keepalive = int(os.environ.get('GUNICORN_KEEPALIVE', 60))
worker_class = "uvicorn.workers.UvicornWorker"
pythonpath = dirname(dirname(dirname(realpath(__file__))))
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
