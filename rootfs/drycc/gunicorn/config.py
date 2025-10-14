import os
from os.path import dirname, realpath, exists

import faulthandler
faulthandler.enable()

# If a certificate exists, set the certificate and bind to port 8443.
CERT_KEY_PATH = os.environ.get(
    'DRYCC_CERT_KEY_PATH', '/etc/controller/cert/key')
CERT_TLS_KEY_PATH = os.environ.get(
    'DRYCC_CERT_TLS_KEY_PATH', '/etc/controller/cert/tls.key')
CERT_TLS_CRT_PATH = os.environ.get(
    'DRYCC_CERT_TLS_CRT_PATH', '/etc/controller/cert/tls.crt')
if exists(CERT_KEY_PATH) and exists(CERT_TLS_KEY_PATH) and exists(CERT_TLS_CRT_PATH):
    bind = '0.0.0.0:8443'
    keyfile = CERT_TLS_KEY_PATH
    certfile = CERT_TLS_CRT_PATH
    reload_extra_files = [CERT_KEY_PATH, CERT_TLS_KEY_PATH, CERT_TLS_CRT_PATH]
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
