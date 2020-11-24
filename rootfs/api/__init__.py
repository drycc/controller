"""
The **api** Django app presents a RESTful web API for interacting with the **drycc** system.
"""
from .settings.celery import app as celery_app

__version__ = '2.3.0'
__all__ = ('celery_app',)
