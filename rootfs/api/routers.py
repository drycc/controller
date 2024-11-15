from asgiref.local import Local
from django.conf import settings


class DefaultReplicaRouter(object):
    """
    If a model of the current thread or coroutine has used the master db,
    the model will also use the master in the future.
    This can avoid the problem that the slave database is not synchronized
    because a transaction is not committed.
    """
    thread_critical = False

    def __init__(self):
        self._tracker = Local(self.thread_critical)

    def db_for_read(self, model, **hints):
        tracker_key = ".".join([model.__module__, model.__name__])
        if hasattr(self._tracker, tracker_key):
            return getattr(self._tracker, tracker_key)
        elif 'replica' in settings.DATABASES:
            return 'replica'
        return 'default'

    def db_for_write(self, model, **hints):
        tracker_key = ".".join([model.__module__, model.__name__])
        if 'replica' in settings.DATABASES:
            setattr(self._tracker, tracker_key, 'default')
        return 'default'

    def allow_relation(self, obj1, obj2, **hints):
        return True

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        if 'replica' in settings.DATABASES and 'model' in hints:
            model = hints['model']
            tracker_key = ".".join([model.__module__, model.__name__])
            setattr(self._tracker, tracker_key, 'default')
        return True
