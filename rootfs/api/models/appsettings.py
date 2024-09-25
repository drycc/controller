import logging
from django.db import models
from django.db import transaction

from rest_framework.exceptions import NotFound
from django.contrib.auth import get_user_model
from api.utils import dict_diff
from api.exceptions import DryccException, AlreadyExists, UnprocessableEntity
from .base import UuidAuditedModel

User = get_user_model()
logger = logging.getLogger(__name__)


class AppSettings(UuidAuditedModel):
    """
    Instance of Application settings used by scheduler
    """

    owner = models.ForeignKey(User, on_delete=models.PROTECT)
    app = models.ForeignKey('App', on_delete=models.CASCADE)
    routable = models.BooleanField(default=None)
    autodeploy = models.BooleanField(default=None)
    autorollback = models.BooleanField(default=None)
    autoscale = models.JSONField(default=dict, blank=True)
    label = models.JSONField(default=dict, blank=True)

    class Meta:
        get_latest_by = 'created'
        unique_together = (('app', 'uuid'), )
        ordering = ['-created']

    def __init__(self, *args, **kwargs):
        UuidAuditedModel.__init__(self, *args, **kwargs)
        self.summary = []

    def __str__(self):
        return "{}-{}".format(self.app.id, str(self.uuid)[:7])

    def log(self, message, level=logging.INFO):
        """Logs a message in the context of this application.

        This prefixes log messages with an application "tag" that the customized
        drycc-logspout will be on the lookout for.  When it's seen, the message-- usually
        an application event of some sort like releasing or scaling, will be considered
        as "belonging" to the application instead of the controller and will be handled
        accordingly.
        """
        logger.log(level, "[{}]: {}".format(self.app.id, message))

    def previous(self):
        """
        Return the previous Release to this one.

        :return: the previous :class:`Release`, or None
        """
        app_settings_set = self.app.appsettings_set
        if self.pk:
            app_settings_set = app_settings_set.exclude(pk=self.pk)
        try:
            # Get the Release previous to this one
            prev_app_settings = app_settings_set.latest()
        except AppSettings.DoesNotExist:
            prev_app_settings = None
        return prev_app_settings

    def _update_field(self, field, previous_settings):
        old = getattr(previous_settings, field, None)
        new = getattr(self, field, None)
        # if nothing changed copy the settings from previous
        if new is None and old is not None:
            setattr(self, field, old)
        elif new is None and isinstance(self._meta.get_field(field), models.BooleanField):
            setattr(self, field, True)
        elif old != new:
            self.summary += ["{} changed {} from {} to {}".format(self.owner, field, old, new)]

    def _update_autoscale(self, previous_settings):
        data = getattr(previous_settings, 'autoscale', {}).copy()
        new = getattr(self, 'autoscale', {}).copy()
        # If no previous settings then do nothing
        if not previous_settings:
            return

        # if nothing changed copy the settings from previous
        if not new and data:
            setattr(self, 'autoscale', data)
        elif data != new:
            for proc, scale in new.items():
                if scale is None:
                    # error if unsetting non-existing key
                    if proc not in data:
                        raise UnprocessableEntity('{} does not exist under {}'.format(proc, 'autoscale'))  # noqa
                    del data[proc]
                else:
                    data[proc] = scale
            setattr(self, 'autoscale', data)

            # only apply new items
            for proc, scale in new.items():
                self.app.autoscale(proc, scale)

            # if the autoscale information changed, log the dict diff
            changes = []
            old_autoscale = getattr(previous_settings, 'autoscale', {})
            diff = dict_diff(self.autoscale, old_autoscale)
            # try to be as succinct as possible
            added = ', '.join(list(map(lambda x: 'default' if x == '' else x, [k for k in diff.get('added', {})])))  # noqa
            added = 'added autoscale for process type ' + added if added else ''
            changed = ', '.join(list(map(lambda x: 'default' if x == '' else x, [k for k in diff.get('changed', {})])))  # noqa
            changed = 'changed autoscale for process type ' + changed if changed else ''
            deleted = ', '.join(list(map(lambda x: 'default' if x == '' else x, [k for k in diff.get('deleted', {})])))  # noqa
            deleted = 'deleted autoscale for process type ' + deleted if deleted else ''
            changes = ', '.join(i for i in (added, changed, deleted) if i)
            if changes:
                self.summary += ["{} {}".format(self.owner, changes)]

    def _update_label(self, previous_settings):
        data = getattr(previous_settings, 'label', {}).copy()
        new = getattr(self, 'label', {}).copy()
        if not previous_settings:
            return

        # if nothing changed copy the settings from previous
        if not new and data:
            setattr(self, 'label', data)
        elif data != new:
            for k, v in new.items():
                if v is not None:
                    data[k] = v
                else:
                    if k not in data:
                        raise UnprocessableEntity('{} does not exist under {}'.format(k, 'label'))  # noqa
                    del data[k]
            setattr(self, 'label', data)

            diff = dict_diff(self.label, getattr(previous_settings, 'label', {}))
            added = ', '.join(list(map(lambda x: 'default' if x == '' else x, [k for k in diff.get('added', {})])))  # noqa
            added = 'added label ' + added if added else ''
            changed = ', '.join(list(map(lambda x: 'default' if x == '' else x, [k for k in diff.get('changed', {})])))  # noqa
            changed = 'changed label ' + changed if changed else ''
            deleted = ', '.join(list(map(lambda x: 'default' if x == '' else x, [k for k in diff.get('deleted', {})])))  # noqa
            deleted = 'deleted label ' + deleted if deleted else ''
            changes = ', '.join(i for i in (added, changed, deleted) if i)
            if changes:
                if self.summary:
                    self.summary += ' and '
                self.summary += ["{} {}".format(self.owner, changes)]

    def _update_fields(self, ignore_update_fields=None):
        previous_settings = None
        try:
            previous_settings = self.app.appsettings_set.latest()
        except AppSettings.DoesNotExist:
            pass
        update_fields = ["routable", "autodeploy", "autorollback", "autoscale", "label"]
        try:
            for update_field in update_fields:
                if ignore_update_fields is None or update_field not in ignore_update_fields:
                    method = getattr(self, "_update_%s" % update_field, None)
                    if method:
                        method(previous_settings)
                    else:
                        self._update_field(update_field, previous_settings)
        except (UnprocessableEntity, NotFound):
            raise
        except Exception as e:
            self.delete()
            raise DryccException(str(e)) from e

        if not self.summary and previous_settings:
            self.delete()
            raise AlreadyExists("{} changed nothing".format(self.owner))
        summary = ' '.join(self.summary)
        self.log('summary of app setting changes: {}'.format(summary), logging.DEBUG)

    @transaction.atomic
    def save(self, ignore_update_field=None, *args, **kwargs):
        self._update_fields(ignore_update_field)
        super(AppSettings, self).save(**kwargs)
