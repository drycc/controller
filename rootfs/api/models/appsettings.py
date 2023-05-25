import logging
from django.db import models
from django.db import transaction

from rest_framework.exceptions import NotFound
from django.contrib.auth import get_user_model
from api.utils import dict_diff
from api.exceptions import DryccException, AlreadyExists, UnprocessableEntity
from .base import UuidAuditedModel

User = get_user_model()


class AppSettings(UuidAuditedModel):
    """
    Instance of Application settings used by scheduler
    """

    owner = models.ForeignKey(User, on_delete=models.PROTECT)
    app = models.ForeignKey('App', on_delete=models.CASCADE)
    canaries = models.JSONField(default=list)
    routable = models.BooleanField(default=True)
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

    def _update_canaries(self, previous_settings):
        old = getattr(previous_settings, 'canaries', [])
        new = getattr(self, 'canaries', [])
        data = old.copy()
        if data and not new:
            setattr(self, 'canaries', data)
        elif data != new:
            for procfile_type in new:
                if procfile_type not in data:
                    data.append(procfile_type)
            setattr(self, 'canaries', data)
            self.summary += [
                "{} add canaries for process types {}".format(self.owner, ','.join(new))]

    def _update_routable(self, previous_settings):
        old = getattr(previous_settings, 'routable', None)
        new = getattr(self, 'routable', None)
        # if nothing changed copy the settings from previous
        if new is None and old is not None:
            setattr(self, 'routable', old)
        elif old != new:
            self.summary += ["{} changed routablity from {} to {}".format(self.owner, old, new)]

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
        update_fields = ["canaries", "routable", "autoscale", "label"]
        try:
            for update_field in update_fields:
                if ignore_update_fields is None or update_field not in ignore_update_fields:
                    getattr(self, "_update_%s" % update_field)(previous_settings)
        except (UnprocessableEntity, NotFound):
            raise
        except Exception as e:
            self.delete()
            raise DryccException(str(e)) from e

        if not self.summary and previous_settings:
            self.delete()
            raise AlreadyExists("{} changed nothing".format(self.owner))
        summary = ' '.join(self.summary)
        self.app.log('summary of app setting changes: {}'.format(summary), logging.DEBUG)

    def diff_canaries(self):
        prev_app_settings = self.previous()
        action, canaries = None, []
        if prev_app_settings is not None:
            if prev_app_settings.canaries != self.canaries:
                for procfile_type in self.canaries:  # add canary
                    if procfile_type not in prev_app_settings.canaries:
                        if action is None:
                            action = "append"
                        canaries.append(procfile_type)
                for procfile_type in prev_app_settings.canaries:  # delete canary
                    if procfile_type not in self.canaries:
                        if action is None:
                            action = "remove"
                        canaries.append(procfile_type)
        return prev_app_settings, action, canaries

    @transaction.atomic
    def save(self, ignore_update_field=None, *args, **kwargs):
        self._update_fields(ignore_update_field)
        super(AppSettings, self).save(**kwargs)
