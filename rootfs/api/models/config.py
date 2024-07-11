import logging
from django.db import models
from django.contrib.auth import get_user_model
from api.utils import dict_diff
from api.exceptions import DryccException, UnprocessableEntity
from .release import Release
from .base import UuidAuditedModel

User = get_user_model()
logger = logging.getLogger(__name__)


class Config(UuidAuditedModel):
    """
    Set of configuration values applied as environment variables
    during runtime execution of the Application.
    """
    procfile_fields = ("lifecycle_post_start", "lifecycle_pre_stop", "tags", "limits",
                       "typed_values", "healthcheck", "termination_grace_period")
    all_diff_fields = ("values", "registry") + procfile_fields

    owner = models.ForeignKey(User, on_delete=models.PROTECT)
    app = models.ForeignKey('App', on_delete=models.CASCADE)
    values = models.JSONField(default=dict, blank=True)
    typed_values = models.JSONField(default=dict, blank=True)
    lifecycle_post_start = models.JSONField(default=dict, blank=True)
    lifecycle_pre_stop = models.JSONField(default=dict, blank=True)
    tags = models.JSONField(default=dict, blank=True)
    limits = models.JSONField(default=dict, blank=True)
    registry = models.JSONField(default=dict, blank=True)
    healthcheck = models.JSONField(default=dict, blank=True)
    termination_grace_period = models.JSONField(default=dict, blank=True)

    class Meta:
        get_latest_by = 'created'
        ordering = ['-created']
        unique_together = (('app', 'uuid'),)

    def __str__(self):
        return "{}-{}".format(self.app.id, str(self.uuid)[:7])

    def previous(self):
        """
        Return the previous Config to this one.

        :return: the previous :class:`Config`, or None
        """
        configs = self.app.config_set
        if self.pk:
            configs = configs.exclude(pk=self.pk)

        try:
            # Get the Config previous to this one
            prev_config = configs.latest()
        except Config.DoesNotExist:
            prev_config = None
        return prev_config

    def diff(self, config=None):
        old_config = config if config else self.previous()
        result = {}
        for field in self.all_diff_fields:
            result[field] = dict_diff(getattr(self, field), getattr(old_config, field))
        return result

    def save(self, **kwargs):
        """merge the old config with the new"""
        try:
            # Get config from the latest available release
            try:
                previous_config = self.app.release_set.filter(failed=False).latest().config
            except Release.DoesNotExist:
                # If that doesn't exist then fallback on app config
                # usually means a totally new app
                previous_config = self.app.config_set.latest()

            for attr in ['registry', 'values', 'lifecycle_post_start',
                         'lifecycle_pre_stop', 'termination_grace_period']:
                data = getattr(previous_config, attr, {}).copy()
                new_data = getattr(self, attr, {}).copy()
                self._merge_data(attr, data, new_data)
                setattr(self, attr, data)
            self._set_typed_values(previous_config)
            self._set_limits(previous_config)
            self._set_healthcheck(previous_config)
            self._set_registry()
            self._set_tags(previous_config)
        except Config.DoesNotExist:
            self._set_tags(previous_config={'tags': {}})

        return super(Config, self).save(**kwargs)

    def _merge_data(self, field, data, new_data):
        # remove config keys if a null value is provided
        for key, value in new_data.items():
            if value is None:
                # error if unsetting non-existing key
                if key not in data:
                    raise UnprocessableEntity('{} does not exist under {}'.format(key, field))  # noqa
                data.pop(key)
            else:
                data[key] = value
        return data

    def _set_registry(self):
        # lower case all registry options for consistency
        self.registry = {key.lower(): value for key, value in self.registry.copy().items()}

        # PORT must be set if private registry is being used
        if self.registry and self.values.get('PORT', None) is None:
            # only thing that can get past post_save in the views
            raise DryccException(
                'PORT needs to be set in the config '
                'when using a private registry')

    def _set_tags(self, previous_config):
        """verify the tags exist on any nodes as labels"""
        data = getattr(previous_config, 'tags', {}).copy()
        new_data = getattr(self, 'tags', {}).copy()
        # remove config keys if a null value is provided
        for procfile_type, values in new_data.items():
            if not values:
                # error if unsetting non-existing key
                if procfile_type not in data:
                    raise UnprocessableEntity(
                        '{} does not exist under {}'.format(procfile_type, 'tags'))
                data.pop(procfile_type)
            else:
                if not self.scheduler().node.get(labels=values).json()['items']:
                    labels = ['{}={}'.format(key, value) for key, value in values.items()]
                    message = 'No nodes matched the provided labels: {}'.format(', '.join(labels))
                    # Find out if there are any other tags around
                    old_tags = previous_config.tags.get(procfile_type, {})
                    if old_tags:
                        old = ['{}={}'.format(key, value) for key, value in old_tags.items()]
                        new = set(labels) - set(old)
                        if new:
                            message += ' - Addition of {} is the cause'.format(', '.join(new))
                    raise DryccException(message)
                data[procfile_type] = self._merge_data(
                    'tags', data.get(procfile_type, {}), values)
        setattr(self, 'tags', data)

    def _set_limits(self, previous_config):
        data = getattr(previous_config, 'limits', {}).copy()
        new_data = getattr(self, 'limits', {}).copy()
        # check procfile
        for key, value in new_data.items():
            if value is None:
                if key in self.app.procfile_types:
                    raise UnprocessableEntity(
                        "the %s has already been used and cannot be deleted" % key)
        self._merge_data('limits', data, new_data)
        setattr(self, 'limits', data)

    def _set_healthcheck(self, previous_config):
        data = getattr(previous_config, 'healthcheck', {}).copy()
        new_data = getattr(self, 'healthcheck', {}).copy()
        # remove config keys if a null value is provided
        for key, value in new_data.items():
            if value is None:
                # error if unsetting non-existing key
                if key not in data:
                    raise UnprocessableEntity(
                        '{} does not exist under {}'.format(key, 'healthcheck'))
                data.pop(key)
            else:
                data[key] = self._merge_data('healthcheck', data.get(key, {}), value)
        setattr(self, 'healthcheck', data)

    def _set_typed_values(self, previous_config):
        data = getattr(previous_config, 'typed_values', {}).copy()
        new_data = getattr(self, 'typed_values', {}).copy()
        # remove config keys if a null value is provided
        for procfile_type, values in new_data.items():
            if not values:
                # error if unsetting non-existing key
                if procfile_type not in data:
                    raise UnprocessableEntity(
                        '{} does not exist under {}'.format(procfile_type, 'typed_values'))
                data.pop(procfile_type)
            else:
                data[procfile_type] = self._merge_data(
                    'typed_values', data.get(procfile_type, {}), values)
        setattr(self, 'typed_values', data)
