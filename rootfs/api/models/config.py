import json
import logging
from django.conf import settings
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
                       "healthcheck", "termination_grace_period")
    all_diff_fields = ("values", "registry") + procfile_fields

    owner = models.ForeignKey(User, on_delete=models.PROTECT)
    app = models.ForeignKey('App', on_delete=models.CASCADE)
    values = models.JSONField(default=dict, blank=True)
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
        Return the previous Release to this one.

        :return: the previous :class:`Release`, or None
        """
        configs = self.app.config_set
        if self.pk:
            configs = configs.exclude(pk=self.pk)

        try:
            # Get the Release previous to this one
            prev_release = configs.latest()
        except Release.DoesNotExist:
            prev_release = None
        return prev_release

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

            for attr in ['tags', 'registry', 'values', 'lifecycle_post_start',
                         'lifecycle_pre_stop', 'termination_grace_period']:
                data = getattr(previous_config, attr, {}).copy()
                new_data = getattr(self, attr, {}).copy()

                # remove config keys if a null value is provided
                for key, value in new_data.items():
                    if value is None:
                        # error if unsetting non-existing key
                        if key not in data:
                            raise UnprocessableEntity('{} does not exist under {}'.format(key, attr))  # noqa
                        data.pop(key)
                    else:
                        data[key] = value
                setattr(self, attr, data)
            self._set_limits(previous_config)
            self._set_healthcheck(previous_config)
            self._set_registry()
            self._set_tags(previous_config)
        except Config.DoesNotExist:
            self._set_tags({'tags': {}})

        return super(Config, self).save(**kwargs)

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
        if not self.tags:
            if settings.DRYCC_DEFAULT_CONFIG_TAGS:
                try:
                    tags = json.loads(settings.DRYCC_DEFAULT_CONFIG_TAGS)
                    self.tags = tags
                except json.JSONDecodeError as e:
                    logger.exception(e)
                    return
            else:
                return

        # Get all nodes with label selectors
        nodes = self.scheduler().node.get(labels=self.tags).json()
        if nodes['items']:
            return

        labels = ['{}={}'.format(key, value) for key, value in self.tags.items()]
        message = 'No nodes matched the provided labels: {}'.format(', '.join(labels))

        # Find out if there are any other tags around
        old_tags = getattr(previous_config, 'tags')
        if old_tags:
            old = ['{}={}'.format(key, value) for key, value in old_tags.items()]
            new = set(labels) - set(old)
            if new:
                message += ' - Addition of {} is the cause'.format(', '.join(new))

        raise DryccException(message)

    def _set_limits(self, previous_config):
        data = getattr(previous_config, 'limits', {}).copy()
        new_data = getattr(self, 'limits', {}).copy()
        # remove config keys if a null value is provided
        for key, value in new_data.items():
            if value is None:
                # error if unsetting non-existing key
                if key not in data:
                    raise UnprocessableEntity(
                        '{} does not exist under {}'.format(key, 'limits'))
                if key in self.app.procfile_types:
                    raise UnprocessableEntity(
                        "the %s has already been used and cannot be deleted" % key)
                else:
                    data.pop(key)
            else:
                data[key] = value
        setattr(self, 'limits', data)

    def _set_healthcheck(self, previous_config):
        data = getattr(previous_config, 'healthcheck', {}).copy()
        new_data = getattr(self, 'healthcheck', {}).copy()
        # remove config keys if a null value is provided
        for key, value in new_data.items():
            if value is None:
                # error if unsetting non-existing key
                if key not in data:
                    raise UnprocessableEntity('{} does not exist under {}'.format(key, 'healthcheck'))  # noqa
                data.pop(key)
            else:
                for probeType, probe in value.items():
                    if probe is None:
                        # error if unsetting non-existing key
                        if key not in data or probeType not in data[key].keys():
                            raise UnprocessableEntity('{} does not exist under {}'.format(key, 'healthcheck'))  # noqa
                        data[key].pop(probeType)
                    else:
                        if key not in data:
                            data[key] = {}
                        data[key][probeType] = probe
        setattr(self, 'healthcheck', data)
