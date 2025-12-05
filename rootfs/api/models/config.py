import logging
from functools import partial
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
    ptype_fields = ("lifecycle", "tags", "limits", "values_refs", "healthcheck",
                    "termination_grace_period", "registry")
    allof_fields = ("values", ) + ptype_fields

    owner = models.ForeignKey(User, on_delete=models.PROTECT)
    app = models.ForeignKey('App', on_delete=models.CASCADE)
    values = models.JSONField(default=list, blank=True)
    values_refs = models.JSONField(default=dict, blank=True)
    tags = models.JSONField(default=dict, blank=True)
    limits = models.JSONField(default=dict, blank=True)
    registry = models.JSONField(default=dict, blank=True)
    lifecycle = models.JSONField(default=dict, blank=True)
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

    def envs(self, ptype):
        envs = {}
        # group env
        groups = ['global']
        groups.extend(self.values_refs.get(ptype, []))
        for group in groups:
            for value in self.values:
                if group == value.get('group'):
                    envs[value['name']] = value['value']
        # ptype env, repetition will replace the previous env
        for value in self.values:
            if value.get('ptype') == ptype:
                envs[value['name']] = value['value']
        return envs

    def diff(self, old_config):
        def flat_values(values):
            ptype_envs, group_envs = {}, {}
            for value in values:
                ptype, group = value.get('ptype'), value.get('group')
                if ptype:
                    ptype_envs[ptype] = ptype_envs.get(ptype, {})
                    ptype_envs[ptype][value['name']] = value['value']
                if group:
                    group_envs[group] = group_envs.get(group, {})
                    group_envs[group][value['name']] = value['value']
            return ptype_envs, group_envs

        old_config = old_config if old_config else self.previous()
        # ptype field diff
        result = {}
        for field in self.ptype_fields:
            new_value = getattr(self, field)
            old_value = getattr(old_config, field)
            result[field] = dict_diff(new_value, old_value)
        values_diff = {}
        (new_ptype_envs, new_group_envs), (old_ptype_envs, old_group_envs) = (
            flat_values(self.values), flat_values(old_config.values))
        # diff ptype env
        for ptype in set(new_ptype_envs.keys()).union(old_ptype_envs.keys()):
            values_diff.update(
                dict_diff(new_ptype_envs.get(ptype, {}), old_ptype_envs.get(ptype, {})))
        # diff group env
        for group in set(new_group_envs.keys()).union(old_group_envs.keys()):
            values_diff.update(
                dict_diff(new_group_envs.get(group, {}), old_group_envs.get(group, {})))
        result["values"] = values_diff
        return result

    def diff_ptypes(self, old_config, include_ptypes):
        old_config = old_config if old_config else self.previous()
        ptypes = set()
        for ptype in include_ptypes:
            for field in self.ptype_fields:
                new_value = getattr(self, field).get(ptype, None)
                old_value = getattr(old_config, field).get(ptype, None)
                if (new_value or old_value) and new_value != old_value:
                    ptypes.add(ptype)
            new_env = self.envs(ptype)
            old_env = old_config.envs(ptype)
            if new_env != old_env:
                ptypes.add(ptype)
        return ptypes

    def save(self, ignore_update_fields=None, *args, **kwargs):
        """merge the old config with the new"""
        try:
            # Get config from the latest available release
            latest_releases = Release.latest(self.app)
            if latest_releases:
                previous_config = latest_releases.config
            else:
                # If that doesn't exist then fallback on app config
                # usually means a totally new app
                previous_config = self.app.config_set.latest()
            for field in self.allof_fields:
                if ignore_update_fields is None or field not in ignore_update_fields:
                    self.merge_field(field, previous_config)
        except Config.DoesNotExist:
            self._update_tags(previous_config={'tags': {}})
        return super(Config, self).save(*args, **kwargs)

    def merge_field(self, field, old_config, *args, **kwargs):
        getattr(
            self,
            "_update_%s" % field,
            partial(self._update_field, field)
        )(old_config, *args, **kwargs)

    def _update_field(self, field, previous_config, replace_ptypes=[]):
        data = {
            k: v for k, v in getattr(previous_config, field, {}).copy().items()
            if k not in replace_ptypes
        }
        new_data = getattr(self, field, {}).copy()
        # remove config keys if a null value is provided
        for key, value in new_data.items():
            if value is None:
                # error if unsetting non-existing key
                if key not in data:
                    raise UnprocessableEntity(
                        '{} does not exist under {}'.format(key, field))
                data.pop(key)
            else:
                data[key] = self._merge_data(field, data.get(key, {}), value)
        setattr(self, field, data)

    def _update_values(self, previous_config, replace_ptypes=[], replace_groups=[]):
        data = [
            item for item in getattr(previous_config, 'values', []).copy()
            if item.get('ptype') not in replace_ptypes and item.get('group') not in replace_groups
        ]
        new_data = getattr(self, 'values', []).copy()
        for new_item in new_data:
            added = True
            for index, item in enumerate(data):
                if (
                    item['name'] == new_item['name'] and
                    item.get('ptype') == new_item.get('ptype') and
                    item.get('group') == new_item.get('group')
                ):
                    data.pop(index)
                    if not new_item['value']:
                        added = False
                    else:  # force to string
                        new_item['value'] = str(new_item['value'])
                    break
            if added and new_item['value'] is not None:
                data.append(new_item)
        setattr(self, 'values', data)

    def _update_values_refs(self, previous_config, replace_ptypes=[]):
        data = {
            k: v for k, v in getattr(previous_config, 'values_refs', {}).copy().items()
            if k not in replace_ptypes
        }
        new_data = getattr(self, 'values_refs', {}).copy()
        # remove config keys if a null value is provided
        for ptype, values in new_data.items():
            if not values:
                # error if unsetting non-existing key
                if ptype not in data:
                    raise UnprocessableEntity(
                        '{} does not exist under {}'.format(ptype, 'values_refs'))
                data.pop(ptype)
            else:
                values_refs = data.get(ptype, [])
                values_refs.extend(values)
                data[ptype] = list(set(values_refs))
        setattr(self, 'values_refs', data)

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

    def _update_tags(self, previous_config, replace_ptypes=[]):
        """verify the tags exist on any nodes as labels"""
        data = {
            k: v for k, v in getattr(previous_config, 'tags', {}).copy().items()
            if k not in replace_ptypes
        }
        new_data = getattr(self, 'tags', {}).copy()
        # remove config keys if a null value is provided
        for ptype, values in new_data.items():
            if not values:
                # error if unsetting non-existing key
                if ptype not in data:
                    raise UnprocessableEntity(
                        '{} does not exist under {}'.format(ptype, 'tags'))
                data.pop(ptype)
            else:
                if not self.scheduler.node.get(labels=values).json()['items']:
                    labels = ['{}={}'.format(key, value) for key, value in values.items()]
                    message = 'No nodes matched the provided labels: {}'.format(', '.join(labels))
                    # Find out if there are any other tags around
                    old_tags = previous_config.tags.get(ptype, {})
                    if old_tags:
                        old = ['{}={}'.format(key, value) for key, value in old_tags.items()]
                        new = set(labels) - set(old)
                        if new:
                            message += ' - Addition of {} is the cause'.format(', '.join(new))
                    raise DryccException(message)
                data[ptype] = self._merge_data(
                    'tags', data.get(ptype, {}), values)
        setattr(self, 'tags', data)

    def _update_limits(self, previous_config, replace_ptypes=[]):
        data = {
            k: v for k, v in getattr(previous_config, 'limits', {}).copy().items()
            if k not in replace_ptypes
        }
        new_data = getattr(self, 'limits', {}).copy()
        # check procfile
        for ptype, value in new_data.items():
            if value is None:
                if ptype in self.app.ptypes:
                    raise UnprocessableEntity(
                        "the %s has already been used and cannot be deleted" % ptype)
        self._merge_data('limits', data, new_data)
        setattr(self, 'limits', data)

    def _update_termination_grace_period(self, previous_config, replace_ptypes=[]):
        data = {
            k: v for k, v in getattr(previous_config, 'termination_grace_period', {}).copy().items()  # noqa
            if k not in replace_ptypes
        }
        new_data = getattr(self, 'termination_grace_period', {}).copy()
        # check procfile
        for ptype, value in new_data.items():
            if value is None:
                if ptype in self.app.ptypes:
                    raise UnprocessableEntity(
                        "the %s has already been used and cannot be deleted" % ptype)
        self._merge_data('termination_grace_period', data, new_data)
        setattr(self, 'termination_grace_period', data)
