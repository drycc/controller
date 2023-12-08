import json
import math
import logging
from decimal import Decimal
from django.conf import settings
from django.db import models
from django.contrib.auth import get_user_model
from api.utils import unit_to_bytes, unit_to_millicpu
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

    owner = models.ForeignKey(User, on_delete=models.PROTECT)
    app = models.ForeignKey('App', on_delete=models.CASCADE)
    values = models.JSONField(default=dict, blank=True)
    memory = models.JSONField(default=dict, blank=True)
    lifecycle_post_start = models.JSONField(default=dict, blank=True)
    lifecycle_pre_stop = models.JSONField(default=dict, blank=True)
    cpu = models.JSONField(default=dict, blank=True)
    tags = models.JSONField(default=dict, blank=True)
    registry = models.JSONField(default=dict, blank=True)
    healthcheck = models.JSONField(default=dict, blank=True)
    termination_grace_period = models.JSONField(default=dict, blank=True)

    class Meta:
        get_latest_by = 'created'
        ordering = ['-created']
        unique_together = (('app', 'uuid'),)

    def __str__(self):
        return "{}-{}".format(self.app.id, str(self.uuid)[:7])

    def _migrate_legacy_healthcheck(self):
        """
        Get all healthchecks options together for use in scheduler
        """
        # return if no legacy healthcheck is found
        if 'HEALTHCHECK_URL' not in self.values.keys():
            return

        path = self.values.get('HEALTHCHECK_URL', '/')
        timeout = int(self.values.get('HEALTHCHECK_TIMEOUT', 50))
        delay = int(self.values.get('HEALTHCHECK_INITIAL_DELAY', 50))
        period_seconds = int(self.values.get('HEALTHCHECK_PERIOD_SECONDS', 10))
        success_threshold = int(self.values.get('HEALTHCHECK_SUCCESS_THRESHOLD', 1))
        failure_threshold = int(self.values.get('HEALTHCHECK_FAILURE_THRESHOLD', 3))

        self.healthcheck['web'] = {}
        self.healthcheck['web']['livenessProbe'] = {
            'initialDelaySeconds': delay,
            'timeoutSeconds': timeout,
            'periodSeconds': period_seconds,
            'successThreshold': success_threshold,
            'failureThreshold': failure_threshold,
            'httpGet': {
                'path': path,
            }
        }

        self.healthcheck['web']['readinessProbe'] = {
            'initialDelaySeconds': delay,
            'timeoutSeconds': timeout,
            'periodSeconds': period_seconds,
            'successThreshold': success_threshold,
            'failureThreshold': failure_threshold,
            'httpGet': {
                'path': path,
            }
        }

        # Unset all the old values
        self.values = {k: v for k, v in self.values.items() if not k.startswith('HEALTHCHECK_')}

    def get_healthcheck(self):
        if (
            'livenessProbe' in self.healthcheck.keys() or
            'readinessProbe' in self.healthcheck.keys()
        ):
            return {'web': self.healthcheck}
        return self.healthcheck

    def _set_cpu_memory(self):
        """
        According to settings.KUBERNETES_CPU_MEMORY_RATIO corrects cpu and memory
        """
        radio = settings.KUBERNETES_CPU_MEMORY_RATIO
        limit_min_cpu = settings.KUBERNETES_LIMITS_MIN_CPU
        limit_max_cpu = settings.KUBERNETES_LIMITS_MAX_CPU
        limit_min_memory = Decimal(settings.KUBERNETES_LIMITS_MIN_MEMORY * math.pow(1024, 2))
        limit_max_memory = Decimal(settings.KUBERNETES_LIMITS_MAX_MEMORY * math.pow(1024, 2))
        memory_cpu_min_radio = Decimal(unit_to_bytes(radio[0])) / Decimal(unit_to_millicpu('1'))
        memory_cpu_max_radio = Decimal(unit_to_bytes(radio[1])) / Decimal(unit_to_millicpu('1'))
        cpu_memory_min_radio = Decimal(unit_to_millicpu('1')) / Decimal(unit_to_bytes(radio[1]))
        cpu_memory_max_radio = Decimal(unit_to_millicpu('1')) / Decimal(unit_to_bytes(radio[0]))
        for container_type in set(
                self.app.structure.keys()).union(set(self.cpu)).union(set(self.memory)):
            if container_type in self.cpu:
                cpu = unit_to_millicpu(self.cpu[container_type])
                min_memory = cpu * memory_cpu_min_radio
                min_memory = limit_min_memory if min_memory < limit_min_memory else min_memory
                max_memory = cpu * memory_cpu_max_radio
                max_memory = limit_max_memory if max_memory > limit_max_memory else max_memory
                if self.memory.get(container_type):
                    memory = unit_to_bytes(self.memory.get(container_type))
                    if memory < min_memory:
                        memory = min_memory
                    elif memory > max_memory:
                        memory = max_memory
                else:
                    memory = min_memory
                if memory % Decimal(math.pow(1024, 3)) == 0:
                    self.memory[container_type] = f'{round(memory / Decimal(math.pow(1024, 3)))}G'
                else:
                    self.memory[container_type] = f'{round(memory / Decimal(math.pow(1024, 2)))}M'
            elif container_type in self.memory:
                memory = Decimal(unit_to_bytes(self.memory[container_type]))
                if container_type not in self.cpu:
                    min_cpu = memory * cpu_memory_min_radio
                    min_cpu = limit_min_cpu if min_cpu < limit_min_cpu else min_cpu
                    max_cpu = memory * cpu_memory_max_radio
                    max_cpu = limit_max_cpu if max_cpu > limit_max_cpu else max_cpu
                    cpu = max_cpu if min_cpu < 1000 else min_cpu
                    if cpu % 1000 == 0:
                        self.cpu[container_type] = f'{round(cpu / 1000)}'
                    else:
                        self.cpu[container_type] = f'{round(cpu)}m'
            else:
                self.cpu[container_type] = f"{settings.KUBERNETES_LIMITS_MIN_CPU}m"
                self.memory[container_type] = f"{settings.KUBERNETES_LIMITS_MIN_MEMORY}M"

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

    def set_registry(self):
        # lower case all registry options for consistency
        self.registry = {key.lower(): value for key, value in self.registry.copy().items()}

        # PORT must be set if private registry is being used
        if self.registry and self.values.get('PORT', None) is None:
            # only thing that can get past post_save in the views
            raise DryccException(
                'PORT needs to be set in the config '
                'when using a private registry')

    def set_tags(self, previous_config):
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
        nodes = self._scheduler.node.get(labels=self.tags).json()
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

    def set_healthcheck(self, previous_config):
        data = getattr(previous_config, 'healthcheck', {}).copy()
        new_data = getattr(self, 'healthcheck', {}).copy()
        # update the config data for healthcheck if they are not
        # present for per proctype
        # TODO: This is required for backward compatibility and can be
        # removed in next major version change.
        if 'livenessProbe' in data.keys() or 'readinessProbe' in data.keys():
            data = {'web': data.copy()}
        if 'livenessProbe' in new_data.keys() or 'readinessProbe' in new_data.keys():  # noqa
            new_data = {'web': new_data.copy()}

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

            for attr in ['cpu', 'memory', 'tags', 'registry', 'values',
                         'lifecycle_post_start', 'lifecycle_pre_stop',
                         'termination_grace_period']:
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
            self._set_cpu_memory()
            self.set_healthcheck(previous_config)
            self._migrate_legacy_healthcheck()
            self.set_registry()
            self.set_tags(previous_config)
        except Config.DoesNotExist:
            self.set_tags({'tags': {}})

        return super(Config, self).save(**kwargs)
