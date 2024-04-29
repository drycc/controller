"""
Classes to serialize the RESTful representation of Drycc API models.
"""
import time
import json
import logging
import re
import idna

from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.utils.translation import gettext_lazy
from rest_framework import serializers


from api import models
from api.utils import validate_json
from api.exceptions import DryccException
from scheduler.resources.pod import DEFAULT_CONTAINER_PORT
from .schemas.rules import SCHEMA as RULES_SCHEMA
from .schemas.volumes import SCHEMA as VOLUMES_SCHEMA
from .schemas.autoscale import SCHEMA as AUTOSCALE_SCHEMA
from .schemas.healthcheck import SCHEMA as HEALTHCHECK_SCHEMA
from .schemas.dryccfile import (SCHEMA as DRYCCFILE_SCHEMA, PROCTYPE_REGEX)


User = get_user_model()
logger = logging.getLogger(__name__)
SERVICE_PROTOCOL_MATCH = re.compile(r'^(TCP|UDP|SCTP)$')
SERVICE_PROTOCOL_MISMATCH_MSG = (
    "the service protocol only supports: %s" % SERVICE_PROTOCOL_MATCH.pattern)
GATEWAY_PROTOCOL_MATCH = re.compile(r'^(HTTP|HTTPS|TCP|TLS|UDP)$')
GATEWAY_PROTOCOL_MISMATCH_MSG = (
    "the gateway protocol only supports: %s" % GATEWAY_PROTOCOL_MATCH.pattern)
ROUTE_PROTOCOL_MATCH = re.compile(r'^(HTTPRoute|TCPRoute|UDPRoute|TLSRoute)$')
ROUTE_PROTOCOL_MISMATCH_MSG = (
    "the route kind only supports: %s" % ROUTE_PROTOCOL_MATCH.pattern)
PROCTYPE_MATCH = re.compile(PROCTYPE_REGEX)
PROCTYPE_MISMATCH_MSG = "Process types can only supports: %s" % PROCTYPE_MATCH.pattern
MEMLIMIT_MATCH = re.compile(r'^(?P<mem>([1-9][0-9]*[mgMG]))$', re.IGNORECASE)
MEMLIMIT_MISMATCH_MSG = (
    "Memory limit format: <number><unit>, "
    "where unit = M or G"
)
CPUSHARE_MATCH = re.compile(r'^(?P<cpu>([-+]?[1-9][0-9]*[m]?))$')
CPUSHARE_MISMATCH_MSG = "CPU limit format: <value>, where value must be a numeric"
TAGVAL_MATCH = re.compile(r'^(?:[a-zA-Z\d][-\.\w]{0,61})?[a-zA-Z\d]$')
CONFIGKEY_MATCH = re.compile(r'^[a-z_]+[a-z0-9_]*$', re.IGNORECASE)
CONFIGKEY_MISMATCH_MSG = (
    "Config keys must start with a letter or underscore and "
    "only contain [A-z0-9_]"
)
CONFIG_LIMITS_MISMATCH_MSG = "The limit plan {} does not exist"

TERMINATION_GRACE_PERIOD_MATCH = re.compile(r'^[0-9]*$')
TERMINATION_GRACE_PERIOD_MISMATCH_MSG = (
    "Termination Grace Period format: %s" % TERMINATION_GRACE_PERIOD_MATCH.pattern)
VOLUME_TYPE_MATCH = re.compile(r'^(csi|nfs)$')
VOLUME_TYPE_MISMATCH_MSG = "Volume type pattern: %s" % VOLUME_TYPE_MATCH.pattern
VOLUME_SIZE_MATCH = re.compile(r'^(?P<volume>([1-9][0-9]*[gG]))$', re.IGNORECASE)
VOLUME_SIZE_MISMATCH_MSG = (
    "Volume size limit format: <number><unit> or <number><unit>/<number><unit>, "
    "where unit = G, range: %sG~%sG"
) % (settings.KUBERNETES_LIMITS_MAX_VOLUME, settings.KUBERNETES_LIMITS_MIN_VOLUME)
VOLUME_PATH_MATCH = re.compile(r'^\/(\w+\/?)+$', re.IGNORECASE)
METRIC_EVERY_MATCH = re.compile(r'^[1-9][0-9]*m$')
HEALTHCHECK_MATCH = re.compile(r'^(livenessProbe|readinessProbe|startupProbe)$')
HEALTHCHECK_MISMATCH_MSG = "Healthcheck pattern: %s" % HEALTHCHECK_MATCH.pattern


class JSONFieldSerializer(serializers.JSONField):
    def __init__(self, *args, **kwargs):
        self.convert_to_str = kwargs.pop('convert_to_str', True)
        super(JSONFieldSerializer, self).__init__(*args, **kwargs)

    def to_internal_value(self, data):
        """Deserialize the field's JSON data, for write operations."""
        try:
            val = json.loads(data)
        except TypeError:
            val = data
        return val

    def to_representation(self, obj):
        """Serialize the field's JSON data, for read operations."""
        for k, v in obj.items():
            if v is None:  # NoneType is used to unset a value
                continue

            try:
                if isinstance(v, (dict, list)):
                    self.to_representation(v)
                elif self.convert_to_str:
                    obj[k] = str(v)
            except ValueError:
                obj[k] = v
                # Do nothing, the validator will catch this later

        return obj


class AuthSerializer(serializers.Serializer):
    username = serializers.CharField(
        label=gettext_lazy("Username"),
        required=False,
        write_only=True
    )
    password = serializers.CharField(
        label=gettext_lazy("Password"),
        style={'input_type': 'password'},
        required=False,
        trim_whitespace=False,
        write_only=True,
    )


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'username', 'password', 'first_name', 'last_name', 'is_superuser',
                  'is_staff', 'groups', 'user_permissions', 'last_login', 'date_joined',
                  'is_active']
        read_only_fields = ['id', 'is_superuser', 'is_staff', 'groups',
                            'user_permissions', 'last_login', 'date_joined', 'is_active']
        extra_kwargs = {'password': {'write_only': True}}

    @staticmethod
    def update_or_create(data):
        now = timezone.now()
        user, created = User.objects.update_or_create(
            id=data['id'],
            defaults={
                "email": data['email'],
                "username": data['username'],
                "first_name": data['first_name'],
                "last_name": data['last_name'],
                "is_staff": data['is_staff'],
                "is_active": data['is_active'],
                "is_superuser": data['is_superuser'],
                'last_login': now
            }
        )
        if created:
            user.date_joined = now
            user.set_unusable_password()
        user.save()
        return user, created


class TokenSerializer(serializers.ModelSerializer):
    """Serialize a :class:`~api.models.base.Token` model."""

    owner = serializers.ReadOnlyField(source='owner.username')

    class Meta:
        model = models.base.Token
        fields = ['uuid', 'owner', 'alias', 'fuzzy_key', 'created', 'updated']
        read_only_fields = fields


class AdminUserSerializer(serializers.ModelSerializer):
    """Serialize admin status for a User model."""

    class Meta:
        model = User
        fields = ['username', 'is_superuser']
        read_only_fields = ['username']


class AppSerializer(serializers.ModelSerializer):
    """Serialize a :class:`~api.models.app.App` model."""

    owner = serializers.ReadOnlyField(source='owner.username')
    structure = serializers.JSONField(required=False)

    class Meta:
        """Metadata options for a :class:`AppSerializer`."""
        model = models.app.App
        fields = ['uuid', 'id', 'owner', 'structure', 'created', 'updated']


class BuildSerializer(serializers.ModelSerializer):
    """Serialize a :class:`~api.models.build.Build` model."""

    app = serializers.SlugRelatedField(slug_field='id', queryset=models.app.App.objects.all())
    owner = serializers.ReadOnlyField(source='owner.username')
    procfile = serializers.JSONField(required=False)
    dryccfile = serializers.JSONField(required=False)

    class Meta:
        """Metadata options for a :class:`BuildSerializer`."""
        model = models.build.Build
        fields = ['owner', 'app', 'image', 'stack', 'sha', 'procfile', 'dryccfile',
                  'dockerfile', 'created', 'updated', 'uuid']

    @staticmethod
    def validate_procfile(data):
        for key, value in data.items():
            if value is None or value == "":
                raise serializers.ValidationError("Command can't be empty for process type")

            if not re.match(PROCTYPE_MATCH, key):
                raise serializers.ValidationError(PROCTYPE_MISMATCH_MSG)

        return data

    @staticmethod
    def validate_dryccfile(data):
        if data:
            return validate_json(data, DRYCCFILE_SCHEMA, serializers.ValidationError)
        return data


class LimitSpecSerializer(serializers.ModelSerializer):
    id = serializers.CharField(required=True)
    cpu = serializers.JSONField(required=True)
    memory = serializers.JSONField(required=True)
    features = serializers.JSONField(required=True)
    disabled = serializers.BooleanField(required=True)

    class Meta:
        """Metadata options for a :class:`LimitSpecSerializer`."""
        model = models.limit.LimitSpec
        fields = ['id', 'cpu', 'memory', 'features', 'disabled']


class LimitPlanSerializer(serializers.ModelSerializer):
    id = serializers.CharField(required=True)
    spec = LimitSpecSerializer(required=True)
    cpu = serializers.IntegerField(required=True)
    memory = serializers.IntegerField(required=True)
    features = serializers.JSONField(required=True)
    disabled = serializers.BooleanField(required=True)

    class Meta:
        """Metadata options for a :class:`LimitPlanSerializer`."""
        model = models.limit.LimitSpec
        fields = ['id', 'spec', 'cpu', 'memory', 'features', 'disabled']


class ConfigSerializer(serializers.ModelSerializer):
    """Serialize a :class:`~api.models.config.Config` model."""

    app = serializers.SlugRelatedField(slug_field='id', queryset=models.app.App.objects.all())
    owner = serializers.ReadOnlyField(source='owner.username')
    values = JSONFieldSerializer(required=False, binary=True)
    typed_values = JSONFieldSerializer(required=False, binary=True)
    limits = JSONFieldSerializer(required=False, binary=True)
    lifecycle_post_start = JSONFieldSerializer(required=False, binary=True)
    lifecycle_pre_stop = JSONFieldSerializer(required=False, binary=True)
    tags = JSONFieldSerializer(required=False, binary=True)
    registry = JSONFieldSerializer(required=False, binary=True)
    healthcheck = JSONFieldSerializer(convert_to_str=False, required=False, binary=True)
    routable = serializers.BooleanField(required=False)
    termination_grace_period = JSONFieldSerializer(required=False, binary=True)

    class Meta:
        """Metadata options for a :class:`ConfigSerializer`."""
        model = models.config.Config
        fields = '__all__'

    @staticmethod
    def validate_values(data):
        for key, value in data.items():
            if not re.match(CONFIGKEY_MATCH, key):
                raise serializers.ValidationError(CONFIGKEY_MISMATCH_MSG)
            if value is None:  # use NoneType to unset an item
                continue
            # Validate PORT
            if key == 'PORT':
                if not str(value).isnumeric():
                    raise serializers.ValidationError('PORT can only be a numeric value')
                elif int(value) not in range(1, 65536):
                    # check if hte port is between 1 and 65535. One extra added for range()
                    # http://kubernetes.io/docs/api-reference/v1/definitions/#_v1_serviceport
                    raise serializers.ValidationError('PORT needs to be between 1 and 65535')
        return data

    @classmethod
    def validate_typed_values(cls, data):
        for procfile_type, values in data.items():
            if not re.match(PROCTYPE_MATCH, procfile_type):
                raise serializers.ValidationError(PROCTYPE_MISMATCH_MSG)
            if values is None:  # use NoneType to unset an item
                continue
            cls.validate_values(values)
        return data

    @staticmethod
    def validate_limits(data):
        req_plan_ids = []
        for procfile_type, plan_id in data.items():
            if not re.match(PROCTYPE_MATCH, procfile_type):
                raise serializers.ValidationError(PROCTYPE_MISMATCH_MSG)
            if plan_id is not None:
                req_plan_ids.append(plan_id)
        plan_ids = [plan.id for plan in models.limit.LimitPlan.objects.filter(
            disabled=False, id__in=req_plan_ids)]
        for req_plan_id in req_plan_ids:
            if req_plan_id not in plan_ids:
                raise serializers.ValidationError(CONFIG_LIMITS_MISMATCH_MSG.format(req_plan_id))
        return data

    @staticmethod
    def validate_termination_grace_period(data):
        for procfile_type, value in data.items():
            if not re.match(PROCTYPE_MATCH, procfile_type):
                raise serializers.ValidationError(PROCTYPE_MISMATCH_MSG)
            if value is None:  # use NoneType to unset an item
                continue
            timeout = re.match(TERMINATION_GRACE_PERIOD_MATCH, str(value))
            if not timeout:
                raise serializers.ValidationError(
                    "Termination Grace Period format: <value>, where value must be a numeric")

        return data

    @staticmethod
    def validate_tags(data):
        for key, value in data.items():
            if value is None:  # use NoneType to unset an item
                continue

            # split key into a prefix and name
            if '/' in key:
                prefix, name = key.split('/')
            else:
                prefix, name = None, key

            # validate optional prefix
            if prefix:
                if len(prefix) > 253:
                    raise serializers.ValidationError(
                        "Tag key prefixes must 253 characters or less.")

                for part in prefix.split('/'):
                    if not re.match(TAGVAL_MATCH, part):
                        raise serializers.ValidationError(
                            "Tag key prefixes must be DNS subdomains.")

            # validate required name
            if not re.match(TAGVAL_MATCH, name):
                raise serializers.ValidationError(
                    "Tag keys must be alphanumeric or \"-_.\", and 1-63 characters.")

            # validate value if it isn't empty
            if value and not re.match(TAGVAL_MATCH, str(value)):
                raise serializers.ValidationError(
                    "Tag values must be alphanumeric or \"-_.\", and 1-63 characters.")

        return data

    @staticmethod
    def validate_registry(data):
        for key, value in data.items():
            if value is None:  # use NoneType to unset an item
                continue

            if not re.match(CONFIGKEY_MATCH, key):
                raise serializers.ValidationError(CONFIGKEY_MISMATCH_MSG)

        return data

    @staticmethod
    def validate_healthcheck(data):
        for procfile_type, healthcheck in data.items():
            if not re.match(PROCTYPE_MATCH, procfile_type):
                raise serializers.ValidationError(PROCTYPE_MISMATCH_MSG)
            if healthcheck is None:
                continue
            for key, value in healthcheck.items():
                if value is None:
                    continue
                if not re.match(HEALTHCHECK_MATCH, key):
                    raise serializers.ValidationError(HEALTHCHECK_MISMATCH_MSG)
                validate_json(value, HEALTHCHECK_SCHEMA, serializers.ValidationError)
        return data


class ReleaseSerializer(serializers.ModelSerializer):
    """Serialize a :class:`~api.models.release.Release` model."""

    app = serializers.SlugRelatedField(slug_field='id', queryset=models.app.App.objects.all())
    owner = serializers.ReadOnlyField(source='owner.username')

    class Meta:
        """Metadata options for a :class:`ReleaseSerializer`."""
        model = models.release.Release
        fields = '__all__'


class KeySerializer(serializers.ModelSerializer):
    """Serialize a :class:`~api.models.key.Key` model."""

    owner = serializers.ReadOnlyField(source='owner.username')

    class Meta:
        """Metadata options for a KeySerializer."""
        model = models.key.Key
        fields = '__all__'


class DomainSerializer(serializers.ModelSerializer):
    """Serialize a :class:`~api.models.domain.Domain` model."""

    app = serializers.SlugRelatedField(slug_field='id', queryset=models.app.App.objects.all())
    owner = serializers.ReadOnlyField(source='owner.username')

    class Meta:
        """Metadata options for a :class:`DomainSerializer`."""
        model = models.domain.Domain
        fields = ['owner', 'created', 'updated', 'app', 'domain']
        read_only_fields = ['uuid']

    @staticmethod
    def validate_domain(value):
        """
        Check that the hostname is valid
        """
        if value[-1:] == ".":
            value = value[:-1]  # strip exactly one dot from the right, if present

        if value == "*":
            raise serializers.ValidationError("Hostname can't only be a wildcard")

        labels = value.split('.')

        # Let wildcards through by not trying to validate it
        wildcard = True if labels[0] == '*' else False
        if wildcard:
            labels.pop(0)

        try:
            # IDN domain labels to ACE (IDNA2008)
            def ToACE(x): return idna.alabel(x).decode("utf-8", "strict")
            labels = list(map(ToACE, labels))
        except idna.IDNAError as e:
            raise serializers.ValidationError(
               "Hostname does not look valid, could not convert to ACE {}: {}"
               .format(value, e))

        # TLD must not only contain digits according to RFC 3696
        if labels[-1].isdigit():
            raise serializers.ValidationError('Hostname does not look valid.')

        # prepend wildcard 'label' again if removed before
        if wildcard:
            labels.insert(0, '*')

        # recreate value using ACE'd labels
        aceValue = '.'.join(labels)

        if len(aceValue) > 253:
            raise serializers.ValidationError('Hostname must be 253 characters or less.')

        if models.domain.Domain.objects.filter(domain=aceValue).exists():
            raise serializers.ValidationError(
               "The domain {} is already in use by another app".format(value))

        return aceValue


class ServiceSerializer(serializers.ModelSerializer):
    """Serialize a :class:`~api.models.service.Service` model."""

    app = serializers.SlugRelatedField(slug_field='id', queryset=models.app.App.objects.all())
    owner = serializers.ReadOnlyField(source='owner.username')
    port = serializers.IntegerField(required=True)
    protocol = serializers.CharField(required=True)
    target_port = serializers.IntegerField(default=DEFAULT_CONTAINER_PORT)
    procfile_type = serializers.CharField(required=True)

    class Meta:
        """Metadata options for a :class:`ServiceSerializer`."""
        model = models.service.Service
        fields = ['owner', 'created', 'updated', 'app', 'procfile_type']
        read_only_fields = ['uuid']

    @staticmethod
    def validate_port(value):
        if not str(value).isnumeric():
            raise serializers.ValidationError('port can only be a numeric value')
        elif int(value) not in range(1, 65536):
            raise serializers.ValidationError('port needs to be between 1 and 65535')
        return value

    @staticmethod
    def validate_protocol(value):
        if not re.match(SERVICE_PROTOCOL_MATCH, value):
            raise serializers.ValidationError(SERVICE_PROTOCOL_MISMATCH_MSG)
        return value

    @classmethod
    def validate_target_port(cls, value):
        return cls.validate_port(value)

    @staticmethod
    def validate_procfile_type(value):
        if not re.match(PROCTYPE_MATCH, value):
            raise serializers.ValidationError(PROCTYPE_MISMATCH_MSG)

        return value


class CertificateSerializer(serializers.ModelSerializer):
    """Serialize a :class:`~api.models.certificate.Certificate` model."""

    owner = serializers.ReadOnlyField(source='owner.username')
    domains = serializers.ReadOnlyField()
    san = serializers.ListField(
        child=serializers.CharField(allow_blank=True, allow_null=True, required=False),
        required=False
    )

    class Meta:
        """Metadata options for CertificateSerializer."""
        model = models.certificate.Certificate
        extra_kwargs = {
            'certificate': {'write_only': True},
            'key': {'write_only': True}
        }
        read_only_fields = ['common_name', 'fingerprint', 'san', 'domains', 'subject', 'issuer']
        fields = '__all__'


class PodSerializer(serializers.BaseSerializer):
    name = serializers.CharField(required=False)
    state = serializers.CharField()
    type = serializers.CharField()
    release = serializers.CharField(required=False)
    started = serializers.DateTimeField(required=False)

    def to_representation(self, obj):
        return obj


class AppSettingsSerializer(serializers.ModelSerializer):
    """Serialize a :class:`~api.models.appsettings.AppSettings` model."""

    app = serializers.SlugRelatedField(slug_field='id', queryset=models.app.App.objects.all())
    owner = serializers.ReadOnlyField(source='owner.username')
    canaries = serializers.JSONField(required=False)
    autoscale = JSONFieldSerializer(convert_to_str=False, required=False, binary=True)
    label = JSONFieldSerializer(convert_to_str=False, required=False, binary=True)

    class Meta:
        """Metadata options for a :class:`AppSettingsSerializer`."""
        model = models.appsettings.AppSettings
        fields = '__all__'

    @staticmethod
    def validate_autoscale(data):
        for _, autoscale in data.items():
            if autoscale is None:
                continue
            validate_json(autoscale, AUTOSCALE_SCHEMA, serializers.ValidationError)
        return data


class TLSSerializer(serializers.ModelSerializer):
    """Serialize a :class:`~api.models.tls.TLS` model."""

    app = serializers.SlugRelatedField(slug_field='id', queryset=models.app.App.objects.all())
    owner = serializers.ReadOnlyField(source='owner.username')
    events = serializers.ReadOnlyField()

    class Meta:
        """Metadata options for a :class:`AppTLSSerializer`."""
        model = models.tls.TLS
        fields = '__all__'


class VolumeSerializer(serializers.ModelSerializer):
    """Serialize a :class:`~api.models.volume.Volume` model."""

    app = serializers.SlugRelatedField(slug_field='id', queryset=models.app.App.objects.all())
    owner = serializers.ReadOnlyField(source='owner.username')
    name = serializers.CharField()
    size = serializers.CharField(required=False)
    path = JSONFieldSerializer(required=False, binary=True)
    type = serializers.CharField(required=False)
    parameters = serializers.JSONField(required=False)

    class Meta:
        """Metadata options for a :class:`AppVolumeSerializer`."""
        model = models.volume.Volume
        fields = '__all__'

    def validate_size(self, data):
        # check size format
        if not re.match(VOLUME_SIZE_MATCH, data):
            raise serializers.ValidationError(VOLUME_SIZE_MISMATCH_MSG)
        # check volume size
        volume_size = int(data[:-1])
        max_volume = settings.KUBERNETES_LIMITS_MAX_VOLUME
        # The minimum limit memory is equal to the memory allocated by default
        min_volume = settings.KUBERNETES_LIMITS_MIN_VOLUME
        if volume_size < min_volume or volume_size > max_volume:
            raise serializers.ValidationError(VOLUME_SIZE_MISMATCH_MSG)
        return data.upper()

    @staticmethod
    def validate_path(data):
        logger.debug(f"mount validate_path data: {data}")
        new_data = {}
        for key, value in data.items():
            if not re.match(PROCTYPE_MATCH, key):
                raise serializers.ValidationError(PROCTYPE_MISMATCH_MSG)
            if value is None:  # use NoneType to unset an item
                new_data[key] = value
                continue

            if not re.match(VOLUME_PATH_MATCH, str(value)):
                raise serializers.ValidationError(
                    "Volume path format: /path")
            if value.endswith("/"):
                value = value.rstrip("/")
            new_data[key] = value
        logger.debug(f"mount validate_path new_data: {new_data}")
        return new_data

    def validate_type(self, data):
        if not re.match(VOLUME_TYPE_MATCH, data):
            raise serializers.ValidationError(VOLUME_TYPE_MISMATCH_MSG)
        elif data != "csi" and not self.initial_data.get("parameters", None):
            raise serializers.ValidationError(
                "parameters cannot be empty when the type is not csi.")
        return data

    @staticmethod
    def validate_parameters(data):
        return validate_json(data, VOLUMES_SCHEMA, serializers.ValidationError)


class ResourceSerializer(serializers.ModelSerializer):
    """Serialize a :class:`~api.models.resource.Resource` model."""
    app = serializers.SlugRelatedField(slug_field='id', queryset=models.app.App.objects.all())
    owner = serializers.ReadOnlyField(source='owner.username')
    name = serializers.CharField(max_length=63, required=True)
    plan = serializers.CharField(max_length=128, required=True)
    data = JSONFieldSerializer(required=False, binary=True)
    options = JSONFieldSerializer(required=False, binary=True)

    class Meta:
        """Metadata options for a :class:`ResourceSerializer`."""
        model = models.resource.Resource
        fields = '__all__'

    def update(self, instance, validated_data):
        if instance.plan.split(':')[0] != validated_data.get('plan', '').split(':')[0]:  # noqa
            raise DryccException("the resource instance cann't changed")
        if instance.status == "Provisioning":
            raise DryccException("this resource instance is in progress")
        instance.plan = validated_data.get('plan')
        instance.options.update(validated_data.get('options', {}))
        instance.attach_update()
        instance.save()
        return instance


class MetricSerializer(serializers.Serializer):
    start = serializers.IntegerField(
        min_value=946656000, max_value=lambda: time.time(),
        required=False, default=lambda: int(time.time() - 3600))
    stop = serializers.IntegerField(
        min_value=946656000, max_value=4102416000,
        required=False, default=lambda: int(time.time()))
    every = serializers.CharField(max_length=50, required=False, default='5m')

    def validate(self, attrs):
        if not re.match(METRIC_EVERY_MATCH, attrs["every"]):
            raise serializers.ValidationError(
                "The format of every is:%s" % METRIC_EVERY_MATCH.pattern
            )
        interval = attrs.get("stop") - attrs.get("start")
        if interval < 0 or interval > 3600 * 24:
            raise serializers.ValidationError(
                'The start and stop intervals must be within 24 hour.'
            )
        quantity = interval / (int(attrs["every"][:-1]) * 60)
        if quantity > 100:
            raise serializers.ValidationError(
                'The amount of data requested is too large.'
            )
        return attrs


class GatewaySerializer(serializers.Serializer):
    app = serializers.SlugRelatedField(slug_field='id', queryset=models.app.App.objects.all())
    owner = serializers.ReadOnlyField(source='owner.username')
    name = serializers.CharField(max_length=63, required=True)
    listeners = serializers.JSONField(required=False)
    addresses = serializers.JSONField(read_only=True)

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation['addresses'] = instance.addresses
        return representation

    @staticmethod
    def validate_port(value):
        if not str(value).isnumeric():
            raise serializers.ValidationError('port can only be a numeric value')
        elif int(value) not in range(1, 65536):
            raise serializers.ValidationError('port needs to be between 1 and 65535')
        return value

    @staticmethod
    def validate_protocol(value):
        if not re.match(GATEWAY_PROTOCOL_MATCH, value):
            raise serializers.ValidationError(GATEWAY_PROTOCOL_MISMATCH_MSG)
        return value

    @staticmethod
    def validate_procfile_type(value):
        if not re.match(PROCTYPE_MATCH, value):
            raise serializers.ValidationError(PROCTYPE_MISMATCH_MSG)

        return value


class RouteSerializer(serializers.Serializer):
    app = serializers.SlugRelatedField(slug_field='id', queryset=models.app.App.objects.all())
    owner = serializers.ReadOnlyField(source='owner.username')
    kind = serializers.CharField(max_length=15, required=False)
    name = serializers.CharField(max_length=63, required=True)
    port = serializers.IntegerField()
    procfile_type = serializers.CharField(max_length=63, required=True)
    rules = serializers.JSONField(required=False)
    parent_refs = serializers.JSONField(required=False)

    @staticmethod
    def validate_port(value):
        if not str(value).isnumeric():
            raise serializers.ValidationError('port can only be a numeric value')
        elif int(value) not in range(1, 65536):
            raise serializers.ValidationError('port needs to be between 1 and 65535')
        return value

    @staticmethod
    def validate_kind(value):
        if not re.match(ROUTE_PROTOCOL_MATCH, value):
            raise serializers.ValidationError(ROUTE_PROTOCOL_MISMATCH_MSG)
        return value

    @staticmethod
    def validate_procfile_type(value):
        if not re.match(PROCTYPE_MATCH, value):
            raise serializers.ValidationError(PROCTYPE_MISMATCH_MSG)

        return value

    @staticmethod
    def validate_rules(value):
        return validate_json(value, RULES_SCHEMA, serializers.ValidationError)
