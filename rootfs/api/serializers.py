"""
Classes to serialize the RESTful representation of Drycc API models.
"""
import time
import json
import logging
import jmespath
import re
import jsonschema
import idna
from urllib.parse import urlparse

from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework import serializers

from api import models
from api.exceptions import DryccException


User = get_user_model()
logger = logging.getLogger(__name__)
SERVICE_PROTOCOL_MATCH = re.compile(r'^(TCP|UDP|SCTP)$')
SERVICE_PROTOCOL_MISMATCH_MSG = "the service protocol only supports TCP, UDP, and SCTP"
GATEWAY_PROTOCOL_MATCH = re.compile(r'^(HTTP|HTTPS|TCP|TLS|UDP)$')
GATEWAY_PROTOCOL_MISMATCH_MSG = "the gateway protocol only supports HTTP, HTTPS, TCP, TLS and UDP"
ROUTE_PROTOCOL_MATCH = re.compile(r'^(HTTPRoute|TCPRoute|UDPRoute|TLSRoute)$')
ROUTE_PROTOCOL_MISMATCH_MSG = "the route kind only supports HTTPRoute, TCPRoute, UDPRoute, and TLSRoute"  # noqa
PROCTYPE_MATCH = re.compile(r'^(?P<type>[a-z0-9]+(\-[a-z0-9]+)*)$')
PROCTYPE_MISMATCH_MSG = "Process types can only contain lowercase alphanumeric characters"
MEMLIMIT_MATCH = re.compile(r'^(?P<mem>([1-9][0-9]*[mgMG]))$', re.IGNORECASE)
CPUSHARE_MATCH = re.compile(r'^(?P<cpu>([-+]?[1-9][0-9]*[m]?))$')
TAGVAL_MATCH = re.compile(r'^(?:[a-zA-Z\d][-\.\w]{0,61})?[a-zA-Z\d]$')
CONFIGKEY_MATCH = re.compile(r'^[a-z_]+[a-z0-9_]*$', re.IGNORECASE)
TERMINATION_GRACE_PERIOD_MATCH = re.compile(r'^[0-9]*$')
VOLUME_SIZE_MATCH = re.compile(r'^(?P<volume>([1-9][0-9]*[gG]))$', re.IGNORECASE)
VOLUME_PATH = re.compile(r'^\/(\w+\/?)+$', re.IGNORECASE)
METRIC_EVERY = re.compile(r'^[1-9][0-9]*m$')

PROBE_SCHEMA = {
    "$schema": "http://json-schema.org/schema#",

    "type": "object",
    "properties": {
        # Exec specifies the action to take.
        # More info: http://kubernetes.io/docs/api-reference/v1/definitions/#_v1_execaction
        "exec": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "array",
                    "minItems": 1,
                    "items": {"type": "string"}
                }
            },
            "required": ["command"]
        },
        # HTTPGet specifies the http request to perform.
        # More info: http://kubernetes.io/docs/api-reference/v1/definitions/#_v1_httpgetaction
        "httpGet": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "port": {"type": "integer"},
                "host": {"type": "string"},
                "scheme": {"type": "string"},
                "httpHeaders": {
                    "type": "array",
                    "minItems": 0,
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "value": {"type": "string"},
                        }
                    }
                }
            },
            "required": ["port"]
        },
        # TCPSocket specifies an action involving a TCP port.
        # More info: http://kubernetes.io/docs/api-reference/v1/definitions/#_v1_tcpsocketaction
        "tcpSocket": {
            "type": "object",
            "properties": {
                "port": {"type": "integer"},
            },
            "required": ["port"]
        },
        # Number of seconds after the container has started before liveness probes are initiated.
        # More info: http://releases.k8s.io/HEAD/docs/user-guide/pod-states.md#container-probes
        "initialDelaySeconds": {"type": "integer"},
        # Number of seconds after which the probe times out.
        # More info: http://releases.k8s.io/HEAD/docs/user-guide/pod-states.md#container-probes
        "timeoutSeconds": {"type": "integer"},
        # How often (in seconds) to perform the probe.
        "periodSeconds": {"type": "integer"},
        # Minimum consecutive successes for the probe to be considered successful
        # after having failed.
        "successThreshold": {"type": "integer"},
        # Minimum consecutive failures for the probe to be considered
        # failed after having succeeded.
        "failureThreshold": {"type": "integer"},
    }
}


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
                if self.convert_to_str:
                    obj[k] = str(v)
            except ValueError:
                obj[k] = v
                # Do nothing, the validator will catch this later

        return obj


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
    procfile_structure = serializers.JSONField(required=False)

    class Meta:
        """Metadata options for a :class:`AppSerializer`."""
        model = models.app.App
        fields = ['uuid', 'id', 'owner', 'structure', 'procfile_structure', 'created', 'updated']


class BuildSerializer(serializers.ModelSerializer):
    """Serialize a :class:`~api.models.build.Build` model."""

    app = serializers.SlugRelatedField(slug_field='id', queryset=models.app.App.objects.all())
    owner = serializers.ReadOnlyField(source='owner.username')
    procfile = serializers.JSONField(required=False)

    class Meta:
        """Metadata options for a :class:`BuildSerializer`."""
        model = models.build.Build
        fields = ['owner', 'app', 'image', 'stack', 'sha', 'procfile',
                  'dockerfile', 'created', 'updated', 'uuid']

    @staticmethod
    def validate_procfile(data):
        for key, value in data.items():
            if value is None or value == "":
                raise serializers.ValidationError("Command can't be empty for process type")

            if not re.match(PROCTYPE_MATCH, key):
                raise serializers.ValidationError(PROCTYPE_MISMATCH_MSG)

        return data


class ConfigSerializer(serializers.ModelSerializer):
    """Serialize a :class:`~api.models.config.Config` model."""

    app = serializers.SlugRelatedField(slug_field='id', queryset=models.app.App.objects.all())
    owner = serializers.ReadOnlyField(source='owner.username')
    values = JSONFieldSerializer(required=False, binary=True)
    memory = JSONFieldSerializer(required=False, binary=True)
    lifecycle_post_start = JSONFieldSerializer(required=False, binary=True)
    lifecycle_pre_stop = JSONFieldSerializer(required=False, binary=True)
    cpu = JSONFieldSerializer(required=False, binary=True)
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
            if value is None:  # use NoneType to unset an item
                continue

            if not re.match(CONFIGKEY_MATCH, key):
                raise serializers.ValidationError(
                    "Config keys must start with a letter or underscore and "
                    "only contain [A-z0-9_]")

            # Validate PORT
            if key == 'PORT':
                if not str(value).isnumeric():
                    raise serializers.ValidationError('PORT can only be a numeric value')
                elif int(value) not in range(1, 65536):
                    # check if hte port is between 1 and 65535. One extra added for range()
                    # http://kubernetes.io/docs/api-reference/v1/definitions/#_v1_serviceport
                    raise serializers.ValidationError('PORT needs to be between 1 and 65535')

            # Validate HEALTHCHECK_*
            if key == 'HEALTHCHECK_URL':
                # Only Path information is supported, not query / anchor or anything else
                # Path is the only thing Kubernetes supports right now
                # See https://github.com/drycc/controller/issues/774
                uri = urlparse(value)

                if not uri.path:
                    raise serializers.ValidationError(
                        '{} is missing a URI path (such as /healthz). '
                        'Without it no health check can be done'.format(key)
                    )

                # Disallow everything but path
                # https://docs.python.org/3/library/urllib.parse.html
                if uri.query or uri.fragment or uri.netloc:
                    raise serializers.ValidationError(
                        '{} can only be a URI path (such as /healthz) that does not contain '
                        'other things such as query params'.format(key)
                    )
            elif key.startswith('HEALTHCHECK_') and not str(value).isnumeric():
                # all other healthchecks are integers
                raise serializers.ValidationError('{} can only be a numeric value'.format(key))

        return data

    @staticmethod
    def validate_memory(data):
        max_memory = settings.KUBERNETES_LIMITS_MAX_MEMORY
        # The minimum limit memory is equal to the memory allocated by default
        min_memory = settings.KUBERNETES_LIMITS_MIN_MEMORY
        for key, value in data.items():
            if value is None:  # use NoneType to unset an item
                continue

            if not re.match(PROCTYPE_MATCH, key):
                raise serializers.ValidationError(PROCTYPE_MISMATCH_MSG)

            if not re.match(MEMLIMIT_MATCH, str(value)):
                raise serializers.ValidationError(
                    "Memory limit format: <number><unit>, "
                    "where unit = M or G")
            range_error = "Memory setting is not in allowed range: %sM~%sM" % (
                min_memory, max_memory)
            memory_size = int(value[:-1]) * 1024 if value.endswith("G") else int(value[:-1])
            if memory_size < min_memory or memory_size > max_memory:
                raise serializers.ValidationError(range_error)
        return data

    @staticmethod
    def validate_cpu(data):
        max_cpu = settings.KUBERNETES_LIMITS_MAX_CPU
        # The minimum CPU limit is equal to the CPU allocated by default
        min_cpu = settings.KUBERNETES_LIMITS_MIN_CPU
        for key, value in data.items():
            if value is None:  # use NoneType to unset an item
                continue

            if not re.match(PROCTYPE_MATCH, key):
                raise serializers.ValidationError(PROCTYPE_MISMATCH_MSG)

            shares = re.match(CPUSHARE_MATCH, str(value))
            if not shares:
                raise serializers.ValidationError(
                    "CPU limit format: <value>, where value must be a numeric")
            range_error = "CPU setting is not in allowed range: %sm~%sm" % (
                min_cpu, max_cpu)
            cpu_size = int(value) * 1000 if value.isdigit() else int(value[:-1])
            if cpu_size < min_cpu or cpu_size > max_cpu:
                raise serializers.ValidationError(range_error)
        return data

    @staticmethod
    def validate_termination_grace_period(data):
        for key, value in data.items():
            if value is None:  # use NoneType to unset an item
                continue

            if not re.match(PROCTYPE_MATCH, key):
                raise serializers.ValidationError(PROCTYPE_MISMATCH_MSG)

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
                raise serializers.ValidationError(
                    "Config keys must start with a letter or underscore and "
                    "only contain [A-z0-9_]")

        return data

    @staticmethod
    def validate_healthcheck(data):
        for procType, healthcheck in data.items():
            if healthcheck is None:
                continue
            for key, value in healthcheck.items():
                if value is None:
                    continue
                if key not in ['livenessProbe', 'readinessProbe']:
                    raise serializers.ValidationError(
                        "Healthcheck keys must be either livenessProbe or readinessProbe")
                try:
                    jsonschema.validate(value, PROBE_SCHEMA)
                except jsonschema.ValidationError as e:
                    raise serializers.ValidationError(
                        "could not validate {}: {}".format(value, e.message))

            # http://kubernetes.io/docs/api-reference/v1/definitions/#_v1_probe
            # liveness only supports successThreshold=1, no other value
            # This is not in the schema since readiness supports other values
            threshold = jmespath.search('livenessProbe.successThreshold', healthcheck)
            if threshold is not None and threshold != 1:
                raise serializers.ValidationError(
                    'livenessProbe successThreshold can only be 1'
                )

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

        if value.endswith(".{}".format(settings.PLATFORM_DOMAIN)):
            raise serializers.ValidationError("This is a reserved domain")

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
    port = serializers.IntegerField(default=5000)
    protocol = serializers.CharField(default="TCP")
    target_port = serializers.IntegerField(default=5000)
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
    autoscale = JSONFieldSerializer(convert_to_str=False, required=False, binary=True)
    label = JSONFieldSerializer(convert_to_str=False, required=False, binary=True)

    class Meta:
        """Metadata options for a :class:`AppSettingsSerializer`."""
        model = models.appsettings.AppSettings
        fields = '__all__'

    @staticmethod
    def validate_autoscale(data):
        schema = {
            "$schema": "http://json-schema.org/schema#",
            "type": "object",
            "properties": {
                # minimum replicas autoscale will keep resource at based on load
                "min": {"type": "integer"},
                # maximum replicas autoscale will keep resource at based on load
                "max": {"type": "integer"},
                # how much CPU load there is to trigger scaling rules
                "cpu_percent": {"type": "integer"},
            },
            "required": ["min", "max", "cpu_percent"],
        }

        for _, autoscale in data.items():
            if autoscale is None:
                continue
            try:
                jsonschema.validate(autoscale, schema)
            except jsonschema.ValidationError as e:
                raise serializers.ValidationError(
                    "could not validate {}: {}".format(autoscale, e.message)
                )
        return data


class TLSSerializer(serializers.ModelSerializer):
    """Serialize a :class:`~api.models.tls.TLS` model."""

    app = serializers.SlugRelatedField(slug_field='id', queryset=models.app.App.objects.all())
    owner = serializers.ReadOnlyField(source='owner.username')

    class Meta:
        """Metadata options for a :class:`AppTLSSerializer`."""
        model = models.tls.TLS
        fields = '__all__'


class VolumeSerializer(serializers.ModelSerializer):
    """Serialize a :class:`~api.models.volume.Volume` model."""

    app = serializers.SlugRelatedField(slug_field='id', queryset=models.app.App.objects.all())
    owner = serializers.ReadOnlyField(source='owner.username')
    name = serializers.CharField()
    size = serializers.CharField()
    path = JSONFieldSerializer(required=False, binary=True)

    class Meta:
        """Metadata options for a :class:`AppVolumeSerializer`."""
        model = models.volume.Volume
        fields = '__all__'

    @staticmethod
    def validate_size(data):
        if not re.match(VOLUME_SIZE_MATCH, data):
            raise serializers.ValidationError(
                "Volume size limit format: <number><unit> or <number><unit>/<number><unit>, "
                "where unit = G")
        max_volume = settings.KUBERNETES_LIMITS_MAX_VOLUME
        # The minimum limit memory is equal to the memory allocated by default
        min_volume = settings.KUBERNETES_LIMITS_MIN_VOLUME
        range_error = "Volume setting is not in allowed range: %sG~%sG" % (
            min_volume, max_volume)
        volume_size = int(data[:-1])
        if volume_size < min_volume or volume_size > max_volume:
            raise serializers.ValidationError(range_error)
        return data.upper()

    @staticmethod
    def validate_path(data):
        for key, value in data.items():
            if value is None:  # use NoneType to unset an item
                continue

            if not re.match(PROCTYPE_MATCH, key):
                raise serializers.ValidationError(PROCTYPE_MISMATCH_MSG)

            if not re.match(VOLUME_PATH, str(value)):
                raise serializers.ValidationError(
                    "Volume path format: /path")
        return data


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
            raise DryccException("the resource cann't changed")
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
        if not re.match(METRIC_EVERY, attrs["every"]):
            raise serializers.ValidationError(
                "The format of every is:%s" % METRIC_EVERY.pattern
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
        http_header_filter_properties = {
            "set": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "value": {"type": "string"}
                    }
                }
            },
            "add": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "value": {"type": "string"}
                    }
                }
            },
            "remove": {"type": "array"}
        }
        filter_properties = {
            # Type identifies the type of filter to apply.
            # As with other API fields, types are classified into three conformance levels:
            "type": {
                "type": "string",
                "enum": ["ExtensionRef", "RequestHeaderModifier", "RequestMirror", "RequestRedirect", "ResponseHeaderModifier", "URLRewrite"],  # noqa
            },
            # ExtensionRef is an optional, implementation-specific extension to the “filter” behavior. # noqa
            # For example, resource “myroutefilter” in group “networking.example.net”).
            # ExtensionRef MUST NOT be used for core and extended filters.
            "extensionRef": {
                "type": "object",
                "properties": {
                    "group": {"type": "string"},
                    "kind": {"type": "string"},
                    "name": {"type": "string"}
                },
                "required": ["group", "kind", "name"],
                "additionalProperties": False
            },
            # RequestHeaderModifier defines a schema for a filter that modifies request headers.
            "requestHeaderModifier": {
                "type": "object",
                "properties": http_header_filter_properties,
                "additionalProperties": False
            },
            # ResponseHeaderModifier defines a schema for a filter that modifies response headers.
            "responseHeaderModifier": {
                "type": "object",
                "properties": http_header_filter_properties,
                "additionalProperties": False
            },
            # RequestMirror defines a schema for a filter that mirrors requests.
            # Requests are sent to the specified destination, but responses from that destination are ignored. # noqa
            "requestMirror": {
                "type": "object",
                "properties": {
                    "backendRef": {
                        "properties": {
                            "group": {"type": "string"},
                            "kind": {"type": "string"},
                            "name": {"type": "string"},
                            "namespace": {"type": "string"},
                            "port": {"type": "integer"},
                        },
                        "required": ["name"],
                        "additionalProperties": False
                    },
                },
                "required": ["backendRef"],
                "additionalProperties": False
            },
            # RequestRedirect defines a schema for a filter that responds to the request with an HTTP redirection. # noqa
            "requestRedirect": {
                "type": "object",
                "properties": {
                    "scheme": {"type": "string"},
                    "hostname": {"type": "string"},
                    "path": {"type": "string"},
                    "port": {"type": "integer"},
                    "statusCode": {"type": "integer"}
                }
            },
            # URLRewrite defines a schema for a filter that modifies a request during forwarding
            "urlRewrite": {
                "hostname": {"type": "string"},
                "path": {"type": "string"},
            }
        }

        # More info: https://gateway-api.sigs.k8s.io/references/spec/#gateway.networking.k8s.io%2fv1beta1.HTTPRouteRule # noqa
        HTTP_RULES_SCHEMA = {
            "$schema": "http://json-schema.org/draft-07/schema#",

            "type": "array",
            "items": {
                "properties": {
                    # Matches define conditions used for matching the rule against incoming HTTP requests. # noqa
                    # Each match is independent, i.e. this rule will be matched if any one of the matches is satisfied. # noqa
                    # More info: https://gateway-api.sigs.k8s.io/references/spec/#gateway.networking.k8s.io/v1beta1.HTTPRouteMatch # noqa
                    "matches": {
                        "type": "array",
                        "items": {
                            "properties": {
                                # Path specifies a HTTP request path matcher.
                                # If this field is not specified, a default prefix match on the “/” path is provided. # noqa
                                "path": {
                                    "type": "object",
                                    "properties": {
                                        "type": {
                                            "type": "string",
                                            "enum": ["Exact", "PathPrefix", "RegularExpression"],
                                            "default": "PathPrefix"
                                        },
                                        "value": {"type": "string"}
                                    },
                                    "additionalProperties": False
                                },
                                # Headers specifies HTTP request header matchers. Multiple match values are ANDed together, # noqa
                                # meaning, a request must match all the specified headers to select the route. # noqa
                                # gateway.networking.k8s.io/v1beta1.HTTPHeaderMatch
                                # More info: https: // gateway-api.sigs.k8s.io/references/spec /
                                "headers": {
                                    "type": "array",
                                    "items": {
                                        "properties": {
                                            "type": {
                                                "type": "string",
                                                "enum": ["Exact", "RegularExpression"],
                                                "default": "Exact"
                                            },
                                            "name": {"type": "string"},
                                            "value": {"type": "string"}
                                        },
                                        "additionalProperties": False
                                    }
                                },
                                # QueryParams specifies HTTP query parameter matchers. Multiple match values are ANDed together, # noqa
                                # meaning, a request must match all the specified query parameters to select the route. # noqa
                                "queryParams": {
                                    "type": "array",
                                    "items": {
                                        "properties": {
                                            "type": {
                                                "type": "string",
                                                "enum": ["Exact", "RegularExpression"],
                                                "default": "Exact"
                                            },
                                            "name": {"type": "string"},
                                            "value": {"type": "string"}
                                        },
                                        "additionalProperties": False
                                    }
                                },
                                "method": {
                                    "type": "string",
                                    "enum": ["CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE"],  # noqa
                                }
                            },
                            "additionalProperties": False
                        }
                    },
                    # Filters define the filters that are applied to requests that match this rule.
                    # More info: https://gateway-api.sigs.k8s.io/references/spec/#gateway.networking.k8s.io/v1beta1.HTTPRouteFilter # noqa
                    "filters": {
                        "type": "array",
                        "items": {
                            "properties": filter_properties,
                            "additionalProperties": False
                        },
                    },
                    # BackendRefs defines the backend(s) where matching requests should be sent.
                    # More info: https://gateway-api.sigs.k8s.io/references/spec/#gateway.networking.k8s.io/v1beta1.HTTPBackendRef # noqa
                    "backendRefs": {
                        "type": "array",
                        "items": {
                            "properties": {
                                "filters": {
                                    "type": "array",
                                    "items": {
                                        "properties": filter_properties,
                                        "additionalProperties": False
                                    },
                                },
                                "group": {"type": "string"},
                                "kind": {"type": "string"},
                                "name": {"type": "string"},
                                "namespace": {"type": "string"},
                                "port": {"type": "integer"},
                                "weight": {"type": "integer"}
                            },
                            "required": ["name"],
                            "additionalProperties": False
                        }
                    }
                },
                "required": ["backendRefs"],
                "additionalProperties": False
            }
        }

        try:
            jsonschema.validate(value, HTTP_RULES_SCHEMA)
        except jsonschema.ValidationError as e:
            raise serializers.ValidationError(
                "could not validate {}: {}".format(value, e.message)
            )
        return value
