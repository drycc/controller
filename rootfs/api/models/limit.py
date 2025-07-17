import logging
from functools import partial
from django.db import models
from django.contrib.auth import get_user_model
from api.utils import validate_json
from .base import AuditedModel


User = get_user_model()
logger = logging.getLogger(__name__)

spec_memory_schema = {
    "$schema": "http://json-schema.org/schema#",
    "type": "object",
    "properties": {
        "size": {"type": "string"},
        "type": {"type": "string"},
    },
    "required": ["size", "type"],
}

spec_cpu_schema = {
    "$schema": "http://json-schema.org/schema#",
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "cores": {"type": "integer"},
        "clock": {"type": "string"},
        "boost": {"type": "string"},
        "threads": {"type": "integer"},
    },
    "required": ["name", "cores", "clock", "boost", "threads"],
}

spec_gpu_schema = {
    "$schema": "http://json-schema.org/schema#",
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "tmus": {"type": "integer"},
        "rops": {"type": "integer"},
        "cores": {"type": "integer"},
        "memory": spec_memory_schema,
    },
    "required": ["name", "tmus", "rops", "cores"],
}

spec_features_schema = {
    "$schema": "http://json-schema.org/schema#",
    "type": "object",
    "properties": {
        "gpu": spec_gpu_schema,
        "network": {"type": "string"},
    },
    "required": ["gpu", "network"],
}

spec_keywords_schema = {
    "$schema": "http://json-schema.org/schema#",
    "type": "array",
    "minItems": 1,
    "items": {"type": "string"}
}

plan_features_schema = {
    "$schema": "http://json-schema.org/schema#",
    "type": "object",
    "properties": {
        "gpu": {"type": "integer"},
        "network": {"type": "integer"},
    },
    "required": ["gpu", "memory"],
}

plan_limits_schema = {
    "$schema": "http://json-schema.org/schema#",
    "type": "object",
    "properties": {
        "cpu": {"type": "integer"},
        "memory": {"type": "integer"},
    },
    "required": ["cpu", "memory"],
}


class LimitSpec(AuditedModel):
    id = models.CharField(max_length=63, primary_key=True)
    cpu = models.JSONField(
        validators=[partial(validate_json, schema=spec_cpu_schema)])
    memory = models.JSONField(
        validators=[partial(validate_json, schema=spec_memory_schema)])
    features = models.JSONField(
        validators=[partial(validate_json, schema=spec_features_schema)])
    keywords = models.JSONField(
        validators=[partial(validate_json, schema=spec_keywords_schema)])
    disabled = models.BooleanField(default=False)
    priority = models.SmallIntegerField(default=100)

    class Meta:
        get_latest_by = 'created'
        ordering = ['-priority']


class LimitPlan(AuditedModel):
    id = models.CharField(max_length=63, primary_key=True)
    spec = models.ForeignKey(LimitSpec, on_delete=models.PROTECT)
    cpu = models.SmallIntegerField(default=1)
    memory = models.SmallIntegerField(default=1)
    features = models.JSONField(
        validators=[partial(validate_json, schema=plan_features_schema)])
    disabled = models.BooleanField(default=False)
    priority = models.SmallIntegerField(default=100)
    limits = models.JSONField(
        validators=[partial(validate_json, schema=plan_limits_schema)])
    requests = models.JSONField(default=dict)
    annotations = models.JSONField(default=dict)
    node_selector = models.JSONField(default=dict)
    runtime_class_name = models.CharField(max_length=63, default="")
    pod_security_context = models.JSONField(default=dict)
    pod_volumes = models.JSONField(default=list)
    container_security_context = models.JSONField(default=dict)
    container_volume_mounts = models.JSONField(default=list)

    class Meta:
        get_latest_by = 'created'
        ordering = ['priority']

    def __str__(self):
        return self.name

    @staticmethod
    def get_default():
        return LimitPlan.objects.filter(disabled=False).first()
