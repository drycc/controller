import logging
from functools import cmp_to_key
from django.db import models, transaction
from django.contrib.auth import get_user_model
from api.exceptions import DryccException, AlreadyExists, ServiceUnavailable
from api.utils import validate_label
from scheduler import KubeException
from .base import UuidAuditedModel

User = get_user_model()
logger = logging.getLogger(__name__)


class Resource(UuidAuditedModel):
    owner = models.ForeignKey(User, on_delete=models.PROTECT)
    app = models.ForeignKey('App', on_delete=models.CASCADE)
    name = models.CharField(max_length=63, validators=[validate_label])
    plan = models.CharField(max_length=128)
    data = models.JSONField(default=dict, blank=True)
    status = models.TextField(blank=True, null=True)
    binding = models.TextField(blank=True, null=True)
    options = models.JSONField(default=dict, blank=True)

    class Meta:
        get_latest_by = 'created'
        unique_together = (('app', 'name'),)
        ordering = ['-created']

    def __str__(self):
        return self.name

    @transaction.atomic
    def save(self, *args, **kwargs):
        # Attach ServiceInstance, updates k8s
        if self.created == self.updated:
            self.attach(*args, **kwargs)
        # Save to DB
        return super(Resource, self).save(*args, **kwargs)

    @classmethod
    def services(cls):
        services = []
        for serviceclass in cls.scheduler().svcat.get_serviceclasses().json()["items"]:
            services.append({
                "id": serviceclass["spec"]["externalID"],
                "name": serviceclass["spec"]["externalName"],
                "updateable": serviceclass["spec"]["planUpdatable"],
            })
        services.sort(key=lambda service: service["name"])
        return services

    @classmethod
    def plans(cls, serviceclass_name):
        serviceclass_id = None
        for service in cls.services():
            if service["name"] == serviceclass_name:
                serviceclass_id = service["id"]
                break
        plans = []
        if serviceclass_id is not None:
            for serviceplan in cls.scheduler().svcat.get_serviceplans().json()["items"]:
                if serviceplan["spec"]["clusterServiceClassRef"]["name"] == serviceclass_id:
                    plans.append({
                        "id": serviceplan["spec"]["externalID"],
                        "name": serviceplan["spec"]["externalName"],
                        "description": serviceplan["spec"]["description"],
                    })
        plans.sort(key=cmp_to_key(
            lambda p1, p2: len(p1["name"]) - len(p2["name"])
            if len(p1["name"]) != len(p2["name"])
            else (1 if p1["name"] > p2["name"] else -1)
        ))
        return plans

    def attach(self, *args, **kwargs):
        try:
            self.scheduler().svcat.get_instance(self.app.id, self.name)
            err = "Resource {} already exists in this namespace".format(self.name)  # noqa
            self.log(err, logging.INFO)
            raise AlreadyExists(err)
        except KubeException as e:
            logger.info(e)
            try:
                instance = self.plan.split(":")
                kwargs = {
                    "instance_class": instance[0],
                    "instance_plan": ":".join(instance[1:]),
                    "parameters": self.options,
                }
                self.scheduler().svcat.create_instance(
                    self.app.id, self.name, **kwargs
                )
            except KubeException as e:
                msg = 'There was a problem creating the resource ' \
                      '{} for {}'.format(self.name, self.app_id)
                raise ServiceUnavailable(msg) from e

    @transaction.atomic
    def delete(self, *args, **kwargs):
        if self.binding == "Ready":
            raise DryccException("the resource instance is still binding")
        if self.status == "Provisioning":
            raise DryccException("the resource instance is provisioning")
        # Deatch ServiceInstance, updates k8s
        self.detach(*args, **kwargs)
        # Delete from DB
        return super(Resource, self).delete(*args, **kwargs)

    def detach(self, *args, **kwargs):
        try:
            resp = self.scheduler().svcat.get_instance(
                self.app.id, self.name, ignore_exception=True)
            if resp.status_code != 404:
                self.scheduler().svcat.delete_instance(self.app.id, self.name)
        except KubeException as e:
            raise ServiceUnavailable("Could not delete resource {} for application {}".format(self.name, self.app_id)) from e  # noqa

    def log(self, message, level=logging.INFO):
        """Logs a message in the context of this service.

        This prefixes log messages with an application "tag" that the customized
        drycc-logspout will be on the lookout for.  When it's seen, the message-- usually
        an application event of some sort like releasing or scaling, will be considered
        as "belonging" to the application instead of the controller and will be handled
        accordingly.
        """
        logger.log(level, "[{}]: {}".format(self.app.id, message))

    def bind(self, *args, **kwargs):
        if self.status != "Ready":
            raise DryccException("the resource instance is not ready")
        if self.binding == "Ready":
            raise DryccException("the resource instance is binding")
        self.binding = "Binding"
        self.save()
        try:
            self.scheduler().svcat.get_binding(self.app.id, self.name)
            err = "Resource {} is binding".format(self.name)
            self.log(err, logging.INFO)
            raise AlreadyExists(err)
        except KubeException as e:
            logger.info(e)
            try:
                self.scheduler().svcat.create_binding(
                    self.app.id, self.name, **kwargs)
            except KubeException as e:
                msg = 'There was a problem binding the resource ' \
                      '{} for {}'.format(self.name, self.app_id)
                raise ServiceUnavailable(msg) from e

    def unbind(self, *args, **kwargs):
        if not self.binding:
            raise DryccException("the resource instance is not binding")
        try:
            # We raise an exception when a resource doesn't exist
            self.scheduler().svcat.get_binding(self.app.id, self.name)
            self.scheduler().svcat.delete_binding(self.app.id, self.name)
            self.binding = None
            self.data = {}
            self.save()
        except KubeException as e:
            raise ServiceUnavailable("Could not unbind resource {} for application {}".format(self.name, self.app_id)) from e  # noqa

    def attach_update(self, *args, **kwargs):
        try:
            data = self.scheduler().svcat.get_instance(
                self.app.id, self.name).json()
        except KubeException as e:
            logger.debug(e)
            self.DryccException("resource {} does not exist".format(self.name))
        try:
            version = data["metadata"]["resourceVersion"]
            instance = self.plan.split(":")
            kwargs = {
                "instance_class": instance[0],
                "instance_plan": ":".join(instance[1:]),
                "parameters": self.options,
                "external_id": data["spec"]["externalID"]
            }
            self.scheduler().svcat.patch_instance(
                self.app.id, self.name, version, **kwargs
            )
        except KubeException as e:
            msg = 'There was a problem update the resource ' \
                  '{} for {}'.format(self.name, self.app_id)
            raise ServiceUnavailable(msg) from e

    @property
    def message(self):
        try:
            resp = self.scheduler().svcat.get_instance(
                self.app.id, self.name)
            if resp.status_code != 200:
                message = ""
            conditions = resp.json().get("status", {}).get("conditions")
            message = conditions[-1].get("message", "") \
                if conditions and isinstance(conditions[-1], dict) else ""
            return message
        except KubeException as e:
            logger.info("retrieve instance info error: {}".format(e))
            return ""

    def retrieve(self, *args, **kwargs):
        if self._retrieve_status() or self._retrieve_binding():
            self.save()
        return self.status == self.binding == "Ready"

    def to_measurements(self, timestamp: float):
        return [{
            "app_id": str(self.app_id),
            "owner": self.owner_id,
            "name": self.plan,
            "type": "resource",
            "unit": "number",
            "usage": 1,
            "kwargs": {
                "name": self.name,
            },
            "timestamp": int(timestamp)
        }]

    def _retrieve_status(self):
        changed = False
        try:
            response = self.scheduler().svcat.get_instance(
                self.app.id, self.name).json()
            status = response.get('status', {}).get('lastConditionState')
            options = response.get('spec', {}).get('parameters', {})
            if self.status != status:
                self.status = status
                changed = True
            if self.options != options:
                self.options = options
                changed = True
        except KubeException as e:
            logger.info("retrieve instance info error: {}".format(e))
        return changed

    def _retrieve_binding(self):
        changed = False
        try:
            # We raise an exception when a resource doesn't exist
            response = self.scheduler().svcat.get_binding(self.app.id, self.name).json()
            binding = response.get('status', {}).get('lastConditionState')
            secret_name = response.get('spec', {}).get('secretName')
            if self.binding != binding:
                self.binding = binding
                changed = True
            if secret_name:
                response = self.scheduler().secret.get(self.app.id, secret_name).json()
                data = response.get('data', {})
                if self.data != data:
                    self.data = data
                    changed = True
        except KubeException as e:
            logger.info("retrieve binding info error: {}".format(e))
        return changed
