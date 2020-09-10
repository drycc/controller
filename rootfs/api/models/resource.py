import logging
import uuid
import time
from django.core import signals
from django.conf import settings
from django.db import models, transaction
from jsonfield import JSONField
from api.exceptions import DryccException, AlreadyExists, ServiceUnavailable
from api.models import UuidAuditedModel, validate_label
from scheduler import KubeException
from tasks import task, apply_async

logger = logging.getLogger(__name__)


class Resource(UuidAuditedModel):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL,
                              on_delete=models.PROTECT)
    app = models.ForeignKey('App', on_delete=models.CASCADE)
    name = models.CharField(max_length=63, validators=[validate_label])
    plan = models.CharField(max_length=128)
    data = JSONField(default={}, blank=True)
    status = models.CharField(max_length=32, null=True)
    binding = models.CharField(max_length=32, null=True)
    options = JSONField(default={}, blank=True)

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

    def attach(self, *args, **kwargs):
        try:
            self._scheduler.servicecatalog.get_instance(self.app.id, self.name)
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
                self._scheduler.servicecatalog.create_instance(
                    self.app.id, self.name, **kwargs
                )
                # create/patch/put  retrieve_task
                data = {
                    "task_id": uuid.uuid4().hex,
                    "resource_id": str(self.uuid),
                }
                apply_async(retrieve_task, delay=30000, args=(data, ))
            except KubeException as e:
                msg = 'There was a problem creating the resource ' \
                      '{} for {}'.format(self.name, self.app_id)
                raise ServiceUnavailable(msg) from e

    @transaction.atomic
    def delete(self, *args, **kwargs):
        if self.binding and self.binding == "Ready":
            raise DryccException("the plan is still binding")
        # Deatch ServiceInstance, updates k8s
        self.detach(*args, **kwargs)
        # Delete from DB
        return super(Resource, self).delete(*args, **kwargs)

    def detach(self, *args, **kwargs):
        try:
            # We raise an exception when a resource doesn't exist
            self._scheduler.servicecatalog.get_instance(self.app.id, self.name)
            self._scheduler.servicecatalog.delete_instance(self.app.id, self.name)
        except KubeException as e:
            raise ServiceUnavailable("Could not delete volume {} for application {}".format(name, self.app_id)) from e  # noqa

    def log(self, message, level=logging.INFO):
        """Logs a message in the context of this service.

        This prefixes log messages with an application "tag" that the customized
        drycc-logspout will be on the lookout for.  When it's seen, the message-- usually
        an application event of some sort like releasing or scaling, will be considered
        as "belonging" to the application instead of the controller and will be handled
        accordingly.
        """
        logger.log(level, "[{}]: {}".format(self.id, message))

    def bind(self, *args, **kwargs):
        if self.status != "Ready":
            raise DryccException("the resource is not ready")
        if self.binding == "Ready":
            raise DryccException("the resource is binding")
        try:
            self._scheduler.servicecatalog.get_binding(self.app.id, self.name)
            err = "Resource {} is binding".format(self.name)
            self.log(err, logging.INFO)
            raise AlreadyExists(err)
        except KubeException as e:
            logger.info(e)
            try:
                self._scheduler.servicecatalog.create_binding(
                    self.app.id, self.name, **kwargs)
                # create/patch/put  retrieve_task
                data = {
                    "task_id": uuid.uuid4().hex,
                    "resource_id": str(self.uuid),
                }
                apply_async(retrieve_task, delay=30000, args=(data, ))
            except KubeException as e:
                msg = 'There was a problem binding the resource ' \
                      '{} for {}'.format(self.name, self.app_id)
                raise ServiceUnavailable(msg) from e

    def unbind(self, *args, **kwargs):
        if self.binding != "Ready":
            raise DryccException("the resource is not binding")
        try:
            # We raise an exception when a resource doesn't exist
            self._scheduler.servicecatalog.get_binding(self.app.id, self.name)
            self._scheduler.servicecatalog.delete_binding(self.app.id, self.name)
        except KubeException as e:
            raise ServiceUnavailable("Could not unbind resource {} for application {}".format(self.name, self.app_id)) from e  # noqa

    def attach_update(self, *args, **kwargs):
        try:
            data = self._scheduler.servicecatalog.get_instance(
                self.app.id, self.name).json()
        except KubeException as e:
            self.log("certificate {} does not exist".format(self.app.id),
                     level=logging.INFO)
            data = None
            logger.info(e)
        try:
            version = data["metadata"]["resourceVersion"]
            instance = self.plan.split(":")
            kwargs = {
                "instance_class": instance[0],
                "instance_plan": ":".join(instance[1:]),
                "parameters": self.options,
            }
            self._scheduler.servicecatalog.put_instance(
                self.app.id, self.name, version, **kwargs
            )
            # create/patch/put  retrieve_task
            data = {
                "task_id": uuid.uuid4().hex,
                "resource_id": str(self.uuid),
            }
            apply_async(retrieve_task, delay=30000, args=(data, ))
        except KubeException as e:
            msg = 'There was a problem update the resource ' \
                  '{} for {}'.format(self.name, self.app_id)
            raise ServiceUnavailable(msg) from e

    def retrieve(self, *args, **kwargs):
        update_flag = False
        if self.status != "Ready":
            try:
                resp_i = self._scheduler.servicecatalog.get_instance(
                    self.app.id, self.name).json()
                self.status = resp_i.get('status', {}).\
                    get('lastConditionState', '').lower()
                update_flag = True
            except KubeException as e:
                logger.info("retrieve instance info error: {}".format(e))
        if self.binding != "Ready":
            try:
                # We raise an exception when a resource doesn't exist
                resp_b = self._scheduler.servicecatalog.get_binding(
                    self.app.id, self.name).json()
                self.binding = resp_b.get('status', {}).\
                    get('lastConditionState', '').lower()
                self.options = resp_b.get('spec', {}).get('parameters', {})
                update_flag = True
                secret_name = resp_b.get('spec', {}).get('secretName')
                if secret_name:
                    resp_s = self._scheduler.secret.get(
                        self.app.id, secret_name).json()
                    self.data = resp_s.get('data', {})
                    update_flag = True
            except KubeException as e:
                logger.info("retrieve binding info error: {}".format(e))
        if update_flag is True:
            self.save()
        if self.status and self.binding:
            return True
        else:
            return False

    def detach_resource(self, *args, **kwargs):
        if self.binding != "Ready":
            try:
                resp_b = self._scheduler.servicecatalog.get_binding(
                    self.app.id, self.name).json()
                secret_name = resp_b.get('spec', {}).get('secretName')
                if secret_name:
                    self._scheduler.secret.delete(self.app.id, secret_name)
                self._scheduler.servicecatalog.delete_binding(
                    self.app.id, self.name)
            except KubeException as e:
                logger.info("delete binding info error: {}".format(e))
            self.binding = None

        if (self.status != "Ready") or (self.binding is None):
            try:
                self._scheduler.servicecatalog.delete_instance(
                    self.app.id, self.name)
            except KubeException as e:
                logger.info("retrieve instance info error: {}".format(e))


@task
def retrieve_task(data):
    try:
        signals.request_started.send(sender=data['task_id'])
        try:
            resource = Resource.objects.get(uuid=data['resource_id'])
        except Resource.DoesNotExist:
            logger.info("retrieve task not found resource: {}".format(data['resource_id']))  # noqa
            return True
        _ = resource.retrieve()
        if _:
            return True
        else:
            t = time.time() - resource.created.timestamps()
            if t < 3600:
                apply_async(retrieve_task, delay=30000, args=(data, ))
            elif t < 3600 * 12:
                apply_async(retrieve_task, delay=1800000, args=(data, ))
            else:
                resource.detach_resource()
    finally:
        signals.request_finished.send(sender=data['task_id'])
