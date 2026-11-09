import logging
from functools import partial
from django.db import models
from django.contrib.auth import get_user_model
from api.tasks import send_app_log
from api.utils import validate_json, validate_label
from api.exceptions import ServiceUnavailable
from scheduler import KubeException
from .base import AuditedModel, PTYPE_MAX_LENGTH


User = get_user_model()
logger = logging.getLogger(__name__)
service_ports_schema = {
    "$schema": "http://json-schema.org/schema#",
    "type": "array",
    "minItems": 1,
    "items": {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "port": {"type": "integer"},
            "protocol": {"type": "string"},
            "targetPort": {"type": "integer"},
        },
        "required": ["name", "port", "protocol", "targetPort"],
    }
}


class Service(AuditedModel):
    app = models.ForeignKey('App', on_delete=models.CASCADE)
    name = models.CharField(max_length=63, db_index=True, validators=[validate_label])
    ports = models.JSONField(
        default=list, validators=[partial(validate_json, schema=service_ports_schema)])
    ptype = models.CharField(max_length=PTYPE_MAX_LENGTH)

    class Meta:
        get_latest_by = 'created'
        unique_together = (('app', 'name'), )
        ordering = ['-created']

    def __str__(self):
        return self.name

    @property
    def domain(self):
        return "{}.{}.svc".format(self.name, self.namespace)

    @property
    def namespace(self):
        return self.app.id

    @classmethod
    def get(cls, app, name):
        return cls.objects.get(app=app, name=name)

    def as_dict(self):
        return {
            "name": self.name,
            "domain": self.domain,
            "ports": self.ports,
            "ptype": self.ptype,
        }

    def port_name(self, port, protocol):
        return "-".join([protocol, str(port)]).lower()

    def get_port(self, port, protocol):
        for item in self.ports:
            if item["port"] == port and item["protocol"] == protocol:
                return item
        return None

    def add_port(self, port, protocol, target_port):
        if self.get_port(port, protocol) is None:
            self.ports.append({
                "name": self.port_name(port, protocol),
                "port": port,
                "protocol": protocol,
                "targetPort": target_port,
            })
            return True
        return False

    def update_port(self, port, protocol, target_port):
        item = self.get_port(port, protocol)
        if not item or item["targetPort"] != target_port:
            if item and item["targetPort"] != target_port:
                self.remove_port(port, protocol)
            self.add_port(port, protocol, target_port)
            return True
        return False

    def remove_port(self, port, protocol):
        ports = []
        for item in self.ports:
            if item["port"] != port or item["protocol"] != protocol:
                ports.append(item)
        if len(self.ports) > len(ports):
            self.ports = ports
            return True
        return False

    def save(self, *args, **kwargs):
        previous_ptype = None
        if not self._state.adding:
            previous_ptype = Service.objects.filter(pk=self.pk).values_list(
                'ptype', flat=True).first()
        service = super(Service, self).save(*args, **kwargs)
        self.refresh_k8s_svc()
        if previous_ptype is not None and previous_ptype != self.ptype:
            try:
                self.refresh_routes()
            except Exception:
                # A database rollback cannot undo Kubernetes updates; compensate before raising.
                self.ptype = previous_ptype
                Service.objects.filter(pk=self.pk).update(ptype=previous_ptype)
                self.refresh_k8s_svc()
                self.refresh_routes()
                raise
        return service

    def delete(self, *args, **kwargs):
        self._delete_k8s_svc(self.name)
        # Delete from DB
        return super(Service, self).delete(*args, **kwargs)

    def log(self, message, level=logging.INFO):
        """Logs a message in the context of this service.

        This prefixes log messages with an application "tag" that the customized
        drycc-logspout will be on the lookout for.  When it's seen, the message-- usually
        an application event of some sort like releasing or scaling, will be considered
        as "belonging" to the application instead of the controller and will be handled
        accordingly.
        """
        send_app_log.delay(self.app.id, message, level)
        logger.log(level, "[{}]: {}".format(self.app.id, message))

    def refresh_k8s_svc(self):
        self.log('creating service: {}'.format(self.name), level=logging.DEBUG)
        try:
            try:
                data = self.scheduler.svc.get(self.namespace, self.name).json()
                self.scheduler.svc.patch(self.namespace, self.name, **{
                    "ports": self.ports,
                    "version": data["metadata"]["resourceVersion"],
                    "ptype": self.ptype,
                })
            except KubeException:
                self.scheduler.svc.create(self.namespace, self.name, **{
                    "ports": self.ports,
                    "ptype": self.ptype,
                })
        except KubeException as e:
            raise ServiceUnavailable('Kubernetes service could not be created') from e

    def refresh_routes(self):
        for route in self.app.route_set.all():
            if self.name in {service.name for service in route.services}:
                route.refresh_to_k8s()

    def _delete_k8s_svc(self, svc_name):
        self.log('deleting Service: {}'.format(svc_name), level=logging.DEBUG)
        self.scheduler.svc.delete(self.namespace, svc_name, ignore_exception=True)
