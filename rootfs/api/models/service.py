import logging
from functools import partial
from django.db import models
from django.conf import settings
from django.contrib.auth import get_user_model
from api.utils import validate_json
from api.exceptions import ServiceUnavailable
from scheduler import KubeException
from .base import AuditedModel, PROCFILE_TYPE_MAX_LENGTH


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
    owner = models.ForeignKey(User, on_delete=models.PROTECT)
    app = models.ForeignKey('App', on_delete=models.CASCADE)
    ports = models.JSONField(
        default=list, validators=[partial(validate_json, schema=service_ports_schema)])
    procfile_type = models.CharField(max_length=PROCFILE_TYPE_MAX_LENGTH)

    class Meta:
        get_latest_by = 'created'
        unique_together = (('app', 'procfile_type'), )
        ordering = ['-created']

    def __str__(self):
        return self._svc_name()

    @property
    def domain(self):
        return "{}.{}.svc.{}".format(
            self._svc_name(), self._namespace(), settings.KUBERNETES_CLUSTER_DOMAIN
        )

    def as_dict(self):
        return {
            "domain": self.domain,
            "ports": self.ports,
            "procfile_type": self.procfile_type,
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
        service = super(Service, self).save(*args, **kwargs)
        self.refresh_k8s_svc()
        return service

    def delete(self, *args, **kwargs):
        self._delete_k8s_svc(self._svc_name())
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
        logger.log(level, "[{}]: {}".format(self.app.id, message))

    def _namespace(self):
        return self.app.id

    def _svc_name(self):
        if self.procfile_type == 'web':
            svc_name = self.app.id
        else:
            svc_name = "{}-{}".format(self.app.id, self.procfile_type)
        return svc_name

    def refresh_k8s_svc(self):
        svc_name = self._svc_name()
        namespace = self._namespace()
        self.log('creating service: {}'.format(svc_name), level=logging.DEBUG)
        try:
            try:
                data = self.scheduler().svc.get(namespace, svc_name).json()
                self.scheduler().svc.patch(namespace, svc_name, **{
                    "ports": self.ports,
                    "version": data["metadata"]["resourceVersion"],
                    "procfile_type": self.procfile_type,
                })
            except KubeException:
                self.scheduler().svc.create(namespace, svc_name, **{
                    "ports": self.ports,
                    "procfile_type": self.procfile_type,
                })
        except KubeException as e:
            raise ServiceUnavailable('Kubernetes service could not be created') from e

    def _delete_k8s_svc(self, svc_name):
        self.log('deleting Service: {}'.format(svc_name), level=logging.DEBUG)
        self.scheduler().svc.delete(self._namespace(), svc_name, ignore_exception=True)
