import logging

from django.db import models
from django.conf import settings
from django.contrib.auth import get_user_model
from api.exceptions import ServiceUnavailable
from scheduler import KubeException
from .base import AuditedModel

User = get_user_model()
logger = logging.getLogger(__name__)


class Service(AuditedModel):
    owner = models.ForeignKey(User, on_delete=models.PROTECT)
    app = models.ForeignKey('App', on_delete=models.CASCADE)
    ports = models.JSONField(default=dict)
    procfile_type = models.TextField()

    class Meta:
        get_latest_by = 'created'
        unique_together = (('app', 'procfile_type'), )
        ordering = ['-created']

    def __str__(self):
        return self._svc_name()

    def as_dict(self):
        namespace = self._namespace()
        svc_name = self._svc_name()
        cluster_domain = settings.KUBERNETES_CLUSTER_DOMAIN
        return {
            "domain": f"{svc_name}.{namespace}.svc.{cluster_domain}",
            "ports": self.ports,
            "procfile_type": self.procfile_type,
        }

    def port_name(self, port, protocol):
        return "%s-%s-%s-%s" % (self.app.id, self.procfile_type, protocol, port)

    def add_port(self, port, protocol, target_port):
        self.ports.append({
            "name": self.port_name(port, protocol),
            "port": port,
            "protocol": protocol,
            "target_port": target_port,
        })

    def refresh_k8s_svc(self):
        svc_name = self._svc_name()
        namespace = self._namespace()
        self.log('creating service: {}'.format(svc_name), level=logging.DEBUG)
        try:
            try:
                data = self._scheduler.svc.get(namespace, svc_name).json()
                self._scheduler.svc.patch(namespace, svc_name, **{
                    "ports": self.ports,
                    "version": data["metadata"]["resourceVersion"],
                })
            except KubeException:
                self._scheduler.svc.create(namespace, svc_name, **{
                    "ports": self.ports,
                })
        except KubeException as e:
            raise ServiceUnavailable('Kubernetes service could not be created') from e

    def save(self, *args, **kwargs):
        service = super(Service, self).save(*args, **kwargs)
        self.refresh_k8s_svc()
        return service

    def delete(self, *args, **kwargs):
        namespace = self._namespace()
        svc_name = self._svc_name()
        self.log('deleting Service: {}'.format(svc_name), level=logging.DEBUG)
        try:
            self._scheduler.svc.delete(namespace, svc_name)
        except KubeException:
            # swallow exception
            # raise ServiceUnavailable('Kubernetes service could not be deleted') from e
            self.log('Kubernetes service cannot be deleted: {}'.format(svc_name),
                     level=logging.ERROR)

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
        logger.log(level, "[{}]: {}".format(self.id, message))

    def _namespace(self):
        return self.app.id

    def _svc_name(self):
        if self.procfile_type in ("web", "cmd"):
            return self.app.id
        return "{}-{}".format(self.app.id, self.procfile_type)
