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
    port = models.PositiveIntegerField(default=5000)
    protocol = models.TextField(default="TCP")
    target_port = models.PositiveIntegerField(default=5000)
    service_type = models.TextField()
    procfile_type = models.TextField()

    class Meta:
        get_latest_by = 'created'
        unique_together = (('app', 'procfile_type'), )
        ordering = ['-created']

    def __str__(self):
        return self._svc_name()

    def _get_ips(self):
        namespace = self._namespace()
        svc_name = self._svc_name()
        response = self._scheduler.svc.get(namespace, svc_name)
        data = response.json()
        cluster_ip = data['spec']['clusterIP']
        if 'ingress' in data['status']['loadBalancer']:
            external_ip = data['status']['loadBalancer']['ingress'][0]['ip']
        else:
            external_ip = None
        return cluster_ip, external_ip

    def as_dict(self):
        namespace = self._namespace()
        svc_name = self._svc_name()
        cluster_domain = settings.KUBERNETES_CLUSTER_DOMAIN
        cluster_ip, external_ip = self._get_ips()
        return {
            "port": self.port,
            "domain": f"{svc_name}.{namespace}.svc.{cluster_domain}",
            "protocol": self.protocol,
            "cluster_ip": cluster_ip,
            "external_ip": external_ip,
            "target_port": self.target_port,
            "service_type": self.service_type,
            "procfile_type": self.procfile_type,
        }

    def create(self):
        namespace = self._namespace()
        svc_name = self._svc_name()
        self.log('creating service: {}'.format(svc_name), level=logging.DEBUG)
        try:
            try:
                self._scheduler.svc.get(namespace, svc_name)
            except KubeException:
                self._scheduler.svc.create(
                    namespace,
                    svc_name,
                    service_type=self.service_type,
                    port=self.port,
                    protocol=self.protocol,
                    target_port=self.target_port,
                )
        except KubeException as e:
            raise ServiceUnavailable('Kubernetes service could not be created') from e

    def save(self, *args, **kwargs):
        service = super(Service, self).save(*args, **kwargs)

        self.create()

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
        return "{}-{}".format(self.app.id, self.procfile_type)
