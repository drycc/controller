import copy
import logging
from django.db import models
from django.db import transaction
from django.contrib.auth import get_user_model
from api.exceptions import AlreadyExists
from api.exceptions import ServiceUnavailable
from scheduler import KubeException
from .base import UuidAuditedModel


User = get_user_model()
logger = logging.getLogger(__name__)


def default_issuer():
    return {
        "email": "anonymous@cert-manager.io",
        "server": "https://acme-v02.api.letsencrypt.org/directory",
        "key_id": "",
        "key_secret": "",
    }


class TLS(UuidAuditedModel):
    owner = models.ForeignKey(User, on_delete=models.PROTECT)
    app = models.ForeignKey('App', on_delete=models.CASCADE)
    issuer = models.JSONField(default=default_issuer)
    https_enforced = models.BooleanField(null=True)
    certs_auto_enabled = models.BooleanField(null=True)

    class Meta:
        get_latest_by = 'created'
        unique_together = (('app', 'uuid'))
        ordering = ['-created']

    def __str__(self):
        return "{}-{}".format(self.app.id, str(self.uuid)[:7])

    def _check_previous_tls_settings(self):
        """
        Only one value can be set at a time
        If the other value is None, using the previous setting.
        """
        try:
            previous_tls_settings = self.app.tls_set.latest()
            if self.https_enforced is not None:
                if previous_tls_settings.https_enforced == self.https_enforced:
                    raise AlreadyExists(
                        "{} changed nothing".format(self.owner))
                self.certs_auto_enabled = previous_tls_settings.certs_auto_enabled
            elif self.certs_auto_enabled is not None:
                if previous_tls_settings.certs_auto_enabled == self.certs_auto_enabled:
                    raise AlreadyExists(
                        "{} changed nothing".format(self.owner))
                self.https_enforced = previous_tls_settings.https_enforced
            previous_tls_settings.delete()
        except TLS.DoesNotExist:
            pass

    def _refresh_secret_to_k8s(self):
        secret_name = f"{self.app.id}-acme-external-account-binding-secret"
        try:
            try:
                data = self.scheduler().secret.get(self.app.id, secret_name).json()
                self.scheduler().secret.patch(self.app.id, secret_name, {
                    "secret": self.issuer["key_secret"],
                    "version": data["metadata"]["resourceVersion"],
                })
            except KubeException:
                self.scheduler().secret.create(self.app.id, secret_name, {
                    "secret": self.issuer["key_secret"],
                })
        except KubeException as e:
            raise ServiceUnavailable('Kubernetes secret could not be created') from e

    def refresh_issuer_to_k8s(self):
        name = namespace = self.app.id
        try:
            if self.issuer["key_id"] and self.issuer["key_secret"]:
                self._refresh_secret_to_k8s()
            data = copy.copy(self.issuer)
            data["parent_refs"] = [
                {
                    "group": "gateway.networking.k8s.io",
                    "kind": "Gateway",
                    "name": gateway.name,
                }
                for gateway in self.app.gateway_set.all()
            ]
            try:
                version = self.scheduler().issuer.get(
                    namespace, name, ignore_exception=False).json()["metadata"]["resourceVersion"]
                data.update({"version": version})
                self.scheduler().issuer.put(namespace, name, **data)
            except KubeException:
                self.scheduler().issuer.create(namespace, name, **data)
        except KubeException as e:
            raise ServiceUnavailable('Kubernetes issuer could not be created') from e

    def refresh_certificate_to_k8s(self):
        namespace = name = self.app.id
        if self.certs_auto_enabled:
            hosts = [domain.domain for domain in self.app.domain_set.all()]
            if len(hosts) > 0:
                response = self.scheduler().certificate.get(namespace, name)
                if response.status_code == 200:
                    data = response.json()
                    version = data["metadata"]["resourceVersion"]
                    self.scheduler().certificate.put(namespace, name, hosts, version)
                else:
                    logger.log(
                        msg="certificate {} does not exist".format(namespace), level=logging.INFO)
                    self.scheduler().certificate.create(namespace, name, hosts)
            else:
                self.app.log("skip creating certificate, no domain name set", logging.WARNING)
        else:
            self.scheduler().certificate.delete(namespace, name, ignore_exception=True)

    @transaction.atomic
    def save(self, *args, **kwargs):
        self._check_previous_tls_settings()
        super(TLS, self).save(*args, **kwargs)
