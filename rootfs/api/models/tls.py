from django.db import models
from django.db import transaction
from django.contrib.auth import get_user_model
from api.exceptions import AlreadyExists
from api.models import UuidAuditedModel

User = get_user_model()


class TLS(UuidAuditedModel):
    owner = models.ForeignKey(User, on_delete=models.PROTECT)
    app = models.ForeignKey('App', on_delete=models.CASCADE)
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

    @transaction.atomic
    def save(self, *args, **kwargs):
        self._check_previous_tls_settings()
        try:
            # Save to DB
            return super(TLS, self).save(*args, **kwargs)
        finally:
            self.app.refresh()

    def sync(self):
        self.app.refresh()
