from django.db import models
from django.conf import settings
from django.db import transaction

from api.models import AuditedModel


class Domain(AuditedModel):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    app = models.ForeignKey('App', on_delete=models.CASCADE)
    domain = models.TextField(
        blank=False, null=False, unique=True,
        error_messages={
            'unique': 'Domain is already in use by another application'
        }
    )
    certificate = models.ForeignKey(
        'Certificate',
        on_delete=models.SET_NULL,
        blank=True,
        null=True
    )

    class Meta:
        ordering = ['domain', 'certificate']

    @transaction.atomic
    def save(self, *args, **kwargs):
        try:
            # Save to DB
            return super(Domain, self).save(*args, **kwargs)
        finally:
            self.app.refresh_ingress_and_tls()

    @transaction.atomic
    def delete(self, *args, **kwargs):
        # Deatch cert, updates k8s
        if self.certificate:
            self.certificate.detach(domain=str(self.domain))
        try:
            # Delete from DB
            return super(Domain, self).delete(*args, **kwargs)
        finally:
            self.app.refresh_ingress_and_tls()

    def __str__(self):
        return self.domain
