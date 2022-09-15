from django.db import models
from django.db import transaction
from django.contrib.auth import get_user_model
from .base import AuditedModel

User = get_user_model()


class Domain(AuditedModel):
    owner = models.ForeignKey(User, on_delete=models.PROTECT)
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
        super(Domain, self).save(*args, **kwargs)
        # Read and write are separated, in transaction the read database is not updated
        domains = list(self.app.domain_set.all())
        if self in domains:
            domains.remove(self)
        domains.append(self)
        self.app.refresh(domains=domains)

    @transaction.atomic
    def delete(self, *args, **kwargs):
        # Deatch cert, updates k8s
        if self.certificate:
            self.certificate.detach(domain=str(self.domain))
        super(Domain, self).delete(*args, **kwargs)
        # Read and write are separated, in transaction the read database is not updated
        domains = list(self.app.domain_set.all())
        if self in domains:
            domains.remove(self)
        self.app.refresh(domains=domains)

    def __str__(self):
        return self.domain
