import base64
from django.db import models
from rest_framework.exceptions import ValidationError
from django.contrib.auth import get_user_model
from api.utils import fingerprint
from .base import UuidAuditedModel

User = get_user_model()


def validate_base64(value):
    """Check that value contains only valid base64 characters."""
    try:
        base64.b64decode(value.split()[1])
    except Exception as e:
        raise ValidationError('Key contains invalid base64 chars') from e


class Key(UuidAuditedModel):
    """An SSH public key."""

    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    id = models.CharField(max_length=128, unique=True)
    public = models.TextField(
        unique=True, validators=[validate_base64],
        error_messages={
            'unique': 'Public Key is already in use'
        }
    )
    fingerprint = models.CharField(max_length=128, editable=False)

    class Meta:
        verbose_name = 'SSH Key'
        unique_together = (('owner', 'fingerprint'))
        ordering = ['public']

    def __str__(self):
        return "{}...{}".format(self.public[:18], self.public[-31:])

    def save(self, *args, **kwargs):
        self.fingerprint = fingerprint(self.public)
        return super(Key, self).save(*args, **kwargs)
