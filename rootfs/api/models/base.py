import uuid
import importlib
from django.db import models
from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _


def get_anonymous_user_instance(user): return user(id=-1, username=settings.ANONYMOUS_USER_NAME)


class AuditedModel(models.Model):
    """Add created and updated fields to a model."""

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    class Meta:
        """Mark :class:`AuditedModel` as abstract."""
        abstract = True

    @classmethod
    def scheduler(cls):
        mod = importlib.import_module(settings.SCHEDULER_MODULE)
        return mod.SchedulerClient(settings.SCHEDULER_URL, settings.K8S_API_VERIFY_TLS)


class UuidAuditedModel(AuditedModel):
    """Add a UUID primary key to an :class:`AuditedModel`."""

    uuid = models.UUIDField('UUID',
                            default=uuid.uuid4,
                            primary_key=True,
                            editable=False,
                            auto_created=True,
                            unique=True)

    class Meta:
        """Mark :class:`UuidAuditedModel` as abstract."""
        abstract = True


class User(AbstractUser):
    id = models.BigIntegerField(_('id'), primary_key=True)
    email = models.EmailField(_('email address'), unique=True)
