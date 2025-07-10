import uuid
import time
import string
import random
from datetime import timedelta
from functools import partial
from django.db import models
from django.conf import settings
from django.utils import timezone
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _


from api.utils import get_session, validate_json, get_scheduler

token_manager_oauth_schema = {
    "$schema": "http://json-schema.org/schema#",
    "type": "object",
    "properties": {
        "access_token": {"type": "string"},
        "expires_in": {"type": "integer"},
        "token_type": {"type": "string"},
        "scope": {"type": "string"},
        "refresh_token": {"type": "string"},
    },
    "required": [
        "access_token", "expires_in", "token_type", "scope", "refresh_token"
    ],
}
PTYPE_WEB = "web"
PTYPE_RUN = "run"
DEFAULT_HTTP_PORT = 80
DEFAULT_HTTPS_PORT = 443
PTYPE_MIN_LENGTH = 3
PTYPE_MAX_LENGTH = 63


def get_anonymous_user_instance(user): return user(id=-1, username=settings.ANONYMOUS_USER_NAME)


class AuditedModel(models.Model):
    """Add created and updated fields to a model."""

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    class Meta:
        """Mark :class:`AuditedModel` as abstract."""
        abstract = True

    def app_log(self, app_id, msg):
        session = get_session()
        session.post(
            "",
            json={
                "timestamp": int(time.time()),
                "log": msg,
                "kubernetes": {
                    "namespace": app_id,
                    "container_name": "drycc-controller",
                }
            }
        )

    @property
    def scheduler(self):
        annotations = {}
        if hasattr(self, 'app'):
            annotations["drycc.cc/project_id"] = str(self.app.id)
        if hasattr(self, 'owner'):
            annotations["drycc.cc/account_id"] = str(self.owner.id)
        return get_scheduler(metadata={"annotations": annotations})


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


class Token(UuidAuditedModel):
    key = models.CharField(_("Key"), max_length=128, unique=True)
    owner = models.ForeignKey(User, on_delete=models.PROTECT)
    alias = models.CharField(_("Alias"), max_length=32, blank=True, default="")
    oauth = models.JSONField(
        validators=[partial(validate_json, schema=token_manager_oauth_schema)])

    @property
    def fuzzy_key(self):
        return f'{self.key[:14]}...{self.key[-14:]}'

    def save(self, *args, **kwargs):
        if not self.key:
            self.key = self.generate_key()
        return super().save(*args, **kwargs)

    def expires(self):
        if self.updated + timedelta(seconds=self.oauth['expires_in']) < timezone.now():
            return True
        return False

    @classmethod
    def generate_key(cls):
        return ''.join(
            [i if random.randint(0, 9) % 2 == 0 else i.upper() for i in uuid.uuid4().hex]
        ) + ''.join(random.choices(string.ascii_letters, k=96))

    def refresh_token(self):
        from api.backend import DryccOIDC
        drycc_open_connect = DryccOIDC()
        self.oauth = drycc_open_connect.refresh_token(self.oauth['refresh_token'])
        self.save()
