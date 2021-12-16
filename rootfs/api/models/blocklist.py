from django.db import models
from django.contrib.auth import get_user_model
from api.models import UuidAuditedModel, App

User = get_user_model()


class Blocklist(UuidAuditedModel):
    """
    You can block apps or users.
    If a user is blocked, all apps owned by the user will be stopped.
    The apps managed by the user will not be affected.
    """
    type_choices = [(1, "app", ), (2, "user")]
    id = models.CharField(max_length=128, db_index=True)
    type = models.PositiveIntegerField(choices=type_choices)
    remark = models.TextField(blank=True, null=True, default="Blocked for unknown reason")

    @property
    def related_apps(self):
        if self.type == 2:
            user = User.objects.get(id=self.id)
            return App.objects.filter(owner=user)
        else:
            return App.objects.filter(id=self.id)

    @classmethod
    def get_type(cls, name: str):
        for _index, _name in cls.type_choices:
            if _name == name:
                return _index
        raise ValueError("This type was not found")

    @classmethod
    def get_blocklist(cls, app: App):
        return cls.objects.filter(
            models.Q(id=app.id, type=1) | models.Q(id=app.owner_id, type=2)
        ).first()

    class Meta:
        ordering = ['-created']
        unique_together = (("id", "type"),)
