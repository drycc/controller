import re
import logging
from django.db import models
from django.core.mail import send_mail
from django.utils.translation import gettext_lazy as _

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.template.loader import render_to_string

from rest_framework.exceptions import ValidationError
from api.utils import validate_reserved_names, get_local_host

User = get_user_model()
logger = logging.getLogger(__name__)


def validate_workspace_name(value):
    """
    Check that the value follows the kubernetes name constraints
    """
    match = re.match(r'^[0-9a-z]{5,}$', value)
    if not match:
        raise ValidationError("App name must start with an alphabetic character, cannot end with a"
                              + " hyphen and can only contain a-z (lowercase), 0-9 and hyphens.")
    validate_reserved_names(value)


class Workspace(models.Model):
    name = models.SlugField(
        _("workspace name"),
        max_length=150,
        unique=True,
        validators=[validate_workspace_name],
    )
    email = models.EmailField(_("email address"))
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    def has_member(self, user, role=None):
        kwargs = {'user': user, 'workspace': self}
        if role:
            kwargs['role'] = role
        return WorkspaceMember.objects.filter(**kwargs).exists()

    def __str__(self):
        return self.name


class WorkspaceMember(models.Model):
    role_choices = [
        ('admin', 'Admin'),
        ('member', 'Member'),
        ('viewer', 'Viewer'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=50, choices=role_choices)
    alerts = models.BooleanField(default=True)
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    workspace = models.ForeignKey(Workspace, on_delete=models.CASCADE)

    def __str__(self):
        return f"{self.user.username} - {self.workspace.name} ({self.role})"

    class Meta:
        unique_together = ('user', 'workspace')


class WorkspaceInvitation(models.Model):
    email = models.EmailField(_("email address"))
    token = models.CharField(max_length=128, unique=True)
    inviter = models.ForeignKey(User, on_delete=models.CASCADE)
    created = models.DateTimeField(auto_now_add=True)
    accepted = models.BooleanField(_("accepted"), default=False)
    workspace = models.ForeignKey(Workspace, on_delete=models.CASCADE)

    class Meta:
        unique_together = ('email', 'workspace')

    def accept(self):
        if not self.accepted:
            self.accepted = True
            self.save()
        user = User.objects.filter(email=self.email).first()
        if not user:
            return
        WorkspaceMember.objects.get_or_create(
            user=user, workspace=self.workspace, defaults={'role': 'member'})

    def send_email(self, request):
        cache_key = f"invitation:email:{self.email}"
        cache.add(cache_key, 0, timeout=settings.DRYCC_INVITATION_EMAIL_TIMEOUT)
        count = cache.incr(cache_key)
        if count > settings.DRYCC_INVITATION_EMAIL_LIMIT:
            raise ValidationError("Too many invitation emails, please try again later")
        domain = get_local_host(request)
        mail_subject = f'We Invite You to Join the {self.workspace.name} Workspace.'
        message = render_to_string(
            'workspace/workspace_invitation.html',
            {'domain': domain, 'invitation': self}
        )
        send_mail(mail_subject, message, None, [self.email], fail_silently=True)

    def __str__(self):
        return f"Invitation for {self.email} to join {self.workspace.name}"
