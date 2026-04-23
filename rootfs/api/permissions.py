import logging
from django.conf import settings
from rest_framework import permissions

from api import clients
from api.models import blocklist
from api.models.workspace import Workspace, WorkspaceMember

logger = logging.getLogger(__name__)


def get_app_status(app):
    block = blocklist.Blocklist.get_blocklist(app)
    if block:
        return False, block.remark
    if settings.WORKFLOW_MANAGER_URL:
        status = clients.WorkspaceAPI().get_status(app.workspace_id)
        if not status["is_active"]:
            return False, status["message"]
    return True, None


class IsOwner(permissions.BasePermission):
    """
    Object-level permission to allow only owners of an object to access it.
    Assumes the model instance has an `owner` attribute.
    """

    def has_object_permission(self, request, view, obj):
        if hasattr(obj, 'owner'):
            return obj.owner == request.user
        else:
            return False


class IsAppUser(permissions.BasePermission):
    """
    Object-level permission to allow only users who are owners
    or collaborators of an app to access it.
    """

    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser or request.user.is_staff:
            return True
        elif getattr(obj, "user", None) == request.user:
            return True
        elif isinstance(obj, Workspace) or hasattr(obj, 'workspace') or hasattr(obj, 'app'):
            workspace = obj if isinstance(obj, Workspace) else getattr(
                obj, "workspace", None) or getattr(getattr(obj, 'app', None), 'workspace', None)
            if request.method in ["GET", "HEAD", "OPTIONS"]:
                allowed_roles = ["viewer", "member", "admin"]
            elif request.method in ["POST", "PUT", "PATCH"]:
                allowed_roles = ["member", "admin"]
            else:
                allowed_roles = ["admin"]
            return WorkspaceMember.objects.filter(
                workspace=workspace, user=request.user, role__in=allowed_roles,
            ).exists()
        return False


class HasOAuthScope(permissions.BasePermission):
    """
    Object-level permission to allow only requests with specific OAuth scopes.
    The required scopes are defined on the view as `required_oauth_scopes = ['scope1', 'scope2']`
    """
    client = clients.PassportAPI()

    def has_permission(self, request, view):
        required_oauth_scopes = getattr(view, 'required_oauth_scopes', [])
        if not required_oauth_scopes:
            return True

        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        parts = auth_header.split()
        if len(parts) == 2 and parts[0].lower() == 'bearer':
            token = parts[1]
        else:
            return False
        scopes = self.client.get_scopes(token)
        return set(required_oauth_scopes).issubset(scopes)
