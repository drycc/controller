import base64
from rest_framework import permissions
from django.conf import settings
from api import manager
from api.models import blocklist
from api.models.workspace import Workspace, WorkspaceMember


def get_app_status(app):
    block = blocklist.Blocklist.get_blocklist(app)
    if block:
        return False, block.remark
    if settings.WORKFLOW_MANAGER_URL:
        status = manager.WorkspaceAPI().get_status(app.workspace_id)
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
        elif isinstance(obj, Workspace) or hasattr(obj, 'workspace'):
            workspace = obj if isinstance(obj, Workspace) else obj.workspace
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


class IsServiceToken(permissions.BasePermission):
    """
    The service token is used for internal communication between Drycc components,
    such as the builder and Quickwit.
    """

    def has_permission(self, request, view):
        """
        Return `True` if permission is granted, `False` otherwise.
        """
        auth_header = request.META.get('HTTP_X_DRYCC_SERVICE_KEY')
        if not auth_header:
            return False
        return auth_header == settings.SERVICE_KEY


class IsWorkflowManager(permissions.BasePermission):
    """
    View permission to allow workflow manager to perform actions
    with a special HTTP header
    """

    def has_permission(self, request, view):
        if request.META.get("HTTP_AUTHORIZATION"):
            token = request.META.get(
                "HTTP_AUTHORIZATION").split(" ")[1].encode("utf8")
            access_key, secret_key = base64.b85decode(token).decode("utf8").split(":")
            if settings.WORKFLOW_MANAGER_ACCESS_KEY == access_key:
                if settings.WORKFLOW_MANAGER_SECRET_KEY == secret_key:
                    return True
        return False
