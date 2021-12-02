import base64
from rest_framework import permissions
from django.conf import settings
from django.contrib.auth.models import AnonymousUser
from api.models import Blocklist, App


def has_app_permission(request, obj):
    if isinstance(obj, App) or hasattr(obj, 'app'):
        app = obj if isinstance(obj, App) else obj.app
        blocklist = Blocklist.get_blocklist(app)
        if blocklist:
            return False, blocklist.remark
        if request.user.is_superuser:
            return True, None
        elif app.owner == request.user:
            return True, None
        elif request.user.is_staff or request.user.has_perm('use_app', app):
            if request.method != 'DELETE':
                return True, None
            else:
                return False, "User does not have permission to delete"
    return False, "App object does not exist or does not have permission."


class IsAnonymous(permissions.BasePermission):
    """
    View permission to allow anonymous users.
    """

    def has_permission(self, request, view):
        """
        Return `True` if permission is granted, `False` otherwise.
        """
        return type(request.user) is AnonymousUser


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


class IsOwnerOrAdmin(permissions.BasePermission):
    """
    Object-level permission to allow only owners of an object or administrators to access it.
    Assumes the model instance has an `owner` attribute.
    """
    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser:
            return True
        if hasattr(obj, 'owner'):
            return obj.owner == request.user
        else:
            return False


class IsAppUser(permissions.BasePermission):
    """
    Object-level permission to allow owners or collaborators to access
    an app-related model.
    """
    def has_object_permission(self, request, view, obj):
        return has_app_permission(request, obj)[0]


class IsAdmin(permissions.BasePermission):
    """
    View permission to allow only admins.
    """

    def has_permission(self, request, view):
        """
        Return `True` if permission is granted, `False` otherwise.
        """
        return request.user.is_superuser


class IsAdminOrSafeMethod(permissions.BasePermission):
    """
    View permission to allow only admins to use unsafe methods
    including POST, PUT, DELETE.

    This allows
    """

    def has_permission(self, request, view):
        """
        Return `True` if permission is granted, `False` otherwise.
        """
        return request.method in permissions.SAFE_METHODS or request.user.is_superuser


class HasBuilderAuth(permissions.BasePermission):
    """
    View permission to allow builder to perform actions
    with a special HTTP header
    """

    def has_permission(self, request, view):
        """
        Return `True` if permission is granted, `False` otherwise.
        """
        auth_header = request.environ.get('HTTP_X_DRYCC_BUILDER_AUTH')
        if not auth_header:
            return False
        return auth_header == settings.BUILDER_KEY


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
