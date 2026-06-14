"""
Workspace views.
"""
import secrets

from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.renderers import JSONRenderer, TemplateHTMLRenderer
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet
from django.shortcuts import get_object_or_404, render

from api import models, serializers


User = get_user_model()


class WorkspaceViewSet(ModelViewSet):
    """
    ViewSet for Workspace model.
    """
    lookup_field = 'id'
    lookup_value_regex = r'[-_\w]+'
    serializer_class = serializers.WorkspaceSerializer
    permission_classes = [IsAuthenticated]

    def _require_admin(self, workspace, message):
        if not workspace.has_member(self.request.user, role='admin'):
            raise PermissionDenied(message)

    def get_queryset(self):
        return models.workspace.Workspace.objects.filter(
            workspacemember__user=self.request.user
        ).distinct()

    def perform_create(self, serializer):
        workspace = serializer.save()
        models.workspace.WorkspaceMember.objects.create(
            user=self.request.user, workspace=workspace, role='admin'
        )

    def get_object(self):
        """Override to get workspace by id instead of pk"""
        return get_object_or_404(self.get_queryset(), id=self.kwargs['id'])

    def update(self, request, *args, **kwargs):
        """Only admins can update workspaces"""
        workspace = self.get_object()
        self._require_admin(workspace, "Only workspace admins can update workspaces")
        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        """Only admins can delete workspaces"""
        workspace = self.get_object()
        self._require_admin(workspace, "Only workspace admins can delete workspaces")
        if models.workspace.WorkspaceMember.objects.filter(workspace=workspace).count() > 1:
            raise PermissionDenied("Cannot delete workspace with more than one member")
        return super().destroy(request, *args, **kwargs)


class WorkspaceMemberViewSet(ModelViewSet):
    """
    ViewSet for WorkspaceMember model.
    """
    serializer_class = serializers.WorkspaceMemberSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        workspace = get_object_or_404(models.workspace.Workspace, id=self.kwargs['id'])
        # Check if user has access to this workspace
        if workspace.has_member(self.request.user):
            return models.workspace.WorkspaceMember.objects.filter(workspace=workspace)
        return models.workspace.WorkspaceMember.objects.none()

    def get_object(self):
        """Override to get member by username and workspace id"""
        workspace = get_object_or_404(models.workspace.Workspace, id=self.kwargs['id'])
        return get_object_or_404(
            models.workspace.WorkspaceMember,
            workspace=workspace, user__username=self.kwargs['user']
        )

    @staticmethod
    def _only_member_workspace(member):
        return models.workspace.WorkspaceMember.objects.filter(
            workspace=member.workspace
        ).count() == 1

    def update(self, request, *args, **kwargs):
        """Update a member. Admins can update any member (role and alerts).
        Non-admins can only update their own alerts field."""
        member = self.get_object()
        is_admin = member.workspace.has_member(request.user, role='admin')
        is_only_member = self._only_member_workspace(member)

        # Only member cannot modify role
        if is_only_member and 'role' in request.data:
            raise PermissionDenied("Cannot modify role: workspace only has one member")

        # Non-admin users restrictions
        if not is_admin:
            # Cannot update other members
            if request.user != member.user:
                raise PermissionDenied("Only workspace admins can update other members")
            # Cannot modify own role
            if 'role' in request.data:
                raise PermissionDenied("Cannot modify your own role")

        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        """Delete a member. Admins can delete any member.
        Non-admins can only delete themselves (leave workspace)."""
        member = self.get_object()
        is_admin = member.workspace.has_member(request.user, role='admin')
        is_only_member = self._only_member_workspace(member)

        # Only member cannot delete self
        if is_only_member and request.user == member.user:
            raise PermissionDenied("Cannot delete: workspace only has one member")

        # Non-admin can delete self
        if request.user == member.user:
            return super().destroy(request, *args, **kwargs)

        # Admin can delete any member
        if is_admin:
            return super().destroy(request, *args, **kwargs)

        # Other cases forbidden
        raise PermissionDenied("Only workspace admins can remove other members")


class WorkspaceInvitationViewSet(ModelViewSet):
    """
    ViewSet for WorkspaceInvitation model.
    """
    serializer_class = serializers.WorkspaceInvitationSerializer

    def get_permissions(self):
        """
        Allow anyone to accept an invitation.
        Only authenticated users can create or list invitations.
        """
        if self.action == 'retrieve':
            return [AllowAny()]
        return super().get_permissions()

    def get_renderers(self):
        if self.action == 'retrieve':
            return [JSONRenderer(), TemplateHTMLRenderer()]
        return super().get_renderers()

    def get_queryset(self):
        workspace = get_object_or_404(models.workspace.Workspace, id=self.kwargs['id'])
        if workspace.has_member(self.request.user):
            return models.workspace.WorkspaceInvitation.objects.filter(
                workspace=workspace, accepted=False)
        return models.workspace.WorkspaceInvitation.objects.none()

    def get_object(self):
        """Override to get invitation by uid and workspace id"""
        return get_object_or_404(
            models.workspace.WorkspaceInvitation,
            workspace=get_object_or_404(models.workspace.Workspace, id=self.kwargs['id']),
            token=self.kwargs['uid'],
            accepted=False,
        )

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.accept()
        user_exists = User.objects.filter(email=instance.email).exists()
        data = {
            'workspace_id': instance.workspace.id,
            'user_exists': user_exists,
            'register_url': settings.DRYCC_REGISTER_URL,
        }
        if isinstance(request.accepted_renderer, TemplateHTMLRenderer):
            return render(request, 'workspace/workspace_invitation_accept.html', data)
        return Response(data)

    def perform_create(self, serializer):
        workspace = get_object_or_404(models.workspace.Workspace, id=self.kwargs['id'])
        if not workspace.has_member(self.request.user, role='admin'):
            raise PermissionDenied("Only workspace admins can create invitations")
        email = serializer.validated_data['email']
        user = User.objects.filter(email=email).first()
        if user and workspace.has_member(user):
            raise ValidationError("User is already a member of the workspace")
        invitation = models.workspace.WorkspaceInvitation.objects.filter(
            email=email, workspace=workspace, accepted=False
        ).first()
        if not invitation:
            models.workspace.WorkspaceInvitation.objects.filter(
                email=email, workspace=workspace, accepted=True
            ).delete()
            invitation = serializer.save(
                token=secrets.token_hex(64), inviter=self.request.user, workspace=workspace)
        if settings.EMAIL_HOST:
            invitation.send_email(self.request)
        else:
            invitation.accept()

    def destroy(self, request, *args, **kwargs):
        """Only admins can revoke invitations"""
        invitation = self.get_object()
        if not invitation.workspace.has_member(request.user, role='admin'):
            raise PermissionDenied("Only workspace admins can revoke invitations")
        return super().destroy(request, *args, **kwargs)
