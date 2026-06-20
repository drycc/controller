"""
Views module - split from views.py for better organization.

This module exports all views from submodules for backwards compatibility.
"""
from api.views.health import ReadinessCheckView, LivenessCheckView
from api.views.auth import AuthLoginView, AuthTokenView, auth, complete
from api.views.user import UserManagementViewSet
from api.views.admission import AdmissionWebhookViewSet
from api.views.workspace import (
    WorkspaceViewSet,
    WorkspaceMemberViewSet,
    WorkspaceInvitationViewSet,
)
from api.views.token import TokenViewSet
from api.views.app import (
    AppFilterViewSet,
    ReleasableViewSet,
    AppViewSet,
    BuildViewSet,
    ConfigViewSet,
    ReleaseViewSet,
)
from api.views.pods import PodViewSet, PtypeViewSet, EventViewSet
from api.views.settings import (
    AppSettingsViewSet,
    DomainViewSet,
    ServiceViewSet,
    CertificateViewSet,
    TLSViewSet,
)
from api.views.limit import LimitSpecViewSet, LimitPlanViewSet
from api.views.key import KeyViewSet
from api.views.addon import AddonClassViewSet, AddonInstanceViewSet
from api.views.volume import AppVolumesViewSet
from api.views.gateway import GatewayViewSet, RouteViewSet
from api.views.hooks import (
    BaseServiceViewSet,
    KeyHookViewSet,
    BuildHookViewSet,
    ConfigHookViewSet,
    AlertsHookViewSet,
)
from api.views.metrics import (
    MetricView,
    MetricsProxyView,
    QuickwitProxyView,
    PrometheusProxyView,
)

__all__ = [
    # Health
    'ReadinessCheckView',
    'LivenessCheckView',
    # Auth
    'AuthLoginView',
    'AuthTokenView',
    'auth',
    'complete',
    # User
    'UserManagementViewSet',
    # Admission
    'AdmissionWebhookViewSet',
    # Workspace
    'WorkspaceViewSet',
    'WorkspaceMemberViewSet',
    'WorkspaceInvitationViewSet',
    # Token
    'TokenViewSet',
    # App
    'AppFilterViewSet',
    'ReleasableViewSet',
    'AppViewSet',
    'BuildViewSet',
    'ConfigViewSet',
    'ReleaseViewSet',
    # Pods
    'PodViewSet',
    'PtypeViewSet',
    'EventViewSet',
    # Settings
    'AppSettingsViewSet',
    'DomainViewSet',
    'ServiceViewSet',
    'CertificateViewSet',
    'TLSViewSet',
    # Limit
    'LimitSpecViewSet',
    'LimitPlanViewSet',
    # Key
    'KeyViewSet',
    # Addon
    'AddonClassViewSet',
    'AddonInstanceViewSet',
    # Volume
    'AppVolumesViewSet',
    # Gateway
    'GatewayViewSet',
    'RouteViewSet',
    # Hooks
    'BaseServiceViewSet',
    'KeyHookViewSet',
    'BuildHookViewSet',
    'ConfigHookViewSet',
    'AlertsHookViewSet',
    # Metrics
    'MetricView',
    'MetricsProxyView',
    'QuickwitProxyView',
    'PrometheusProxyView',
]
