"""
REST API URL routing for CTI module.
Enhanced with comprehensive API endpoints for enterprise integration.
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework.authtoken.views import obtain_auth_token
from .api_views import (
    UserViewSet, ThreatFeedViewSet, ThreatIndicatorViewSet,
    ThreatCampaignViewSet, AlertViewSet, CorrelationLogViewSet,
    ThreatHuntingViewSet, ReportingViewSet, DashboardViewSet,
    SystemHealthViewSet, ThreatIntelExchangeViewSet,
    AuditLogViewSet, APITokenViewSet
)

# Create router and register viewsets
router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')
router.register(r'feeds', ThreatFeedViewSet, basename='feed')
router.register(r'indicators', ThreatIndicatorViewSet, basename='indicator')
router.register(r'campaigns', ThreatCampaignViewSet, basename='campaign')
router.register(r'alerts', AlertViewSet, basename='alert')
router.register(r'correlation-logs', CorrelationLogViewSet, basename='correlation-log')
router.register(r'threat-hunting', ThreatHuntingViewSet, basename='threat-hunting')
router.register(r'reports', ReportingViewSet, basename='report')
router.register(r'dashboard', DashboardViewSet, basename='dashboard')
router.register(r'system-health', SystemHealthViewSet, basename='system-health')
router.register(r'intel-exchange', ThreatIntelExchangeViewSet, basename='intel-exchange')
router.register(r'audit-logs', AuditLogViewSet, basename='audit-log')
router.register(r'api-tokens', APITokenViewSet, basename='api-token')

urlpatterns = [
    # Router URLs
    path('', include(router.urls)),
    
    # Authentication
    path('auth/token/', obtain_auth_token, name='api_token_auth'),
    # In api_urls.py, add this to urlpatterns
    path('alerts/generate_simulated/', AlertViewSet.as_view({'post': 'generate_simulated'}), name='generate_simulated_alert'),
]

# Helper function views (if needed for non-ViewSet endpoints)
def refresh_api_token(request):
    """Refresh API token endpoint."""
    from rest_framework.authtoken.models import Token
    from django.http import JsonResponse
    
    if request.user.is_authenticated:
        Token.objects.filter(user=request.user).delete()
        token = Token.objects.create(user=request.user)
        return JsonResponse({'token': token.key})
    return JsonResponse({'error': 'Not authenticated'}, status=401)

def system_version(request):
    """Get system version."""
    from django.http import JsonResponse
    return JsonResponse({'version': '2.0.0', 'build': '2026-05-05'})

def websocket_info(request):
    """Get WebSocket connection info."""
    from django.http import JsonResponse
    return JsonResponse({
        'websocket_endpoint': '/ws/dashboard/live/',
        'supported': True,
        'protocol': 'ws' if not request.is_secure() else 'wss'
    })