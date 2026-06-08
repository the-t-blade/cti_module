"""
Django REST Framework viewsets for CTI API.
Enhanced with Dashboard, System Health, Intel Exchange, Audit Logs, and API Token viewsets.
"""

import logging
from rest_framework import viewsets, status, filters
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.authtoken.models import Token
from django_filters.rest_framework import DjangoFilterBackend
from django.contrib.auth.models import User
from django.utils import timezone
from django.db.models import Count, Q, Avg, Sum
from django.core.cache import cache
from datetime import timedelta

from .models import ThreatFeed, ThreatIndicator, ThreatCampaign, Alert, CorrelationLog
from .serializers import (
    UserSerializer, ThreatFeedSerializer, ThreatIndicatorSerializer,
    ThreatCampaignSerializer, AlertSerializer, CorrelationLogSerializer,
    ThreatStatisticsSerializer, ThreatHuntingQuerySerializer, ReportSerializer
)
from .services import CorrelationService, AlertService
from .ml_services import AnomalyDetectionService, PredictiveAnalyticsService, ThreatIntelligenceAnalytics
from .services import RealTimeAlertSimulator

logger = logging.getLogger(__name__)


class UserViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing users.
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter]
    search_fields = ['username', 'email', 'first_name', 'last_name']
    
    def get_queryset(self):
        """Only staff can see all users, regular users see only themselves."""
        if self.request.user.is_staff:
            return User.objects.all()
        return User.objects.filter(id=self.request.user.id)
    
    @action(detail=False, methods=['get'])
    def me(self, request):
        """Get current user information."""
        serializer = self.get_serializer(request.user)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def reset_password(self, request, pk=None):
        """Reset user password (admin only)."""
        if not request.user.is_staff:
            return Response({'error': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
        
        user = self.get_object()
        import secrets
        import string
        alphabet = string.ascii_letters + string.digits
        new_password = ''.join(secrets.choice(alphabet) for _ in range(12))
        user.set_password(new_password)
        user.save()
        
        return Response({'success': True, 'new_password': new_password})


class ThreatFeedViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing threat feeds.
    """
    queryset = ThreatFeed.objects.all()
    serializer_class = ThreatFeedSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['is_active', 'feed_type']
    search_fields = ['name', 'description']
    ordering_fields = ['created_at', 'last_ingested']
    ordering = ['-last_ingested']
    
    @action(detail=True, methods=['post'])
    def ingest(self, request, pk=None):
        """Manually trigger ingestion for a specific feed."""
        feed = self.get_object()
        feed.last_ingested = timezone.now()
        feed.save()
        return Response({'status': 'ingestion_started', 'feed_id': str(feed.id)})
    
    @action(detail=True, methods=['post'])
    def toggle(self, request, pk=None):
        """Toggle feed active status."""
        feed = self.get_object()
        feed.is_active = not feed.is_active
        feed.save()
        return Response({'success': True, 'is_active': feed.is_active})


class ThreatIndicatorViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing threat indicators.
    """
    queryset = ThreatIndicator.objects.all()
    serializer_class = ThreatIndicatorSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['indicator_type', 'severity', 'is_active', 'campaign']
    search_fields = ['indicator_value', 'context', 'tags']
    ordering_fields = ['confidence', 'severity', 'last_seen', 'created_at']
    ordering = ['-last_seen']
    
    def get_queryset(self):
        """Limit API results to Zimbabwe-specific indicators only."""
        qs = ThreatIndicator.objects.all()
        # Prefer indicators with explicit Zimbabwe context/tags or .zw domains
        qs = qs.filter(
            Q(context__icontains='zimbabwe') |
            Q(tags__icontains='zimbabwe') |
            Q(indicator_value__icontains='.zw') |
            Q(indicator_value__iendswith='.zw')
        ).distinct()
        return qs
    
    @action(detail=False, methods=['get'])
    def statistics(self, request):
        """Get indicator statistics."""
        total = ThreatIndicator.objects.filter(is_active=True).count()
        by_type = ThreatIndicator.objects.filter(is_active=True).values(
            'indicator_type'
        ).annotate(count=Count('id'))
        by_severity = ThreatIndicator.objects.filter(is_active=True).values(
            'severity'
        ).annotate(count=Count('id'))
        
        return Response({
            'total': total,
            'by_type': list(by_type),
            'by_severity': list(by_severity),
        })
    
    @action(detail=False, methods=['post'])
    def bulk_create(self, request):
        """Bulk create indicators."""
        indicators_data = request.data.get('indicators', [])
        created = []
        errors = []
        
        for ind_data in indicators_data:
            serializer = self.get_serializer(data=ind_data)
            if serializer.is_valid():
                serializer.save()
                created.append(serializer.data)
            else:
                errors.append(serializer.errors)
        
        return Response({
            'created': len(created),
            'errors': len(errors),
            'indicators': created
        }, status=status.HTTP_201_CREATED if created else status.HTTP_400_BAD_REQUEST)
    
    @action(detail=True, methods=['patch'])
    def update_severity(self, request, pk=None):
        """Update indicator severity."""
        indicator = self.get_object()
        new_severity = request.data.get('severity')
        
        if new_severity in dict(ThreatIndicator.SEVERITY_CHOICES):
            indicator.severity = new_severity
            indicator.save()
            return Response(self.get_serializer(indicator).data)
        
        return Response({'error': 'Invalid severity'}, status=status.HTTP_400_BAD_REQUEST)


class ThreatCampaignViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing threat campaigns.
    """
    queryset = ThreatCampaign.objects.all()
    serializer_class = ThreatCampaignSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['status', 'correlation_method']
    search_fields = ['name', 'description', 'threat_actor', 'tactics', 'techniques']
    ordering_fields = ['confidence_score', 'last_seen', 'created_at']
    ordering = ['-last_seen']
    
    @action(detail=True, methods=['get'])
    def indicators(self, request, pk=None):
        """Get all indicators for a campaign."""
        campaign = self.get_object()
        indicators = campaign.threatindicator_set.all()
        serializer = ThreatIndicatorSerializer(indicators, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['get'])
    def alerts(self, request, pk=None):
        """Get all alerts for a campaign."""
        campaign = self.get_object()
        alerts = Alert.objects.filter(campaign=campaign)
        serializer = AlertSerializer(alerts, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def merge(self, request, pk=None):
        """Merge this campaign into another."""
        if not request.user.is_staff:
            return Response({'error': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
        
        source_campaign = self.get_object()
        target_id = request.data.get('target_campaign_id')
        
        if not target_id:
            return Response({'error': 'Target campaign ID required'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            target_campaign = ThreatCampaign.objects.get(id=target_id)
        except ThreatCampaign.DoesNotExist:
            return Response({'error': 'Target campaign not found'}, status=status.HTTP_404_NOT_FOUND)
        
        # Move all indicators to target campaign
        source_campaign.indicators.update(campaign=target_campaign)
        source_campaign.alerts.update(campaign=target_campaign)
        
        # Delete source campaign
        source_campaign.delete()
        
        return Response({'success': True, 'merged_into': str(target_campaign.id)})
    
    @action(detail=True, methods=['get'])
    def timeline(self, request, pk=None):
        """Get campaign timeline data."""
        campaign = self.get_object()
        indicators = campaign.indicators.order_by('first_seen')
        
        timeline = []
        for ind in indicators:
            timeline.append({
                'date': ind.first_seen.isoformat(),
                'type': ind.indicator_type,
                'value': ind.indicator_value,
                'severity': ind.severity
            })
        
        return Response({'timeline': timeline})
    
    @action(detail=True, methods=['get'])
    def escalation_prediction(self, request, pk=None):
        """Get escalation prediction for this campaign."""
        campaign = self.get_object()
        prediction = PredictiveAnalyticsService.predict_threat_escalation(campaign)
        return Response(prediction)


class AlertViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing alerts.
    """
    queryset = Alert.objects.all()
    serializer_class = AlertSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['severity', 'status', 'assigned_to']
    search_fields = ['title', 'description', 'explanation']
    ordering_fields = ['severity', 'created_at', 'updated_at']
    ordering = ['-created_at']
    
    @action(detail=True, methods=['post'])
    def acknowledge(self, request, pk=None):
        """Acknowledge an alert."""
        alert = self.get_object()
        alert.status = 'Acknowledged'
        alert.acknowledged_at = timezone.now()
        alert.assigned_to = request.user
        alert.save()
        return Response(AlertSerializer(alert).data)
    
    @action(detail=True, methods=['post'])
    def resolve(self, request, pk=None):
        """Resolve an alert."""
        alert = self.get_object()
        alert.status = 'Resolved'
        alert.resolved_at = timezone.now()
        alert.save()
        return Response(AlertSerializer(alert).data)
    
    @action(detail=True, methods=['post'])
    def escalate(self, request, pk=None):
        """Escalate an alert to Critical."""
        if not request.user.is_staff:
            return Response({'error': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
        
        alert = self.get_object()
        alert.severity = 'Critical'
        alert.status = 'Investigating'
        alert.save()
        return Response(AlertSerializer(alert).data)
    
    @action(detail=False, methods=['get'])
    def statistics(self, request):
        """Get alert statistics."""
        total = Alert.objects.count()
        by_severity = Alert.objects.values('severity').annotate(count=Count('id'))
        by_status = Alert.objects.values('status').annotate(count=Count('id'))
        critical = Alert.objects.filter(severity='Critical', status='New').count()
        
        return Response({
            'total': total,
            'critical': critical,
            'by_severity': list(by_severity),
            'by_status': list(by_status),
        })
    
    @action(detail=False, methods=['post'])
    def bulk_acknowledge(self, request):
        """Bulk acknowledge alerts."""
        if not request.user.is_staff:
            return Response({'error': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
        
        alert_ids = request.data.get('alert_ids', [])
        if not alert_ids:
            return Response({'error': 'No alert IDs provided'}, status=status.HTTP_400_BAD_REQUEST)
        
        updated_count = Alert.objects.filter(
            id__in=alert_ids, 
            status='New'
        ).update(
            status='Acknowledged',
            acknowledged_at=timezone.now(),
            assigned_to=request.user
        )
        
        return Response({'success': True, 'acknowledged_count': updated_count})
    
    # ============================================================
    # SIMULATED ALERT GENERATION - ADD THIS METHOD
    # ============================================================
    @action(detail=False, methods=['post'])
    def generate_simulated(self, request):
        """Generate a simulated alert for testing (no Celery needed)."""
        try:
            alert, indicator = RealTimeAlertSimulator.create_alert_and_indicator()
            return Response({
                'success': True,
                'alert_id': str(alert.id),
                'severity': alert.severity,
                'title': alert.title,
                'indicator': indicator.indicator_value,
                'indicator_type': indicator.indicator_type
            })
        except Exception as e:
            logger.error(f"Failed to generate simulated alert: {str(e)}")
            return Response({
                'success': False, 
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class CorrelationLogViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for viewing correlation logs (read-only).
    """
    queryset = CorrelationLog.objects.all()
    serializer_class = CorrelationLogSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['method', 'campaign']
    ordering_fields = ['created_at', 'correlation_score']
    ordering = ['-created_at']


class ThreatHuntingViewSet(viewsets.ViewSet):
    """
    ViewSet for advanced threat hunting queries.
    """
    permission_classes = [IsAuthenticated]
    
    @action(detail=False, methods=['post'])
    def search(self, request):
        """Execute a threat hunting query."""
        serializer = ThreatHuntingQuerySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        query = serializer.validated_data['query']
        filters_data = serializer.validated_data.get('filters', {})
        limit = serializer.validated_data.get('limit', 100)
        
        # Search indicators
        indicators = ThreatIndicator.objects.filter(
            Q(indicator_value__icontains=query) |
            Q(context__icontains=query) |
            Q(tags__icontains=query)
        )
        
        # Apply additional filters
        if 'severity' in filters_data:
            indicators = indicators.filter(severity=filters_data['severity'])
        if 'indicator_type' in filters_data:
            indicators = indicators.filter(indicator_type=filters_data['indicator_type'])
        
        indicators = indicators[:limit]
        
        serializer = ThreatIndicatorSerializer(indicators, many=True)
        return Response({
            'query': query,
            'results_count': len(indicators),
            'results': serializer.data
        })
    
    @action(detail=False, methods=['post'])
    def save_query(self, request):
        """Save a hunting query for later use."""
        # In production, save to database
        return Response({'success': True, 'message': 'Query saved'})


class ReportingViewSet(viewsets.ViewSet):
    """
    ViewSet for generating threat reports.
    """
    permission_classes = [IsAuthenticated]
    
    @action(detail=False, methods=['post'])
    def generate(self, request):
        """Generate a threat report."""
        serializer = ReportSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        report_type = serializer.validated_data['report_type']
        report_format = serializer.validated_data.get('format', 'pdf')
        
        # In production, this would call the actual reporting service
        from .reporting_service import ReportingService
        
        if report_type == 'daily':
            result = ReportingService.generate_daily_report(report_format)
        elif report_type == 'campaign':
            campaign_id = serializer.validated_data.get('campaign_id')
            if campaign_id:
                campaign = ThreatCampaign.objects.get(id=campaign_id)
                result = ReportingService.generate_campaign_report(campaign, report_format)
            else:
                return Response({'error': 'Campaign ID required'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'error': 'Unknown report type'}, status=status.HTTP_400_BAD_REQUEST)
        
        return Response(result)
    
    @action(detail=False, methods=['get'])
    def daily(self, request):
        """Get the latest daily report."""
        return Response({
            'report_type': 'daily',
            'generated_at': timezone.now(),
            'indicators_count': ThreatIndicator.objects.count(),
            'alerts_count': Alert.objects.count(),
            'campaigns_count': ThreatCampaign.objects.count(),
        })
    
    @action(detail=False, methods=['get'])
    def templates(self, request):
        """Get available report templates."""
        templates = [
            {'name': 'Daily Threat Report', 'type': 'daily', 'description': 'Summary of last 24 hours'},
            {'name': 'Weekly Threat Report', 'type': 'weekly', 'description': 'Summary of last 7 days'},
            {'name': 'Campaign Analysis', 'type': 'campaign', 'description': 'Detailed campaign report'},
            {'name': 'Threat Actor Profile', 'type': 'threat_actor', 'description': 'Threat actor intelligence'},
        ]
        return Response({'templates': templates})


# ============================================================
# NEW VIEWSETS - Added for enhanced API functionality
# ============================================================

class DashboardViewSet(viewsets.ViewSet):
    """
    ViewSet for dashboard statistics and metrics.
    """
    permission_classes = [IsAuthenticated]
    
    @action(detail=False, methods=['get'])
    def stats(self, request):
        """Get main dashboard statistics."""
        now = timezone.now()
        start_time = now - timedelta(hours=24)
        
        # Cache for 10 seconds to reduce DB load
        cache_key = 'api_dashboard_stats'
        cached_data = cache.get(cache_key)
        if cached_data:
            return Response(cached_data)
        
        stats = {
            'total_indicators': ThreatIndicator.objects.count(),
            'total_campaigns': ThreatCampaign.objects.filter(status__in=['Active', 'Monitoring']).count(),
            'active_alerts': Alert.objects.filter(status__in=['New', 'Acknowledged']).count(),
            'critical_alerts': Alert.objects.filter(severity='Critical', status='New').count(),
            'ingest_last_24h': ThreatIndicator.objects.filter(created_at__gte=start_time).count(),
            'alerts_last_24h': Alert.objects.filter(created_at__gte=start_time).count(),
            'live_status': 'LIVE',
        }
        
        cache.set(cache_key, stats, 10)
        return Response(stats)
    
    @action(detail=False, methods=['get'])
    def alerts_by_severity(self, request):
        """Get alerts grouped by severity."""
        data = Alert.objects.values('severity').annotate(count=Count('id'))
        return Response(data)
    
    @action(detail=False, methods=['get'])
    def indicators_by_type(self, request):
        """Get indicators grouped by type."""
        data = ThreatIndicator.objects.values('indicator_type').annotate(count=Count('id')).order_by('-count')[:10]
        return Response(data)
    
    @action(detail=False, methods=['get'])
    def activity_timeline(self, request):
        """Get activity timeline for charts."""
        now = timezone.now()
        hours = []
        counts = []
        
        for i in range(23, -1, -1):
            hour_start = now - timedelta(hours=i)
            hour_end = hour_start + timedelta(hours=1)
            hours.append(hour_start.strftime('%H:%M'))
            counts.append(Alert.objects.filter(created_at__gte=hour_start, created_at__lt=hour_end).count())
        
        return Response({'labels': hours, 'data': counts})


class SystemHealthViewSet(viewsets.ViewSet):
    """
    ViewSet for system health monitoring.
    """
    permission_classes = [IsAuthenticated]
    
    @action(detail=False, methods=['get'])
    def health_check(self, request):
        """Comprehensive system health check."""
        from django.db import connection
        
        # Check database
        db_status = 'healthy'
        try:
            connection.ensure_connection()
        except Exception as e:
            db_status = f'unhealthy: {str(e)}'
        
        # Check cache
        cache_status = 'healthy'
        try:
            cache.set('health_check', 'ok', 1)
            if cache.get('health_check') != 'ok':
                cache_status = 'unhealthy'
        except Exception as e:
            cache_status = f'unhealthy: {str(e)}'
        
        return Response({
            'status': 'healthy' if db_status == 'healthy' and cache_status == 'healthy' else 'degraded',
            'database': db_status,
            'cache': cache_status,
            'timestamp': timezone.now().isoformat(),
            'version': '2.0.0'
        })
    
    @action(detail=False, methods=['get'])
    def metrics(self, request):
        """Get system metrics."""
        return Response({
            'total_users': User.objects.count(),
            'total_indicators': ThreatIndicator.objects.count(),
            'total_campaigns': ThreatCampaign.objects.count(),
            'total_alerts': Alert.objects.count(),
            'uncorrelated_indicators': ThreatIndicator.objects.filter(campaign__isnull=True).count(),
        })
    
    @action(detail=False, methods=['post'])
    def retrain_models(self, request):
        """Retrain ML models."""
        if not request.user.is_staff:
            return Response({'error': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
        
        # Clear cache
        cache.clear()
        
        # Trigger model retraining (in production, use Celery)
        return Response({'success': True, 'message': 'Model retraining initiated'})


class ThreatIntelExchangeViewSet(viewsets.ViewSet):
    """
    ViewSet for threat intelligence exchange (MISP/OpenCTI compatible).
    """
    permission_classes = [IsAuthenticated]
    
    @action(detail=False, methods=['post'])
    def import_indicators(self, request):
        """Import indicators from external source."""
        source = request.data.get('source')
        indicators_data = request.data.get('indicators', [])
        
        imported_count = 0
        for ind_data in indicators_data:
            serializer = ThreatIndicatorSerializer(data=ind_data)
            if serializer.is_valid():
                serializer.save()
                imported_count += 1
        
        return Response({'imported': imported_count, 'source': source})
    
    @action(detail=False, methods=['get'])
    def export_stix(self, request):
        """Export indicators in STIX format."""
        # In production, generate STIX 2.1 bundle
        return Response({'message': 'STIX export endpoint', 'format': 'STIX 2.1'})


class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for viewing audit logs (admin only).
    """
    permission_classes = [IsAuthenticated, IsAdminUser]
    
    # In production, replace with actual AuditLog model
    queryset = CorrelationLog.objects.all()
    serializer_class = CorrelationLogSerializer
    
    @action(detail=False, methods=['get'])
    def user_activity(self, request):
        """Get user activity logs."""
        # In production, query ActivityLog model
        return Response({'activities': []})


class APITokenViewSet(viewsets.ViewSet):
    """
    ViewSet for managing API tokens.
    """
    permission_classes = [IsAuthenticated]
    
    @action(detail=False, methods=['get'])
    def list_tokens(self, request):
        """List user's API tokens."""
        tokens = Token.objects.filter(user=request.user)
        data = [{'key': token.key, 'created': token.created.isoformat()} for token in tokens]
        return Response({'tokens': data})
    
    @action(detail=False, methods=['post'])
    def create_token(self, request):
        """Create a new API token."""
        # Delete old token if exists
        Token.objects.filter(user=request.user).delete()
        
        # Create new token
        token = Token.objects.create(user=request.user)
        
        return Response({
            'success': True,
            'token': token.key,
            'message': 'Token created successfully. Keep it secure!'
        })
    
    @action(detail=True, methods=['delete'])
    def revoke_token(self, request, pk=None):
        """Revoke an API token."""
        try:
            token = Token.objects.get(user=request.user, pk=pk)
            token.delete()
            return Response({'success': True, 'message': 'Token revoked'})
        except Token.DoesNotExist:
            return Response({'error': 'Token not found'}, status=status.HTTP_404_NOT_FOUND)