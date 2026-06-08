"""
Django REST Framework serializers for CTI models.
"""

from rest_framework import serializers
from django.contrib.auth.models import User
from .models import ThreatFeed, ThreatIndicator, ThreatCampaign, Alert, CorrelationLog


class UserSerializer(serializers.ModelSerializer):
    """Serializer for User model."""
    
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'is_staff', 'is_active']
        read_only_fields = ['id']


class ThreatFeedSerializer(serializers.ModelSerializer):
    """Serializer for ThreatFeed model."""
    
    class Meta:
        model = ThreatFeed
        fields = [
            'id', 'name', 'description', 'source_url', 'feed_type',
            'is_active', 'last_ingested', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class ThreatIndicatorSerializer(serializers.ModelSerializer):
    """Serializer for ThreatIndicator model."""
    
    source_name = serializers.CharField(source='source.name', read_only=True)
    campaign_name = serializers.CharField(source='campaign.name', read_only=True)
    
    class Meta:
        model = ThreatIndicator
        fields = [
            'id', 'indicator_type', 'indicator_value', 'source', 'source_name',
            'confidence', 'severity', 'campaign', 'campaign_name', 'context',
            'tags', 'is_active', 'first_seen', 'last_seen', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'first_seen']


class ThreatCampaignSerializer(serializers.ModelSerializer):
    """Serializer for ThreatCampaign model."""
    
    indicator_count = serializers.SerializerMethodField()
    
    class Meta:
        model = ThreatCampaign
        fields = [
            'id', 'name', 'description', 'status', 'threat_actor',
            'tactics', 'techniques', 'target_sectors', 'target_countries',
            'confidence_score', 'correlation_method', 'indicator_count',
            'first_seen', 'last_seen', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'first_seen']
    
    def get_indicator_count(self, obj):
        """Get count of indicators in this campaign."""
        return obj.threatindicator_set.count()


class AlertSerializer(serializers.ModelSerializer):
    """Serializer for Alert model."""
    
    indicator_value = serializers.CharField(source='indicator.indicator_value', read_only=True)
    campaign_name = serializers.CharField(source='campaign.name', read_only=True)
    assigned_to_username = serializers.CharField(source='assigned_to.username', read_only=True)
    
    class Meta:
        model = Alert
        fields = [
            'id', 'indicator', 'indicator_value', 'campaign', 'campaign_name',
            'title', 'description', 'severity', 'status', 'assigned_to',
            'assigned_to_username', 'explanation', 'recommended_actions',
            'created_at', 'updated_at', 'acknowledged_at', 'resolved_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'explanation', 'recommended_actions']


class CorrelationLogSerializer(serializers.ModelSerializer):
    """Serializer for CorrelationLog model."""
    
    campaign_name = serializers.CharField(source='campaign.name', read_only=True)
    
    class Meta:
        model = CorrelationLog
        fields = [
            'id', 'campaign', 'campaign_name', 'indicators_count',
            'correlation_score', 'method', 'parameters', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']


class ThreatStatisticsSerializer(serializers.Serializer):
    """Serializer for threat statistics."""
    
    total_indicators = serializers.IntegerField()
    total_campaigns = serializers.IntegerField()
    active_alerts = serializers.IntegerField()
    critical_alerts = serializers.IntegerField()
    indicators_by_type = serializers.ListField()
    alerts_by_severity = serializers.ListField()
    campaigns_by_status = serializers.ListField()


class ThreatHuntingQuerySerializer(serializers.Serializer):
    """Serializer for threat hunting queries."""
    
    query = serializers.CharField(max_length=500)
    filters = serializers.JSONField(required=False)
    limit = serializers.IntegerField(default=100, min_value=1, max_value=1000)


class ReportSerializer(serializers.Serializer):
    """Serializer for threat reports."""
    
    report_type = serializers.ChoiceField(
        choices=['daily', 'weekly', 'campaign', 'threat_actor']
    )
    start_date = serializers.DateTimeField(required=False)
    end_date = serializers.DateTimeField(required=False)
    format = serializers.ChoiceField(
        choices=['pdf', 'json', 'html'],
        default='pdf'
    )
