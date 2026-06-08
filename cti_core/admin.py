"""Django admin configuration for CTI models."""

from django.contrib import admin
from .models import ThreatFeed, ThreatIndicator, ThreatCampaign, Alert, CorrelationLog


@admin.register(ThreatFeed)
class ThreatFeedAdmin(admin.ModelAdmin):
    list_display = ('name', 'feed_type', 'is_active', 'last_ingested', 'updated_at')
    list_filter = ('is_active', 'feed_type', 'created_at')
    search_fields = ('name', 'description')
    readonly_fields = ('id', 'created_at', 'updated_at')


@admin.register(ThreatIndicator)
class ThreatIndicatorAdmin(admin.ModelAdmin):
    list_display = ('indicator_type', 'indicator_value', 'severity', 'confidence', 'campaign', 'last_seen')
    list_filter = ('indicator_type', 'severity', 'confidence', 'is_active', 'last_seen')
    search_fields = ('indicator_value', 'context', 'tags')
    readonly_fields = ('id', 'created_at', 'updated_at', 'first_seen')


@admin.register(ThreatCampaign)
class ThreatCampaignAdmin(admin.ModelAdmin):
    list_display = ('name', 'status', 'threat_actor', 'confidence_score', 'correlation_method', 'last_seen')
    list_filter = ('status', 'correlation_method', 'last_seen')
    search_fields = ('name', 'description', 'threat_actor', 'tactics', 'techniques')
    readonly_fields = ('id', 'created_at', 'updated_at', 'first_seen')


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ('title', 'severity', 'status', 'indicator', 'campaign', 'created_at')
    list_filter = ('severity', 'status', 'created_at')
    search_fields = ('title', 'description', 'explanation')
    readonly_fields = ('id', 'created_at', 'updated_at', 'acknowledged_at', 'resolved_at')


@admin.register(CorrelationLog)
class CorrelationLogAdmin(admin.ModelAdmin):
    list_display = ('campaign', 'indicators_count', 'correlation_score', 'method', 'created_at')
    list_filter = ('method', 'created_at')
    search_fields = ('campaign__name',)
    readonly_fields = ('id', 'created_at')
