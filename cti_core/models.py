"""Core models for the Cyber Threat Intelligence module.
Includes ThreatIndicator, ThreatCampaign, ThreatFeed, and Alert models.
"""

from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User
import uuid


# Add to your existing models.py

class UserProfile(models.Model):
    """Extended user profile with roles"""
    
    ROLE_CHOICES = [
        ('super_admin', 'Super Administrator'),
        ('admin', 'Administrator'),
        ('analyst_lead', 'Lead Security Analyst'),
        ('analyst', 'Security Analyst'),
        ('viewer', 'Viewer'),
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='analyst')
    department = models.CharField(max_length=100, blank=True, null=True)
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    notifications_enabled = models.BooleanField(default=True)
    last_activity = models.DateTimeField(auto_now=True)
    
    def has_permission(self, permission):
        """Check if user has specific permission based on role"""
        permissions = {
            'super_admin': ['view_all', 'create_users', 'edit_users', 'delete_users', 
                           'manage_feeds', 'view_reports', 'create_reports', 
                           'acknowledge_alerts', 'resolve_alerts', 'run_correlation',
                           'view_anomalies', 'edit_settings'],
            'admin': ['view_all', 'create_users', 'edit_users', 'manage_feeds',
                     'view_reports', 'create_reports', 'acknowledge_alerts',
                     'resolve_alerts', 'run_correlation', 'view_anomalies'],
            'analyst_lead': ['view_all', 'view_reports', 'create_reports',
                            'acknowledge_alerts', 'resolve_alerts', 'run_correlation',
                            'view_anomalies'],
            'analyst': ['view_indicators', 'view_campaigns', 'acknowledge_alerts',
                       'view_reports', 'threat_hunting'],
            'viewer': ['view_dashboard', 'view_alerts'],
        }
        return permission in permissions.get(self.role, [])
    
    def __str__(self):
        return f"{self.user.username} - {self.get_role_display()}"



class ThreatFeed(models.Model):
    """
    Represents an external threat intelligence feed source.
    Examples: AlienVault OTX, MISP, custom feeds.
    """
    FEED_TYPE_CHOICES = [
        ('STIX/TAXII', 'STIX/TAXII'),
        ('JSON', 'JSON'),
        ('CSV', 'CSV'),
        ('RSS', 'RSS'),
        ('API', 'API'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True, null=True)
    source_url = models.URLField()
    api_key = models.CharField(max_length=500, blank=True, null=True)
    feed_type = models.CharField(max_length=20, choices=FEED_TYPE_CHOICES, default='JSON')
    is_active = models.BooleanField(default=True)
    last_ingested = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-updated_at']
        verbose_name = 'Threat Feed'
        verbose_name_plural = 'Threat Feeds'

    def __str__(self):
        return self.name


class ThreatIndicator(models.Model):
    """
    Represents a single indicator of compromise (IOC).
    Examples: IP addresses, domains, file hashes, malware signatures.
    """
    INDICATOR_TYPE_CHOICES = [
        ('IPv4', 'IPv4 Address'),
        ('IPv6', 'IPv6 Address'),
        ('Domain', 'Domain'),
        ('URL', 'URL'),
        ('FileHash-MD5', 'MD5 Hash'),
        ('FileHash-SHA1', 'SHA1 Hash'),
        ('FileHash-SHA256', 'SHA256 Hash'),
        ('Email', 'Email Address'),
        ('YARA', 'YARA Rule'),
        ('Malware', 'Malware Family'),
        ('ASN', 'ASN'),
        ('CIDR', 'CIDR Block'),
    ]

    SEVERITY_CHOICES = [
        ('Critical', 'Critical'),
        ('High', 'High'),
        ('Medium', 'Medium'),
        ('Low', 'Low'),
        ('Info', 'Informational'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    indicator_type = models.CharField(max_length=20, choices=INDICATOR_TYPE_CHOICES)
    indicator_value = models.TextField()
    source = models.ForeignKey(ThreatFeed, on_delete=models.SET_NULL, null=True, blank=True)
    confidence = models.FloatField(default=0.5, help_text="Confidence score between 0 and 1")
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='Medium')
    campaign = models.ForeignKey('ThreatCampaign', on_delete=models.SET_NULL, null=True, blank=True, related_name='indicators')
    context = models.TextField(blank=True, null=True, help_text="Rich contextual information about this indicator")
    tags = models.CharField(max_length=500, blank=True, null=True, help_text="Comma-separated tags")
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-last_seen']
        verbose_name = 'Threat Indicator'
        verbose_name_plural = 'Threat Indicators'
        indexes = [
            models.Index(fields=['indicator_type', 'indicator_value']),
            models.Index(fields=['campaign']),
            models.Index(fields=['severity']),
            models.Index(fields=['-last_seen']),
        ]

    def __str__(self):
        return f"{self.indicator_type}: {self.indicator_value}"

    def get_tags_list(self):
        """Return tags as a list."""
        if self.tags:
            return [tag.strip() for tag in self.tags.split(',')]
        return []


class ThreatCampaign(models.Model):
    """
    Represents a correlated threat campaign.
    Multiple indicators are grouped into a single campaign through AI correlation.
    """
    CAMPAIGN_STATUS_CHOICES = [
        ('Active', 'Active'),
        ('Inactive', 'Inactive'),
        ('Resolved', 'Resolved'),
        ('Monitoring', 'Monitoring'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=20, choices=CAMPAIGN_STATUS_CHOICES, default='Active')
    threat_actor = models.CharField(max_length=255, blank=True, null=True)
    tactics = models.CharField(max_length=500, blank=True, null=True, help_text="MITRE ATT&CK tactics")
    techniques = models.CharField(max_length=500, blank=True, null=True, help_text="MITRE ATT&CK techniques")
    target_sectors = models.CharField(max_length=500, blank=True, null=True, help_text="Targeted sectors/industries")
    target_countries = models.CharField(max_length=500, blank=True, null=True, help_text="Target countries")
    confidence_score = models.FloatField(default=0.5, help_text="AI-generated confidence score")
    correlation_method = models.CharField(max_length=100, blank=True, null=True, help_text="Method used for correlation (e.g., DBSCAN)")
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-last_seen']
        verbose_name = 'Threat Campaign'
        verbose_name_plural = 'Threat Campaigns'
        indexes = [
            models.Index(fields=['status']),
            models.Index(fields=['-last_seen']),
        ]

    def __str__(self):
        return self.name

    def get_indicator_count(self):
        """Return the count of indicators in this campaign."""
        return self.indicators.count()

    def get_tactics_list(self):
        """Return tactics as a list."""
        if self.tactics:
            return [tactic.strip() for tactic in self.tactics.split(',')]
        return []


class Alert(models.Model):
    """
    Represents a real-time alert generated by the system.
    Alerts are triggered when new high-confidence indicators are detected.
    """
    ALERT_STATUS_CHOICES = [
        ('New', 'New'),
        ('Acknowledged', 'Acknowledged'),
        ('Investigating', 'Investigating'),
        ('Resolved', 'Resolved'),
        ('False Positive', 'False Positive'),
    ]

    ALERT_SEVERITY_CHOICES = [
        ('Critical', 'Critical'),
        ('High', 'High'),
        ('Medium', 'Medium'),
        ('Low', 'Low'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    indicator = models.ForeignKey(ThreatIndicator, on_delete=models.CASCADE, related_name='alerts')
    campaign = models.ForeignKey(ThreatCampaign, on_delete=models.SET_NULL, null=True, blank=True, related_name='alerts')
    title = models.CharField(max_length=255)
    description = models.TextField()
    severity = models.CharField(max_length=20, choices=ALERT_SEVERITY_CHOICES)
    status = models.CharField(max_length=20, choices=ALERT_STATUS_CHOICES, default='New')
    assigned_to = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    explanation = models.TextField(blank=True, null=True, help_text="AI-generated explanation of why this alert was triggered")
    recommended_actions = models.TextField(blank=True, null=True, help_text="Recommended response actions")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Alert'
        verbose_name_plural = 'Alerts'
        indexes = [
            models.Index(fields=['status']),
            models.Index(fields=['severity']),
            models.Index(fields=['-created_at']),
        ]

    def __str__(self):
        return self.title

    def acknowledge(self, user=None):
        """Mark alert as acknowledged."""
        self.status = 'Acknowledged'
        self.acknowledged_at = timezone.now()
        if user:
            self.assigned_to = user
        self.save()

    def resolve(self):
        """Mark alert as resolved."""
        self.status = 'Resolved'
        self.resolved_at = timezone.now()
        self.save()


class CorrelationLog(models.Model):
    """
    Logs correlation operations for audit and debugging purposes.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    campaign = models.ForeignKey(ThreatCampaign, on_delete=models.CASCADE, related_name='correlation_logs')
    indicators_count = models.IntegerField()
    correlation_score = models.FloatField()
    method = models.CharField(max_length=100)
    parameters = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Correlation Log'
        verbose_name_plural = 'Correlation Logs'

    def __str__(self):
        return f"Correlation: {self.campaign.name} ({self.indicators_count} indicators)"
