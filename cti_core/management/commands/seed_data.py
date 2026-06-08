"""
Management command to seed sample threat intelligence data for demonstration.
"""

from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from django.utils import timezone
from cti_core.models import ThreatFeed, ThreatIndicator, ThreatCampaign, Alert
from cti_core.services import AlertService
import random


class Command(BaseCommand):
    help = 'Seed sample threat intelligence data'

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('Starting data seeding...'))
        
        # Create admin user if not exists
        if not User.objects.filter(username='admin').exists():
            User.objects.create_superuser('admin', 'admin@example.com', 'admin123')
            self.stdout.write(self.style.SUCCESS('✓ Created admin user'))
        
        # Create threat feeds
        feeds = [
            ThreatFeed.objects.get_or_create(
                name='AlienVault OTX',
                defaults={
                    'description': 'AlienVault Open Threat Exchange',
                    'source_url': 'https://otx.alienvault.com',
                    'feed_type': 'JSON',
                    'is_active': True
                }
            ),
            ThreatFeed.objects.get_or_create(
                name='MISP Feed',
                defaults={
                    'description': 'Malware Information Sharing Platform',
                    'source_url': 'https://misp.example.com',
                    'feed_type': 'STIX/TAXII',
                    'is_active': True
                }
            ),
            ThreatFeed.objects.get_or_create(
                name='Custom Internal Feed',
                defaults={
                    'description': 'Internal threat intelligence feed',
                    'source_url': 'https://internal.example.com/feed',
                    'feed_type': 'JSON',
                    'is_active': True
                }
            ),
        ]
        self.stdout.write(self.style.SUCCESS('✓ Created threat feeds'))
        
        # Sample indicators data
        indicators_data = [
            # Banking Sector Campaign
            {
                'indicator_type': 'IPv4',
                'indicator_value': '192.168.1.100',
                'severity': 'Critical',
                'confidence': 0.95,
                'context': 'C2 server for banking trojan',
                'tags': 'malware:emotet, sector:banking, tactic:command-and-control',
                'feed': feeds[0][0]
            },
            {
                'indicator_type': 'Domain',
                'indicator_value': 'malicious-bank.com',
                'severity': 'Critical',
                'confidence': 0.92,
                'context': 'Phishing domain targeting bank customers',
                'tags': 'malware:emotet, sector:banking, tactic:initial-access',
                'feed': feeds[0][0]
            },
            {
                'indicator_type': 'FileHash-SHA256',
                'indicator_value': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                'severity': 'High',
                'confidence': 0.88,
                'context': 'Banking trojan executable',
                'tags': 'malware:emotet, sector:banking',
                'feed': feeds[1][0]
            },
            
            # Telecommunications Campaign
            {
                'indicator_type': 'IPv4',
                'indicator_value': '10.0.0.50',
                'severity': 'High',
                'confidence': 0.85,
                'context': 'Botnet node targeting telecom infrastructure',
                'tags': 'malware:mirai, sector:telecommunications, tactic:exploitation',
                'feed': feeds[0][0]
            },
            {
                'indicator_type': 'Domain',
                'indicator_value': 'telecom-exploit.net',
                'severity': 'High',
                'confidence': 0.82,
                'context': 'Exploit kit distribution server',
                'tags': 'malware:mirai, sector:telecommunications',
                'feed': feeds[1][0]
            },
            
            # Government Sector Campaign
            {
                'indicator_type': 'IPv4',
                'indicator_value': '203.0.113.25',
                'severity': 'Critical',
                'confidence': 0.93,
                'context': 'APT command and control server',
                'tags': 'actor:APT28, sector:government, tactic:command-and-control',
                'feed': feeds[2][0]
            },
            {
                'indicator_type': 'URL',
                'indicator_value': 'http://suspicious-gov-site.com/payload.exe',
                'severity': 'Critical',
                'confidence': 0.91,
                'context': 'Malware delivery URL',
                'tags': 'actor:APT28, sector:government',
                'feed': feeds[2][0]
            },
            
            # Additional indicators
            {
                'indicator_type': 'Email',
                'indicator_value': 'attacker@phishing-domain.com',
                'severity': 'Medium',
                'confidence': 0.75,
                'context': 'Phishing campaign sender',
                'tags': 'tactic:initial-access',
                'feed': feeds[0][0]
            },
            {
                'indicator_type': 'Malware',
                'indicator_value': 'Emotet',
                'severity': 'Critical',
                'confidence': 0.96,
                'context': 'Banking trojan malware family',
                'tags': 'malware:emotet, sector:banking',
                'feed': feeds[1][0]
            },
        ]
        
        # Create indicators
        created_indicators = []
        for ind_data in indicators_data:
            feed = ind_data.pop('feed')
            indicator, created = ThreatIndicator.objects.get_or_create(
                indicator_type=ind_data['indicator_type'],
                indicator_value=ind_data['indicator_value'],
                defaults={**ind_data, 'source': feed}
            )
            if created:
                created_indicators.append(indicator)
        
        self.stdout.write(self.style.SUCCESS(f'✓ Created {len(created_indicators)} indicators'))
        
        # Create campaigns
        campaigns_data = [
            {
                'name': 'Campaign-Critical-IPv4+Domain-0',
                'description': 'Banking sector targeting campaign using Emotet malware',
                'status': 'Active',
                'threat_actor': 'Emotet Gang',
                'tactics': 'Initial Access, Command and Control, Exfiltration',
                'techniques': 'Phishing, C2 Communication',
                'target_sectors': 'Banking, Financial Services',
                'target_countries': 'Zimbabwe, South Africa, Kenya',
                'confidence_score': 0.92,
                'correlation_method': 'DBSCAN'
            },
            {
                'name': 'Campaign-High-IPv4+Domain-1',
                'description': 'Telecommunications infrastructure attack campaign',
                'status': 'Active',
                'threat_actor': 'Mirai Botnet Operators',
                'tactics': 'Exploitation, Command and Control',
                'techniques': 'Botnet, DDoS',
                'target_sectors': 'Telecommunications',
                'target_countries': 'Zimbabwe, Regional',
                'confidence_score': 0.84,
                'correlation_method': 'DBSCAN'
            },
            {
                'name': 'Campaign-Critical-IPv4+URL-2',
                'description': 'Advanced persistent threat targeting government infrastructure',
                'status': 'Monitoring',
                'threat_actor': 'APT28',
                'tactics': 'Initial Access, Persistence, Command and Control',
                'techniques': 'Spear Phishing, Malware, C2',
                'target_sectors': 'Government, Defense',
                'target_countries': 'Zimbabwe',
                'confidence_score': 0.92,
                'correlation_method': 'DBSCAN'
            },
        ]
        
        created_campaigns = []
        for camp_data in campaigns_data:
            campaign, created = ThreatCampaign.objects.get_or_create(
                name=camp_data['name'],
                defaults=camp_data
            )
            if created:
                created_campaigns.append(campaign)
        
        self.stdout.write(self.style.SUCCESS(f'✓ Created {len(created_campaigns)} campaigns'))
        
        # Link indicators to campaigns
        if created_campaigns:
            # Link banking indicators to first campaign
            ThreatIndicator.objects.filter(
                indicator_value__in=['192.168.1.100', 'malicious-bank.com', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']
            ).update(campaign=created_campaigns[0])
            
            # Link telecom indicators to second campaign
            ThreatIndicator.objects.filter(
                indicator_value__in=['10.0.0.50', 'telecom-exploit.net']
            ).update(campaign=created_campaigns[1])
            
            # Link government indicators to third campaign
            ThreatIndicator.objects.filter(
                indicator_value__in=['203.0.113.25', 'http://suspicious-gov-site.com/payload.exe']
            ).update(campaign=created_campaigns[2])
        
        self.stdout.write(self.style.SUCCESS('✓ Linked indicators to campaigns'))
        
        # Generate alerts for high-confidence indicators
        high_confidence_indicators = ThreatIndicator.objects.filter(confidence__gte=0.85)
        alerts_created = 0
        for indicator in high_confidence_indicators:
            alert = AlertService.generate_alert_for_indicator(indicator)
            if alert:
                alerts_created += 1
        
        self.stdout.write(self.style.SUCCESS(f'✓ Generated {alerts_created} alerts'))
        
        self.stdout.write(self.style.SUCCESS('\n✅ Data seeding completed successfully!'))
        self.stdout.write(self.style.WARNING('\nDemo Credentials:'))
        self.stdout.write(self.style.WARNING('Username: admin'))
        self.stdout.write(self.style.WARNING('Password: admin123'))
