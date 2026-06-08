"""
Custom Django management command to populate analyst dashboard with realistic data.
Run: python manage.py populate_analyst_data
"""

import random
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from django.utils import timezone
from django.db.models import Count

from cti_core.models import ThreatIndicator, ThreatCampaign, Alert, ThreatFeed


class Command(BaseCommand):
    help = 'Populates analyst dashboard with realistic sample data'

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('🚀 Starting data population...'))
        
        # ============================================================
        # 1. Create or update analyst users
        # ============================================================
        analysts = [
            {'username': 'analyst_john', 'email': 'john@zimcert.gov.zw', 'first_name': 'John', 'last_name': 'Moyo'},
            {'username': 'analyst_sarah', 'email': 'sarah@zimcert.gov.zw', 'first_name': 'Sarah', 'last_name': 'Ncube'},
            {'username': 'analyst_mike', 'email': 'mike@zimcert.gov.zw', 'first_name': 'Mike', 'last_name': 'Chikwanha'},
            {'username': 'analyst_linda', 'email': 'linda@zimcert.gov.zw', 'first_name': 'Linda', 'last_name': 'Dube'},
        ]
        
        created_users = []
        for analyst_data in analysts:
            user, created = User.objects.get_or_create(
                username=analyst_data['username'],
                defaults={
                    'email': analyst_data['email'],
                    'first_name': analyst_data['first_name'],
                    'last_name': analyst_data['last_name'],
                    'is_staff': False,
                    'is_active': True
                }
            )
            if created:
                user.set_password('analyst123')
                user.save()
                self.stdout.write(f"  ✅ Created analyst: {user.username}")
            else:
                self.stdout.write(f"  ⏭️ Analyst already exists: {user.username}")
            created_users.append(user)
        
        # ============================================================
        # 2. Create threat feeds if not exist
        # ============================================================
        feeds = [
            {'name': 'External Intelligence', 'source_url': 'https://api.threatintel.com/v1', 'feed_type': 'API', 'is_active': True},
            {'name': 'CISA KEV', 'source_url': 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', 'feed_type': 'API', 'is_active': True},
            {'name': 'Feodo Tracker', 'source_url': 'https://feodotracker.abuse.ch/downloads/ipblocklist.json', 'feed_type': 'API', 'is_active': True},
        ]
        
        feed_objects = []
        for feed_data in feeds:
            feed, created = ThreatFeed.objects.get_or_create(
                name=feed_data['name'],
                defaults=feed_data
            )
            feed_objects.append(feed)
            if created:
                self.stdout.write(f"  ✅ Created feed: {feed.name}")
        
        # ============================================================
        # 3. Create threat indicators with geolocation
        # ============================================================
        self.stdout.write("  📊 Creating threat indicators...")
        
        # Sample malicious IPs with geolocation
        sample_indicators = [
            {'value': '45.227.254.8', 'type': 'IPv4', 'severity': 'Critical', 'conf': 0.95, 'lat': 40.7128, 'lng': -74.0060, 'country': 'USA', 'city': 'New York'},
            {'value': '185.142.53.35', 'type': 'IPv4', 'severity': 'Critical', 'conf': 0.92, 'lat': 51.5074, 'lng': -0.1278, 'country': 'UK', 'city': 'London'},
            {'value': '103.124.12.45', 'type': 'IPv4', 'severity': 'High', 'conf': 0.88, 'lat': 35.6762, 'lng': 139.6503, 'country': 'Japan', 'city': 'Tokyo'},
            {'value': '185.225.72.45', 'type': 'IPv4', 'severity': 'Critical', 'conf': 0.96, 'lat': 55.7558, 'lng': 37.6173, 'country': 'Russia', 'city': 'Moscow'},
            {'value': 'malware-c2.net', 'type': 'Domain', 'severity': 'High', 'conf': 0.85, 'lat': 48.8566, 'lng': 2.3522, 'country': 'France', 'city': 'Paris'},
            {'value': '45.238.181.99', 'type': 'IPv4', 'severity': 'High', 'conf': 0.82, 'lat': -23.5505, 'lng': -46.6333, 'country': 'Brazil', 'city': 'Sao Paulo'},
            {'value': '196.52.43.12', 'type': 'IPv4', 'severity': 'High', 'conf': 0.87, 'lat': -26.2041, 'lng': 28.0473, 'country': 'South Africa', 'city': 'Johannesburg'},
            {'value': '104.244.42.1', 'type': 'IPv4', 'severity': 'Medium', 'conf': 0.75, 'lat': 34.0522, 'lng': -118.2437, 'country': 'USA', 'city': 'Los Angeles'},
            {'value': '95.214.27.166', 'type': 'IPv4', 'severity': 'Medium', 'conf': 0.72, 'lat': 52.5200, 'lng': 13.4050, 'country': 'Germany', 'city': 'Berlin'},
            {'value': '45.155.205.233', 'type': 'IPv4', 'severity': 'Critical', 'conf': 0.94, 'lat': 31.2304, 'lng': 121.4737, 'country': 'China', 'city': 'Shanghai'},
        ]
        
        indicator_ids = []
        for ind in sample_indicators:
            indicator, created = ThreatIndicator.objects.get_or_create(
                indicator_value=ind['value'],
                defaults={
                    'indicator_type': ind['type'],
                    'source': random.choice(feed_objects),
                    'confidence': ind['conf'],
                    'severity': ind['severity'],
                    'context': f"Geo: lat={ind['lat']}, lng={ind['lng']} - {ind['city']}, {ind['country']}\nDetected by ML correlation engine.",
                    'tags': f"geo,{ind['country'].lower()},malicious",
                    'is_active': True
                }
            )
            indicator_ids.append(indicator)
            if created:
                self.stdout.write(f"    ✅ Created indicator: {ind['value']}")
        
        self.stdout.write(f"  ✅ Created {len(indicator_ids)} threat indicators")
        
        # ============================================================
        # 4. Create threat campaigns from indicators
        # ============================================================
        self.stdout.write("  🎯 Creating threat campaigns...")
        
        campaigns = [
            {'name': 'APT28 - Election Interference', 'actor': 'APT28 (Fancy Bear)', 'status': 'Active', 'sectors': 'Government,Political', 'countries': 'USA,Germany,France'},
            {'name': 'Lazarus - Financial Theft', 'actor': 'Lazarus Group', 'status': 'Active', 'sectors': 'Finance,Cryptocurrency', 'countries': 'Global'},
            {'name': 'TA505 - Ransomware Campaign', 'actor': 'TA505', 'status': 'Monitoring', 'sectors': 'Healthcare,Education', 'countries': 'USA,UK,Canada'},
            {'name': 'Sandworm - Critical Infrastructure', 'actor': 'Sandworm', 'status': 'Active', 'sectors': 'Energy,Utilities', 'countries': 'Ukraine,USA'},
            {'name': 'Cozy Bear - Diplomatic Phishing', 'actor': 'APT29 (Cozy Bear)', 'status': 'Monitoring', 'sectors': 'Diplomatic,Defense', 'countries': 'Europe,USA'},
        ]
        
        campaign_objects = []
        for camp_data in campaigns:
            campaign, created = ThreatCampaign.objects.get_or_create(
                name=camp_data['name'],
                defaults={
                    'description': f"AI-correlated threat campaign involving {camp_data['actor']} targeting {camp_data['sectors']}.",
                    'status': camp_data['status'],
                    'threat_actor': camp_data['actor'],
                    'target_sectors': camp_data['sectors'],
                    'target_countries': camp_data['countries'],
                    'confidence_score': random.uniform(0.75, 0.95),
                    'correlation_method': 'AI_DBSCAN_v2'
                }
            )
            campaign_objects.append(campaign)
            if created:
                self.stdout.write(f"    ✅ Created campaign: {camp_data['name']}")
        
        # Associate indicators with campaigns
        for i, indicator in enumerate(indicator_ids[:8]):
            indicator.campaign = campaign_objects[i % len(campaign_objects)]
            indicator.save()
        
        self.stdout.write(f"  ✅ Created {len(campaign_objects)} threat campaigns")
        
        # ============================================================
        # 5. Create alerts for each analyst (spanning last 30 days)
        # ============================================================
        self.stdout.write("  🚨 Creating alert history...")
        
        severity_choices = ['Critical', 'High', 'Medium', 'Low']
        severity_weights = [0.15, 0.25, 0.35, 0.25]
        
        status_history = ['New', 'Acknowledged', 'Investigating', 'Resolved', 'Resolved', 'Resolved', 'False Positive']
        
        alert_count = 0
        
        for analyst in created_users:
            # Generate 20-40 alerts per analyst over last 30 days
            num_alerts = random.randint(20, 40)
            
            for i in range(num_alerts):
                # Random date in last 30 days
                days_ago = random.randint(0, 30)
                hours_ago = random.randint(0, 23)
                created_date = timezone.now() - timedelta(days=days_ago, hours=hours_ago)
                
                # Status based on age (older alerts more likely to be resolved)
                if days_ago <= 3:
                    status_options = ['New', 'Acknowledged', 'Investigating']
                elif days_ago <= 7:
                    status_options = ['Acknowledged', 'Investigating', 'Resolved']
                else:
                    status_options = ['Resolved', 'Resolved', 'Resolved', 'False Positive']
                
                status = random.choice(status_options)
                severity = random.choices(severity_choices, weights=severity_weights)[0]
                indicator = random.choice(indicator_ids)
                
                # Calculate resolution time if resolved
                resolved_at = None
                if status == 'Resolved':
                    resolved_at = created_date + timedelta(hours=random.randint(1, 48))
                elif status == 'False Positive':
                    resolved_at = created_date + timedelta(hours=random.randint(1, 12))
                
                # Acknowledged time
                acknowledged_at = None
                if status in ['Acknowledged', 'Investigating', 'Resolved']:
                    acknowledged_at = created_date + timedelta(minutes=random.randint(5, 120))
                
                alert, created = Alert.objects.get_or_create(
                    indicator=indicator,
                    assigned_to=analyst,
                    title=f"{severity} Threat: {indicator.indicator_value[:40]}",
                    defaults={
                        'description': f"ML-detected {severity} threat indicator from {indicator.source.name if indicator.source else 'External feed'}",
                        'severity': severity,
                        'status': status,
                        'campaign': indicator.campaign,
                        'explanation': f"Alert triggered by Isolation Forest anomaly detection. Indicator shows unusual pattern with {indicator.confidence:.0%} confidence.",
                        'recommended_actions': self._get_recommendations(indicator.indicator_type),
                        'created_at': created_date,
                        'acknowledged_at': acknowledged_at,
                        'resolved_at': resolved_at
                    }
                )
                
                if created:
                    alert_count += 1
        
        self.stdout.write(f"  ✅ Created {alert_count} alerts across {len(created_users)} analysts")
        
        # ============================================================
        # 6. Create correlation logs
        # ============================================================
        self.stdout.write("  📊 Creating correlation logs...")
        
        from cti_core.models import CorrelationLog
        
        for campaign in campaign_objects:
            CorrelationLog.objects.get_or_create(
                campaign=campaign,
                defaults={
                    'indicators_count': campaign.indicators.count(),
                    'correlation_score': campaign.confidence_score,
                    'method': 'AI_DBSCAN_v2',
                    'parameters': {'eps': 0.5, 'min_samples': 2}
                }
            )
        
        self.stdout.write(self.style.SUCCESS(f"""
╔══════════════════════════════════════════════════════════════════╗
║                    DATA POPULATION COMPLETE                       ║
╠══════════════════════════════════════════════════════════════════╣
║  ✅ Created/Updated: {len(created_users)} analysts                         ║
║  ✅ Created: {len(indicator_ids)} threat indicators                        ║
║  ✅ Created: {len(campaign_objects)} threat campaigns                      ║
║  ✅ Created: {alert_count} alerts                                         ║
╠══════════════════════════════════════════════════════════════════╣
║  📝 Login credentials for analysts:                              ║
║     Username: analyst_john, analyst_sarah, analyst_mike, analyst_linda ║
║     Password: analyst123                                        ║
╠══════════════════════════════════════════════════════════════════╣
║  🌐 Access the platform at: http://127.0.0.1:8000/cti/         ║
║  📊 Visit Analyst Dashboard: /cti/analyst/                      ║
╚══════════════════════════════════════════════════════════════════╝
        """))
    
    def _get_recommendations(self, indicator_type):
        recommendations = {
            'IPv4': "1. Block IP at firewall\n2. Search SIEM for connections\n3. Check for lateral movement\n4. Add to blocklist",
            'Domain': "1. Sinkhole domain\n2. Block DNS resolution\n3. Review DNS logs\n4. Add to proxy blocklist",
            'URL': "1. Block URL at web proxy\n2. Scan for infections\n3. Check access logs",
            'FileHash': "1. Quarantine matching files\n2. Run YARA scans\n3. Hunt in EDR",
        }
        return recommendations.get(indicator_type, "1. Investigate immediately\n2. Contain affected systems\n3. Update threat intel")