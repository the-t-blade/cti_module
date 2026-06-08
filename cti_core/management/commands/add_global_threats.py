"""
Management command to add global threat indicators with geolocation coordinates.
Run: python manage.py add_global_threats
"""

import random
from django.core.management.base import BaseCommand
from django.utils import timezone
from cti_core.models import ThreatIndicator, ThreatFeed


class Command(BaseCommand):
    help = 'Adds global threat indicators with geolocation coordinates'

    def add_arguments(self, parser):
        parser.add_argument(
            '--count',
            type=int,
            default=50,
            help='Number of threat indicators to add (default: 50)'
        )

    def handle(self, *args, **options):
        count = options['count']
        
        self.stdout.write(self.style.SUCCESS(f'🌍 Adding {count} global threat indicators...'))
        
        # Get or create a feed for global threats
        global_feed, created = ThreatFeed.objects.get_or_create(
            name="Global Threat Intelligence",
            defaults={
                'description': "Global threat indicators with geolocation coordinates",
                'source_url': "https://internal.cti.global",
                'feed_type': 'API',
                'is_active': True
            }
        )
        
        if created:
            self.stdout.write("  ✅ Created Global Threat Intelligence feed")
        
        # Global threats with coordinates from around the world
        # Format: (ip, type, lat, lng, country, city, severity, confidence)
        global_threats = [
            # North America
            ("45.227.254.8", "IPv4", 40.7128, -74.0060, "USA", "New York", "Critical", 0.95),
            ("185.142.53.35", "IPv4", 34.0522, -118.2437, "USA", "Los Angeles", "High", 0.88),
            ("104.244.42.1", "IPv4", 41.8781, -87.6298, "USA", "Chicago", "Medium", 0.72),
            ("198.51.100.1", "IPv4", 37.7749, -122.4194, "USA", "San Francisco", "High", 0.85),
            ("203.0.113.1", "IPv4", 39.9526, -75.1652, "USA", "Philadelphia", "Medium", 0.78),
            
            # Europe
            ("185.130.5.253", "IPv4", 51.5074, -0.1278, "UK", "London", "Critical", 0.92),
            ("91.121.89.155", "IPv4", 48.8566, 2.3522, "France", "Paris", "High", 0.86),
            ("95.214.27.166", "IPv4", 52.5200, 13.4050, "Germany", "Berlin", "Medium", 0.75),
            ("45.155.205.233", "IPv4", 50.1109, 8.6821, "Germany", "Frankfurt", "High", 0.82),
            ("185.225.72.45", "IPv4", 55.7558, 37.6173, "Russia", "Moscow", "Critical", 0.94),
            ("193.124.188.1", "IPv4", 59.9311, 30.3609, "Russia", "St Petersburg", "High", 0.87),
            ("87.121.45.1", "IPv4", 41.9028, 12.4964, "Italy", "Rome", "Medium", 0.71),
            ("89.34.56.1", "IPv4", 40.4168, -3.7038, "Spain", "Madrid", "Medium", 0.74),
            ("94.56.78.1", "IPv4", 52.3676, 4.9041, "Netherlands", "Amsterdam", "High", 0.83),
            ("185.142.53.1", "IPv4", 59.3293, 18.0686, "Sweden", "Stockholm", "Medium", 0.76),
            
            # Asia
            ("103.124.12.45", "IPv4", 35.6762, 139.6503, "Japan", "Tokyo", "High", 0.89),
            ("103.150.200.11", "IPv4", 28.6139, 77.2090, "India", "New Delhi", "Medium", 0.73),
            ("45.155.205.1", "IPv4", 31.2304, 121.4737, "China", "Shanghai", "Critical", 0.93),
            ("103.86.45.1", "IPv4", 39.9042, 116.4074, "China", "Beijing", "High", 0.86),
            ("113.21.56.1", "IPv4", 37.5665, 126.9780, "South Korea", "Seoul", "High", 0.84),
            ("115.78.34.1", "IPv4", -6.2088, 106.8456, "Indonesia", "Jakarta", "Medium", 0.72),
            ("124.56.78.1", "IPv4", 1.3521, 103.8198, "Singapore", "Singapore", "High", 0.81),
            ("175.45.67.1", "IPv4", 13.7367, 100.5231, "Thailand", "Bangkok", "Medium", 0.75),
            
            # South America
            ("45.238.181.99", "IPv4", -23.5505, -46.6333, "Brazil", "Sao Paulo", "High", 0.87),
            ("191.34.56.1", "IPv4", -34.6037, -58.3816, "Argentina", "Buenos Aires", "Medium", 0.74),
            ("190.45.67.1", "IPv4", -33.4489, -70.6693, "Chile", "Santiago", "Low", 0.68),
            ("181.56.78.1", "IPv4", 4.7110, -74.0721, "Colombia", "Bogota", "Medium", 0.73),
            
            # Africa
            ("196.52.43.12", "IPv4", -26.2041, 28.0473, "South Africa", "Johannesburg", "High", 0.86),
            ("154.126.126.11", "IPv4", -1.2864, 36.8172, "Kenya", "Nairobi", "Medium", 0.74),
            ("41.56.78.1", "IPv4", 30.0444, 31.2357, "Egypt", "Cairo", "High", 0.82),
            ("197.45.67.1", "IPv4", 5.6037, -0.1870, "Ghana", "Accra", "Medium", 0.71),
            ("213.34.56.1", "IPv4", 9.0320, 38.7469, "Ethiopia", "Addis Ababa", "Low", 0.65),
            ("105.45.67.1", "IPv4", 31.7917, -7.0926, "Morocco", "Casablanca", "Medium", 0.72),
            
            # Middle East
            ("185.142.53.45", "IPv4", 25.2048, 55.2708, "UAE", "Dubai", "High", 0.85),
            ("87.121.45.67", "IPv4", 24.7136, 46.6753, "Saudi Arabia", "Riyadh", "Medium", 0.76),
            ("91.121.45.67", "IPv4", 32.0853, 34.7818, "Israel", "Tel Aviv", "High", 0.83),
            ("93.45.67.89", "IPv4", 41.0082, 28.9784, "Turkey", "Istanbul", "Medium", 0.77),
            
            # Oceania
            ("45.63.1.1", "IPv4", -33.8688, 151.2093, "Australia", "Sydney", "Medium", 0.75),
            ("45.63.2.1", "IPv4", -37.8136, 144.9631, "Australia", "Melbourne", "Low", 0.68),
            ("103.86.45.67", "IPv4", -36.8485, 174.7633, "New Zealand", "Auckland", "Medium", 0.73),
            
            # Domains and URLs
            ("malware-distribution-01.com", "Domain", 55.7558, 37.6173, "Russia", "Moscow", "High", 0.88),
            ("phishing-attempt-02.net", "Domain", 40.7128, -74.0060, "USA", "New York", "Critical", 0.91),
            ("c2-server-03.ru", "Domain", 59.9311, 30.3609, "Russia", "St Petersburg", "High", 0.86),
            ("ransomware-payload-04.biz", "Domain", 48.8566, 2.3522, "France", "Paris", "Medium", 0.78),
            ("https://malicious-site.com/api", "URL", 52.5200, 13.4050, "Germany", "Berlin", "High", 0.84),
            ("https://phishing-portal.net/login", "URL", 35.6762, 139.6503, "Japan", "Tokyo", "Medium", 0.79),
            
            # Additional random IPs
            ("200.34.56.1", "IPv4", -34.6037, -58.3816, "Argentina", "Buenos Aires", "Medium", 0.74),
            ("202.45.67.1", "IPv4", 28.6139, 77.2090, "India", "New Delhi", "High", 0.83),
            ("210.56.78.1", "IPv4", 13.7367, 100.5231, "Thailand", "Bangkok", "Low", 0.66),
            ("220.67.89.1", "IPv4", 31.2304, 121.4737, "China", "Shanghai", "Critical", 0.92),
        ]
        
        # Add more random threats to reach desired count
        while len(global_threats) < count:
            # Generate random coordinates
            lat = random.uniform(-90, 90)
            lng = random.uniform(-180, 180)
            country = random.choice(['USA', 'UK', 'Germany', 'France', 'Japan', 'Brazil', 'Australia', 'India', 'China', 'Russia'])
            severity = random.choices(['Critical', 'High', 'Medium', 'Low'], weights=[0.15, 0.25, 0.35, 0.25])[0]
            confidence = random.uniform(0.65, 0.98)
            
            global_threats.append((
                f"185.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                "IPv4",
                lat, lng, country, f"City-{random.randint(1,100)}",
                severity, confidence
            ))
        
        indicators_created = 0
        indicators_skipped = 0
        
        for threat in global_threats[:count]:
            value, ind_type, lat, lng, country, city, severity, confidence = threat
            
            # Check if indicator already exists
            if ThreatIndicator.objects.filter(indicator_value=value).exists():
                indicators_skipped += 1
                continue
            
            context = f"""Geo: lat={lat}, lng={lng} - {city}, {country}
Global threat indicator added via management command.
Coordinates: {lat}, {lng}
Target: Zimbabwe"""

            try:
                indicator = ThreatIndicator.objects.create(
                    indicator_value=value,
                    indicator_type=ind_type,
                    source=global_feed,
                    confidence=confidence,
                    severity=severity,
                    context=context,
                    tags=f"global,geo,{country.lower()},automated",
                    is_active=True
                )
                indicators_created += 1
                self.stdout.write(f"  ✅ Added: {value} ({country}) - {severity}")
                
            except Exception as e:
                self.stdout.write(f"  ❌ Failed: {value} - {e}")
        
        self.stdout.write(self.style.SUCCESS(f"""
╔══════════════════════════════════════════════════════════════════╗
║              GLOBAL THREATS ADDED SUCCESSFULLY                    ║
╠══════════════════════════════════════════════════════════════════╣
║  ✅ New Indicators: {indicators_created}                                   ║
║  ⏭️ Skipped (duplicates): {indicators_skipped}                           ║
║  🌍 Countries Covered: ~{len(set(t[4] for t in global_threats[:count]))}                         ║
╠══════════════════════════════════════════════════════════════════╣
║  🗺️ Visit the Threat Map to see these indicators visualized!    ║
╚══════════════════════════════════════════════════════════════════╝
        """))