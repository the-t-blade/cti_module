"""
Management command to add geolocation coordinates to existing IP indicators.
Run: python manage.py geolocate_indicators
"""

import requests
import time
import ipaddress
import re
from django.core.management.base import BaseCommand
from django.core.cache import cache
from django.utils import timezone
from cti_core.models import ThreatIndicator


class Command(BaseCommand):
    help = 'Adds geolocation coordinates to IP-based threat indicators'

    def add_arguments(self, parser):
        parser.add_argument(
            '--limit',
            type=int,
            default=100,
            help='Limit number of indicators to process (default: 100)'
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force reprocessing even if already has geolocation'
        )

    def handle(self, *args, **options):
        limit = options['limit']
        force = options['force']
        
        self.stdout.write(self.style.SUCCESS('🌍 Starting geolocation enrichment...'))
        
        # Get indicators without geolocation
        if force:
            indicators = ThreatIndicator.objects.filter(
                indicator_type__in=['IPv4', 'IPv6'],
                is_active=True
            )[:limit]
        else:
            indicators = ThreatIndicator.objects.filter(
                indicator_type__in=['IPv4', 'IPv6'],
                is_active=True,
                context__icontains='Geo: lat='
            ).exclude(context__icontains='Geo: lat=')[:limit]
        
        self.stdout.write(f"📊 Found {indicators.count()} indicators to process")
        
        updated_count = 0
        skipped_count = 0
        error_count = 0
        
        for idx, indicator in enumerate(indicators):
            ip = indicator.indicator_value
            
            # Skip private IPs
            try:
                if ipaddress.ip_address(ip).is_private:
                    skipped_count += 1
                    continue
            except:
                pass
            
            # Rate limiting
            if idx > 0 and idx % 15 == 0:
                self.stdout.write(f"⏳ Rate limiting: Waiting 2 seconds...")
                time.sleep(2)
            
            try:
                # Free geolocation API (no key required)
                response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if data.get('status') == 'success':
                        lat = data.get('lat')
                        lng = data.get('lon')
                        country = data.get('countryCode', 'Unknown')
                        city = data.get('city', '')
                        region = data.get('regionName', '')
                        
                        # Check if already has geolocation
                        if indicator.context and 'Geo: lat=' in indicator.context and not force:
                            self.stdout.write(f"⏭️ {ip} already has coordinates, skipping")
                            continue
                        
                        # Update indicator context with coordinates
                        new_context = f"""Geo: lat={lat}, lng={lng} - {city}, {country}
Source: ip-api.com
Region: {region}
Last Updated: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}
{indicator.context or ''}"""
                        
                        indicator.context = new_context[:500]
                        indicator.save()
                        updated_count += 1
                        
                        # Cache the result
                        cache_key = f"geo_{ip}"
                        cache.set(cache_key, {'lat': lat, 'lng': lng, 'country': country}, 86400)
                        
                        self.stdout.write(f"✅ {ip} -> {country} ({lat}, {lng})")
                        
                    else:
                        self.stdout.write(f"⚠️ {ip}: {data.get('message', 'Unknown')}")
                        error_count += 1
                else:
                    self.stdout.write(f"❌ {ip}: HTTP {response.status_code}")
                    error_count += 1
                    
            except requests.exceptions.Timeout:
                self.stdout.write(f"⏰ {ip}: Request timeout")
                error_count += 1
            except Exception as e:
                self.stdout.write(f"❌ {ip}: Error - {e}")
                error_count += 1
            
            time.sleep(0.1)  # Small delay to be respectful to the API
        
        self.stdout.write(self.style.SUCCESS(f"""
╔══════════════════════════════════════════════════════════════════╗
║                    GEOLOCATION COMPLETE                           ║
╠══════════════════════════════════════════════════════════════════╣
║  ✅ Updated: {updated_count} indicators                                 ║
║  ⏭️ Skipped: {skipped_count} indicators (private IPs)                  ║
║  ❌ Errors: {error_count}                                              ║
╚══════════════════════════════════════════════════════════════════╝
        """))