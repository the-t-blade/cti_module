"""
Django views for the CTI module dashboard.
Implements HTMX-powered real-time updates.
"""

import json
import logging
import ipaddress
import re
import socket
from urllib.parse import urlparse

import requests
from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse, HttpResponse
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.db.models import Count, Q, F
from django.utils import timezone
from django.core.paginator import Paginator
from datetime import timedelta
from .models import ThreatIndicator, ThreatCampaign, Alert, ThreatFeed, UserProfile
from .services import CorrelationService, AlertService

logger = logging.getLogger(__name__)


# Add to views.py - Replace the existing role_required decorator

from functools import wraps
from django.core.exceptions import PermissionDenied
from django.contrib.auth.models import User

def role_required(allowed_roles):
    """Decorator to check user role permissions - with fallback for staff"""
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect('login')
            
            # Staff users always get access (admin override)
            if request.user.is_staff or request.user.is_superuser:
                return view_func(request, *args, **kwargs)
            
            # Check if user has profile with role
            if hasattr(request.user, 'profile') and request.user.profile:
                user_role = request.user.profile.role
                if user_role in allowed_roles:
                    return view_func(request, *args, **kwargs)
            else:
                # If no profile exists, create one with default 'analyst' role
                try:
                    from .models import UserProfile
                    UserProfile.objects.get_or_create(user=request.user, defaults={'role': 'analyst'})
                    # Allow access for default analyst role
                    if 'analyst' in allowed_roles:
                        return view_func(request, *args, **kwargs)
                except:
                    pass
                
                # Fall back to checking if analyst role is allowed anyway
                if 'analyst' in allowed_roles:
                    return view_func(request, *args, **kwargs)
            
            raise PermissionDenied("You don't have permission to access this page.")
        return wrapper
    return decorator


# ============================================================
# ENHANCED GEOGRAPHIC DATA - Multiple countries and Zimbabwe targets
# ============================================================

_GEO_CACHE = {}

# Expanded country coordinates with major cities
_COUNTRY_COORDS = {
    # Africa
    'zimbabwe': (-19.0154, 29.1549),
    'zimbabwe harare': (-17.8252, 31.0335),
    'zimbabwe bulawayo': (-20.1486, 28.6222),
    'zimbabwe mutare': (-18.9757, 32.6704),
    'zimbabwe gweru': (-19.4500, 29.8167),
    'zimbabwe kwekwe': (-18.9200, 29.8100),
    'zimbabwe masvingo': (-20.0667, 30.8167),
    'zimbabwe marondera': (-18.1667, 31.5500),
    'zimbabwe chinhoyi': (-17.3500, 30.2000),
    'zimbabwe kadoma': (-18.3333, 29.9167),
    'south africa': (-26.2041, 28.0473),
    'south africa johannesburg': (-26.2041, 28.0473),
    'south africa cape town': (-33.9249, 18.4241),
    'south africa durban': (-29.8587, 31.0218),
    'kenya': (-1.2864, 36.8172),
    'kenya nairobi': (-1.2864, 36.8172),
    'kenya mombasa': (-4.0435, 39.6682),
    'nigeria': (9.0820, 8.6753),
    'nigeria lagos': (6.5244, 3.3792),
    'nigeria abuja': (9.0765, 7.3986),
    'egypt': (30.0444, 31.2357),
    'egypt cairo': (30.0444, 31.2357),
    'ghana': (5.6037, -0.1870),
    'ghana accra': (5.6037, -0.1870),
    'ethiopia': (9.0320, 38.7469),
    'ethiopia addis ababa': (9.0320, 38.7469),
    'morocco': (31.7917, -7.0926),
    'morocco casablanca': (33.5731, -7.5898),
    
    # Europe
    'uk': (51.5074, -0.1278),
    'united kingdom': (51.5074, -0.1278),
    'london': (51.5074, -0.1278),
    'france': (48.8566, 2.3522),
    'paris': (48.8566, 2.3522),
    'germany': (52.5200, 13.4050),
    'berlin': (52.5200, 13.4050),
    'germany frankfurt': (50.1109, 8.6821),
    'russia': (55.7558, 37.6173),
    'moscow': (55.7558, 37.6173),
    'russia st petersburg': (59.9311, 30.3609),
    'italy': (41.9028, 12.4964),
    'rome': (41.9028, 12.4964),
    'spain': (40.4168, -3.7038),
    'madrid': (40.4168, -3.7038),
    'netherlands': (52.3676, 4.9041),
    'amsterdam': (52.3676, 4.9041),
    'sweden': (59.3293, 18.0686),
    'stockholm': (59.3293, 18.0686),
    'poland': (52.2297, 21.0122),
    'warsaw': (52.2297, 21.0122),
    'ukraine': (50.4501, 30.5234),
    'kyiv': (50.4501, 30.5234),
    
    # North America
    'usa': (38.9072, -77.0369),
    'united states': (38.9072, -77.0369),
    'new york': (40.7128, -74.0060),
    'los angeles': (34.0522, -118.2437),
    'chicago': (41.8781, -87.6298),
    'miami': (25.7617, -80.1918),
    'canada': (43.6532, -79.3832),
    'toronto': (43.6532, -79.3832),
    'vancouver': (49.2827, -123.1207),
    'montreal': (45.5017, -73.5673),
    'mexico': (19.4326, -99.1332),
    'mexico city': (19.4326, -99.1332),
    
    # South America
    'brazil': (-23.5505, -46.6333),
    'sao paulo': (-23.5505, -46.6333),
    'rio de janeiro': (-22.9068, -43.1729),
    'argentina': (-34.6037, -58.3816),
    'buenos aires': (-34.6037, -58.3816),
    'chile': (-33.4489, -70.6693),
    'santiago': (-33.4489, -70.6693),
    'colombia': (4.7110, -74.0721),
    'bogota': (4.7110, -74.0721),
    'peru': (-12.0464, -77.0428),
    'lima': (-12.0464, -77.0428),
    
    # Asia
    'china': (39.9042, 116.4074),
    'beijing': (39.9042, 116.4074),
    'shanghai': (31.2304, 121.4737),
    'shenzhen': (22.5431, 114.0579),
    'india': (28.6139, 77.2090),
    'new delhi': (28.6139, 77.2090),
    'mumbai': (19.0760, 72.8777),
    'japan': (35.6762, 139.6503),
    'tokyo': (35.6762, 139.6503),
    'osaka': (34.6937, 135.5023),
    'south korea': (37.5665, 126.9780),
    'seoul': (37.5665, 126.9780),
    'indonesia': (-6.2088, 106.8456),
    'jakarta': (-6.2088, 106.8456),
    'singapore': (1.3521, 103.8198),
    'singapore city': (1.3521, 103.8198),
    'thailand': (13.7367, 100.5231),
    'bangkok': (13.7367, 100.5231),
    'vietnam': (21.0285, 105.8542),
    'hanoi': (21.0285, 105.8542),
    'malaysia': (3.1390, 101.6869),
    'kuala lumpur': (3.1390, 101.6869),
    'pakistan': (24.8607, 67.0011),
    'karachi': (24.8607, 67.0011),
    'bangladesh': (23.8103, 90.4125),
    'dhaka': (23.8103, 90.4125),
    
    # Middle East
    'uae': (25.2048, 55.2708),
    'dubai': (25.2048, 55.2708),
    'abu dhabi': (24.4539, 54.3773),
    'saudi arabia': (24.7136, 46.6753),
    'riyadh': (24.7136, 46.6753),
    'israel': (31.0461, 34.8516),
    'tel aviv': (32.0853, 34.7818),
    'turkey': (41.0082, 28.9784),
    'istanbul': (41.0082, 28.9784),
    'iran': (35.6892, 51.3890),
    'tehran': (35.6892, 51.3890),
    
    # Oceania
    'australia': (-33.8688, 151.2093),
    'sydney': (-33.8688, 151.2093),
    'melbourne': (-37.8136, 144.9631),
    'brisbane': (-27.4698, 153.0251),
    'new zealand': (-36.8485, 174.7633),
    'auckland': (-36.8485, 174.7633),
    'wellington': (-41.2866, 174.7756),
}

# ============================================================
# MULTIPLE ZIMBABWE TARGETS (Different cities across the country)
# ============================================================
_ZIMBABWE_TARGETS = [
    {'name': 'Harare, Zimbabwe', 'lat': -17.8252, 'lng': 31.0335, 'region': 'Harare', 'criticality': 'HIGH'},
    {'name': 'Bulawayo, Zimbabwe', 'lat': -20.1486, 'lng': 28.6222, 'region': 'Bulawayo', 'criticality': 'HIGH'},
    {'name': 'Mutare, Zimbabwe', 'lat': -18.9757, 'lng': 32.6704, 'region': 'Manicaland', 'criticality': 'MEDIUM'},
    {'name': 'Gweru, Zimbabwe', 'lat': -19.4500, 'lng': 29.8167, 'region': 'Midlands', 'criticality': 'MEDIUM'},
    {'name': 'Kwekwe, Zimbabwe', 'lat': -18.9200, 'lng': 29.8100, 'region': 'Midlands', 'criticality': 'MEDIUM'},
    {'name': 'Masvingo, Zimbabwe', 'lat': -20.0667, 'lng': 30.8167, 'region': 'Masvingo', 'criticality': 'MEDIUM'},
    {'name': 'Marondera, Zimbabwe', 'lat': -18.1667, 'lng': 31.5500, 'region': 'Mashonaland East', 'criticality': 'LOW'},
    {'name': 'Chinhoyi, Zimbabwe', 'lat': -17.3500, 'lng': 30.2000, 'region': 'Mashonaland West', 'criticality': 'LOW'},
    {'name': 'Kadoma, Zimbabwe', 'lat': -18.3333, 'lng': 29.9167, 'region': 'Midlands', 'criticality': 'LOW'},
    {'name': 'Hwange, Zimbabwe', 'lat': -18.3667, 'lng': 26.4833, 'region': 'Matabeleland North', 'criticality': 'LOW'},
    {'name': 'Victoria Falls, Zimbabwe', 'lat': -17.9333, 'lng': 25.8333, 'region': 'Matabeleland North', 'criticality': 'MEDIUM'},
    {'name': 'Bindura, Zimbabwe', 'lat': -17.3000, 'lng': 31.3333, 'region': 'Mashonaland Central', 'criticality': 'LOW'},
    {'name': 'Chiredzi, Zimbabwe', 'lat': -21.0500, 'lng': 31.6667, 'region': 'Masvingo', 'criticality': 'LOW'},
    {'name': 'Kariba, Zimbabwe', 'lat': -16.5167, 'lng': 28.8000, 'region': 'Mashonaland West', 'criticality': 'MEDIUM'},
]

# Default target for backward compatibility
_TARGET_ZW = _ZIMBABWE_TARGETS[0]  # Harare as default

# ============================================================
# Helper function to get a random Zimbabwe target
# ============================================================
import random

def get_random_zimbabwe_target():
    """Return a random Zimbabwe target city for attack paths"""
    return random.choice(_ZIMBABWE_TARGETS)

def get_zimbabwe_target_by_region(region):
    """Get Zimbabwe target by region name"""
    for target in _ZIMBABWE_TARGETS:
        if target['region'].lower() == region.lower():
            return target
    return _TARGET_ZW

def get_all_zimbabwe_targets():
    """Return all Zimbabwe targets"""
    return _ZIMBABWE_TARGETS

def _extract_ip_from_value(value):
    """Extract IP candidate from indicator text."""
    if not value:
        return None
    text = value.strip()
    try:
        ipaddress.ip_address(text)
        return text
    except ValueError:
        pass

    match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    if match:
        candidate = match.group(0)
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            return None
    return None


def _resolve_domain_or_url_to_ip(value):
    """Resolve a domain/url to an IP address."""
    if not value:
        return None
    text = value.strip()
    if text.startswith('http://') or text.startswith('https://'):
        parsed = urlparse(text)
        host = parsed.hostname
    else:
        host = text.split('/')[0].split(':')[0]

    if not host:
        return None
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def _geo_lookup_ip(ip):
    """Get geolocation from IP with a small in-memory cache."""
    if not ip:
        return None
    if ip in _GEO_CACHE:
        return _GEO_CACHE[ip]

    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=1.2)
        if response.ok:
            payload = response.json()
            if payload.get('status') == 'success' and payload.get('lat') and payload.get('lon'):
                result = {
                    'name': f"{payload.get('city') or payload.get('country')}, {payload.get('countryCode') or ''}".strip(', '),
                    'lat': payload['lat'],
                    'lng': payload['lon'],
                    'country': payload.get('country', ''),
                }
                _GEO_CACHE[ip] = result
                return result
    except Exception:
        pass
    return None


def _fallback_geo_from_text(indicator):
    """Fallback geolocation from known country keywords in context/tags."""
    text = f"{indicator.context or ''} {indicator.tags or ''}".lower()
    for key, coords in _COUNTRY_COORDS.items():
        if key in text:
            return {'name': key.title(), 'lat': coords[0], 'lng': coords[1]}
    return None


def _locate_indicator(indicator):
    """Resolve indicator location from value/content."""
    ip = _extract_ip_from_value(indicator.indicator_value)
    if not ip and indicator.indicator_type in ['Domain', 'URL']:
        ip = _resolve_domain_or_url_to_ip(indicator.indicator_value)

    geo = _geo_lookup_ip(ip) if ip else None
    if geo:
        return geo
    return _fallback_geo_from_text(indicator)


def _is_zimbabwe_geo(geo):
    """Return True when a geolocation points to Zimbabwe."""
    if not geo:
        return False

    name = str(geo.get('name', '')).lower()
    country = str(geo.get('country', '')).lower()
    lat = geo.get('lat')
    lng = geo.get('lng')

    if 'zimbabwe' in country or 'zimbabwe' in name:
        return True

    try:
        lat = float(lat)
        lng = float(lng)
    except (TypeError, ValueError):
        return False

    return -23.5 <= lat <= -15.5 and 25.3 <= lng <= 33.2


def _build_dashboard_stats_payload():
    """Build live dashboard payload for both HTTP and WebSocket."""
    import re
    import random
    from .models import ThreatIndicator, ThreatCampaign, Alert
    
    now = timezone.now()
    start_time = now - timedelta(hours=24)

    active_campaigns = ThreatCampaign.objects.filter(status__in=['Active', 'Monitoring']).count()
    recent_alerts_qs = Alert.objects.select_related('indicator').filter(status='New').order_by('-created_at')[:12]

    alerts_by_severity = {
        item['severity']: item['count']
        for item in Alert.objects.values('severity').annotate(count=Count('id'))
    }
    severity_order = ['Critical', 'High', 'Medium', 'Low']
    severity_chart = [alerts_by_severity.get(level, 0) for level in severity_order]

    hours = []
    hourly_counts = []
    for i in range(5, -1, -1):
        hour_start = now - timedelta(hours=i)
        hour_end = hour_start + timedelta(hours=1)
        hours.append(hour_start.strftime('%H:%M'))
        hourly_counts.append(
            Alert.objects.filter(created_at__gte=hour_start, created_at__lt=hour_end).count()
        )

    map_events = []
    map_paths = []
    attacked_country_rollup = {}
    country_heat = {}
    
    # ============================================================
    # ZIMBABWE TARGETS - Multiple cities across the country
    # ============================================================
    ZIMBABWE_TARGETS = [
        {'name': 'Harare, Zimbabwe', 'lat': -17.8252, 'lng': 31.0335, 'region': 'Harare'},
        {'name': 'Bulawayo, Zimbabwe', 'lat': -20.1486, 'lng': 28.6222, 'region': 'Bulawayo'},
        {'name': 'Mutare, Zimbabwe', 'lat': -18.9757, 'lng': 32.6704, 'region': 'Manicaland'},
        {'name': 'Gweru, Zimbabwe', 'lat': -19.4500, 'lng': 29.8167, 'region': 'Midlands'},
        {'name': 'Kwekwe, Zimbabwe', 'lat': -18.9200, 'lng': 29.8100, 'region': 'Midlands'},
        {'name': 'Masvingo, Zimbabwe', 'lat': -20.0667, 'lng': 30.8167, 'region': 'Masvingo'},
        {'name': 'Marondera, Zimbabwe', 'lat': -18.1667, 'lng': 31.5500, 'region': 'Mashonaland East'},
        {'name': 'Chinhoyi, Zimbabwe', 'lat': -17.3500, 'lng': 30.2000, 'region': 'Mashonaland West'},
        {'name': 'Kadoma, Zimbabwe', 'lat': -18.3333, 'lng': 29.9167, 'region': 'Midlands'},
        {'name': 'Victoria Falls, Zimbabwe', 'lat': -17.9333, 'lng': 25.8333, 'region': 'Matabeleland North'},
        {'name': 'Hwange, Zimbabwe', 'lat': -18.3667, 'lng': 26.4833, 'region': 'Matabeleland North'},
        {'name': 'Bindura, Zimbabwe', 'lat': -17.3000, 'lng': 31.3333, 'region': 'Mashonaland Central'},
        {'name': 'Chiredzi, Zimbabwe', 'lat': -21.0500, 'lng': 31.6667, 'region': 'Masvingo'},
        {'name': 'Kariba, Zimbabwe', 'lat': -16.5167, 'lng': 28.8000, 'region': 'Mashonaland West'},
    ]
    
    def get_random_target():
        return random.choice(ZIMBABWE_TARGETS)
    
    # ============================================================
    # PART 1: Process alerts for map data
    # ============================================================
    for alert in recent_alerts_qs:
        indicator = alert.indicator
        if not indicator:
            continue
        source_geo = _locate_indicator(indicator)
        if not source_geo or not _is_zimbabwe_geo(source_geo):
            continue
        country = source_geo.get('country') or source_geo.get('name', 'Unknown')
        attacked_country_rollup[country] = attacked_country_rollup.get(country, 0) + 1
        heat_key = f"{round(source_geo['lat'], 2)}:{round(source_geo['lng'], 2)}:{country}"
        if heat_key not in country_heat:
            country_heat[heat_key] = {
                'name': country,
                'lat': source_geo['lat'],
                'lng': source_geo['lng'],
                'weight': 0,
            }
        country_heat[heat_key]['weight'] += 1
        map_events.append({
            'name': source_geo.get('name') or indicator.indicator_value[:40],
            'lat': source_geo['lat'],
            'lng': source_geo['lng'],
            'count': 1 + int(alert.severity in ['High', 'Critical']),
            'severity': alert.severity,
            'indicator': indicator.indicator_value[:60],
            'country': country,
            'indicator_type': indicator.indicator_type,
        })
        # Use random Zimbabwe target instead of always Harare
        target = get_random_target()
        map_paths.append({
            'from': {'lat': source_geo['lat'], 'lng': source_geo['lng'], 'name': source_geo.get('name', 'Source')},
            'to': target,
            'severity': alert.severity,
        })
    
    # ============================================================
    # PART 2: Add ALL indicators with geolocation in context
    # ============================================================
    geo_indicators = ThreatIndicator.objects.filter(
        is_active=True,
        context__icontains='Geo: lat='
    ).exclude(indicator_type='CVE')[:50]
    
    for indicator in geo_indicators:
        context = indicator.context or ""
        
        lat_match = re.search(r'lat[=:]\s*([-\d.]+)', context)
        lng_match = re.search(r'lng[=:]\s*([-\d.]+)', context)
        
        if lat_match and lng_match:
            lat = float(lat_match.group(1))
            lng = float(lng_match.group(1))
            
            country_match = re.search(r'-\s*([A-Za-z\s,]+?)(?:\n|$)', context)
            country = country_match.group(1).strip() if country_match else 'Unknown'
            if not _is_zimbabwe_geo({'name': country, 'country': country, 'lat': lat, 'lng': lng}):
                continue

            if abs(lat) > 90 or abs(lng) > 180:
                continue
            
            map_events.append({
                'name': f"{indicator.indicator_value}",
                'lat': lat,
                'lng': lng,
                'count': 1,
                'severity': indicator.severity,
                'indicator': indicator.indicator_value[:60],
                'country': country[:30],
                'indicator_type': indicator.indicator_type,
            })
            
            # Use random Zimbabwe target
            target = get_random_target()
            map_paths.append({
                'from': {'lat': lat, 'lng': lng, 'name': indicator.indicator_value[:30]},
                'to': target,
                'severity': indicator.severity,
            })
            
            heat_key = f"{round(lat, 2)}:{round(lng, 2)}:{country}"
            if heat_key not in country_heat:
                country_heat[heat_key] = {
                    'name': country,
                    'lat': lat,
                    'lng': lng,
                    'weight': 0,
                }
            country_heat[heat_key]['weight'] += 1
    
    # ============================================================
    # PART 3: Add sample fallback data if no geo indicators exist
    # ============================================================
    if not map_events:
        sample_threats = [
            {'lat': -17.8252, 'lng': 31.0335, 'name': 'Harare, Zimbabwe', 'severity': 'Critical', 'indicator': '196.1.2.3', 'type': 'IPv4'},
            {'lat': -20.1486, 'lng': 28.6222, 'name': 'Bulawayo, Zimbabwe', 'severity': 'High', 'indicator': '196.4.5.6', 'type': 'IPv4'},
            {'lat': -18.9757, 'lng': 32.6704, 'name': 'Mutare, Zimbabwe', 'severity': 'High', 'indicator': '196.7.8.9', 'type': 'IPv4'},
            {'lat': -19.4500, 'lng': 29.8167, 'name': 'Gweru, Zimbabwe', 'severity': 'Medium', 'indicator': '196.10.11.12', 'type': 'IPv4'},
            {'lat': -20.0667, 'lng': 30.8167, 'name': 'Masvingo, Zimbabwe', 'severity': 'Medium', 'indicator': '196.13.14.15', 'type': 'IPv4'},
            {'lat': -17.9333, 'lng': 25.8333, 'name': 'Victoria Falls, Zimbabwe', 'severity': 'Medium', 'indicator': '196.16.17.18', 'type': 'IPv4'},
        ]
        
        for threat in sample_threats:
            map_events.append({
                'name': threat['name'],
                'lat': threat['lat'],
                'lng': threat['lng'],
                'count': 1,
                'severity': threat['severity'],
                'indicator': threat['indicator'],
                'country': threat['name'].split(',')[-1].strip(),
                'indicator_type': threat['type'],
            })
            # Use random Zimbabwe target for each threat
            target = get_random_target()
            map_paths.append({
                'from': {'lat': threat['lat'], 'lng': threat['lng'], 'name': threat['name']},
                'to': target,
                'severity': threat['severity'],
            })
            heat_key = f"{round(threat['lat'], 2)}:{round(threat['lng'], 2)}:{threat['name']}"
            if heat_key not in country_heat:
                country_heat[heat_key] = {
                    'name': threat['name'].split(',')[-1].strip(),
                    'lat': threat['lat'],
                    'lng': threat['lng'],
                    'weight': 1,
                }
            else:
                country_heat[heat_key]['weight'] += 1

    # ============================================================
    # PART 4: Calculate top attacked country
    # ============================================================
    top_country = {'name': 'N/A', 'count': 0}
    if attacked_country_rollup:
        name, count = max(attacked_country_rollup.items(), key=lambda item: item[1])
        top_country = {'name': name, 'count': count}
    elif map_events:
        country_counts = {}
        for event in map_events:
            country = event.get('country', 'Unknown')
            country_counts[country] = country_counts.get(country, 0) + 1
        if country_counts:
            name, count = max(country_counts.items(), key=lambda item: item[1])
            top_country = {'name': name, 'count': count}

    # ============================================================
    # PART 5: Calculate attack vectors (indicator types)
    # ============================================================
    attack_vector_rows = (
        ThreatIndicator.objects.filter(created_at__gte=start_time)
        .values('indicator_type')
        .annotate(count=Count('id'))
        .order_by('-count')[:6]
    )
    attack_vectors = [{'name': row['indicator_type'], 'count': row['count']} for row in attack_vector_rows]
    
    if not attack_vectors:
        attack_vectors = [
            {'name': 'IPv4', 'count': 156},
            {'name': 'Domain', 'count': 89},
            {'name': 'FileHash', 'count': 45},
            {'name': 'URL', 'count': 34},
            {'name': 'CVE', 'count': 100},
        ]

    # ============================================================
    # PART 6: Get threat actors (from campaigns)
    # ============================================================
    threat_actors_data = []
    threat_actors = ThreatCampaign.objects.exclude(threat_actor__isnull=True).exclude(threat_actor='').values('threat_actor').annotate(
        count=Count('indicators')
    ).order_by('-count')[:5]
    
    for actor in threat_actors:
        campaigns = ThreatCampaign.objects.filter(threat_actor=actor['threat_actor']).values_list('name', flat=True)[:3]
        max_count = threat_actors[0]['count'] if threat_actors else 1
        threat_actors_data.append({
            'name': actor['threat_actor'],
            'count': actor['count'],
            'percentage': (actor['count'] / max_count) * 100 if max_count > 0 else 100,
            'campaigns': list(campaigns)
        })
    
    if not threat_actors_data:
        threat_actors_data = [
            {'name': 'APT28 (Fancy Bear)', 'count': 47, 'percentage': 100, 'campaigns': ['Election Interference', 'Military Intel']},
            {'name': 'APT29 (Cozy Bear)', 'count': 32, 'percentage': 68, 'campaigns': ['Diplomatic Phishing', 'Cloud Attacks']},
            {'name': 'Lazarus Group', 'count': 28, 'percentage': 60, 'campaigns': ['Financial Theft', 'Cryptocurrency']},
            {'name': 'TA505', 'count': 19, 'percentage': 40, 'campaigns': ['Ransomware Distribution']},
            {'name': 'Sandworm', 'count': 14, 'percentage': 30, 'campaigns': ['Critical Infrastructure']},
        ]

    # ============================================================
    # PART 7: Get top countries from map events
    # ============================================================
    top_countries = []
    country_counts = {}
    for event in map_events:
        country = event.get('country', 'Unknown')
        country_counts[country] = country_counts.get(country, 0) + 1
    
    for country, count in sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
        top_countries.append({'name': country, 'count': count})

    # ============================================================
    # PART 8: Build final stats payload
    # ============================================================
    stats = {
        'total_indicators': ThreatIndicator.objects.count(),
        'total_campaigns': active_campaigns,
        'active_alerts': Alert.objects.filter(status__in=['New', 'Acknowledged']).count(),
        'critical_alerts': Alert.objects.filter(severity='Critical', status='New').count(),
        'ingest_last_24h': ThreatIndicator.objects.filter(created_at__gte=start_time).count(),
        'alerts_last_24h': Alert.objects.filter(created_at__gte=start_time).count(),
        'high_alerts': Alert.objects.filter(severity='High', status='New').count(),
        'live_status': 'LIVE',
        'recent_alerts': list(
            recent_alerts_qs.values('id', 'title', 'severity', 'status', 'created_at')
        ),
        'alerts_by_severity': {
            'labels': severity_order,
            'data': severity_chart,
        },
        'activity_series': {
            'labels': hours,
            'data': hourly_counts,
        },
        'map_events': map_events,
        'map_paths': map_paths,
        'country_heat': list(country_heat.values()),
        'most_attacked_country': top_country,
        'attack_vectors': attack_vectors,
        'threat_actors': threat_actors_data,
        'top_countries': top_countries,
    }
    
    return stats



@login_required
@role_required(['super_admin', 'admin', 'analyst_lead', 'analyst'])
def dashboard(request):
    """Main CTI dashboard view."""
    from django.db.models import Count, Sum
    
    active_campaigns = ThreatCampaign.objects.filter(status__in=['Active', 'Monitoring']).count()
    
    # Get threat actors with counts
    threat_actors_data = []
    threat_actors = ThreatCampaign.objects.exclude(threat_actor__isnull=True).exclude(threat_actor='').values('threat_actor').annotate(
        count=Count('indicators')
    ).order_by('-count')[:5]
    
    for actor in threat_actors:
        campaigns = ThreatCampaign.objects.filter(threat_actor=actor['threat_actor']).values_list('name', flat=True)[:3]
        threat_actors_data.append({
            'name': actor['threat_actor'],
            'count': actor['count'],
            'percentage': 100,
            'campaigns': list(campaigns)
        })
    
    # If no data, show sample data
    if not threat_actors_data:
        threat_actors_data = [
            {'name': 'APT28 (Fancy Bear)', 'count': 47, 'percentage': 100, 'campaigns': ['Election Interference', 'Military Intel']},
            {'name': 'APT29 (Cozy Bear)', 'count': 32, 'percentage': 68, 'campaigns': ['Diplomatic Phishing', 'Cloud Attacks']},
            {'name': 'Lazarus Group', 'count': 28, 'percentage': 60, 'campaigns': ['Financial Theft', 'Cryptocurrency']},
            {'name': 'TA505', 'count': 19, 'percentage': 40, 'campaigns': ['Ransomware Distribution']},
            {'name': 'Sandworm', 'count': 14, 'percentage': 30, 'campaigns': ['Critical Infrastructure']},
        ]
    
    # Get statistics by severity
    alerts_by_severity = {
        item['severity']: item['count']
        for item in Alert.objects.values('severity').annotate(count=Count('id'))
    }
    
    context = {
        'total_indicators': ThreatIndicator.objects.count(),
        'total_campaigns': active_campaigns,
        'active_alerts': Alert.objects.filter(status__in=['New', 'Acknowledged']).count(),
        'critical_alerts': Alert.objects.filter(severity='Critical', status='New').count(),
        'recent_alerts': Alert.objects.select_related('campaign').order_by('-created_at')[:6],
        'alerts_by_severity': alerts_by_severity,
        'threat_actors': threat_actors_data,
        'threat_actors_json': json.dumps(threat_actors_data),
    }
    return render(request, 'cti_core/dashboard.html', context)


@login_required
def indicators_list(request):
    """List all threat indicators with filtering and pagination."""
    indicators = ThreatIndicator.objects.select_related('source', 'campaign').all()
    
    # Filtering
    indicator_type = request.GET.get('type')
    severity = request.GET.get('severity')
    campaign_id = request.GET.get('campaign')
    
    if indicator_type:
        indicators = indicators.filter(indicator_type=indicator_type)
    if severity:
        indicators = indicators.filter(severity=severity)
    if campaign_id:
        indicators = indicators.filter(campaign_id=campaign_id)
    
    # Search
    search_query = request.GET.get('q')
    if search_query:
        indicators = indicators.filter(
            Q(indicator_value__icontains=search_query) |
            Q(context__icontains=search_query) |
            Q(tags__icontains=search_query)
        )
    
    # Pagination
    paginator = Paginator(indicators, 20)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'indicators': page_obj.object_list,
        'total_count': indicators.count(),
        'indicator_types': ThreatIndicator.INDICATOR_TYPE_CHOICES,
        'severities': ThreatIndicator.SEVERITY_CHOICES,
    }
    
    # Return partial HTML if HTMX request
    if request.headers.get('HX-Request'):
        return render(request, 'cti_core/partials/indicators_table.html', context)
    
    return render(request, 'cti_core/indicators.html', context)


@login_required
def indicator_detail(request, pk):
    """Display detailed view of a single indicator."""
    indicator = get_object_or_404(ThreatIndicator, pk=pk)
    related_indicators = ThreatIndicator.objects.filter(
        campaign=indicator.campaign
    ).exclude(pk=pk)[:10]
    
    context = {
        'indicator': indicator,
        'related_indicators': related_indicators,
        'alerts': indicator.alerts.all(),
    }
    return render(request, 'cti_core/indicator_detail.html', context)


@login_required
def campaigns_list(request):
    """List all threat campaigns."""
    campaigns = ThreatCampaign.objects.annotate(
        indicator_count=Count('indicators'),
        alert_count=Count('alerts')
    ).all()
    
    # Filtering
    status = request.GET.get('status')
    if status:
        campaigns = campaigns.filter(status=status)
    
    # Search
    search_query = request.GET.get('q')
    if search_query:
        campaigns = campaigns.filter(
            Q(name__icontains=search_query) |
            Q(description__icontains=search_query) |
            Q(threat_actor__icontains=search_query)
        )
    
    # Pagination
    paginator = Paginator(campaigns, 15)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'campaigns': page_obj.object_list,
        'total_count': campaigns.count(),
        'statuses': ThreatCampaign.CAMPAIGN_STATUS_CHOICES,
    }
    
    # Return partial HTML if HTMX request
    if request.headers.get('HX-Request'):
        return render(request, 'cti_core/partials/campaigns_table.html', context)
    
    return render(request, 'cti_core/campaigns.html', context)


@login_required
def campaign_detail(request, pk):
    """Display detailed view of a campaign."""
    campaign = get_object_or_404(ThreatCampaign, pk=pk)
    indicators = campaign.indicators.all()
    alerts = campaign.alerts.all()
    correlation_logs = campaign.correlation_logs.all()[:10]
    
    context = {
        'campaign': campaign,
        'indicators': indicators,
        'alerts': alerts,
        'correlation_logs': correlation_logs,
    }
    return render(request, 'cti_core/campaign_detail.html', context)


@login_required
def alerts_list(request):
    """List all alerts with filtering."""
    alerts = Alert.objects.select_related('indicator', 'campaign', 'assigned_to').all()
    
    # Filtering
    status = request.GET.get('status')
    severity = request.GET.get('severity')
    
    if status:
        alerts = alerts.filter(status=status)
    if severity:
        alerts = alerts.filter(severity=severity)
    
    # Search
    search_query = request.GET.get('q')
    if search_query:
        alerts = alerts.filter(
            Q(title__icontains=search_query) |
            Q(description__icontains=search_query)
        )
    
    # Pagination
    paginator = Paginator(alerts, 20)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'alerts': page_obj.object_list,
        'total_count': alerts.count(),
        'statuses': Alert.ALERT_STATUS_CHOICES,
        'severities': Alert.ALERT_SEVERITY_CHOICES,
    }
    
    # Return partial HTML if HTMX request
    if request.headers.get('HX-Request'):
        return render(request, 'cti_core/partials/alerts_table.html', context)
    
    return render(request, 'cti_core/alerts.html', context)


@login_required
def alert_detail(request, pk):
    """Display detailed view of an alert."""
    alert = get_object_or_404(Alert, pk=pk)
    context = {'alert': alert}
    return render(request, 'cti_core/alert_detail.html', context)


@login_required
@require_http_methods(["POST"])
def acknowledge_alert(request, pk):
    """Acknowledge an alert via HTMX."""
    alert = AlertService.acknowledge_alert(pk, request.user)
    if alert:
        return render(request, 'cti_core/partials/alert_status_badge.html', {'alert': alert})
    return HttpResponse(status=404)


@login_required
@require_http_methods(["POST"])
def resolve_alert(request, pk):
    """Resolve an alert via HTMX."""
    alert = AlertService.resolve_alert(pk)
    if alert:
        return render(request, 'cti_core/partials/alert_status_badge.html', {'alert': alert})
    return HttpResponse(status=404)


@login_required
@require_http_methods(["POST"])
def run_correlation(request):
    """Run threat correlation via HTMX."""
    service = CorrelationService(eps=0.5, min_samples=2)
    result = service.correlate_indicators()
    
    context = {
        'result': result,
        'total_campaigns': ThreatCampaign.objects.count(),
    }
    return render(request, 'cti_core/partials/correlation_result.html', context)


@login_required
def feeds_list(request):
    """List all threat feeds."""
    feeds = ThreatFeed.objects.all()
    context = {'feeds': feeds}
    return render(request, 'cti_core/feeds.html', context)


@login_required
def dashboard_stats(request):
    """Return dashboard statistics as JSON (for HTMX polling)."""
    return JsonResponse(_build_dashboard_stats_payload())


@login_required
def threat_landscape(request):
    """Display threat landscape visualization data."""
    # Indicators by type
    indicators_by_type = ThreatIndicator.objects.values('indicator_type').annotate(
        count=Count('id')
    ).order_by('-count')
    
    # Alerts by severity
    alerts_by_severity = Alert.objects.values('severity').annotate(
        count=Count('id')
    ).order_by('-count')
    
    # Campaigns by status
    campaigns_by_status = ThreatCampaign.objects.values('status').annotate(
        count=Count('id')
    ).order_by('-count')
    
    # Recent activity
    recent_indicators = ThreatIndicator.objects.order_by('-created_at')[:10]
    recent_campaigns = ThreatCampaign.objects.order_by('-created_at')[:10]
    
    context = {
        'indicators_by_type': indicators_by_type,
        'alerts_by_severity': alerts_by_severity,
        'campaigns_by_status': campaigns_by_status,
        'recent_indicators': recent_indicators,
        'recent_campaigns': recent_campaigns,
    }
    return render(request, 'cti_core/threat_landscape.html', context)


# ============================================================
# ENHANCED VIEWS FOR NEW FEATURES (Previously in views_enhanced.py)
# ============================================================

@login_required
def threat_map(request):
    """Display global cyber threat map with Leaflet.js."""
    context = {
        'threat_map_center': [-17.8252, 31.0335],  # Zimbabwe
        'threat_map_zoom': 5,
    }
    return render(request, 'cti_core/threat_map.html', context)


@login_required
def threat_map_data(request):
    """API endpoint for threat map data."""
    from .views import _build_dashboard_stats_payload
    
    stats = _build_dashboard_stats_payload()
    
    # Ensure we have valid data
    map_events = stats.get('map_events', [])
    map_paths = stats.get('map_paths', [])
    country_heat = stats.get('country_heat', [])
    
    # If no real data, return sample data for demo
    if not map_events:
        map_events = [
            {'lat': -17.8252, 'lng': 31.0335, 'name': 'Harare, Zimbabwe', 'severity': 'Critical', 'count': 45, 'indicator_type': 'IPv4', 'indicator': '196.1.2.3'},
            {'lat': -20.1486, 'lng': 28.6222, 'name': 'Bulawayo, Zimbabwe', 'severity': 'High', 'count': 32, 'indicator_type': 'IPv4', 'indicator': '196.4.5.6'},
            {'lat': -18.9757, 'lng': 32.6704, 'name': 'Mutare, Zimbabwe', 'severity': 'High', 'count': 28, 'indicator_type': 'IPv4', 'indicator': '196.7.8.9'},
        ]
        map_paths = [
            {'from': {'lat': -17.8252, 'lng': 31.0335, 'name': 'Harare, Zimbabwe'}, 'to': {'lat': -17.8252, 'lng': 31.0335, 'name': 'Zimbabwe'}, 'severity': 'Critical'}
        ]
        country_heat = [
            {'name': 'Zimbabwe', 'lat': -18.9757, 'lng': 31.0335, 'weight': 105},
        ]
    
    return JsonResponse({
        'map_events': map_events,
        'map_paths': map_paths,
        'country_heat': country_heat,
    })
@login_required
@role_required(['super_admin', 'admin'])
def users_list(request):
    """Display list of users with management options and statistics."""
    from django.db.models import Count, Q
    from django.utils import timezone
    from datetime import timedelta
    
    # Get all users
    users = User.objects.all().order_by('-date_joined')
    
    # Calculate statistics
    total_users = users.count()
    admin_count = users.filter(is_staff=True).count()
    
    # Users active today (last 24 hours)
    today_cutoff = timezone.now() - timedelta(hours=24)
    active_today = users.filter(last_login__gte=today_cutoff).count()
    
    # Users who logged in last 7 days
    week_cutoff = timezone.now() - timedelta(days=7)
    last_login_count = users.filter(last_login__gte=week_cutoff).count()
    
    # Pagination
    paginator = Paginator(users, 15)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    context = {
        'users': page_obj,
        'total_users': total_users,
        'admin_count': admin_count,
        'active_today': active_today,
        'last_login_count': last_login_count,
    }
    return render(request, 'cti_core/user_management.html', context)


@login_required
@role_required(['super_admin', 'admin'])
def user_create(request):
    """Create a new user."""
    if not request.user.is_staff:
        messages.error(request, 'Permission denied.')
        return redirect('cti_core:dashboard')
    
    if request.method == 'POST':
        try:
            username = request.POST.get('username')
            email = request.POST.get('email')
            password = request.POST.get('password')
            password_confirm = request.POST.get('password_confirm')
            is_staff = request.POST.get('is_staff') == 'on'
            is_active = request.POST.get('is_active', 'on') == 'on'
            role = request.POST.get('role', 'analyst')
            department = request.POST.get('department', '')
            phone_number = request.POST.get('phone_number', '')
            
            # Validation
            if password != password_confirm:
                messages.error(request, 'Passwords do not match.')
                return redirect('cti_core:user_create')
            
            if User.objects.filter(username=username).exists():
                messages.error(request, f'Username "{username}" already exists.')
                return redirect('cti_core:user_create')
            
            if User.objects.filter(email=email).exists():
                messages.error(request, f'Email "{email}" already exists.')
                return redirect('cti_core:user_create')
            
            # Create user
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                is_staff=is_staff,
                is_active=is_active
            )
            
            # Create or update profile
            profile, created = UserProfile.objects.get_or_create(
                user=user,
                defaults={
                    'role': role,
                    'department': department,
                    'phone_number': phone_number
                }
            )
            if not created:
                profile.role = role
                profile.department = department
                profile.phone_number = phone_number
                profile.save()
            
            messages.success(request, f'User {username} created successfully.')
            logger.info(f"User {username} created by {request.user.username}")
            return redirect('cti_core:users_list')
        
        except Exception as e:
            logger.error(f"Error creating user: {str(e)}")
            messages.error(request, f'Error creating user: {str(e)}')
            return redirect('cti_core:user_create')
    
    context = {
        'user_obj': None,
        'roles': UserProfile.ROLE_CHOICES
    }
    return render(request, 'cti_core/user_form.html', context)


@login_required
@role_required(['super_admin', 'admin'])
def user_edit(request, pk):
    """Edit an existing user."""
    if not request.user.is_staff:
        messages.error(request, 'Permission denied.')
        return redirect('cti_core:dashboard')
    
    user = get_object_or_404(User, pk=pk)
    
    # Get or create profile
    from .models import UserProfile
    profile, _ = UserProfile.objects.get_or_create(user=user)
    
    if request.method == 'POST':
        try:
            user.email = request.POST.get('email', user.email)
            user.first_name = request.POST.get('first_name', user.first_name)
            user.last_name = request.POST.get('last_name', user.last_name)
            user.is_staff = request.POST.get('is_staff') == 'on'
            user.is_active = request.POST.get('is_active') == 'on'
            user.save()
            
            # Update profile
            profile.role = request.POST.get('role', 'analyst')
            profile.department = request.POST.get('department', '')
            profile.phone_number = request.POST.get('phone_number', '')
            profile.save()
            
            # Change password if provided
            new_password = request.POST.get('new_password')
            if new_password:
                user.set_password(new_password)
                user.save()
                messages.warning(request, f'Password changed for {user.username}. User will need to log in again.')
            
            messages.success(request, f'User {user.username} updated successfully.')
            logger.info(f"User {user.username} updated by {request.user.username}")
            return redirect('cti_core:users_list')
        
        except Exception as e:
            logger.error(f"Error editing user: {str(e)}")
            messages.error(request, f'Error editing user: {str(e)}')
            return redirect('cti_core:user_edit', pk=pk)
    
    context = {
        'user_obj': user,
        'profile': profile,
        'roles': UserProfile.ROLE_CHOICES
    }
    return render(request, 'cti_core/user_form.html', context)


@login_required
@require_http_methods(["POST"])
def user_delete(request, pk):
    """Delete a user."""
    if not request.user.is_staff:
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    try:
        user = get_object_or_404(User, pk=pk)
        
        if user == request.user:
            return JsonResponse({'error': 'You cannot delete your own account.'}, status=400)
        
        username = user.username
        user.delete()
        
        logger.info(f"User {username} deleted by {request.user.username}")
        return JsonResponse({'success': True, 'message': f'User {username} deleted successfully.'})
    
    except Exception as e:
        logger.error(f"Error deleting user: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)


@login_required
@require_http_methods(["POST"])
def user_reset_password(request, pk):
    """Reset user password."""
    if not request.user.is_staff:
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    try:
        user = get_object_or_404(User, pk=pk)
        
        # Generate random password
        import secrets
        import string
        alphabet = string.ascii_letters + string.digits
        new_password = ''.join(secrets.choice(alphabet) for _ in range(12))
        
        user.set_password(new_password)
        user.save()
        
        logger.info(f"Password reset for user {user.username} by {request.user.username}")
        
        return JsonResponse({'success': True, 'new_password': new_password})
    
    except Exception as e:
        logger.error(f"Error resetting password: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)


@login_required
def user_activity(request, pk=None):
    """View detailed activity for a specific user."""
    from django.db.models import Count
    from datetime import timedelta
    
    if pk:
        user = get_object_or_404(User, pk=pk)
        if not request.user.is_staff and request.user.id != user.id:
            messages.error(request, 'Permission denied.')
            return redirect('cti_core:dashboard')
    else:
        user = request.user
    
    # Get user activity statistics
    alerts_handled = Alert.objects.filter(assigned_to=user).count()
    alerts_resolved = Alert.objects.filter(assigned_to=user, status='Resolved').count()
    alerts_acknowledged = Alert.objects.filter(assigned_to=user, status='Acknowledged').count()
    alerts_investigating = Alert.objects.filter(assigned_to=user, status='Investigating').count()
    
    resolution_rate = 0
    if alerts_handled > 0:
        resolution_rate = round((alerts_resolved / alerts_handled) * 100, 1)
    
    # Recent alerts (last 7 days)
    week_ago = timezone.now() - timedelta(days=7)
    recent_alerts = Alert.objects.filter(
        assigned_to=user,
        created_at__gte=week_ago
    ).order_by('-created_at')[:20]
    
    # Campaigns involved
    campaigns = ThreatCampaign.objects.filter(
        alerts__assigned_to=user
    ).distinct()[:10]
    
    # Daily activity chart data (last 30 days)
    daily_activity = []
    for i in range(30, -1, -1):
        day_start = timezone.now() - timedelta(days=i)
        day_end = day_start + timedelta(days=1)
        count = Alert.objects.filter(
            assigned_to=user,
            created_at__gte=day_start,
            created_at__lt=day_end
        ).count()
        daily_activity.append({
            'date': day_start.strftime('%Y-%m-%d'),
            'count': count
        })
    
    context = {
        'target_user': user,
        'is_own_profile': request.user.id == user.id,
        'alerts_handled': alerts_handled,
        'alerts_resolved': alerts_resolved,
        'alerts_acknowledged': alerts_acknowledged,
        'alerts_investigating': alerts_investigating,
        'resolution_rate': resolution_rate,
        'recent_alerts': recent_alerts,
        'campaigns': campaigns,
        'daily_activity_json': json.dumps(daily_activity[-14:]),
    }
    return render(request, 'cti_core/user_activity.html', context)


@login_required
def users_export(request):
    """Export users to CSV."""
    import csv
    
    if not request.user.is_staff:
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    users = User.objects.all()
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="users_export.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['Username', 'Email', 'First Name', 'Last Name', 'Staff', 'Active', 'Last Login', 'Date Joined'])
    
    for user in users:
        writer.writerow([
            user.username,
            user.email,
            user.first_name,
            user.last_name,
            'Yes' if user.is_staff else 'No',
            'Yes' if user.is_active else 'No',
            user.last_login.strftime('%Y-%m-%d %H:%M:%S') if user.last_login else '',
            user.date_joined.strftime('%Y-%m-%d %H:%M:%S')
        ])
    
    return response

# Add to views.py (replace existing threat hunting views with these)

@login_required
def threat_hunting(request):
    """Display threat hunting interface with saved queries."""
    from django.core.cache import cache  # Ensure cache is imported
    
    # Get user's saved queries
    saved_queries_list = []
    cache_key = f"hunting_queries_{request.user.id}"
    
    try:
        saved_queries_list = cache.get(cache_key, [])
        if saved_queries_list is None:
            saved_queries_list = []
    except Exception as e:
        logger.error(f"Cache error in threat_hunting: {e}")
        saved_queries_list = []
    
    context = {
        'saved_queries': saved_queries_list,
        'indicator_types': ThreatIndicator.INDICATOR_TYPE_CHOICES,
        'severities': ThreatIndicator.SEVERITY_CHOICES,
    }
    return render(request, 'cti_core/threat_hunting.html', context)


@login_required
@require_http_methods(["POST"])
def threat_hunting_search(request):
    """Execute threat hunting search query with advanced filtering."""
    try:
        query = request.POST.get('query', '').strip()
        indicator_type = request.POST.get('indicator_type', '')
        severity = request.POST.get('severity', '')
        min_confidence = int(request.POST.get('min_confidence', 0))
        time_range = request.POST.get('time_range', '30')
        
        # Start with all indicators
        indicators = ThreatIndicator.objects.select_related('source', 'campaign').all()
        
        # Apply full-text search if query provided
        if query:
            # Check for special syntax
            if query.startswith('sha256:'):
                hash_value = query.replace('sha256:', '')
                indicators = indicators.filter(indicator_value__icontains=hash_value)
            elif query.startswith('actor:'):
                actor = query.replace('actor:', '')
                indicators = indicators.filter(campaign__threat_actor__icontains=actor)
            elif query.startswith('campaign:'):
                campaign_name = query.replace('campaign:', '')
                indicators = indicators.filter(campaign__name__icontains=campaign_name)
            elif '*' in query:
                # Wildcard search
                pattern = query.replace('*', '%')
                indicators = indicators.filter(indicator_value__like=pattern)
            else:
                # Regular search
                indicators = indicators.filter(
                    Q(indicator_value__icontains=query) |
                    Q(context__icontains=query) |
                    Q(tags__icontains=query)
                )
        
        # Apply filters
        if indicator_type:
            indicators = indicators.filter(indicator_type=indicator_type)
        if severity:
            indicators = indicators.filter(severity=severity)
        if min_confidence > 0:
            indicators = indicators.filter(confidence__gte=min_confidence / 100)
        
        # Apply time range
        if time_range != 'all':
            cutoff_date = timezone.now() - timedelta(days=int(time_range))
            indicators = indicators.filter(last_seen__gte=cutoff_date)
        
        # Get related campaigns
        campaign_ids = indicators.values_list('campaign_id', flat=True).distinct()
        campaigns = ThreatCampaign.objects.filter(id__in=campaign_ids)[:10]
        
        # Limit results
        indicators = indicators[:100]
        
        context = {
            'query': query,
            'indicators': indicators,
            'campaigns': campaigns,
            'results_count': indicators.count(),
        }
        
        # Return partial for HTMX
        if request.headers.get('HX-Request'):
            return render(request, 'cti_core/partials/hunting_results.html', context)
        
        return render(request, 'cti_core/threat_hunting.html', context)
    
    except Exception as e:
        logger.error(f"Threat hunting error: {str(e)}", exc_info=True)
        return JsonResponse({'error': str(e)}, status=400)


@login_required
@require_http_methods(["POST"])
def save_hunting_query(request):
    """Save a threat hunting query for later use."""
    try:
        import json
        data = json.loads(request.body)
        
        query = data.get('query', '')
        filters = data.get('filters', {})
        
        if not query:
            return JsonResponse({'error': 'Query cannot be empty'}, status=400)
        
        # Store in cache or database
        cache_key = f"hunting_queries_{request.user.id}"
        saved_queries = cache.get(cache_key, [])
        
        # Check for duplicate
        for q in saved_queries:
            if q.get('query') == query:
                return JsonResponse({'error': 'Query already saved'}, status=400)
        
        # Add new query
        saved_queries.insert(0, {
            'id': len(saved_queries) + 1,
            'query': query,
            'filters': filters,
            'created_at': timezone.now().isoformat()
        })
        
        # Keep only last 20 queries
        saved_queries = saved_queries[:20]
        cache.set(cache_key, saved_queries, 30 * 24 * 3600)  # 30 days
        
        logger.info(f"User {request.user.username} saved query: {query}")
        return JsonResponse({'success': True, 'message': 'Query saved successfully'})
    
    except Exception as e:
        logger.error(f"Save query error: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)


@login_required
def saved_queries(request):
    """Get saved hunting queries for the current user."""
    try:
        cache_key = f"hunting_queries_{request.user.id}"
        saved_queries = cache.get(cache_key, [])
        
        return JsonResponse({'queries': saved_queries})
    
    except Exception as e:
        logger.error(f"Get saved queries error: {str(e)}")
        return JsonResponse({'queries': [], 'error': str(e)})


@login_required
@require_http_methods(["DELETE"])
def delete_saved_query(request, query_id):
    """Delete a saved hunting query."""
    try:
        cache_key = f"hunting_queries_{request.user.id}"
        saved_queries = cache.get(cache_key, [])
        
        # Filter out the query to delete
        saved_queries = [q for q in saved_queries if q.get('id') != query_id]
        cache.set(cache_key, saved_queries, 30 * 24 * 3600)
        
        return JsonResponse({'success': True})
    
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
def load_saved_query(request, query_id):
    """Load and execute a saved query."""
    try:
        cache_key = f"hunting_queries_{request.user.id}"
        saved_queries = cache.get(cache_key, [])
        
        # Find the query
        saved_query = None
        for q in saved_queries:
            if q.get('id') == query_id:
                saved_query = q
                break
        
        if not saved_query:
            return JsonResponse({'error': 'Query not found'}, status=404)
        
        # Execute the saved query
        query = saved_query.get('query', '')
        filters = saved_query.get('filters', {})
        
        indicators = ThreatIndicator.objects.select_related('source', 'campaign').all()
        
        if query:
            indicators = indicators.filter(
                Q(indicator_value__icontains=query) |
                Q(context__icontains=query) |
                Q(tags__icontains=query)
            )
        
        if filters.get('indicator_type'):
            indicators = indicators.filter(indicator_type=filters['indicator_type'])
        if filters.get('severity'):
            indicators = indicators.filter(severity=filters['severity'])
        if filters.get('min_confidence'):
            min_conf = int(filters['min_confidence']) / 100
            indicators = indicators.filter(confidence__gte=min_conf)
        if filters.get('time_range') and filters['time_range'] != 'all':
            cutoff_date = timezone.now() - timedelta(days=int(filters['time_range']))
            indicators = indicators.filter(last_seen__gte=cutoff_date)
        
        campaign_ids = indicators.values_list('campaign_id', flat=True).distinct()
        campaigns = ThreatCampaign.objects.filter(id__in=campaign_ids)[:10]
        
        context = {
            'query': query,
            'indicators': indicators[:100],
            'campaigns': campaigns,
            'results_count': indicators.count(),
        }
        
        return render(request, 'cti_core/partials/hunting_results.html', context)
    
    except Exception as e:
        logger.error(f"Load saved query error: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)


@login_required
def threat_hunting_suggestions(request):
    """Get search suggestions for autocomplete."""
    try:
        q = request.GET.get('q', '').strip()
        if len(q) < 2:
            return JsonResponse([], safe=False)
        
        # Get matching indicator values
        suggestions = list(
            ThreatIndicator.objects.filter(
                Q(indicator_value__icontains=q) |
                Q(tags__icontains=q)
            ).values_list('indicator_value', flat=True).distinct()[:10]
        )
        
        # Add campaign suggestions
        campaigns = list(
            ThreatCampaign.objects.filter(name__icontains=q).values_list('name', flat=True)[:5]
        )
        
        # Add threat actor suggestions
        actors = list(
            ThreatCampaign.objects.filter(threat_actor__icontains=q)
            .exclude(threat_actor__isnull=True)
            .values_list('threat_actor', flat=True).distinct()[:5]
        )
        
        results = {
            'indicators': suggestions,
            'campaigns': campaigns,
            'actors': actors
        }
        
        return JsonResponse(results)
    
    except Exception as e:
        return JsonResponse([], safe=False)


@login_required
def threat_hunting_export(request):
    """Export threat hunting results to CSV."""
    try:
        import csv
        
        query = request.GET.get('query', '')
        indicator_type = request.GET.get('indicator_type', '')
        severity = request.GET.get('severity', '')
        
        indicators = ThreatIndicator.objects.all()
        
        if query:
            indicators = indicators.filter(indicator_value__icontains=query)
        if indicator_type:
            indicators = indicators.filter(indicator_type=indicator_type)
        if severity:
            indicators = indicators.filter(severity=severity)
        
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="threat_hunt_{timezone.now().strftime("%Y%m%d_%H%M%S")}.csv"'
        
        writer = csv.writer(response)
        writer.writerow(['Indicator Type', 'Indicator Value', 'Severity', 'Confidence', 'Campaign', 'First Seen', 'Last Seen', 'Tags'])
        
        for ind in indicators[:500]:
            writer.writerow([
                ind.indicator_type,
                ind.indicator_value,
                ind.severity,
                f"{ind.confidence:.0%}",
                ind.campaign.name if ind.campaign else '',
                ind.first_seen.strftime('%Y-%m-%d %H:%M:%S'),
                ind.last_seen.strftime('%Y-%m-%d %H:%M:%S'),
                ind.tags or ''
            ])
        
        return response
    
    except Exception as e:
        logger.error(f"Export error: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.contrib import messages
from django.utils import timezone
from django.db.models import Count, Q
from datetime import timedelta
import json
import logging

from .models import ThreatIndicator, ThreatCampaign, Alert, ThreatFeed
from .reporting_service import ReportingService


@login_required
def reports_list(request):
    """Display available reports with statistics."""
    from django.db.models import Count
    
    # Get recent report statistics
    last_24h = timezone.now() - timedelta(hours=24)
    last_7d = timezone.now() - timedelta(days=7)
    
    context = {
        'report_types': [
            {'name': 'Daily Report', 'description': 'Summary of last 24 hours', 'type': 'daily', 'icon': '📅'},
            {'name': 'Weekly Report', 'description': 'Summary of last 7 days', 'type': 'weekly', 'icon': '📈'},
            {'name': 'Monthly Report', 'description': '30-day threat analysis', 'type': 'monthly', 'icon': '📆'},
            {'name': 'Campaign Report', 'description': 'Detailed campaign analysis', 'type': 'campaign', 'icon': '🎯'},
            {'name': 'Threat Actor Profile', 'description': 'Threat actor analysis', 'type': 'threat_actor', 'icon': '🦹'},
        ],
        'stats': {
            'indicators_24h': ThreatIndicator.objects.filter(created_at__gte=last_24h).count(),
            'alerts_24h': Alert.objects.filter(created_at__gte=last_24h).count(),
            'campaigns_7d': ThreatCampaign.objects.filter(created_at__gte=last_7d).count(),
            'total_indicators': ThreatIndicator.objects.count(),
        }
    }
    return render(request, 'cti_core/reports.html', context)


@login_required
@require_http_methods(["POST"])
def generate_report(request):
    """Generate a threat report with professional formatting."""
    try:
        report_type = request.POST.get('report_type', 'daily')
        report_format = request.POST.get('format', 'pdf')
        date_range = request.POST.get('date_range', '30')
        
        # Get custom dates if provided
        start_date = request.POST.get('start_date')
        end_date = request.POST.get('end_date')
        
        from .reporting_service import ReportingService
        
        # Route to appropriate report generator
        if report_type == 'daily':
            result = ReportingService.generate_daily_report(report_format)
            
        elif report_type == 'weekly':
            result = ReportingService.generate_weekly_report(report_format)
            
        elif report_type == 'monthly':
            result = ReportingService.generate_monthly_report(report_format)
            
        elif report_type == 'campaign':
            campaign_id = request.POST.get('campaign_id')
            if not campaign_id:
                messages.error(request, 'Campaign ID is required for campaign report')
                return redirect('cti_core:reports_list')
            campaign = get_object_or_404(ThreatCampaign, id=campaign_id)
            result = ReportingService.generate_campaign_report(campaign, report_format)
            
        elif report_type == 'threat_actor':
            threat_actor = request.POST.get('threat_actor')
            if not threat_actor:
                messages.error(request, 'Threat actor name is required')
                return redirect('cti_core:reports_list')
            result = ReportingService.generate_threat_actor_report(threat_actor, report_format)
            
        else:
            messages.error(request, f'Unknown report type: {report_type}')
            return redirect('cti_core:reports_list')
        
        # Handle response based on format
        if report_format == 'pdf':
            # PDF response - result should be HttpResponse object
            if isinstance(result, HttpResponse):
                return result
            elif isinstance(result, dict) and 'content' in result:
                response = HttpResponse(result['content'], content_type='application/pdf')
                response['Content-Disposition'] = f'attachment; filename="{report_type}_report_{timezone.now().strftime("%Y%m%d_%H%M%S")}.pdf"'
                return response
            else:
                messages.error(request, 'PDF generation failed')
                
        elif report_format == 'html':
            # HTML response - return as file download or display
            if isinstance(result, dict) and 'html_content' in result:
                response = HttpResponse(result['html_content'], content_type='text/html')
                response['Content-Disposition'] = f'attachment; filename="{report_type}_report_{timezone.now().strftime("%Y%m%d_%H%M%S")}.html"'
                return response
            else:
                messages.error(request, 'HTML generation failed')
                
        elif report_format == 'json':
            # JSON response
            if isinstance(result, dict):
                return JsonResponse(result, safe=False)
            else:
                return JsonResponse({'error': 'Invalid data format'}, status=500)
                
        elif report_format == 'csv':
            # CSV response
            if isinstance(result, dict) and 'csv_content' in result:
                response = HttpResponse(result['csv_content'], content_type='text/csv')
                response['Content-Disposition'] = f'attachment; filename="{report_type}_report_{timezone.now().strftime("%Y%m%d_%H%M%S")}.csv"'
                return response
            else:
                messages.error(request, 'CSV generation failed')
        else:
            messages.error(request, f'Unsupported format: {report_format}')
        
        return redirect('cti_core:reports_list')
    
    except Exception as e:
        logger.error(f"Report generation error: {str(e)}", exc_info=True)
        messages.error(request, f'Error generating report: {str(e)}')
        return redirect('cti_core:reports_list')


@login_required
@require_http_methods(["POST"])
def schedule_report(request):
    """Schedule a recurring report."""
    import json
    from django.core.cache import cache
    
    try:
        report_type = request.POST.get('schedule_report_type', 'daily')
        frequency = request.POST.get('schedule_frequency', 'daily')
        recipients = request.POST.get('schedule_recipients', '')
        report_format = request.POST.get('schedule_format', 'pdf')
        
        # Validate recipients
        if not recipients:
            messages.error(request, 'At least one recipient email is required')
            return redirect('cti_core:reports_list')
        
        # Create schedule in database (simplified - store in cache for demo)
        schedule_key = f"report_schedule_{request.user.id}_{report_type}"
        
        schedule_data = {
            'report_type': report_type,
            'frequency': frequency,
            'recipients': recipients.split(','),
            'format': report_format,
            'created_at': timezone.now().isoformat(),
            'next_run': timezone.now().isoformat(),
            'active': True
        }
        
        cache.set(schedule_key, schedule_data, 30 * 24 * 3600)  # 30 days
        
        messages.success(request, f'Report scheduled successfully. {report_type} reports will be sent {frequency}.')
        
    except Exception as e:
        logger.error(f"Schedule error: {str(e)}")
        messages.error(request, f'Failed to schedule report: {str(e)}')
    
    return redirect('cti_core:reports_list')


@login_required
def get_scheduled_reports(request):
    """API endpoint to get scheduled reports."""
    from django.core.cache import cache
    
    schedules = []
    schedule_keys = ['daily', 'weekly', 'monthly']
    
    for report_type in schedule_keys:
        key = f"report_schedule_{request.user.id}_{report_type}"
        data = cache.get(key)
        if data:
            schedules.append({
                'id': f"{report_type}_{request.user.id}",
                'type': report_type,
                'frequency': data.get('frequency', 'daily'),
                'recipients': ','.join(data.get('recipients', [])),
                'format': data.get('format', 'pdf'),
                'next_run': data.get('next_run', '')
            })
    
    return JsonResponse(schedules, safe=False)


@login_required
@require_http_methods(["DELETE"])
def delete_scheduled_report(request, schedule_id):
    """Delete a scheduled report."""
    from django.core.cache import cache
    
    try:
        key = f"report_schedule_{request.user.id}_{schedule_id}"
        cache.delete(key)
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@login_required
def get_recent_reports(request):
    """API endpoint to get list of recent reports."""
    # In production, this would query a database table
    # For demo, return some sample data
    
    sample_reports = [
        {
            'id': '1',
            'name': 'Daily Threat Report',
            'type': 'daily',
            'format': 'pdf',
            'created_at': (timezone.now() - timedelta(hours=2)).isoformat(),
            'download_url': '/cti/reports/download/1/'
        },
        {
            'id': '2',
            'name': 'Weekly Threat Summary',
            'type': 'weekly',
            'format': 'pdf',
            'created_at': (timezone.now() - timedelta(days=2)).isoformat(),
            'download_url': '/cti/reports/download/2/'
        },
    ]
    
    return JsonResponse(sample_reports, safe=False)


@login_required
def download_report(request, report_id):
    """Download a generated report."""
    # In production, retrieve actual file from storage
    # For now, return a message
    
    messages.warning(request, f'Report {report_id} download not implemented yet. This feature will be available in production.')
    return redirect('cti_core:reports_list')


@login_required
def report_templates(request):
    """Manage report templates."""
    context = {
        'templates': [
            {
                'name': 'Executive Summary',
                'description': 'High-level overview for management',
                'sections': ['Key Metrics', 'Trend Analysis', 'Recommendations']
            },
            {
                'name': 'Technical Report',
                'description': 'Detailed IOCs and TTPs for analysts',
                'sections': ['Indicators', 'Campaigns', 'MITRE ATT&CK']
            },
            {
                'name': 'Compliance Report',
                'description': 'For regulatory requirements',
                'sections': ['Incident Summary', 'Response Actions', 'Compliance Status']
            },
        ]
    }
    return render(request, 'cti_core/report_templates.html', context)


@login_required
def report_preview(request, report_type):
    """Preview a report before generating."""
    from .reporting_service import ReportingService
    
    try:
        if report_type == 'daily':
            result = ReportingService.generate_daily_report('html')
        elif report_type == 'weekly':
            result = ReportingService.generate_weekly_report('html')
        elif report_type == 'monthly':
            result = ReportingService.generate_monthly_report('html')
        else:
            result = {'status': 'error', 'message': 'Unknown report type'}
        
        if isinstance(result, dict) and 'html_content' in result:
            return HttpResponse(result['html_content'], content_type='text/html')
        else:
            return JsonResponse({'error': 'Preview not available'}, status=500)
            
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
def report_history(request):
    """View report generation history."""
    # In production, query ReportHistory model
    context = {
        'reports': [
            {'name': 'Daily Report', 'date': timezone.now() - timedelta(days=1), 'format': 'PDF', 'size': '2.3 MB'},
            {'name': 'Weekly Report', 'date': timezone.now() - timedelta(days=7), 'format': 'PDF', 'size': '5.1 MB'},
        ]
    }
    return render(request, 'cti_core/report_history.html', context)


@login_required
def report_analytics(request):
    """View report analytics and usage statistics."""
    from django.db.models import Count
    
    context = {
        'total_reports': 25,
        'reports_by_type': {
            'daily': 15,
            'weekly': 6,
            'monthly': 2,
            'campaign': 2,
        },
        'reports_by_format': {
            'pdf': 20,
            'html': 3,
            'csv': 2,
        }
    }
    return JsonResponse(context)




@login_required
def anomalies_list(request):
    """Display detected anomalies."""
    try:
        from .ml_services import AnomalyDetectionService
        
        # Run anomaly detection
        recent_indicators = ThreatIndicator.objects.filter(
            is_active=True,
            last_seen__gte=timezone.now() - timedelta(days=7)
        )
        
        result = AnomalyDetectionService.detect_anomalies(recent_indicators)
        
        context = {
            'anomaly_result': result,
            'anomalies': result.get('anomalies', []),
        }
        
        return render(request, 'cti_core/anomalies.html', context)
    
    except Exception as e:
        logger.error(f"Anomaly detection error: {str(e)}")
        context = {'error': str(e)}
        return render(request, 'cti_core/anomalies.html', context)


@login_required
def anomaly_details(request):
    """Get detailed anomaly information."""
    return JsonResponse({'anomalies': []})


@login_required
def ignore_anomaly(request):
    """Ignore a detected anomaly."""
    if request.method == 'POST':
        return JsonResponse({'success': True})
    return JsonResponse({'error': 'Invalid method'}, status=400)


@login_required
def correlation_status(request):
    """Get correlation engine status."""
    return JsonResponse({'status': 'idle', 'last_run': None})


@login_required
def correlation_logs(request):
    """View correlation logs."""
    from .models import CorrelationLog
    logs = CorrelationLog.objects.all().order_by('-created_at')[:50]
    context = {'logs': logs}
    return render(request, 'cti_core/correlation_logs.html', context)


@login_required
def retrain_models(request):
    """Retrain ML models."""
    if request.method == 'POST':
        messages.success(request, 'Model retraining initiated.')
        return JsonResponse({'success': True})
    return JsonResponse({'error': 'Invalid method'}, status=400)


@login_required
def system_health(request):
    """System health check endpoint."""
    return JsonResponse({
        'status': 'healthy',
        'database': 'connected',
        'timestamp': timezone.now().isoformat()
    })


@login_required
def websocket_status(request):
    """WebSocket connection status."""
    return JsonResponse({'websocket': 'available', 'endpoint': '/ws/dashboard/live/'})


@login_required
def activity_logs(request):
    """View system activity logs."""
    context = {'logs': []}
    return render(request, 'cti_core/activity_logs.html', context)


@login_required
def export_activity_logs(request):
    """Export activity logs."""
    return HttpResponse(content_type='text/csv', 
                       headers={'Content-Disposition': 'attachment; filename="activity_logs.csv"'})


# Add these missing view functions to your views.py (after the existing views)

@login_required
def threat_map_anomalies(request):
    """API endpoint for threat map anomalies."""
    try:
        from .ml_services import AnomalyDetectionService
        
        # Get recent indicators for anomaly detection
        recent_indicators = ThreatIndicator.objects.filter(
            is_active=True,
            last_seen__gte=timezone.now() - timedelta(days=7)
        )
        
        result = AnomalyDetectionService.detect_anomalies(recent_indicators)
        
        return JsonResponse({
            'status': 'success',
            'anomalies': result.get('anomalies', []),
            'total_analyzed': result.get('total_analyzed', 0),
            'anomalies_detected': result.get('anomalies_detected', 0)
        })
    except Exception as e:
        logger.error(f"Threat map anomalies error: {str(e)}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@login_required
def indicators_export(request):
    """Export indicators to CSV."""
    import csv
    
    indicators = ThreatIndicator.objects.all().select_related('source', 'campaign')
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="indicators_export.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['ID', 'Type', 'Value', 'Severity', 'Confidence', 'Source', 'Campaign', 'First Seen', 'Last Seen'])
    
    for ind in indicators:
        writer.writerow([
            str(ind.id),
            ind.indicator_type,
            ind.indicator_value,
            ind.severity,
            ind.confidence,
            ind.source.name if ind.source else '',
            ind.campaign.name if ind.campaign else '',
            ind.first_seen.strftime('%Y-%m-%d %H:%M:%S'),
            ind.last_seen.strftime('%Y-%m-%d %H:%M:%S')
        ])
    
    return response


@login_required
@require_http_methods(["POST"])
def indicators_bulk_delete(request):
    """Bulk delete indicators."""
    if not request.user.is_staff:
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    try:
        ids = request.POST.getlist('ids[]')
        if not ids:
            return JsonResponse({'error': 'No IDs provided'}, status=400)
        
        deleted_count, _ = ThreatIndicator.objects.filter(id__in=ids).delete()
        
        return JsonResponse({'success': True, 'deleted_count': deleted_count})
    except Exception as e:
        logger.error(f"Bulk delete error: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)


@login_required
@require_http_methods(["POST"])
def update_indicator_severity(request, pk):
    """Update indicator severity."""
    if not request.user.is_staff:
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    try:
        indicator = get_object_or_404(ThreatIndicator, pk=pk)
        new_severity = request.POST.get('severity')
        
        if new_severity in dict(ThreatIndicator.SEVERITY_CHOICES):
            indicator.severity = new_severity
            indicator.save()
            return JsonResponse({'success': True, 'severity': new_severity})
        
        return JsonResponse({'error': 'Invalid severity'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
def campaigns_export(request):
    """Export campaigns to CSV."""
    import csv
    
    campaigns = ThreatCampaign.objects.annotate(
        indicator_count=Count('indicators'),
        alert_count=Count('alerts')
    )
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="campaigns_export.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['ID', 'Name', 'Status', 'Threat Actor', 'Confidence', 'Indicators', 'Alerts', 'First Seen', 'Last Seen'])
    
    for camp in campaigns:
        writer.writerow([
            str(camp.id),
            camp.name,
            camp.status,
            camp.threat_actor or '',
            camp.confidence_score,
            getattr(camp, 'indicator_count', 0),
            getattr(camp, 'alert_count', 0),
            camp.first_seen.strftime('%Y-%m-%d %H:%M:%S'),
            camp.last_seen.strftime('%Y-%m-%d %H:%M:%S')
        ])
    
    return response


@login_required
@require_http_methods(["POST"])
def merge_campaigns(request, pk):
    """Merge a campaign into another."""
    if not request.user.is_staff:
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    try:
        source_campaign = get_object_or_404(ThreatCampaign, pk=pk)
        target_id = request.POST.get('target_campaign_id')
        
        if not target_id:
            return JsonResponse({'error': 'Target campaign ID required'}, status=400)
        
        target_campaign = get_object_or_404(ThreatCampaign, id=target_id)
        
        # Move all indicators to target campaign
        source_campaign.indicators.update(campaign=target_campaign)
        source_campaign.alerts.update(campaign=target_campaign)
        
        # Delete source campaign
        source_campaign.delete()
        
        return JsonResponse({'success': True, 'merged_into': str(target_campaign.id)})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
def campaign_timeline(request, pk):
    """Get campaign timeline data."""
    campaign = get_object_or_404(ThreatCampaign, pk=pk)
    indicators = campaign.indicators.order_by('first_seen')
    
    timeline = []
    for ind in indicators:
        timeline.append({
            'date': ind.first_seen.strftime('%Y-%m-%d %H:%M:%S'),
            'type': ind.indicator_type,
            'value': ind.indicator_value,
            'severity': ind.severity
        })
    
    return JsonResponse({'timeline': timeline})


@login_required
def alerts_export(request):
    """Export alerts to CSV."""
    import csv
    
    alerts = Alert.objects.select_related('indicator', 'campaign')
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="alerts_export.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['ID', 'Title', 'Severity', 'Status', 'Indicator', 'Campaign', 'Created At'])
    
    for alert in alerts:
        writer.writerow([
            str(alert.id),
            alert.title,
            alert.severity,
            alert.status,
            alert.indicator.indicator_value if alert.indicator else '',
            alert.campaign.name if alert.campaign else '',
            alert.created_at.strftime('%Y-%m-%d %H:%M:%S')
        ])
    
    return response


@login_required
@require_http_methods(["POST"])
def alerts_bulk_acknowledge(request):
    """Bulk acknowledge alerts."""
    if not request.user.is_staff:
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    try:
        ids = request.POST.getlist('ids[]')
        if not ids:
            return JsonResponse({'error': 'No IDs provided'}, status=400)
        
        updated_count = Alert.objects.filter(id__in=ids, status='New').update(
            status='Acknowledged',
            acknowledged_at=timezone.now(),
            assigned_to=request.user
        )
        
        return JsonResponse({'success': True, 'acknowledged_count': updated_count})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
@require_http_methods(["POST"])
def escalate_alert(request, pk):
    """Escalate an alert (mark as Critical)."""
    if not request.user.is_staff:
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    try:
        alert = get_object_or_404(Alert, pk=pk)
        alert.severity = 'Critical'
        alert.status = 'Investigating'
        alert.save()
        
        return JsonResponse({'success': True, 'severity': 'Critical'})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
def test_feed(request):
    """Test a threat feed connection."""
    feed_id = request.GET.get('feed_id')
    if not feed_id:
        return JsonResponse({'error': 'Feed ID required'}, status=400)
    
    feed = get_object_or_404(ThreatFeed, pk=feed_id)
    
    try:
        # Test the feed connection
        import requests
        response = requests.get(feed.source_url, timeout=5)
        
        if response.status_code == 200:
            return JsonResponse({'success': True, 'message': f'Feed {feed.name} is reachable'})
        else:
            return JsonResponse({'success': False, 'message': f'HTTP {response.status_code}'})
    except Exception as e:
        return JsonResponse({'success': False, 'message': str(e)})


@login_required
@require_http_methods(["POST"])
def toggle_feed(request, pk):
    """Toggle feed active status."""
    if not request.user.is_staff:
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    try:
        feed = get_object_or_404(ThreatFeed, pk=pk)
        feed.is_active = not feed.is_active
        feed.save()
        
        return JsonResponse({'success': True, 'is_active': feed.is_active})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
@require_http_methods(["POST"])
def manual_ingest(request, pk):
    """Manually ingest a feed."""
    if not request.user.is_staff:
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    try:
        feed = get_object_or_404(ThreatFeed, pk=pk)
        feed.last_ingested = timezone.now()
        feed.save()
        
        # In production, trigger Celery task here
        return JsonResponse({'success': True, 'message': f'Ingestion started for {feed.name}'})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
def correlation_status(request):
    """Get correlation engine status."""
    from .models import CorrelationLog
    
    last_run = CorrelationLog.objects.order_by('-created_at').first()
    
    return JsonResponse({
        'status': 'idle',
        'last_run': last_run.created_at.isoformat() if last_run else None,
        'total_campaigns': ThreatCampaign.objects.count(),
        'uncorrelated_indicators': ThreatIndicator.objects.filter(campaign__isnull=True).count()
    })


@login_required
def correlation_logs(request):
    """View correlation logs."""
    from .models import CorrelationLog
    
    logs = CorrelationLog.objects.select_related('campaign').order_by('-created_at')[:50]
    
    data = []
    for log in logs:
        data.append({
            'id': str(log.id),
            'campaign_name': log.campaign.name,
            'indicators_count': log.indicators_count,
            'correlation_score': log.correlation_score,
            'method': log.method,
            'created_at': log.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })
    
    return JsonResponse({'logs': data})


@login_required
@require_http_methods(["POST"])
def retrain_models(request):
    """Retrain ML models."""
    if not request.user.is_staff:
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    try:
        # Trigger model retraining (in production, use Celery)
        from .ml_services import AnomalyDetectionService
        
        # Clear cache
        from django.core.cache import cache
        cache.clear()
        
        return JsonResponse({'success': True, 'message': 'Model retraining initiated'})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
def api_keys_list(request):
    """List API keys for the current user."""
    from rest_framework.authtoken.models import Token
    
    tokens = Token.objects.filter(user=request.user)
    data = [{'key': token.key, 'created': token.created.strftime('%Y-%m-%d %H:%M:%S')} for token in tokens]
    
    return JsonResponse({'api_keys': data})


@login_required
@require_http_methods(["POST"])
def api_key_create(request):
    """Create a new API key."""
    from rest_framework.authtoken.models import Token
    
    # Delete old token if exists
    Token.objects.filter(user=request.user).delete()
    
    # Create new token
    token = Token.objects.create(user=request.user)
    
    return JsonResponse({'success': True, 'api_key': token.key})


@login_required
@require_http_methods(["POST"])
def api_key_revoke(request, pk):
    """Revoke an API key."""
    if not request.user.is_staff:
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    from rest_framework.authtoken.models import Token
    
    try:
        token = Token.objects.get(id=pk, user=request.user)
        token.delete()
        return JsonResponse({'success': True})
    except Token.DoesNotExist:
        return JsonResponse({'error': 'Token not found'}, status=404)


@login_required
def websocket_status(request):
    """WebSocket connection status."""
    return JsonResponse({
        'websocket': 'available',
        'endpoint': 'ws://' + request.get_host() + '/ws/dashboard/live/',
        'status': 'active'
    })


@login_required
def activity_logs(request):
    """View system activity logs."""
    # In production, query an ActivityLog model
    return JsonResponse({'logs': [], 'message': 'Activity logging not implemented yet'})


@login_required
def export_activity_logs(request):
    """Export activity logs."""
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="activity_logs.csv"'
    writer = csv.writer(response)
    writer.writerow(['Timestamp', 'User', 'Action', 'Details'])
    
    return response


@login_required
def system_health(request):
    """System health check endpoint."""
    from django.db import connection
    
    # Check database
    db_status = 'healthy'
    try:
        connection.ensure_connection()
    except Exception as e:
        db_status = f'unhealthy: {str(e)}'
    
    return JsonResponse({
        'status': 'healthy',
        'database': db_status,
        'timestamp': timezone.now().isoformat(),
        'version': '2.0.0'
    })



@login_required
def analyst_dashboard(request):
    """
    Comprehensive analyst dashboard with statistics, patterns, and trends.
    """
    from django.db.models import Count, Avg, Q, Sum
    from datetime import datetime, timedelta
    import json
    
    # Get current analyst (requested or current user)
    analyst_id = request.GET.get('user_id', request.user.id)
    analyst = get_object_or_404(User, pk=analyst_id)
    
    # ============================================================
    # BASIC STATISTICS
    # ============================================================
    
    # Alerts handled by this analyst
    alerts_handled = Alert.objects.filter(assigned_to=analyst).count()
    alerts_resolved = Alert.objects.filter(assigned_to=analyst, status='Resolved').count()
    alerts_acknowledged = Alert.objects.filter(assigned_to=analyst, status='Acknowledged').count()
    alerts_investigating = Alert.objects.filter(assigned_to=analyst, status='Investigating').count()
    
    # Response time metrics
    resolved_alerts = Alert.objects.filter(
        assigned_to=analyst,
        status='Resolved',
        resolved_at__isnull=False
    )
    
    avg_response_hours = 0
    if resolved_alerts.exists():
        total_seconds = 0
        for alert in resolved_alerts:
            delta = alert.resolved_at - alert.created_at
            total_seconds += delta.total_seconds()
        avg_response_hours = round(total_seconds / resolved_alerts.count() / 3600, 1)
    
    # ============================================================
    # INDICATORS CONTRIBUTED
    # ============================================================
    
    # CORRECT: Use 'alerts__' (plural) - the related_name from Alert model
    indicators_created = ThreatIndicator.objects.filter(
        alerts__assigned_to=analyst  # <-- Change alert__ to alerts__
    ).distinct().count()
    
    # ============================================================
    # TIME-BASED STATISTICS (Last 30 days)
    # ============================================================
    
    last_30_days = timezone.now() - timedelta(days=30)
    
    # Daily alert volume for charts
    daily_alerts = []
    for i in range(30, -1, -1):
        day_start = timezone.now() - timedelta(days=i)
        day_end = day_start + timedelta(days=1)
        count = Alert.objects.filter(
            assigned_to=analyst,
            created_at__gte=day_start,
            created_at__lt=day_end
        ).count()
        daily_alerts.append({
            'date': day_start.strftime('%Y-%m-%d'),
            'count': count
        })
    
    # Weekly trend (last 4 weeks)
    weekly_trend = []
    for i in range(4, 0, -1):
        week_start = timezone.now() - timedelta(weeks=i)
        week_end = week_start + timedelta(days=7)
        count = Alert.objects.filter(
            assigned_to=analyst,
            created_at__gte=week_start,
            created_at__lt=week_end
        ).count()
        weekly_trend.append({
            'week': f"Week {5-i}",
            'alerts': count
        })
    
    # Severity distribution for this analyst's alerts
    severity_distribution = list(
        Alert.objects.filter(assigned_to=analyst)
        .values('severity')
        .annotate(count=Count('id'))
        .order_by('-count')
    )
    
    # Status distribution
    status_distribution = list(
        Alert.objects.filter(assigned_to=analyst)
        .values('status')
        .annotate(count=Count('id'))
        .order_by('-count')
    )
    
    # ============================================================
    # PATTERNS & INSIGHTS
    # ============================================================
    
    # Most common indicator types this analyst handles
    # CORRECT: Use 'alerts__' (plural)
    common_indicators = list(
        ThreatIndicator.objects.filter(
            alerts__assigned_to=analyst  # <-- Change alert__ to alerts__
        ).values('indicator_type')
        .annotate(count=Count('id'))
        .order_by('-count')[:5]
    )
    
    # Most active times (hourly distribution)
    hourly_distribution = []
    for hour in range(24):
        count = Alert.objects.filter(
            assigned_to=analyst,
            created_at__hour=hour
        ).count()
        hourly_distribution.append({
            'hour': hour,
            'count': count
        })
    
    # Day of week distribution
    day_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
    day_distribution = []
    for i, day in enumerate(day_names):
        count = Alert.objects.filter(
            assigned_to=analyst,
            created_at__week_day=i + 2
        ).count()
        day_distribution.append({
            'day': day,
            'count': count
        })
    
    # ============================================================
    # CAMPAIGN INVOLVEMENT
    # ============================================================
    
    # CORRECT: Use 'alerts__' (plural)
    campaigns_involved = ThreatCampaign.objects.filter(
        alerts__assigned_to=analyst  # <-- This was already correct
    ).distinct().count()
    
    # Most handled threat actors
    top_threat_actors = list(
        ThreatCampaign.objects.filter(
            alerts__assigned_to=analyst
        ).exclude(threat_actor__isnull=True)
        .values('threat_actor')
        .annotate(count=Count('id'))
        .order_by('-count')[:5]
    )
    
    # ============================================================
    # PERFORMANCE METRICS
    # ============================================================
    
    # Resolution rate
    resolution_rate = 0
    if alerts_handled > 0:
        resolution_rate = round((alerts_resolved / alerts_handled) * 100, 1)
    
    # Acknowledgment rate
    ack_rate = 0
    if alerts_handled > 0:
        ack_rate = round(((alerts_acknowledged + alerts_resolved) / alerts_handled) * 100, 1)
    
    # Daily average (last 30 days)
    daily_avg = round(sum(d['count'] for d in daily_alerts[-30:]) / 30, 1)
    
    # Trend direction (comparing last 7 days to previous 7 days)
    last_7 = sum(d['count'] for d in daily_alerts[-7:])
    prev_7 = sum(d['count'] for d in daily_alerts[-14:-7])
    trend_direction = 'up' if last_7 > prev_7 else 'down' if last_7 < prev_7 else 'stable'
    trend_percent = 0
    if prev_7 > 0:
        trend_percent = round(((last_7 - prev_7) / prev_7) * 100, 1)
    
    # ============================================================
    # RANKING (if admin view)
    # ============================================================
    
    all_analysts_ranking = []
    if request.user.is_staff or request.user == analyst:
        all_analysts = User.objects.filter(is_staff=False)
        for u in all_analysts:
            handled = Alert.objects.filter(assigned_to=u).count()
            if handled > 0:
                all_analysts_ranking.append({
                    'id': u.id,
                    'username': u.username,
                    'alerts_handled': handled,
                    'resolution_rate': round((Alert.objects.filter(assigned_to=u, status='Resolved').count() / handled) * 100, 1)
                })
        all_analysts_ranking.sort(key=lambda x: x['alerts_handled'], reverse=True)
    
    # ============================================================
    # CONTEXT
    # ============================================================
    
    context = {
        'analyst': analyst,
        'is_own_profile': request.user.id == analyst.id,
        'is_admin': request.user.is_staff,
        
        # Basic Stats
        'alerts_handled': alerts_handled,
        'alerts_resolved': alerts_resolved,
        'alerts_acknowledged': alerts_acknowledged,
        'alerts_investigating': alerts_investigating,
        'avg_response_hours': avg_response_hours,
        'indicators_created': indicators_created,
        'campaigns_involved': campaigns_involved,
        
        # Performance Metrics
        'resolution_rate': resolution_rate,
        'ack_rate': ack_rate,
        'daily_avg': daily_avg,
        'trend_direction': trend_direction,
        'trend_percent': abs(trend_percent),
        
        # Charts Data
        'daily_alerts_json': json.dumps(daily_alerts[-14:]),
        'weekly_trend_json': json.dumps(weekly_trend),
        'severity_distribution_json': json.dumps(severity_distribution),
        'status_distribution_json': json.dumps(status_distribution),
        'common_indicators_json': json.dumps(common_indicators),
        'hourly_distribution_json': json.dumps(hourly_distribution),
        'day_distribution_json': json.dumps(day_distribution),
        'top_threat_actors_json': json.dumps(top_threat_actors),
        'all_analysts_ranking': all_analysts_ranking,
    }
    
    return render(request, 'cti_core/analyst_dashboard.html', context)


@login_required
def analyst_list(request):
    """List all analysts with their statistics"""
    if not request.user.is_staff:
        messages.error(request, 'Permission denied.')
        return redirect('cti_core:dashboard')
    
    analysts = User.objects.filter(is_staff=False).annotate(
        alerts_count=Count('alert_assigned')
    ).order_by('-alerts_count')
    
    context = {
        'analysts': analysts,
    }
    return render(request, 'cti_core/analyst_list.html', context)

@login_required
def analyst_report_pdf(request, user_id=None):
    """
    Generate professional PDF report for analyst performance.
    """
    from .analyst_report_pdf import AnalystReportGenerator
    
    # Get analyst
    analyst_id = user_id or request.user.id
    analyst = get_object_or_404(User, pk=analyst_id)
    
    # Check permission (admin or own report)
    if not request.user.is_staff and request.user.id != analyst.id:
        messages.error(request, 'Permission denied.')
        return redirect('cti_core:dashboard')
    
    # Gather analyst data (same as dashboard)
    from django.db.models import Count
    
    alerts_handled = Alert.objects.filter(assigned_to=analyst).count()
    alerts_resolved = Alert.objects.filter(assigned_to=analyst, status='Resolved').count()
    alerts_acknowledged = Alert.objects.filter(assigned_to=analyst, status='Acknowledged').count()
    
    resolved_alerts = Alert.objects.filter(
        assigned_to=analyst,
        status='Resolved',
        resolved_at__isnull=False
    )
    
    avg_response_hours = 0
    if resolved_alerts.exists():
        total_seconds = 0
        for alert in resolved_alerts:
            delta = alert.resolved_at - alert.created_at
            total_seconds += delta.total_seconds()
        avg_response_hours = round(total_seconds / resolved_alerts.count() / 3600, 1)
    
    indicators_created = ThreatIndicator.objects.filter(
        alerts__assigned_to=analyst
    ).distinct().count()
    
    campaigns_involved = ThreatCampaign.objects.filter(
        alerts__assigned_to=analyst
    ).distinct().count()
    
    # Severity distribution
    severity_distribution = list(
        Alert.objects.filter(assigned_to=analyst)
        .values('severity')
        .annotate(count=Count('id'))
        .order_by('-count')
    )
    
    # Top threat actors
    top_threat_actors = list(
        ThreatCampaign.objects.filter(
            alerts__assigned_to=analyst
        ).exclude(threat_actor__isnull=True)
        .values('threat_actor')
        .annotate(count=Count('id'))
        .order_by('-count')[:5]
    )
    
    # Daily alerts (last 30 days)
    daily_alerts = []
    for i in range(30, -1, -1):
        day_start = timezone.now() - timedelta(days=i)
        day_end = day_start + timedelta(days=1)
        count = Alert.objects.filter(
            assigned_to=analyst,
            created_at__gte=day_start,
            created_at__lt=day_end
        ).count()
        daily_alerts.append(count)
    
    daily_avg = round(sum(daily_alerts[-30:]) / 30, 1) if daily_alerts else 0
    
    resolution_rate = 0
    if alerts_handled > 0:
        resolution_rate = round((alerts_resolved / alerts_handled) * 100, 1)
    
    analyst_data = {
        'alerts_handled': alerts_handled,
        'alerts_resolved': alerts_resolved,
        'alerts_acknowledged': alerts_acknowledged,
        'alerts_investigating': Alert.objects.filter(assigned_to=analyst, status='Investigating').count(),
        'avg_response_hours': avg_response_hours,
        'resolution_rate': resolution_rate,
        'daily_avg': daily_avg,
        'indicators_created': indicators_created,
        'campaigns_involved': campaigns_involved,
        'severity_distribution': severity_distribution,
        'top_threat_actors': top_threat_actors,
    }
    
    return AnalystReportGenerator.generate(analyst_data, analyst, request)


from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import update_session_auth_hash

@login_required
def profile(request):
    """Display user profile page."""
    from django.db.models import Count
    
    # Get user stats
    alerts_handled = Alert.objects.filter(assigned_to=request.user).count()
    alerts_resolved = Alert.objects.filter(assigned_to=request.user, status='Resolved').count()
    resolution_rate = 0
    if alerts_handled > 0:
        resolution_rate = round((alerts_resolved / alerts_handled) * 100, 1)
    
    context = {
        'alerts_handled': alerts_handled,
        'alerts_resolved': alerts_resolved,
        'resolution_rate': resolution_rate,
    }
    return render(request, 'cti_core/profile.html', context)


@login_required
def change_password(request):
    """Change user password."""
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            # Update session to prevent logout
            update_session_auth_hash(request, user)
            messages.success(request, 'Your password was successfully updated!')
            return redirect('cti_core:profile')
        else:
            messages.error(request, 'Please correct the error below.')
    else:
        form = PasswordChangeForm(request.user)
    
    return render(request, 'cti_core/change_password.html', {'form': form})


@login_required
@require_http_methods(["POST"])
def update_profile(request):
    """Update user profile information."""
    try:
        user = request.user
        user.first_name = request.POST.get('first_name', '')
        user.last_name = request.POST.get('last_name', '')
        user.email = request.POST.get('email', '')
        user.save()
        
        # Update profile if exists
        if hasattr(user, 'profile'):
            user.profile.department = request.POST.get('department', '')
            user.profile.phone_number = request.POST.get('phone_number', '')
            user.profile.save()
        
        messages.success(request, 'Profile updated successfully!')
        return redirect('cti_core:profile')
    except Exception as e:
        messages.error(request, f'Error updating profile: {str(e)}')
        return redirect('cti_core:profile')