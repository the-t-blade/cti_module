"""
External threat feed connectors for CTI module.
Integrates AlienVault OTX, AbuseIPDB, Feodo Tracker, and CISA KEV for global threat intelligence.
"""

import logging
import requests
import json
import ipaddress
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from django.utils import timezone
from django.core.cache import cache
from django.conf import settings

from .models import ThreatIndicator, ThreatFeed

logger = logging.getLogger(__name__)


def _is_zimbabwe_indicator(indicator_value: str, indicator_type: str) -> bool:
    """Return True if the indicator appears to be Zimbabwe-specific.

    - IPv4/IPv6: use ip-api.com to check country == Zimbabwe (countryCode 'ZW')
    - Domain: accept if TLD contains '.zw'
    - Others: return False by default
    """
    try:
        if indicator_type in ['IPv4', 'IPv6']:
            try:
                resp = requests.get(f"http://ip-api.com/json/{indicator_value}", timeout=3)
                if resp.status_code == 200:
                    data = resp.json()
                    country = (data.get('country') or '').lower()
                    code = (data.get('countryCode') or '').upper()
                    return 'zimbabwe' in country or code == 'ZW'
            except Exception:
                return False

        if indicator_type == 'Domain' or ('.' in (indicator_value or '')):
            v = indicator_value.lower()
            return v.endswith('.zw') or '.zw' in v

    except Exception:
        return False

    return False


class AlienVaultOTXConnector:
    """
    AlienVault OTX (Open Threat Exchange) connector.
    Free API: 20,000 requests/day, 4 requests/second.
    """
    
    API_URL = "https://otx.alienvault.com/api/v1"
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or getattr(settings, 'ALIENVAULT_OTX_API_KEY', None)
        
        if not self.api_key:
            logger.warning("⚠️ AlienVault OTX API key not found!")
        else:
            logger.info("✅ AlienVault OTX connector initialized")
        
        self.headers = {"X-OTX-API-KEY": self.api_key} if self.api_key else {}
    
    def get_pulses(self, limit: int = 20, page: int = 1) -> List[Dict]:
        """Get recent threat pulses."""
        if not self.api_key:
            return []
        
        url = f"{self.API_URL}/pulses/subscribed"
        params = {"limit": limit, "page": page, "sort": "-modified"}
        
        try:
            response = requests.get(url, headers=self.headers, params=params, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                pulses = data.get('results', [])
                logger.info(f"✅ Fetched {len(pulses)} pulses from OTX")
                return pulses
            elif response.status_code == 401:
                logger.error("❌ OTX API key invalid!")
                return []
            else:
                logger.error(f"❌ OTX API error: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"❌ Error fetching OTX pulses: {str(e)}")
            return []
    
    def get_indicators_from_pulse(self, pulse_id: str) -> List[Dict]:
        """Get indicators from a specific pulse."""
        if not self.api_key or not pulse_id:
            return []
        
        url = f"{self.API_URL}/pulses/{pulse_id}"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=15)
            
            if response.status_code == 200:
                pulse_data = response.json()
                indicators = pulse_data.get('indicators', [])
                return indicators
            elif response.status_code == 404:
                logger.warning(f"⚠️ Pulse {pulse_id} not found")
                
        except Exception as e:
            logger.error(f"❌ Error: {e}")
        
        return []
    
    def get_pulse_indicators_direct(self, pulse_id: str) -> List[Dict]:
        """Alternative method using the pulse/indicators endpoint."""
        url = f"{self.API_URL}/pulses/{pulse_id}/indicators"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=15)
            if response.status_code == 200:
                return response.json().get('indicators', [])
        except Exception as e:
            logger.error(f"Error: {e}")
        
        return []
    
    def get_geoip_data(self, ip: str) -> Optional[Dict]:
        """Get geolocation for IP."""
        if not self.api_key:
            return None
        
        url = f"{self.API_URL}/indicators/IPv4/{ip}/geo"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('latitude') and data.get('longitude'):
                    return {
                        'lat': data['latitude'],
                        'lng': data['longitude'],
                        'country': data.get('country_code', 'Unknown'),
                        'city': data.get('city', '')
                    }
        except Exception:
            pass
        return None
    
    def _get_severity(self, risk_level: str) -> str:
        """Map OTX risk level to severity."""
        risk_map = {
            'high': 'Critical',
            'medium': 'High', 
            'low': 'Medium',
            'info': 'Low'
        }
        return risk_map.get(risk_level.lower() if risk_level else 'medium', 'Medium')
    
    def _map_indicator_type(self, otx_type: str) -> str:
        """Map OTX indicator type to internal type."""
        type_map = {
            'IPv4': 'IPv4',
            'IPv6': 'IPv6',
            'domain': 'Domain',
            'hostname': 'Domain', 
            'URL': 'URL',
            'url': 'URL',
            'email': 'Email',
            'FileHash-MD5': 'FileHash-MD5',
            'FileHash-SHA1': 'FileHash-SHA1',
            'FileHash-SHA256': 'FileHash-SHA256',
            'MD5': 'FileHash-MD5',
            'SHA1': 'FileHash-SHA1',
            'SHA256': 'FileHash-SHA256',
            'CVE': 'CVE'
        }
        return type_map.get(otx_type, 'IPv4')
    
    def ingest_recent_threats(self, feed_obj: ThreatFeed, max_pulses: int = 15) -> int:
        """Ingest recent threats from OTX pulses."""
        if not self.api_key:
            logger.error("❌ No API key configured")
            return 0
        
        logger.info(f"🚀 Starting OTX ingestion...")
        
        pulses = self.get_pulses(limit=max_pulses)
        
        if not pulses:
            logger.warning("⚠️ No pulses found")
            return 0
        
        indicators_created = 0
        
        for pulse in pulses:
            pulse_id = pulse.get('id')
            pulse_name = pulse.get('name', 'Unknown')
            
            if not pulse_id:
                continue
            
            indicators = self.get_indicators_from_pulse(pulse_id)
            
            if not indicators:
                indicators = self.get_pulse_indicators_direct(pulse_id)
            
            for ind in indicators:
                indicator_type = ind.get('indicator_type', '')
                indicator_value = ind.get('indicator')
                
                if not indicator_value:
                    continue
                
                if indicator_type in ['IPv4', 'IPv6']:
                    try:
                        if ipaddress.ip_address(indicator_value).is_private:
                            continue
                    except:
                        pass
                
                mapped_type = self._map_indicator_type(indicator_type)
                confidence = pulse.get('confidence', 70) / 100.0
                confidence = min(0.99, max(0.1, confidence))
                risk_level = pulse.get('risk_level', 'medium')
                severity = self._get_severity(risk_level)
                context = pulse.get('description', '')[:500]
                
                tags = []
                if pulse.get('tags'):
                    tags.extend(pulse['tags'][:3])
                
                try:
                    # Only ingest indicators that are Zimbabwe-specific
                    if not _is_zimbabwe_indicator(indicator_value, mapped_type):
                        continue

                    obj, created = ThreatIndicator.objects.update_or_create(
                        indicator_value=indicator_value,
                        defaults={
                            'indicator_type': mapped_type,
                            'source': feed_obj,
                            'confidence': confidence,
                            'severity': severity,
                            'context': context,
                            'tags': ','.join(tags[:5]) if tags else '',
                            'is_active': True
                        }
                    )

                    if created:
                        indicators_created += 1
                        logger.debug(f"➕ New OTX indicator: {indicator_value}")

                except Exception as e:
                    logger.error(f"Error saving {indicator_value}: {e}")
            
            if indicators:
                logger.info(f"📦 Pulse '{pulse_name}': {len(indicators)} indicators")
        
        logger.info(f"🎉 OTX complete! Created {indicators_created} new indicators")
        return indicators_created


class AbuseIPDBConnector:
    """
    AbuseIPDB connector - reports and geolocation for malicious IPs.
    """
    
    API_URL = "https://api.abuseipdb.com/api/v2"
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or getattr(settings, 'ABUSEIPDB_API_KEY', None)
        
        if not self.api_key:
            logger.warning("⚠️ AbuseIPDB API key not found!")
        
        self.headers = {"Key": self.api_key, "Accept": "application/json"} if self.api_key else {}
    
    def get_recent_reports(self, days: int = 7, limit: int = 100) -> List[Dict]:
        """Get recent abuse reports."""
        if not self.api_key:
            return []
        
        url = f"{self.API_URL}/reports"
        params = {"days": days, "limit": limit, "confidenceMinimum": 50}
        
        try:
            response = requests.get(url, headers=self.headers, params=params, timeout=15)
            if response.status_code == 200:
                return response.json().get('data', [])
            elif response.status_code == 401:
                logger.error("❌ AbuseIPDB authentication failed!")
        except Exception as e:
            logger.error(f"❌ AbuseIPDB error: {e}")
        
        return []
    
    def ingest_recent_reports(self, feed_obj: ThreatFeed, days: int = 3, limit: int = 50) -> int:
        """Ingest recent abuse reports."""
        if not self.api_key:
            return 0
        
        logger.info(f"🚀 Starting AbuseIPDB ingestion...")
        
        reports = self.get_recent_reports(days=days, limit=limit)
        
        if not reports:
            logger.warning("⚠️ No abuse reports found")
            return 0
        
        indicators_created = 0
        
        for report in reports:
            ip = report.get('ipAddress')
            if not ip:
                continue
            
            try:
                if ipaddress.ip_address(ip).is_private:
                    continue
            except:
                pass
            
            confidence = min(0.99, report.get('abuseConfidenceScore', 50) / 100)
            severity = 'Critical' if confidence > 0.8 else 'High' if confidence > 0.6 else 'Medium'
            
            categories = report.get('categories', [])
            
            obj, created = ThreatIndicator.objects.update_or_create(
                indicator_value=ip,
                indicator_type='IPv4',
                defaults={
                    'source': feed_obj,
                    'confidence': confidence,
                    'severity': severity,
                    'context': f"AbuseIPDB: {report.get('totalReports', 0)} reports",
                    'tags': f"abuseipdb,category:{','.join(map(str, categories[:3]))}",
                    'is_active': True
                }
            )
            
            if created:
                indicators_created += 1
                logger.debug(f"➕ Added AbuseIPDB indicator: {ip}")

            # Remove indicators not in Zimbabwe
            if not _is_zimbabwe_indicator(ip, 'IPv4'):
                # If we accidentally created it above, delete it
                if created:
                    try:
                        obj.delete()
                        indicators_created -= 1
                    except Exception:
                        pass
                continue
        
        logger.info(f"🎉 AbuseIPDB complete! Created {indicators_created} new indicators")
        return indicators_created


class FeodoTrackerConnector:
    """
    Feodo Tracker - C2 server intelligence.
    """
    
    def get_c2_ips(self, limit: int = 200) -> List[Dict]:
        """Get list of C2 IPs."""
        url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
        
        try:
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, dict):
                    return data.get('data', data.get('urlhaus', []))[:limit]
                elif isinstance(data, list):
                    return data[:limit]
        except Exception as e:
            logger.error(f"❌ Feodo Tracker error: {e}")
        
        return []
    
    def ingest_c2_ips(self, feed_obj: ThreatFeed, limit: int = 200) -> int:
        """Ingest C2 IPs."""
        logger.info(f"🚀 Starting Feodo Tracker ingestion...")
        
        ips = self.get_c2_ips(limit=limit)
        
        if not ips:
            logger.warning("⚠️ No C2 IPs found")
            return 0
        
        indicators_created = 0
        
        for entry in ips:
            if isinstance(entry, dict):
                ip = entry.get('ip_address') or entry.get('ip')
                malware = entry.get('malware') or entry.get('malware_family', 'Unknown')
            else:
                continue
            
            if not ip:
                continue
            
            try:
                if ipaddress.ip_address(ip).is_private:
                    continue
            except:
                pass
            
            obj, created = ThreatIndicator.objects.update_or_create(
                indicator_value=ip,
                indicator_type='IPv4',
                defaults={
                    'source': feed_obj,
                    'confidence': 0.95,
                    'severity': 'Critical',
                    'context': f"Command & Control (C2) server - Malware: {malware}",
                    'tags': f"c2,feodo,malware:{malware[:30]}",
                    'is_active': True
                }
            )
            
            if created:
                indicators_created += 1
                logger.debug(f"➕ Added C2 indicator: {ip}")

            # Remove/skip non-Zimbabwe C2 IPs
            if not _is_zimbabwe_indicator(ip, 'IPv4'):
                if created:
                    try:
                        obj.delete()
                        indicators_created -= 1
                    except Exception:
                        pass
                continue
        
        logger.info(f"🎉 Feodo Tracker complete! Created {indicators_created} new indicators")
        return indicators_created


# ============================================================
# CISA KEV CONNECTOR - ADD THIS CLASS
# ============================================================

class CISAKEVConnector:
    """
    CISA Known Exploited Vulnerabilities feed.
    Free, no API key required.
    Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
    """
    
    def fetch_kev(self) -> List[Dict]:
        """Fetch CISA Known Exploited Vulnerabilities."""
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        
        try:
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                logger.info(f"✅ Fetched {len(vulnerabilities)} vulnerabilities from CISA KEV")
                return vulnerabilities
            else:
                logger.error(f"❌ CISA KEV returned HTTP {response.status_code}")
                return []
        except Exception as e:
            logger.error(f"❌ CISA KEV error: {e}")
            return []
    
    def ingest_kev(self, feed_obj: ThreatFeed, limit: int = 100) -> int:
        """
        Ingest CISA KEV indicators into database.
        
        Args:
            feed_obj: ThreatFeed database object
            limit: Maximum number of CVEs to ingest
            
        Returns:
            Number of new indicators created
        """
        logger.info(f"🚀 Starting CISA KEV ingestion...")
        
        vulnerabilities = self.fetch_kev()
        
        if not vulnerabilities:
            logger.warning("⚠️ No CISA KEV data found")
            return 0
        
        indicators_created = 0
        indicators_skipped = 0
        
        for vuln in vulnerabilities[:limit]:
            cve_id = vuln.get('cveID')
            if not cve_id:
                continue
            
            # Check if already exists
            if ThreatIndicator.objects.filter(indicator_value=cve_id, indicator_type='CVE').exists():
                indicators_skipped += 1
                continue
            
            # Get vulnerability details
            description = vuln.get('shortDescription', '')
            vendor = vuln.get('vendorProject', '')
            product = vuln.get('product', '')
            date_added = vuln.get('dateAdded', '')
            due_date = vuln.get('dueDate', '')
            
            # Build context
            context = f"""CISA Known Exploited Vulnerability
Vendor: {vendor}
Product: {product}
Description: {description}
Date Added to KEV: {date_added}
Required Action Due Date: {due_date}
"""
            
            try:
                obj, created = ThreatIndicator.objects.update_or_create(
                    indicator_value=cve_id,
                    indicator_type='CVE',
                    defaults={
                        'source': feed_obj,
                        'confidence': 0.95,  # High confidence - CISA verified
                        'severity': 'Critical',
                        'context': context[:500],
                        'tags': f"cisa,kev,{vendor},{product},exploited",
                        'is_active': True
                    }
                )
                
                # CISA KEV vulnerabilities are global and not country-specific.
                # Skip ingesting these when enforcing Zimbabwe-only threat data.
                indicators_skipped += 1
                    
            except Exception as e:
                logger.error(f"❌ Error saving {cve_id}: {e}")
        
        logger.info(f"🎉 CISA KEV complete! Created {indicators_created} new indicators (skipped {indicators_skipped})")
        return indicators_created


class GlobalThreatIngestionService:
    """
    Master service to ingest from all external threat feeds.
    """
    
    @staticmethod
    def run_full_ingestion() -> Dict[str, int]:
        """Run ingestion from all external sources."""
        results = {}
        
        # Get or create feed objects
        alienvault_feed, _ = ThreatFeed.objects.get_or_create(
            name="AlienVault OTX",
            defaults={
                'description': "AlienVault Open Threat Exchange",
                'source_url': "https://otx.alienvault.com",
                'feed_type': 'API',
                'is_active': True
            }
        )
        
        abuseipdb_feed, _ = ThreatFeed.objects.get_or_create(
            name="AbuseIPDB",
            defaults={
                'description': "AbuseIPDB - IP reputation",
                'source_url': "https://abuseipdb.com",
                'feed_type': 'API',
                'is_active': True
            }
        )
        
        feodo_feed, _ = ThreatFeed.objects.get_or_create(
            name="Feodo Tracker",
            defaults={
                'description': "Feodo Tracker - C2 servers",
                'source_url': "https://feodotracker.abuse.ch",
                'feed_type': 'API',
                'is_active': True
            }
        )
        
        # CISA KEV Feed
        cisa_feed, _ = ThreatFeed.objects.get_or_create(
            name="CISA KEV",
            defaults={
                'description': "CISA Known Exploited Vulnerabilities Catalog",
                'source_url': "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                'feed_type': 'API',
                'is_active': True
            }
        )
        
        # Ingest from AlienVault OTX
        if getattr(settings, 'ALIENVAULT_OTX_API_KEY', None):
            try:
                otx = AlienVaultOTXConnector()
                results['alienvault'] = otx.ingest_recent_threats(alienvault_feed, max_pulses=15)
            except Exception as e:
                logger.error(f"AlienVault failed: {e}")
                results['alienvault'] = 0
        else:
            results['alienvault'] = 0
        
        # Ingest from AbuseIPDB
        if getattr(settings, 'ABUSEIPDB_API_KEY', None):
            try:
                abuse = AbuseIPDBConnector()
                results['abuseipdb'] = abuse.ingest_recent_reports(abuseipdb_feed, days=3, limit=50)
            except Exception as e:
                logger.error(f"AbuseIPDB failed: {e}")
                results['abuseipdb'] = 0
        else:
            results['abuseipdb'] = 0
        
        # Ingest from Feodo Tracker
        try:
            feodo = FeodoTrackerConnector()
            results['feodotracker'] = feodo.ingest_c2_ips(feodo_feed, limit=150)
        except Exception as e:
            logger.error(f"Feodo failed: {e}")
            results['feodotracker'] = 0
        
        # Ingest from CISA KEV
        try:
            cisa = CISAKEVConnector()
            results['cisa_kev'] = cisa.ingest_kev(cisa_feed, limit=100)
        except Exception as e:
            logger.error(f"CISA KEV failed: {e}")
            results['cisa_kev'] = 0
        
        # Update timestamps
        for feed in [alienvault_feed, abuseipdb_feed, feodo_feed, cisa_feed]:
            feed.last_ingested = timezone.now()
            feed.save(update_fields=['last_ingested'])
        
        # Invalidate cache
        cache.delete('dashboard_stats')
        cache.delete('threat_map_cache')
        
        total = sum(results.values())
        logger.info(f"🎉 Global ingestion complete! Total new: {total}")
        logger.info(f"📊 Results: {results}")
        
        return results