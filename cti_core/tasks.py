"""
Celery tasks for CTI module.
Handles asynchronous operations like external feed ingestion, correlation, and anomaly detection.
"""

import logging
from celery import shared_task
from django.utils import timezone
from django.db.models import Q
from django.core.cache import cache

from .models import ThreatFeed, ThreatIndicator, ThreatCampaign, Alert
from .services import CorrelationService, AlertService
from .ml_services import AnomalyDetectionService

logger = logging.getLogger(__name__)


def _is_zimbabwe_indicator(indicator_value: str, indicator_type: str = 'IPv4') -> bool:
    """Heuristic check for Zimbabwe-specific indicators used by tasks ingestion.

    Uses ip-api.com for IPs and TLD check for domains.
    """
    import requests
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



@shared_task(bind=True, max_retries=3)
def ingest_threat_feeds(self):
    """
    Ingest threat data from all active feeds.
    """
    try:
        logger.info("Starting threat feed ingestion from external sources...")
        
        active_feeds = ThreatFeed.objects.filter(is_active=True)
        results = {}
        
        for feed in active_feeds:
            try:
                logger.info(f"Ingesting feed: {feed.name}")
                indicators_created = 0
                
                if feed.name.lower() == 'alienvault otx':
                    from .feed_connector import AlienVaultOTXConnector
                    connector = AlienVaultOTXConnector()
                    indicators_created = connector.ingest_recent_threats(feed)
                    
                elif feed.name.lower() == 'abuseipdb':
                    from .feed_connector import AbuseIPDBConnector
                    connector = AbuseIPDBConnector()
                    indicators_created = connector.ingest_recent_reports(feed)
                    
                elif feed.name.lower() == 'feodo tracker':
                    from .feed_connector import FeodoTrackerConnector
                    connector = FeodoTrackerConnector()
                    indicators_created = connector.ingest_c2_ips(feed)
                    
                elif feed.name.lower() == 'cisa kev':
                    from .feed_connector import CISAKEVConnector
                    connector = CISAKEVConnector()
                    indicators_created = connector.ingest_kev(feed, limit=50)
                    
                else:
                    # Generic feed ingestion - NO AWAIT here (this is not async)
                    indicators_created = ingest_generic_feed(feed)  # Fixed!
                
                feed.last_ingested = timezone.now()
                feed.save(update_fields=['last_ingested'])
                
                results[feed.name] = {
                    'status': 'success',
                    'indicators_created': indicators_created
                }
                
            except Exception as e:
                logger.error(f"Error ingesting {feed.name}: {str(e)}")
                results[feed.name] = {'status': 'error', 'error': str(e)}
        
        cache.delete('dashboard_stats')
        cache.delete('threat_map_cache')
        
        return {
            'status': 'success',
            'feeds_processed': len(active_feeds),
            'results': results
        }
    
    except Exception as exc:
        logger.error(f"Feed ingestion task failed: {str(exc)}")
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))


def ingest_generic_feed(feed: ThreatFeed) -> int:
    """
    Generic feed ingestion for custom JSON/CSV feeds.
    This is a regular function, NOT async.
    """
    import requests
    import json
    
    indicators_created = 0
    
    try:
        headers = {}
        if feed.api_key:
            headers['Authorization'] = f'Bearer {feed.api_key}'
        
        response = requests.get(feed.source_url, headers=headers, timeout=30)
        
        if response.status_code != 200:
            logger.error(f"Failed to fetch feed {feed.name}: HTTP {response.status_code}")
            return 0
        
        # Try to parse as JSON
        try:
            data = response.json()
        except json.JSONDecodeError:
            # Try CSV
            data = response.text
        
        # Process based on feed format
        if feed.feed_type == 'JSON' and isinstance(data, dict):
            indicators = data.get('indicators', data.get('data', []))
            for ind in indicators:
                indicator_value = ind.get('value') or ind.get('indicator') or ind.get('ip')
                indicator_type = ind.get('type', 'IPv4')

                if not indicator_value:
                    continue

                # Skip indicators that are not Zimbabwe-specific
                if not _is_zimbabwe_indicator(indicator_value, indicator_type):
                    continue

                obj, created = ThreatIndicator.objects.update_or_create(
                    indicator_value=indicator_value,
                    defaults={
                        'indicator_type': indicator_type,
                        'source': feed,
                        'confidence': ind.get('confidence', 0.7),
                        'severity': ind.get('severity', 'Medium'),
                        'context': ind.get('description', ''),
                        'tags': ind.get('tags', '')
                    }
                )
                if created:
                    indicators_created += 1
        
        elif feed.feed_type == 'CSV':
            import csv
            from io import StringIO
            
            csv_data = StringIO(response.text)
            reader = csv.DictReader(csv_data)
            
            for row in reader:
                indicator_value = row.get('ip') or row.get('domain') or row.get('indicator')
                if not indicator_value:
                    continue

                # Determine type heuristically
                indicator_type = 'IPv4' if (row.get('ip') or '').strip() else 'Domain'

                if not _is_zimbabwe_indicator(indicator_value, indicator_type):
                    continue

                obj, created = ThreatIndicator.objects.update_or_create(
                    indicator_value=indicator_value,
                    defaults={
                        'indicator_type': indicator_type,
                        'source': feed,
                        'confidence': 0.7,
                        'severity': 'Medium'
                    }
                )
                if created:
                    indicators_created += 1
        
        return indicators_created
        
    except Exception as e:
        logger.error(f"Generic feed ingestion error for {feed.name}: {str(e)}")
        return 0



def ingest_generic_feed(feed: ThreatFeed) -> int:
    """
    Generic feed ingestion for custom JSON/CSV feeds.
    """
    import requests
    import json
    
    indicators_created = 0
    
    try:
        headers = {}
        if feed.api_key:
            headers['Authorization'] = f'Bearer {feed.api_key}'
        
        response = requests.get(feed.source_url, headers=headers, timeout=30)
        
        if response.status_code != 200:
            logger.error(f"Failed to fetch feed {feed.name}: HTTP {response.status_code}")
            return 0
        
        # Try to parse as JSON
        try:
            data = response.json()
        except json.JSONDecodeError:
            # Try CSV
            data = response.text
        
        # Process based on feed format
        if feed.feed_type == 'JSON' and isinstance(data, dict):
            indicators = data.get('indicators', data.get('data', []))
            for ind in indicators:
                indicator_value = ind.get('value') or ind.get('indicator') or ind.get('ip')
                indicator_type = ind.get('type', 'IPv4')

                if not indicator_value:
                    continue

                # Enforce Zimbabwe-only ingestion
                if not _is_zimbabwe_indicator(indicator_value, indicator_type):
                    continue

                obj, created = ThreatIndicator.objects.update_or_create(
                    indicator_value=indicator_value,
                    defaults={
                        'indicator_type': indicator_type,
                        'source': feed,
                        'confidence': ind.get('confidence', 0.7),
                        'severity': ind.get('severity', 'Medium'),
                        'context': ind.get('description', ''),
                        'tags': ind.get('tags', '')
                    }
                )
                if created:
                    indicators_created += 1
        
        elif feed.feed_type == 'CSV':
            import csv
            from io import StringIO
            
            csv_data = StringIO(response.text)
            reader = csv.DictReader(csv_data)
            
            for row in reader:
                indicator_value = row.get('ip') or row.get('domain') or row.get('indicator')
                if not indicator_value:
                    continue

                indicator_type = 'IPv4' if (row.get('ip') or '').strip() else 'Domain'

                if not _is_zimbabwe_indicator(indicator_value, indicator_type):
                    continue

                obj, created = ThreatIndicator.objects.update_or_create(
                    indicator_value=indicator_value,
                    defaults={
                        'indicator_type': indicator_type,
                        'source': feed,
                        'confidence': 0.7,
                        'severity': 'Medium'
                    }
                )
                if created:
                    indicators_created += 1
        
        return indicators_created
        
    except Exception as e:
        logger.error(f"Generic feed ingestion error for {feed.name}: {str(e)}")
        return 0


@shared_task(bind=True, max_retries=3)
def run_correlation_task(self):
    """
    Run threat correlation algorithm using ML.
    Groups related indicators into campaigns.
    """
    try:
        logger.info("Starting AI correlation task...")
        
        # Get uncorrelated indicators
        uncorrelated = ThreatIndicator.objects.filter(
            campaign__isnull=True, 
            is_active=True
        ).select_related('source')
        
        total_uncorrelated = uncorrelated.count()
        logger.info(f"Found {total_uncorrelated} uncorrelated indicators")
        
        if total_uncorrelated < 2:
            logger.info("Not enough indicators for correlation")
            return {
                'status': 'skipped',
                'reason': 'insufficient_data',
                'total_uncorrelated': total_uncorrelated
            }
        
        # Run enhanced correlation with ML
        correlation_service = CorrelationService(eps=0.5, min_samples=2)
        result = correlation_service.correlate_indicators()
        
        # Invalidate cache after correlation
        cache.delete('dashboard_stats')
        cache.delete('threat_map_cache')
        
        # Generate alerts for high-confidence correlated indicators
        new_campaigns = result.get('campaigns_created', [])
        if new_campaigns:
            logger.info(f"Created {len(new_campaigns)} new threat campaigns via ML correlation")
        
        logger.info(f"Correlation completed: {result}")
        return result
    
    except Exception as exc:
        logger.error(f"Correlation task failed: {str(exc)}")
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=3)
def detect_anomalies(self):
    """
    Detect anomalies in threat data using Isolation Forest ML.
    """
    try:
        logger.info("Starting ML anomaly detection...")
        
        # Get recent indicators
        recent_indicators = ThreatIndicator.objects.filter(
            is_active=True,
            last_seen__gte=timezone.now() - timezone.timedelta(days=7)
        ).select_related('campaign')
        
        if recent_indicators.count() < 5:
            logger.info("Not enough recent data for anomaly detection")
            return {
                'status': 'skipped',
                'reason': 'insufficient_data',
                'total_available': recent_indicators.count()
            }
        
        # Run anomaly detection with Isolation Forest
        result = AnomalyDetectionService.detect_anomalies(recent_indicators)
        
        if result.get('anomalies_detected', 0) > 0:
            logger.info(f"ML anomaly detection found {result['anomalies_detected']} anomalies")
            
            # Invalidate cache so dashboard shows anomalies
            cache.delete('dashboard_stats')
        
        return result
    
    except Exception as exc:
        logger.error(f"Anomaly detection task failed: {str(exc)}")
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=2)
def generate_daily_report(self):
    """
    Generate daily threat intelligence report.
    """
    try:
        logger.info("Generating daily threat report...")
        
        from .reporting_service import ReportingService
        
        report = ReportingService.generate_daily_report('html')
        
        if report.get('status') == 'success':
            logger.info(f"Daily report generated: {report.get('filename', 'unknown')}")
            
            # In production, email the report to stakeholders
            # send_report_email.delay(report)
        
        return report
    
    except Exception as e:
        logger.error(f"Report generation failed: {str(e)}")
        raise self.retry(exc=e, countdown=300)


@shared_task(bind=True, max_retries=2)
def generate_campaign_report(self, campaign_id):
    """
    Generate detailed report for a specific campaign.
    """
    try:
        logger.info(f"Generating campaign report for {campaign_id}...")
        
        from .reporting_service import ReportingService
        
        campaign = ThreatCampaign.objects.get(id=campaign_id)
        report = ReportingService.generate_campaign_report(campaign, 'html')
        
        logger.info(f"Campaign report generated for {campaign.name}")
        return report
    
    except ThreatCampaign.DoesNotExist:
        logger.error(f"Campaign not found: {campaign_id}")
        return {'status': 'error', 'message': 'Campaign not found'}
    
    except Exception as e:
        logger.error(f"Campaign report generation failed: {str(e)}")
        raise self.retry(exc=e, countdown=300)


@shared_task
def cleanup_old_data():
    """
    Clean up old threat data (older than 90 days).
    """
    try:
        logger.info("Starting data cleanup...")
        
        cutoff_date = timezone.now() - timezone.timedelta(days=90)
        
        # Delete old resolved alerts
        deleted_alerts, alert_details = Alert.objects.filter(
            status='Resolved',
            resolved_at__lt=cutoff_date
        ).delete()
        
        # Delete old inactive indicators (older than 180 days)
        older_cutoff = timezone.now() - timezone.timedelta(days=180)
        deleted_indicators, indicator_details = ThreatIndicator.objects.filter(
            is_active=False,
            last_seen__lt=older_cutoff
        ).delete()
        
        logger.info(f"Cleanup completed: deleted {deleted_alerts} alerts and {deleted_indicators} indicators")
        
        return {
            'status': 'success',
            'deleted_alerts': deleted_alerts,
            'deleted_indicators': deleted_indicators,
            'cutoff_date': cutoff_date.isoformat()
        }
    
    except Exception as e:
        logger.error(f"Data cleanup failed: {str(e)}")
        raise


@shared_task
def refresh_threat_intelligence():
    """
    Refresh threat intelligence from all sources.
    This task orchestrates the entire intelligence pipeline.
    """
    try:
        logger.info("Starting full threat intelligence refresh pipeline...")
        
        results = {}
        
        # Step 1: Ingest external feeds
        logger.info("Step 1: Ingesting external feeds...")
        feed_result = ingest_threat_feeds.delay().get(timeout=300)
        results['ingestion'] = feed_result
        
        # Step 2: Run correlation to create campaigns
        logger.info("Step 2: Running correlation...")
        correlation_result = run_correlation_task.delay().get(timeout=300)
        results['correlation'] = correlation_result
        
        # Step 3: Detect anomalies
        logger.info("Step 3: Detecting anomalies...")
        anomaly_result = detect_anomalies.delay().get(timeout=300)
        results['anomaly_detection'] = anomaly_result
        
        # Step 4: Generate daily report
        logger.info("Step 4: Generating daily report...")
        report_result = generate_daily_report.delay().get(timeout=300)
        results['report'] = report_result
        
        logger.info("Full intelligence pipeline completed successfully")
        
        return {
            'status': 'success',
            'pipeline_results': results,
            'timestamp': timezone.now().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Threat intelligence pipeline failed: {str(e)}")
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': timezone.now().isoformat()
        }


@shared_task
def enrich_indicator_geolocation():
    """
    Enrich existing indicators with geolocation data from external APIs.
    This improves map visualization.
    """
    try:
        import requests
        import ipaddress
        
        logger.info("Starting geolocation enrichment...")
        
        # Get indicators without geolocation (IP type)
        indicators = ThreatIndicator.objects.filter(
            indicator_type__in=['IPv4', 'IPv6'],
            is_active=True
        )[:500]  # Limit to 500 per run
        
        enriched_count = 0
        
        for indicator in indicators:
            ip = indicator.indicator_value
            
            # Skip private IPs
            try:
                if ipaddress.ip_address(ip).is_private:
                    continue
            except:
                continue
            
            # Check if we already have geo data in cache
            cache_key = f"geo_{ip}"
            if cache.get(cache_key):
                continue
            
            # Fetch geolocation from free API
            try:
                response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
                if response.status_code == 200:
                    data = response.json()
                    if data.get('status') == 'success':
                        lat = data.get('lat')
                        lng = data.get('lon')
                        country = data.get('countryCode', '')
                        city = data.get('city', '')
                        
                        # Store geolocation info (you'd need to add lat/lng fields to model)
                        # For now, add to context or tags
                        context = f"Geo: {city}, {country} - Lat: {lat}, Lng: {lng}"
                        indicator.context = f"{indicator.context or ''}\n{context}"
                        indicator.save()
                        
                        cache.set(cache_key, {'lat': lat, 'lng': lng}, 86400)  # Cache for 24 hours
                        enriched_count += 1
                        
            except Exception as e:
                logger.debug(f"Geolocation failed for {ip}: {e}")
                continue
        
        logger.info(f"Enriched {enriched_count} indicators with geolocation")
        
        # Invalidate map cache
        cache.delete('threat_map_cache')
        
        return {
            'status': 'success',
            'enriched_count': enriched_count,
            'total_processed': indicators.count()
        }
    
    except Exception as e:
        logger.error(f"Geolocation enrichment failed: {str(e)}")
        return {'status': 'error', 'message': str(e)}


@shared_task
def update_threat_severity_scores():
    """
    Automatically update severity scores based on multiple factors.
    Uses AI/ML scoring internally.
    """
    try:
        logger.info("Updating threat severity scores...")
        
        # Get all active indicators without campaign correlation
        indicators = ThreatIndicator.objects.filter(is_active=True)
        updated_count = 0
        
        for indicator in indicators:
            old_severity = indicator.severity
            
            # Calculate new severity based on multiple factors
            score = 0
            
            # Factor 1: Confidence (0-1)
            score += indicator.confidence * 3
            
            # Factor 2: Alert count (max 2)
            alert_count = indicator.alert_set.count()
            score += min(2, alert_count * 0.5)
            
            # Factor 3: Campaign confidence if any
            if indicator.campaign:
                score += indicator.campaign.confidence_score * 1.5
            
            # Factor 4: Recency (newer = higher score)
            days_since_seen = (timezone.now() - indicator.last_seen).days
            if days_since_seen < 7:
                score += 1
            elif days_since_seen < 30:
                score += 0.5
            
            # Map score to severity
            if score >= 6:
                new_severity = 'Critical'
            elif score >= 4:
                new_severity = 'High'
            elif score >= 2.5:
                new_severity = 'Medium'
            elif score >= 1:
                new_severity = 'Low'
            else:
                new_severity = 'Info'
            
            if new_severity != old_severity:
                indicator.severity = new_severity
                indicator.save()
                updated_count += 1
        
        logger.info(f"Updated severity for {updated_count} indicators")
        
        return {
            'status': 'success',
            'updated_count': updated_count,
            'total_processed': indicators.count()
        }
    
    except Exception as e:
        logger.error(f"Severity update failed: {str(e)}")
        return {'status': 'error', 'message': str(e)}



# Add to tasks.py

@shared_task
def generate_simulated_alerts():
    """
    Generate simulated threat alerts every 3 minutes.
    This keeps the dashboard alive with real-time data.
    """
    from .services import RealTimeAlertSimulator
    
    try:
        logger.info("Generating simulated threat alerts...")
        
        # Generate 1-3 alerts per cycle
        num_alerts = random.randint(1, 3)
        alerts_created = []
        
        for i in range(num_alerts):
            alert, indicator = RealTimeAlertSimulator.create_alert_and_indicator()
            alerts_created.append({
                'id': str(alert.id),
                'title': alert.title,
                'severity': alert.severity,
                'indicator': indicator.indicator_value
            })
            logger.info(f"Created simulated alert: {alert.title}")
        
        # Invalidate cache
        cache.delete('dashboard_stats')
        cache.delete('threat_map_cache')
        
        return {
            'status': 'success',
            'alerts_created': len(alerts_created),
            'alerts': alerts_created
        }
    
    except Exception as e:
        logger.error(f"Simulated alert generation failed: {str(e)}")
        return {'status': 'error', 'message': str(e)}