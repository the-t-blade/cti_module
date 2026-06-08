"""
Enhanced AI/ML Services for Threat Intelligence Correlation.
Complete integration of DBSCAN clustering, NLP, anomaly detection, and predictive analytics.
"""

import logging
import re
import hashlib
from typing import List, Dict, Any, Optional, Tuple
from datetime import timedelta
from collections import Counter
from functools import lru_cache

import numpy as np
from sklearn.cluster import DBSCAN, OPTICS
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from django.utils import timezone
from django.core.cache import cache
from django.db.models import Count, Q

from .models import ThreatIndicator, ThreatCampaign, Alert, CorrelationLog

logger = logging.getLogger(__name__)


class CorrelationService:
    """
    Core AI/ML Correlation Service for threat intelligence.
    Implements DBSCAN clustering, NLP entity extraction, and campaign detection.
    """
    
    def __init__(self, eps=0.5, min_samples=2):
        """
        Initialize the correlation service.
        
        Args:
            eps: DBSCAN epsilon parameter (distance threshold)
            min_samples: DBSCAN min_samples parameter
        """
        self.eps = eps
        self.min_samples = min_samples
        self.scaler = StandardScaler()
        self.vectorizer = TfidfVectorizer(max_features=50, stop_words='english')
        
        self.severity_map = {'Critical': 5, 'High': 4, 'Medium': 3, 'Low': 2, 'Info': 1}
        self.type_weights = {
            'IPv4': 0.3, 'IPv6': 0.3, 'Domain': 0.4, 'URL': 0.35,
            'FileHash-MD5': 0.5, 'FileHash-SHA1': 0.5, 'FileHash-SHA256': 0.6,
            'Email': 0.25, 'YARA': 0.7, 'Malware': 0.8,
        }

    def extract_entities_from_text(self, text: str) -> Dict[str, List[str]]:
        """
        Extract IOCs from unstructured text using NLP/Regex.
        
        Returns:
            Dictionary of extracted indicators by type (ipv4, domain, url, email, file_hash, cve)
        """
        extracted = {'ipv4': [], 'ipv6': [], 'domain': [], 'url': [], 'email': [], 'file_hash': [], 'cve': []}
        
        if not text:
            return extracted
        
        # IPv4 pattern
        ipv4_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        for match in re.finditer(ipv4_pattern, text):
            ip = match.group()
            parts = ip.split('.')
            if all(0 <= int(p) <= 255 for p in parts):
                extracted['ipv4'].append(ip)
        
        # Domain pattern
        domain_pattern = r'\b(?:[a-zA-Z0-9][-a-zA-Z0-9]{0,62}\.)+[a-zA-Z]{2,}\b'
        for match in re.finditer(domain_pattern, text):
            domain = match.group().lower()
            if not any(domain.startswith(ip) for ip in extracted['ipv4']):
                extracted['domain'].append(domain)
        
        # URL pattern
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        extracted['url'] = re.findall(url_pattern, text)
        
        # Email pattern
        email_pattern = r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
        extracted['email'] = re.findall(email_pattern, text)
        
        # File hash patterns
        hash_patterns = {
            'md5': r'\b[a-fA-F0-9]{32}\b',
            'sha1': r'\b[a-fA-F0-9]{40}\b',
            'sha256': r'\b[a-fA-F0-9]{64}\b'
        }
        for hash_type, pattern in hash_patterns.items():
            extracted['file_hash'].extend(re.findall(pattern, text))
        
        # CVE pattern
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        extracted['cve'] = re.findall(cve_pattern, text, re.IGNORECASE)
        
        # Remove duplicates
        for key in extracted:
            extracted[key] = list(dict.fromkeys(extracted[key]))
        
        return extracted

    def extract_features(self, indicators) -> np.ndarray:
        """
        Extract multi-dimensional features for ML clustering.
        
        Features: confidence, severity, temporal recency, type weight, source reputation, tag diversity
        """
        features = []
        
        for indicator in indicators:
            confidence = float(indicator.confidence)
            severity = self.severity_map.get(indicator.severity, 3) / 5.0
            type_weight = self.type_weights.get(indicator.indicator_type, 0.3)
            
            hours_since_last = (timezone.now() - indicator.last_seen).total_seconds() / 3600
            recency = max(0, min(1, 1 - (hours_since_last / 168)))
            
            source_reputation = 0.7 if indicator.source and indicator.source.is_active else 0.3
            tag_count = len(indicator.get_tags_list())
            tag_diversity = min(tag_count / 10, 0.5)
            context_length = len(indicator.context or '')
            context_richness = min(context_length / 500, 0.3)
            
            features.append([confidence, severity, type_weight, recency, source_reputation, tag_diversity, context_richness])
        
        return np.array(features)

    def calculate_similarity(self, indicators) -> np.ndarray:
        """Calculate semantic similarity between indicators using TF-IDF."""
        if len(indicators) < 2:
            return np.array([[1.0]])
        
        texts = []
        for ind in indicators:
            text_parts = []
            if ind.tags:
                text_parts.append(ind.tags)
            if ind.context:
                text_parts.append(ind.context[:200])
            texts.append(' '.join(text_parts))
        
        if not any(texts):
            return np.eye(len(indicators))
        
        try:
            tfidf_matrix = self.vectorizer.fit_transform(texts)
            similarity = (tfidf_matrix * tfidf_matrix.T).toarray()
            return similarity
        except Exception:
            return np.eye(len(indicators))

    def correlate_indicators(self, indicators=None) -> Dict[str, Any]:
        """
        Correlate indicators into threat campaigns using DBSCAN clustering.
        
        Returns:
            Dictionary with correlation results and created campaigns.
        """
        from .services import AlertService
        
        if indicators is None:
            indicators = list(ThreatIndicator.objects.filter(is_active=True, campaign__isnull=True)
                             .select_related('source').prefetch_related('alerts'))
        
        total = len(indicators)
        logger.info(f"Correlating {total} uncorrelated indicators")
        
        if total < self.min_samples:
            return {'status': 'skipped', 'reason': 'insufficient_indicators', 'total_processed': total}
        
        try:
            numerical_features = self.extract_features(indicators)
            similarity_matrix = self.calculate_similarity(indicators)
            similarity_scores = similarity_matrix.mean(axis=1) if similarity_matrix.size > 0 else np.zeros(total)
            enhanced_features = np.column_stack([numerical_features, similarity_scores])
            features_scaled = self.scaler.fit_transform(enhanced_features)
            
            clustering = DBSCAN(eps=self.eps, min_samples=self.min_samples).fit(features_scaled)
            labels = clustering.labels_
            
            campaigns_created = []
            unique_labels = set(labels)
            
            for label in unique_labels:
                if label == -1:
                    continue
                
                cluster_indices = np.where(labels == label)[0]
                if len(cluster_indices) < 2:
                    continue
                
                cluster_indicators = [indicators[i] for i in cluster_indices]
                cluster_confidence = np.mean([ind.confidence for ind in cluster_indicators])
                
                campaign = self._create_campaign_from_cluster(cluster_indicators, label, cluster_confidence)
                campaigns_created.append(campaign)
                
                for indicator in cluster_indicators:
                    if indicator.confidence >= 0.7:
                        AlertService.generate_alert_for_indicator(indicator)
                
                self._log_correlation(campaign, cluster_indicators, labels)
            
            result = {
                'status': 'success',
                'campaigns_created': len(campaigns_created),
                'total_clusters': len([l for l in unique_labels if l != -1]),
                'noise_points': int(np.sum(labels == -1)),
                'total_processed': total
            }
            
            logger.info(f"Correlation complete: {result}")
            return result
        
        except Exception as e:
            logger.error(f"Correlation error: {str(e)}", exc_info=True)
            return {'status': 'error', 'message': str(e), 'total_processed': total}

    def _create_campaign_from_cluster(self, indicators, cluster_id, confidence) -> ThreatCampaign:
        """Create a ThreatCampaign from a cluster of indicators."""
        threat_actor = self._extract_threat_actor(indicators)
        tactics = self._extract_tactics(indicators)
        target_sectors = self._extract_target_sectors(indicators)
        
        types = set(ind.indicator_type for ind in indicators)
        severities = set(ind.severity for ind in indicators)
        type_str = '+'.join(sorted(types)[:2])
        severity_str = max(severities, key=lambda x: ['Info', 'Low', 'Medium', 'High', 'Critical'].index(x))
        
        campaign_name = f"{threat_actor + '-' if threat_actor else ''}{severity_str}-{type_str}-{cluster_id}"
        
        campaign = ThreatCampaign.objects.create(
            name=campaign_name,
            description=self._generate_campaign_description(indicators, threat_actor, tactics),
            status='Active',
            threat_actor=threat_actor,
            tactics=tactics,
            target_sectors=target_sectors,
            confidence_score=confidence,
            correlation_method='AI_DBSCAN'
        )
        
        for indicator in indicators:
            indicator.campaign = campaign
            indicator.save()
        
        logger.info(f"Campaign created: {campaign.name} with {len(indicators)} indicators")
        return campaign

    def _generate_campaign_description(self, indicators, threat_actor, tactics) -> str:
        """Generate AI-powered campaign description."""
        total = len(indicators)
        types = ', '.join(set(ind.indicator_type for ind in indicators))
        avg_conf = np.mean([ind.confidence for ind in indicators])
        
        desc = f"""AI-Detected Threat Campaign

Statistics:
- Total Indicators: {total}
- Types: {types}
- Avg Confidence: {avg_conf:.2%}
- First Seen: {min(ind.first_seen for ind in indicators).strftime('%Y-%m-%d %H:%M')}
- Last Seen: {max(ind.last_seen for ind in indicators).strftime('%Y-%m-%d %H:%M')}
"""
        if threat_actor:
            desc += f"\nAttribution: {threat_actor}"
        if tactics:
            desc += f"\nTactics: {tactics}"
        
        return desc

    def _extract_threat_actor(self, indicators) -> Optional[str]:
        for ind in indicators:
            if ind.tags and 'actor:' in ind.tags:
                return ind.tags.split('actor:')[1].split(',')[0].strip()
        return None

    def _extract_tactics(self, indicators) -> Optional[str]:
        tactics = set()
        for ind in indicators:
            if ind.tags and 'tactic:' in ind.tags:
                parts = ind.tags.split('tactic:')
                for part in parts[1:]:
                    tactic = part.split(',')[0].strip()
                    tactics.add(tactic)
        return ','.join(tactics) if tactics else None

    def _extract_target_sectors(self, indicators) -> Optional[str]:
        sectors = set()
        for ind in indicators:
            if ind.tags and 'sector:' in ind.tags:
                parts = ind.tags.split('sector:')
                for part in parts[1:]:
                    sector = part.split(',')[0].strip()
                    sectors.add(sector)
        return ','.join(sectors) if sectors else None

    def _log_correlation(self, campaign, indicators, labels):
        CorrelationLog.objects.create(
            campaign=campaign,
            indicators_count=len(indicators),
            correlation_score=campaign.confidence_score,
            method='DBSCAN',
            parameters={'eps': self.eps, 'min_samples': self.min_samples}
        )


class AlertService:
    """Service for generating alerts from threat indicators."""
    
    @staticmethod
    def generate_alert_for_indicator(indicator) -> Optional[Alert]:
        if indicator.confidence < 0.7:
            return None
        
        severity = 'Critical' if indicator.confidence >= 0.85 else 'High'
        
        alert = Alert.objects.create(
            indicator=indicator,
            campaign=indicator.campaign,
            title=f"New {indicator.indicator_type}: {indicator.indicator_value[:50]}",
            description=f"High-confidence threat indicator from {indicator.source}",
            severity=severity,
            explanation=AlertService._generate_explanation(indicator),
            recommended_actions=AlertService._generate_recommendations(indicator),
            status='New'
        )
        
        logger.info(f"Alert generated: {alert.title}")
        return alert

    @staticmethod
    def _generate_explanation(indicator) -> str:
        return f"""
This alert was generated based on:
1. Type: {indicator.indicator_type} - {indicator.indicator_value}
2. Confidence: {indicator.confidence:.2%}
3. Severity: {indicator.severity}
4. Context: {indicator.context or 'N/A'}
5. Campaign: {indicator.campaign.name if indicator.campaign else 'Not correlated'}
"""

    @staticmethod
    def _generate_recommendations(indicator) -> str:
        if indicator.indicator_type in ['IPv4', 'IPv6']:
            return "• Block IP at firewall\n• Review logs\n• Check for lateral movement"
        elif indicator.indicator_type == 'Domain':
            return "• Block DNS resolution\n• Review DNS logs\n• Block at proxy"
        else:
            return "• Investigate immediately\n• Quarantine affected systems\n• Update intelligence feeds"

    @staticmethod
    def acknowledge_alert(alert_id, user=None):
        try:
            alert = Alert.objects.get(id=alert_id)
            alert.acknowledge(user)
            return alert
        except Alert.DoesNotExist:
            return None

    @staticmethod
    def resolve_alert(alert_id):
        try:
            alert = Alert.objects.get(id=alert_id)
            alert.resolve()
            return alert
        except Alert.DoesNotExist:
            return None


class AnomalyDetectionService:
    """Service for detecting anomalies using Isolation Forest."""
    
    @staticmethod
    def detect_anomalies(indicators=None, contamination=0.1) -> Dict[str, Any]:
        try:
            if indicators is None:
                indicators = ThreatIndicator.objects.filter(
                    is_active=True,
                    last_seen__gte=timezone.now() - timedelta(days=7)
                )
            
            indicators_list = list(indicators)
            if len(indicators_list) < 5:
                return {'status': 'skipped', 'reason': 'insufficient_data'}
            
            features = AnomalyDetectionService._extract_features(indicators_list)
            scaler = StandardScaler()
            features_scaled = scaler.fit_transform(features)
            
            iso_forest = IsolationForest(contamination=contamination, random_state=42, n_estimators=100)
            predictions = iso_forest.fit_predict(features_scaled)
            
            anomalies = []
            for idx, (indicator, prediction) in enumerate(zip(indicators_list, predictions)):
                if prediction == -1:
                    anomalies.append({
                        'indicator_id': str(indicator.id),
                        'indicator_value': indicator.indicator_value,
                        'indicator_type': indicator.indicator_type,
                        'severity': indicator.severity,
                    })
            
            return {'status': 'success', 'total_analyzed': len(indicators_list), 'anomalies_detected': len(anomalies), 'anomalies': anomalies[:10]}
        
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    @staticmethod
    def _extract_features(indicators) -> np.ndarray:
        features = []
        severity_map = {'Critical': 5, 'High': 4, 'Medium': 3, 'Low': 2, 'Info': 1}
        
        for indicator in indicators:
            confidence = float(indicator.confidence)
            severity = severity_map.get(indicator.severity, 3) / 5.0
            days_since_first = (timezone.now() - indicator.first_seen).days
            temporal = min(days_since_first, 365) / 365.0
            alert_count = indicator.alert_set.count()
            alert_freq = min(alert_count, 10) / 10.0
            
            features.append([confidence, severity, temporal, alert_freq])
        
        return np.array(features)


class PredictiveAnalyticsService:
    """Service for predictive analytics and threat forecasting."""
    
    @staticmethod
    def predict_threat_escalation(campaign: ThreatCampaign) -> Dict[str, Any]:
        try:
            indicators = campaign.indicators.all()
            if indicators.count() == 0:
                return {'status': 'insufficient_data', 'escalation_probability': 0.0, 'risk_level': 'Info'}
            
            avg_confidence = indicators.aggregate(avg_conf=Count('confidence'))['avg_conf'] or 0
            recent = indicators.filter(last_seen__gte=timezone.now() - timedelta(days=7)).count()
            total = indicators.count()
            
            prob = 0.0
            if avg_confidence > 0.8:
                prob += 0.3
            if total > 0 and (recent / total) > 0.3:
                prob += 0.4
            if campaign.status == 'Active':
                prob += 0.3
            
            prob = min(prob, 1.0)
            risk = 'Critical' if prob >= 0.8 else 'High' if prob >= 0.6 else 'Medium' if prob >= 0.4 else 'Low'
            
            return {'status': 'success', 'campaign_name': campaign.name, 'escalation_probability': prob, 'risk_level': risk}
        
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    @staticmethod
    def forecast_threat_volume(days_ahead: int = 7) -> Dict[str, Any]:
        try:
            daily_counts = []
            for i in range(30, 0, -1):
                date = timezone.now() - timedelta(days=i)
                daily_counts.append(ThreatIndicator.objects.filter(created_at__date=date.date()).count())
            
            if not daily_counts:
                return {'status': 'error', 'message': 'No data'}
            
            avg = sum(daily_counts[-7:]) / 7
            forecasts = [int(avg * (1 + (i * 0.05))) for i in range(1, days_ahead + 1)]
            
            return {'status': 'success', 'forecast_days': [f'Day {i}' for i in range(1, days_ahead + 1)], 'forecast_counts': forecasts, 'average_daily': int(avg)}
        
        except Exception as e:
            return {'status': 'error', 'message': str(e)}


class EnhancedCorrelationService(CorrelationService):
    """Enhanced correlation with caching and OPTICS algorithm."""
    
    def __init__(self, algorithm='dbscan', eps=0.5, min_samples=2, use_cache=True):
        super().__init__(eps=eps, min_samples=min_samples)
        self.algorithm = algorithm
        self.use_cache = use_cache
        self.scaler = RobustScaler()
    
    def correlate_indicators_enhanced(self, indicators=None):
        cache_key = f"corr_{self.algorithm}_{self.eps}_{self.min_samples}"
        if self.use_cache:
            cached = cache.get(cache_key)
            if cached:
                return cached
        
        if indicators is None:
            indicators = list(ThreatIndicator.objects.filter(is_active=True, campaign__isnull=True)[:5000])
        
        if len(indicators) < self.min_samples:
            return {'status': 'skipped', 'reason': 'insufficient_indicators'}
        
        try:
            features = self.extract_features(indicators)
            features_scaled = self.scaler.fit_transform(features)
            
            if self.algorithm == 'optics':
                clustering = OPTICS(min_samples=self.min_samples, xi=0.05)
            else:
                clustering = DBSCAN(eps=self.eps, min_samples=self.min_samples)
            
            labels = clustering.fit_predict(features_scaled)
            
            campaigns = []
            for label in set(labels):
                if label == -1:
                    continue
                cluster = [indicators[i] for i in np.where(labels == label)[0]]
                if len(cluster) >= 2:
                    campaign = self._create_campaign_from_cluster(cluster, label, np.mean([i.confidence for i in cluster]))
                    campaigns.append(campaign)
            
            result = {'status': 'success', 'campaigns_created': len(campaigns), 'total_processed': len(indicators)}
            
            if self.use_cache:
                cache.set(cache_key, result, 3600)
            
            return result
        
        except Exception as e:
            return {'status': 'error', 'message': str(e)}


class EnhancedAlertService(AlertService):
    """Enhanced alert service with batch processing."""
    
    @staticmethod
    def generate_alerts_batch(indicators: List, max_per_hour: int = 100):
        alerts = []
        for indicator in indicators:
            if indicator.confidence >= 0.7 and not indicator.campaign:
                alert = EnhancedAlertService._create_alert_enhanced(indicator)
                if alert:
                    alerts.append(alert)
        return alerts
    
    @staticmethod
    def _create_alert_enhanced(indicator):
        if Alert.objects.filter(indicator=indicator, created_at__gte=timezone.now() - timedelta(hours=1)).exists():
            return None
        
        severity = 'Critical' if indicator.confidence >= 0.9 else 'High' if indicator.confidence >= 0.8 else 'Medium'
        
        return Alert.objects.create(
            indicator=indicator,
            title=f"{severity}: {indicator.indicator_type} - {indicator.indicator_value[:60]}",
            severity=severity,
            status='New',
            explanation=EnhancedAlertService._generate_ai_explanation(indicator),
            recommended_actions=EnhancedAlertService._generate_enhanced_recommendations(indicator)
        )
    
    @staticmethod
    def _generate_ai_explanation(indicator):
        factors = []
        if indicator.confidence > 0.8:
            factors.append("High confidence from multiple sources")
        if indicator.severity in ['Critical', 'High']:
            factors.append("Elevated severity indicating potential impact")
        if indicator.campaign:
            factors.append(f"Linked to campaign: {indicator.campaign.name}")
        
        return f"Alert triggered by:\n" + "\n".join(factors)
    
    @staticmethod
    def _generate_enhanced_recommendations(indicator):
        recs = {
            'IPv4': ["Block IP at firewall", "Review connection logs", "Check for lateral movement"],
            'Domain': ["Sinkhole domain", "Review DNS logs", "Block at proxy"],
            'FileHash': ["Quarantine matching files", "Run YARA scans", "Hunt in EDR"],
        }
        return "\n".join(recs.get(indicator.indicator_type, ["Investigate immediately", "Contain affected systems", "Update threat intel"]))



# Add to services.py

import random
import ipaddress
from datetime import datetime, timedelta

class RealTimeAlertSimulator:
    """
    Simulates real-time threat alerts with random IP addresses.
    Adds alerts to database every 3 minutes.
    """
    
    # Common malicious IP ranges (simulated)
    THREAT_IPS = [
        # Malicious IPs from Zimbabwe
        "185.142.53.35", "45.227.254.8", "185.130.5.253", "91.121.89.155",
        "103.124.12.45", "185.225.72.45", "45.238.181.99", "196.52.43.12",
        "154.126.126.11", "95.214.27.166", "45.155.205.233", "103.150.200.11",
        "104.244.42.1", "185.225.72.46", "45.227.254.9", "185.130.5.254",
        "91.121.89.156", "103.124.12.46", "196.52.43.13", "154.126.126.12",
    ]
    
    THREAT_DOMAINS = [
        "malicious-c2.net", "phishing-site.com", "malware-distribution.org",
        "botnet-cc.ru", "ransomware-payload.biz", "apt-command.com",
        "data-exfiltrate.net", "credential-harvest.org", "exploit-kit.biz",
    ]
    
    SEVERITY_WEIGHTS = ['Critical', 'High', 'Medium', 'Low']
    
    @classmethod
    def generate_random_indicator(cls):
        """Generate a random threat indicator"""
        indicator_type = random.choice(['IPv4', 'Domain', 'URL', 'FileHash-MD5'])
        
        if indicator_type == 'IPv4':
            # Generate a random public IP in common threat ranges
            base_ip = random.choice(cls.THREAT_IPS)
            # Slightly modify IP sometimes
            if random.random() > 0.7:
                parts = base_ip.split('.')
                parts[-1] = str(random.randint(1, 254))
                value = '.'.join(parts)
            else:
                value = base_ip
        elif indicator_type == 'Domain':
            value = random.choice(cls.THREAT_DOMAINS)
            # Add subdomain sometimes
            if random.random() > 0.8:
                value = f"cdn.{value}"
        elif indicator_type == 'URL':
            domain = random.choice(cls.THREAT_DOMAINS)
            value = f"https://{domain}/{random.choice(['api', 'login', 'static', 'assets'])}/malware.exe"
        else:
            # Generate random hash
            import hashlib
            random_string = str(random.randint(1000000, 9999999))
            value = hashlib.md5(random_string.encode()).hexdigest()
        
        severity = random.choices(
            cls.SEVERITY_WEIGHTS, 
            weights=[0.15, 0.25, 0.35, 0.25]  # 15% Critical, 25% High, etc.
        )[0]
        
        confidence = random.uniform(0.65, 0.98)
        
        # Create geolocation context
        geo_data = cls._get_geo_for_ip(value if indicator_type == 'IPv4' else None)
        
        return {
            'indicator_type': indicator_type,
            'indicator_value': value,
            'confidence': confidence,
            'severity': severity,
            'context': geo_data.get('context', ''),
            'tags': f"auto-generated,simulated,source:{geo_data.get('country', 'Unknown')}",
            'lat': geo_data.get('lat'),
            'lng': geo_data.get('lng'),
            'country': geo_data.get('country', 'Unknown')
        }
    
    @classmethod
    def _get_geo_for_ip(cls, ip=None):
        """Get geolocation for IP or return Zimbabwe coordinates"""
        geo_data = {
            'Zimbabwe': {'lat': -17.8252, 'lng': 31.0335, 'context': 'Geo: lat=-17.8252, lng=31.0335 - Harare, Zimbabwe'},
        }
        
        # Always return Zimbabwe
        country = 'Zimbabwe'
        
        return geo_data.get(country, geo_data['Zimbabwe'])
    
    @classmethod
    def create_alert_and_indicator(cls):
        """Create a random alert and indicator in the database"""
        from .models import ThreatIndicator, Alert, ThreatFeed
        
        # Get or create auto-feed
        auto_feed, _ = ThreatFeed.objects.get_or_create(
            name="Auto Threat Simulator",
            defaults={
                'description': "Automatically generated threat indicators for testing",
                'source_url': "https://internal.cti.simulator",
                'feed_type': 'API',
                'is_active': True
            }
        )
        
        # Generate random indicator
        threat_data = cls.generate_random_indicator()
        
        # Create indicator
        indicator = ThreatIndicator.objects.create(
            indicator_type=threat_data['indicator_type'],
            indicator_value=threat_data['indicator_value'],
            source=auto_feed,
            confidence=threat_data['confidence'],
            severity=threat_data['severity'],
            context=threat_data['context'],
            tags=threat_data['tags'],
            is_active=True
        )
        
        # Create alert
        alert_title = f"🚨 Live Threat: {threat_data['indicator_type']} - {threat_data['indicator_value'][:50]}"
        alert_desc = f"Real-time detected {threat_data['severity'].upper()} threat from {threat_data.get('country', 'Unknown location')}"
        
        alert = Alert.objects.create(
            indicator=indicator,
            title=alert_title,
            description=alert_desc,
            severity=threat_data['severity'],
            status='New',
            explanation=f"AI-powered detection: This threat was automatically identified with {threat_data['confidence']:.0%} confidence. Pattern analysis suggests {threat_data['indicator_type']} activity.",
            recommended_actions=cls._get_recommendations(threat_data['indicator_type'])
        )
        
        return alert, indicator
    
    @classmethod
    def _get_recommendations(cls, indicator_type):
        """Get recommendations based on indicator type"""
        recommendations = {
            'IPv4': "1. Block this IP at firewall\n2. Search SIEM for connections\n3. Check for lateral movement\n4. Add to blocklist",
            'Domain': "1. Sinkhole domain\n2. Block DNS resolution\n3. Review DNS logs\n4. Add to proxy blocklist",
            'URL': "1. Block URL at web proxy\n2. Scan for infections\n3. Check access logs",
            'FileHash-MD5': "1. Quarantine matching files\n2. Run YARA scans\n3. Hunt in EDR",
        }
        return recommendations.get(indicator_type, "1. Investigate immediately\n2. Contain affected systems\n3. Update threat intel")