"""
Machine Learning services for CTI module.
Includes anomaly detection, predictive analytics, threat intelligence analytics, and time-series forecasting.
All services use scikit-learn for ML capabilities.
"""

import logging
import numpy as np
from typing import List, Dict, Any, Optional
from datetime import timedelta
from django.utils import timezone
from django.db.models import Count
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from .models import ThreatIndicator, ThreatCampaign, Alert

logger = logging.getLogger(__name__)


class AnomalyDetectionService:
    """
    Service for detecting anomalies in threat data using Isolation Forest.
    This is an unsupervised ML algorithm that identifies unusual patterns.
    """
    
    @staticmethod
    def detect_anomalies(indicators=None, contamination=0.1) -> Dict[str, Any]:
        """
        Detect anomalous indicators using Isolation Forest algorithm.
        
        Args:
            indicators: QuerySet of indicators to analyze
            contamination: Expected proportion of anomalies (0.0-1.0)
        
        Returns:
            Dictionary with anomaly detection results
        """
        try:
            logger.info("Starting anomaly detection with Isolation Forest...")
            
            if indicators is None:
                indicators = ThreatIndicator.objects.filter(
                    is_active=True,
                    last_seen__gte=timezone.now() - timedelta(days=7)
                )
            
            indicators_list = list(indicators)
            
            if len(indicators_list) < 5:
                logger.warning("Not enough indicators for anomaly detection")
                return {
                    'status': 'skipped',
                    'reason': 'insufficient_data',
                    'indicators_count': len(indicators_list)
                }
            
            # Extract features for ML
            features = AnomalyDetectionService._extract_features(indicators_list)
            
            if features.shape[0] < 5:
                return {
                    'status': 'skipped',
                    'reason': 'insufficient_features',
                }
            
            # Scale features for better ML performance
            scaler = StandardScaler()
            features_scaled = scaler.fit_transform(features)
            
            # Apply Isolation Forest (unsupervised anomaly detection)
            iso_forest = IsolationForest(
                contamination=contamination,
                random_state=42,
                n_estimators=100
            )
            predictions = iso_forest.fit_predict(features_scaled)
            anomaly_scores = iso_forest.score_samples(features_scaled)
            
            # Identify anomalies
            anomalies = []
            for idx, (indicator, prediction, score) in enumerate(
                zip(indicators_list, predictions, anomaly_scores)
            ):
                if prediction == -1:  # Anomaly detected by ML
                    anomalies.append({
                        'indicator_id': str(indicator.id),
                        'indicator_value': indicator.indicator_value,
                        'indicator_type': indicator.indicator_type,
                        'anomaly_score': float(score),
                        'severity': indicator.severity,
                        'confidence': indicator.confidence,
                    })
            
            logger.info(f"ML anomaly detection complete: {len(anomalies)} anomalies found out of {len(indicators_list)}")
            
            # Generate alerts for high-confidence anomalies
            from .services import AlertService
            for anomaly in anomalies:
                if anomaly['anomaly_score'] < -0.5:  # Strong anomaly signal
                    try:
                        indicator = ThreatIndicator.objects.get(id=anomaly['indicator_id'])
                        alert = AlertService.generate_alert_for_indicator(indicator)
                        if alert:
                            logger.info(f"ML anomaly alert created for {indicator.indicator_value}")
                    except Exception as e:
                        logger.error(f"Error creating anomaly alert: {str(e)}")
            
            return {
                'status': 'success',
                'total_analyzed': len(indicators_list),
                'anomalies_detected': len(anomalies),
                'anomalies': anomalies[:10],
                'ml_model': 'IsolationForest'
            }
        
        except Exception as e:
            logger.error(f"Anomaly detection error: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }
    
    @staticmethod
    def _extract_features(indicators) -> np.ndarray:
        """
        Extract features from indicators for ML analysis.
        
        Features used:
        1. Confidence score (0-1)
        2. Severity level normalized (1-5)
        3. Temporal proximity (days since first seen)
        4. Alert frequency (normalized)
        5. Campaign size (if any)
        """
        features = []
        
        severity_map = {
            'Critical': 5,
            'High': 4,
            'Medium': 3,
            'Low': 2,
            'Info': 1
        }
        
        for indicator in indicators:
            # Feature 1: Confidence
            confidence = float(indicator.confidence)
            
            # Feature 2: Severity (normalized to 0-1)
            severity = severity_map.get(indicator.severity, 1) / 5.0
            
            # Feature 3: Temporal proximity (days since first seen, normalized)
            days_since_first = (timezone.now() - indicator.first_seen).days
            temporal = min(days_since_first, 365) / 365.0
            
            # Feature 4: Alert frequency (normalized)
            alert_count = indicator.alert_set.count()
            alert_freq = min(alert_count, 10) / 10.0
            
            # Feature 5: Campaign size (normalized)
            campaign_size = 0
            if indicator.campaign:
                campaign_size = indicator.campaign.indicators.count()
            campaign_size_norm = min(campaign_size, 100) / 100.0
            
            features.append([
                confidence,
                severity,
                temporal,
                alert_freq,
                campaign_size_norm
            ])
        
        return np.array(features)


class PredictiveAnalyticsService:
    """
    Service for predictive analytics and threat forecasting.
    Uses statistical methods and ML for predictions.
    """
    
    @staticmethod
    def predict_threat_escalation(campaign: ThreatCampaign) -> Dict[str, Any]:
        """
        Predict if a threat campaign is likely to escalate.
        Uses multiple factors: confidence, activity trend, alerts, status.
        
        Returns:
            Dict with escalation probability and risk level
        """
        try:
            indicators = campaign.indicators.all()
            
            if indicators.count() == 0:
                return {
                    'status': 'insufficient_data',
                    'escalation_probability': 0.0,
                    'risk_level': 'Info'
                }
            
            # Calculate metrics
            avg_confidence = 0
            for ind in indicators:
                avg_confidence += ind.confidence
            avg_confidence = avg_confidence / indicators.count() if indicators.count() > 0 else 0
            
            recent_indicators = indicators.filter(
                last_seen__gte=timezone.now() - timedelta(days=7)
            ).count()
            
            total_indicators = indicators.count()
            
            # Multi-factor escalation scoring
            escalation_prob = 0.0
            
            # Factor 1: Confidence trend (30%)
            if avg_confidence > 0.8:
                escalation_prob += 0.3
            elif avg_confidence > 0.6:
                escalation_prob += 0.15
            
            # Factor 2: Activity trend (40%)
            if total_indicators > 0:
                activity_ratio = recent_indicators / total_indicators
                if activity_ratio > 0.3:
                    escalation_prob += 0.4
                elif activity_ratio > 0.1:
                    escalation_prob += 0.2
            
            # Factor 3: Campaign status (30%)
            if campaign.status == 'Active':
                escalation_prob += 0.3
            elif campaign.status == 'Monitoring':
                escalation_prob += 0.15
            
            # Factor 4: Alert severity boost
            if campaign.alerts.exists():
                critical_alerts = campaign.alerts.filter(severity='Critical').count()
                high_alerts = campaign.alerts.filter(severity='High').count()
                escalation_prob += min(0.2, (critical_alerts * 0.1) + (high_alerts * 0.05))
            
            escalation_prob = min(escalation_prob, 1.0)
            
            return {
                'status': 'success',
                'campaign_id': str(campaign.id),
                'campaign_name': campaign.name,
                'escalation_probability': escalation_prob,
                'risk_level': PredictiveAnalyticsService._get_risk_level(escalation_prob),
                'indicators_count': total_indicators,
                'recent_activity': recent_indicators,
                'avg_confidence': avg_confidence,
                'factors_analyzed': ['confidence', 'activity_trend', 'status', 'alerts']
            }
        
        except Exception as e:
            logger.error(f"Escalation prediction error: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }
    
    @staticmethod
    def _get_risk_level(probability: float) -> str:
        """Convert probability to risk level."""
        if probability >= 0.8:
            return 'Critical'
        elif probability >= 0.6:
            return 'High'
        elif probability >= 0.4:
            return 'Medium'
        elif probability >= 0.2:
            return 'Low'
        else:
            return 'Info'
    
    @staticmethod
    def forecast_threat_volume(days_ahead: int = 7) -> Dict[str, Any]:
        """
        Simple time series forecasting for threat volume.
        Uses moving average with trend adjustment.
        
        Args:
            days_ahead: Number of days to forecast
            
        Returns:
            Dictionary with forecast data
        """
        try:
            # Get daily counts for last 30 days
            daily_counts = []
            dates = []
            
            for i in range(30, 0, -1):
                date = timezone.now() - timedelta(days=i)
                count = ThreatIndicator.objects.filter(
                    created_at__date=date.date()
                ).count()
                daily_counts.append(count)
                dates.append(date.strftime('%Y-%m-%d'))
            
            if not daily_counts:
                return {'status': 'error', 'message': 'No historical data'}
            
            # Calculate moving average (7-day window)
            window = 7
            if len(daily_counts) >= window:
                avg = sum(daily_counts[-window:]) / window
            else:
                avg = sum(daily_counts) / len(daily_counts)
            
            # Calculate trend (rate of change)
            if len(daily_counts) >= 14:
                recent_avg = sum(daily_counts[-7:]) / 7
                previous_avg = sum(daily_counts[-14:-7]) / 7
                trend_rate = (recent_avg - previous_avg) / previous_avg if previous_avg > 0 else 0
            else:
                trend_rate = 0.05  # Default 5% growth assumption
            
            # Generate forecasts with trend
            forecasts = []
            for i in range(1, days_ahead + 1):
                forecast = avg * (1 + (trend_rate * i))
                forecasts.append(int(forecast))
            
            # Calculate confidence based on data stability
            std_dev = np.std(daily_counts) if daily_counts else 0
            confidence = max(0.5, min(0.95, 1 - (std_dev / max(daily_counts)) if max(daily_counts) > 0 else 0.5))
            
            return {
                'status': 'success',
                'historical_dates': dates[-7:],
                'historical_counts': daily_counts[-7:],
                'forecast_days': [f"Day {i}" for i in range(1, days_ahead + 1)],
                'forecast_counts': forecasts,
                'average_daily': int(avg),
                'trend_rate': round(trend_rate * 100, 1),
                'confidence': confidence,
                'method': 'MovingAverage'
            }
        
        except Exception as e:
            logger.error(f"Forecast error: {str(e)}")
            return {'status': 'error', 'message': str(e)}


class ThreatIntelligenceAnalytics:
    """
    Service for advanced threat intelligence analytics.
    Provides insights on threat actors, sectors, and temporal trends.
    """
    
    @staticmethod
    def get_threat_actor_profile(threat_actor_name: str) -> Dict[str, Any]:
        """
        Get detailed profile of a threat actor.
        Analyzes campaigns, indicators, TTPs, and targets.
        
        Args:
            threat_actor_name: Name of the threat actor (e.g., 'APT28')
        
        Returns:
            Dictionary with threat actor profile
        """
        try:
            campaigns = ThreatCampaign.objects.filter(
                threat_actor__icontains=threat_actor_name
            )
            
            if not campaigns.exists():
                return {
                    'status': 'not_found',
                    'threat_actor': threat_actor_name,
                    'message': f'No data found for threat actor: {threat_actor_name}'
                }
            
            # Aggregate statistics
            total_indicators = ThreatIndicator.objects.filter(
                campaign__in=campaigns
            ).count()
            
            # Extract unique targets and TTPs
            target_sectors = set()
            target_countries = set()
            tactics = set()
            techniques = set()
            
            for campaign in campaigns:
                if campaign.target_sectors:
                    for sector in campaign.target_sectors.split(','):
                        target_sectors.add(sector.strip())
                if campaign.target_countries:
                    for country in campaign.target_countries.split(','):
                        target_countries.add(country.strip())
                if campaign.tactics:
                    for tactic in campaign.tactics.split(','):
                        tactics.add(tactic.strip())
                if campaign.techniques:
                    for technique in campaign.techniques.split(','):
                        techniques.add(technique.strip())
            
            # Severity distribution
            severity_dist = {}
            for indicator in ThreatIndicator.objects.filter(campaign__in=campaigns):
                severity_dist[indicator.severity] = severity_dist.get(indicator.severity, 0) + 1
            
            return {
                'status': 'success',
                'threat_actor': threat_actor_name,
                'campaigns_count': campaigns.count(),
                'total_indicators': total_indicators,
                'target_sectors': list(target_sectors)[:10],
                'target_countries': list(target_countries)[:10],
                'tactics': list(tactics)[:10],
                'techniques': list(techniques)[:20],
                'severity_distribution': severity_dist,
                'first_seen': campaigns.earliest('first_seen').first_seen.isoformat(),
                'last_seen': campaigns.latest('last_seen').last_seen.isoformat(),
                'active_campaigns': campaigns.filter(status='Active').count(),
            }
        
        except Exception as e:
            logger.error(f"Threat actor profiling error: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }
    
    @staticmethod
    def get_sector_threat_analysis(sector: str) -> Dict[str, Any]:
        """
        Get threat analysis for a specific sector.
        
        Args:
            sector: Sector name (e.g., 'Banking', 'Telecommunications')
        
        Returns:
            Dictionary with sector threat analysis
        """
        try:
            campaigns = ThreatCampaign.objects.filter(
                target_sectors__icontains=sector
            )
            
            indicators = ThreatIndicator.objects.filter(
                campaign__in=campaigns
            )
            
            # Statistics
            severity_dist = indicators.values('severity').annotate(
                count=Count('id')
            )
            type_dist = indicators.values('indicator_type').annotate(
                count=Count('id')
            )
            
            # Unique threat actors
            threat_actors = []
            for campaign in campaigns:
                if campaign.threat_actor and campaign.threat_actor not in threat_actors:
                    threat_actors.append(campaign.threat_actor)
            
            return {
                'status': 'success',
                'sector': sector,
                'campaigns_count': campaigns.count(),
                'indicators_count': indicators.count(),
                'threat_actors': threat_actors[:10],
                'severity_distribution': list(severity_dist),
                'indicator_types': list(type_dist),
                'active_campaigns': campaigns.filter(status='Active').count(),
                'risk_level': 'High' if campaigns.filter(severity='Critical').count() > 0 else 'Medium'
            }
        
        except Exception as e:
            logger.error(f"Sector analysis error: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }
    
    @staticmethod
    def get_temporal_trends(days: int = 30) -> Dict[str, Any]:
        """
        Analyze temporal trends in threat activity.
        
        Args:
            days: Number of days to analyze
            
        Returns:
            Dictionary with trend analysis
        """
        try:
            trends = []
            for i in range(days, 0, -1):
                date = timezone.now() - timedelta(days=i)
                count = ThreatIndicator.objects.filter(
                    created_at__date=date.date()
                ).count()
                trends.append({
                    'date': date.strftime('%Y-%m-%d'),
                    'count': count
                })
            
            # Determine trend direction
            if len(trends) >= 14:
                recent_avg = sum(t['count'] for t in trends[-7:]) / 7
                previous_avg = sum(t['count'] for t in trends[-14:-7]) / 7
                
                if recent_avg > previous_avg * 1.2:
                    direction = 'increasing_significantly'
                elif recent_avg > previous_avg * 1.05:
                    direction = 'increasing'
                elif recent_avg < previous_avg * 0.8:
                    direction = 'decreasing_significantly'
                elif recent_avg < previous_avg * 0.95:
                    direction = 'decreasing'
                else:
                    direction = 'stable'
            else:
                direction = 'stable'
            
            return {
                'status': 'success',
                'trends': trends,
                'direction': direction,
                'total_indicators': sum(t['count'] for t in trends),
                'average_daily': round(sum(t['count'] for t in trends) / len(trends), 1) if trends else 0,
                'peak_day': max(trends, key=lambda x: x['count']) if trends else None,
                'days_analyzed': days
            }
        
        except Exception as e:
            logger.error(f"Temporal trend analysis error: {str(e)}")
            return {'status': 'error', 'message': str(e)}


class TimeSeriesForecastingService:
    """
    Time series forecasting for threat prediction.
    Uses exponential smoothing and pattern recognition.
    """
    
    @staticmethod
    def forecast_threat_volume(days_ahead: int = 7) -> Dict[str, Any]:
        """
        Forecast threat indicator volume using exponential smoothing.
        
        Args:
            days_ahead: Number of days to forecast
            
        Returns:
            Dictionary with forecast data and confidence intervals
        """
        try:
            # Get 30 days of historical data
            daily_counts = []
            dates = []
            
            for i in range(30, 0, -1):
                day_start = timezone.now() - timedelta(days=i)
                day_end = day_start + timedelta(days=1)
                count = ThreatIndicator.objects.filter(
                    created_at__gte=day_start,
                    created_at__lt=day_end
                ).count()
                daily_counts.append(count)
                dates.append(day_start.strftime('%Y-%m-%d'))
            
            if not daily_counts:
                return {'status': 'error', 'message': 'No historical data'}
            
            # Exponential smoothing
            alpha = 0.3  # Smoothing factor
            smoothed = [daily_counts[0]]
            for value in daily_counts[1:]:
                smoothed.append(alpha * value + (1 - alpha) * smoothed[-1])
            
            # Calculate trend
            if len(smoothed) > 1:
                trend = (smoothed[-1] - smoothed[0]) / len(smoothed)
            else:
                trend = 0
            
            # Generate forecasts
            forecasts = []
            last_value = smoothed[-1] if smoothed else daily_counts[-1]
            for i in range(1, days_ahead + 1):
                forecast = max(0, last_value + (trend * i))
                forecasts.append(int(forecast))
            
            # Calculate confidence intervals
            residuals = [daily_counts[i] - smoothed[i] for i in range(len(daily_counts)) if i < len(smoothed)]
            std_dev = float(np.std(residuals)) if residuals else float(np.std(daily_counts))
            confidence_lower = [max(0, f - std_dev) for f in forecasts]
            confidence_upper = [f + std_dev for f in forecasts]
            
            return {
                'status': 'success',
                'historical': {
                    'dates': dates[-7:],
                    'counts': daily_counts[-7:]
                },
                'forecast': {
                    'days': [f"Day +{i}" for i in range(1, days_ahead + 1)],
                    'values': forecasts,
                    'lower_bound': [int(l) for l in confidence_lower],
                    'upper_bound': [int(u) for u in confidence_upper]
                },
                'trend': 'increasing' if trend > 0 else 'decreasing' if trend < 0 else 'stable',
                'confidence': max(0.5, min(0.95, 1 - (std_dev / max(daily_counts)) if max(daily_counts) > 0 else 0.5)),
                'method': 'ExponentialSmoothing'
            }
        
        except Exception as e:
            logger.error(f"Forecast error: {str(e)}")
            return {'status': 'error', 'message': str(e)}
    
    @staticmethod
    def predict_attack_timing(campaign: ThreatCampaign) -> Dict[str, Any]:
        """
        Predict potential attack timing for a campaign based on historical patterns.
        Uses inter-arrival time analysis.
        
        Args:
            campaign: ThreatCampaign instance
            
        Returns:
            Dictionary with attack timing prediction
        """
        try:
            indicators = campaign.indicators.order_by('first_seen')
            
            if indicators.count() < 3:
                return {'status': 'insufficient_data', 'message': 'Need at least 3 indicators for pattern detection'}
            
            # Calculate inter-arrival times
            timestamps = [ind.first_seen for ind in indicators]
            intervals = []
            
            for i in range(1, len(timestamps)):
                interval = (timestamps[i] - timestamps[i-1]).total_seconds() / 3600
                intervals.append(interval)
            
            avg_interval = float(np.mean(intervals)) if intervals else 24.0
            std_interval = float(np.std(intervals)) if intervals else 12.0
            
            last_seen = max(timestamps)
            next_prediction = last_seen + timedelta(hours=avg_interval)
            
            # Calculate confidence (lower std = higher confidence)
            confidence = min(0.9, 1.0 - (std_interval / avg_interval)) if avg_interval > 0 else 0.5
            
            # Determine pattern (regular vs irregular)
            pattern = 'regular' if std_interval < avg_interval * 0.3 else 'irregular'
            
            return {
                'status': 'success',
                'campaign_id': str(campaign.id),
                'campaign_name': campaign.name,
                'average_interval_hours': round(avg_interval, 1),
                'std_deviation_hours': round(std_interval, 1),
                'last_activity': last_seen.isoformat(),
                'predicted_next_activity': next_prediction.isoformat(),
                'confidence': confidence,
                'pattern': pattern,
                'samples_analyzed': len(intervals)
            }
        
        except Exception as e:
            logger.error(f"Attack timing prediction error: {str(e)}")
            return {'status': 'error', 'message': str(e)}