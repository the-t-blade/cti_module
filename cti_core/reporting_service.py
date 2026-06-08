"""
Reporting service for generating threat intelligence reports.
Supports PDF, JSON, HTML, and CSV formats with professional styling.
"""

import logging
import json
import csv
import io
from datetime import datetime, timedelta
from django.utils import timezone
from django.db.models import Count, Q, Sum, Avg
from django.conf import settings
from django.http import HttpResponse
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, 
    PageBreak, HRFlowable, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
import os

from .models import ThreatIndicator, ThreatCampaign, Alert
from .threat_report_pdf import ThreatReportGenerator

logger = logging.getLogger(__name__)


class ReportingService:
    """
    Service for generating threat intelligence reports.
    Supports both analyst dashboards and main threat reports.
    """
    
    # Color scheme matching the CTI platform
    COLORS = {
        'primary': colors.HexColor('#0891b2'),      # Cyan
        'secondary': colors.HexColor('#3b82f6'),    # Blue
        'success': colors.HexColor('#22c55e'),      # Green
        'warning': colors.HexColor('#eab308'),      # Yellow
        'danger': colors.HexColor('#ef4444'),       # Red
        'dark': colors.HexColor('#1f2937'),         # Dark Gray
        'gray': colors.whitesmoke,                  # Light Gray
        'white': colors.white,
        'critical': colors.HexColor('#dc2626'),
        'high': colors.HexColor('#f97316'),
        'medium': colors.HexColor('#eab308'),
        'low': colors.HexColor('#3b82f6'),
    }
    
    # ============================================================
    # MAIN REPORT GENERATION METHODS
    # ============================================================
    
    @staticmethod
    def generate_daily_report(output_format='pdf'):
        """Generate daily threat intelligence report."""
        try:
            logger.info("Generating daily report...")
            
            cutoff_time = timezone.now() - timedelta(hours=24)
            prev_cutoff = timezone.now() - timedelta(hours=48)
            
            # Gather statistics
            new_indicators = ThreatIndicator.objects.filter(created_at__gte=cutoff_time).count()
            prev_indicators = ThreatIndicator.objects.filter(created_at__gte=prev_cutoff, created_at__lt=cutoff_time).count()
            
            new_alerts = Alert.objects.filter(created_at__gte=cutoff_time).count()
            prev_alerts = Alert.objects.filter(created_at__gte=prev_cutoff, created_at__lt=cutoff_time).count()
            
            critical_alerts = Alert.objects.filter(severity='Critical', created_at__gte=cutoff_time).count()
            high_alerts = Alert.objects.filter(severity='High', created_at__gte=cutoff_time).count()
            medium_alerts = Alert.objects.filter(severity='Medium', created_at__gte=cutoff_time).count()
            
            new_campaigns = ThreatCampaign.objects.filter(created_at__gte=cutoff_time).count()
            active_campaigns = ThreatCampaign.objects.filter(status='Active').count()
            
            # Severity distribution
            severity_dist = list(
                Alert.objects.filter(created_at__gte=cutoff_time)
                .values('severity')
                .annotate(count=Count('id'))
            )
            
            # Top indicators
            top_indicators = list(
                ThreatIndicator.objects.filter(created_at__gte=cutoff_time)
                .values('indicator_type', 'indicator_value', 'severity', 'confidence')
                .order_by('-confidence')[:10]
            )
            
            # Top campaigns
            top_campaigns = list(
                ThreatCampaign.objects.filter(created_at__gte=cutoff_time)
                .values('name', 'threat_actor', 'confidence_score', 'status')
                .order_by('-confidence_score')[:5]
            )
            
            report_data = {
                'report_type': 'daily',
                'title': 'Daily Threat Intelligence Report',
                'subtitle': '24-hour threat summary and analysis',
                'generated_at': timezone.now().isoformat(),
                'period': {
                    'start': cutoff_time.isoformat(),
                    'end': timezone.now().isoformat(),
                },
                'summary': {
                    'new_indicators': new_indicators,
                    'new_alerts': new_alerts,
                    'critical_alerts': critical_alerts,
                    'high_alerts': high_alerts,
                    'medium_alerts': medium_alerts,
                    'new_campaigns': new_campaigns,
                    'active_campaigns': active_campaigns,
                    'trend_percent': round(((new_indicators - prev_indicators) / max(prev_indicators, 1)) * 100, 1) if prev_indicators > 0 else 0,
                    'alert_trend': round(((new_alerts - prev_alerts) / max(prev_alerts, 1)) * 100, 1) if prev_alerts > 0 else 0,
                },
                'severity_distribution': severity_dist,
                'top_indicators': top_indicators,
                'top_campaigns': top_campaigns,
            }
            
            return ReportingService._handle_output(report_data, output_format, 'daily')
            
        except Exception as e:
            logger.error(f"Daily report error: {str(e)}", exc_info=True)
            return {'status': 'error', 'message': str(e)}
    
    @staticmethod
    def generate_weekly_report(output_format='pdf'):
        """Generate weekly threat intelligence report."""
        try:
            logger.info("Generating weekly report...")
            
            cutoff_time = timezone.now() - timedelta(days=7)
            prev_cutoff = timezone.now() - timedelta(days=14)
            
            # Gather statistics
            new_indicators = ThreatIndicator.objects.filter(created_at__gte=cutoff_time).count()
            prev_indicators = ThreatIndicator.objects.filter(created_at__gte=prev_cutoff, created_at__lt=cutoff_time).count()
            
            new_alerts = Alert.objects.filter(created_at__gte=cutoff_time).count()
            critical_alerts = Alert.objects.filter(severity='Critical', created_at__gte=cutoff_time).count()
            
            new_campaigns = ThreatCampaign.objects.filter(created_at__gte=cutoff_time).count()
            
            # Daily breakdown
            daily_breakdown = []
            for i in range(7, 0, -1):
                day_start = timezone.now() - timedelta(days=i)
                day_end = day_start + timedelta(days=1)
                count = Alert.objects.filter(created_at__gte=day_start, created_at__lt=day_end).count()
                daily_breakdown.append({
                    'date': day_start.strftime('%Y-%m-%d'),
                    'alerts': count
                })
            
            report_data = {
                'report_type': 'weekly',
                'title': 'Weekly Threat Intelligence Summary',
                'subtitle': '7-day threat landscape overview with trends',
                'generated_at': timezone.now().isoformat(),
                'period': {
                    'start': cutoff_time.isoformat(),
                    'end': timezone.now().isoformat(),
                },
                'summary': {
                    'new_indicators': new_indicators,
                    'new_alerts': new_alerts,
                    'critical_alerts': critical_alerts,
                    'new_campaigns': new_campaigns,
                    'trend_percent': round(((new_indicators - prev_indicators) / max(prev_indicators, 1)) * 100, 1) if prev_indicators > 0 else 0,
                },
                'daily_breakdown': daily_breakdown,
            }
            
            return ReportingService._handle_output(report_data, output_format, 'weekly')
            
        except Exception as e:
            logger.error(f"Weekly report error: {str(e)}", exc_info=True)
            return {'status': 'error', 'message': str(e)}
    
    @staticmethod
    def generate_monthly_report(output_format='pdf'):
        """Generate monthly threat analysis report."""
        try:
            logger.info("Generating monthly report...")
            
            cutoff_time = timezone.now() - timedelta(days=30)
            prev_cutoff = timezone.now() - timedelta(days=60)
            
            # Gather statistics
            new_indicators = ThreatIndicator.objects.filter(created_at__gte=cutoff_time).count()
            prev_indicators = ThreatIndicator.objects.filter(created_at__gte=prev_cutoff, created_at__lt=cutoff_time).count()
            
            new_alerts = Alert.objects.filter(created_at__gte=cutoff_time).count()
            new_campaigns = ThreatCampaign.objects.filter(created_at__gte=cutoff_time).count()
            
            # Top threat actors
            top_actors = list(
                ThreatCampaign.objects.filter(created_at__gte=cutoff_time)
                .exclude(threat_actor__isnull=True)
                .values('threat_actor')
                .annotate(count=Count('id'))
                .order_by('-count')[:5]
            )
            
            report_data = {
                'report_type': 'monthly',
                'title': 'Monthly Threat Analysis Report',
                'subtitle': '30-day deep dive into threat patterns',
                'generated_at': timezone.now().isoformat(),
                'period': {
                    'start': cutoff_time.isoformat(),
                    'end': timezone.now().isoformat(),
                },
                'summary': {
                    'new_indicators': new_indicators,
                    'new_alerts': new_alerts,
                    'new_campaigns': new_campaigns,
                    'monthly_trend': round(((new_indicators - prev_indicators) / max(prev_indicators, 1)) * 100, 1) if prev_indicators > 0 else 0,
                },
                'top_threat_actors': top_actors,
            }
            
            return ReportingService._handle_output(report_data, output_format, 'monthly')
            
        except Exception as e:
            logger.error(f"Monthly report error: {str(e)}", exc_info=True)
            return {'status': 'error', 'message': str(e)}
    
    @staticmethod
    def generate_campaign_report(campaign, output_format='pdf'):
        """Generate detailed report for a specific campaign."""
        try:
            logger.info(f"Generating campaign report for {campaign.name}...")
            
            indicators = campaign.indicators.all()
            alerts = Alert.objects.filter(campaign=campaign)
            
            report_data = {
                'report_type': 'campaign',
                'title': f'Campaign Analysis: {campaign.name}',
                'subtitle': f'Threat Actor: {campaign.threat_actor or "Unknown"}',
                'generated_at': timezone.now().isoformat(),
                'campaign': {
                    'id': str(campaign.id),
                    'name': campaign.name,
                    'description': campaign.description or 'No description available',
                    'threat_actor': campaign.threat_actor,
                    'status': campaign.status,
                    'confidence_score': float(campaign.confidence_score),
                },
                'indicators': {
                    'total': indicators.count(),
                    'by_type': list(indicators.values('indicator_type').annotate(count=Count('id'))),
                    'by_severity': list(indicators.values('severity').annotate(count=Count('id'))),
                },
                'alerts': {
                    'total': alerts.count(),
                    'by_severity': list(alerts.values('severity').annotate(count=Count('id'))),
                    'by_status': list(alerts.values('status').annotate(count=Count('id'))),
                },
                'tactics': campaign.tactics,
                'techniques': campaign.techniques,
                'target_sectors': campaign.target_sectors,
                'target_countries': campaign.target_countries,
                'first_seen': campaign.first_seen.isoformat(),
                'last_seen': campaign.last_seen.isoformat(),
            }
            
            return ReportingService._handle_output(report_data, output_format, 'campaign', campaign=campaign)
            
        except Exception as e:
            logger.error(f"Campaign report error: {str(e)}", exc_info=True)
            return {'status': 'error', 'message': str(e)}
    
    @staticmethod
    def generate_threat_actor_report(threat_actor_name, output_format='pdf'):
        """Generate threat actor profile report."""
        try:
            logger.info(f"Generating threat actor report for {threat_actor_name}...")
            
            campaigns = ThreatCampaign.objects.filter(threat_actor__icontains=threat_actor_name)
            
            report_data = {
                'report_type': 'threat_actor',
                'title': f'Threat Actor Profile: {threat_actor_name}',
                'subtitle': 'Intelligence summary and campaign history',
                'generated_at': timezone.now().isoformat(),
                'threat_actor': {
                    'name': threat_actor_name,
                    'campaigns_count': campaigns.count(),
                    'total_indicators': ThreatIndicator.objects.filter(campaign__in=campaigns).count(),
                },
                'campaigns': list(campaigns.values('name', 'status', 'confidence_score')),
            }
            
            return ReportingService._handle_output(report_data, output_format, 'threat_actor')
            
        except Exception as e:
            logger.error(f"Threat actor report error: {str(e)}", exc_info=True)
            return {'status': 'error', 'message': str(e)}
    
    # ============================================================
    # OUTPUT HANDLERS
    # ============================================================
    
    @staticmethod
    def _handle_output(report_data, output_format, report_type, campaign=None):
        """Handle different output formats"""
        
        if output_format == 'pdf':
            return ReportingService._generate_professional_pdf(report_data, report_type, campaign)
        elif output_format == 'json':
            return ReportingService._generate_json_output(report_data)
        elif output_format == 'html':
            return ReportingService._generate_html_output(report_data)
        elif output_format == 'csv':
            return ReportingService._generate_csv_output(report_data, report_type)
        else:
            return report_data
    
    @staticmethod
    def _generate_professional_pdf(report_data, report_type, campaign=None):
        """Generate professional PDF using the ThreatReportGenerator"""
        
        if report_type == 'daily':
            pdf_content = ThreatReportGenerator.generate_daily_report(report_data)
        elif report_type == 'weekly':
            pdf_content = ThreatReportGenerator.generate_weekly_report(report_data)
        elif report_type == 'monthly':
            pdf_content = ThreatReportGenerator.generate_monthly_report(report_data)
        elif report_type == 'campaign' and campaign:
            pdf_content = ThreatReportGenerator.generate_campaign_report(report_data, campaign)
        elif report_type == 'threat_actor':
            pdf_content = ThreatReportGenerator.generate_threat_actor_report(report_data, report_data.get('threat_actor', {}).get('name', 'Unknown'))
        else:
            pdf_content = ThreatReportGenerator.generate_daily_report(report_data)
        
        if pdf_content:
            response = HttpResponse(pdf_content, content_type='application/pdf')
            filename = f"{report_type}_report_{timezone.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            response['Content-Disposition'] = f'attachment; filename="{filename}"'
            return response
        
        return {'status': 'error', 'message': 'PDF generation failed'}
    
    @staticmethod
    def _generate_json_output(report_data):
        """Generate JSON output"""
        return report_data
    
    @staticmethod
    def _generate_html_output(report_data):
        """Generate simple HTML output (can be extended)"""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>{report_data.get('title', 'Threat Report')}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                h1 {{ color: #0891b2; }}
                table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #0891b2; color: white; }}
            </style>
        </head>
        <body>
            <h1>{report_data.get('title', 'Threat Intelligence Report')}</h1>
            <p>Generated: {report_data.get('generated_at', '')}</p>
            <p>Period: {report_data.get('period', {}).get('start', '')} to {report_data.get('period', {}).get('end', '')}</p>
            <hr>
            <h2>Executive Summary</h2>
            <ul>
                <li>New Indicators: {report_data.get('summary', {}).get('new_indicators', 0)}</li>
                <li>New Alerts: {report_data.get('summary', {}).get('new_alerts', 0)}</li>
                <li>Critical Alerts: {report_data.get('summary', {}).get('critical_alerts', 0)}</li>
            </ul>
        </body>
        </html>
        """
        return {'status': 'success', 'html_content': html_content}
    
    @staticmethod
    def _generate_csv_output(report_data, report_type):
        """Generate CSV output for data export"""
        output = io.StringIO()
        
        if report_type == 'daily' and 'top_indicators' in report_data:
            writer = csv.writer(output)
            writer.writerow(['Indicator Type', 'Indicator Value', 'Severity', 'Confidence'])
            for ind in report_data.get('top_indicators', []):
                writer.writerow([ind.get('type'), ind.get('value'), ind.get('severity'), ind.get('confidence')])
        
        csv_content = output.getvalue()
        output.close()
        
        return {'status': 'success', 'csv_content': csv_content}