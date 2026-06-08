"""
Enhanced views for CTI module with new features.
Includes threat map, user management, threat hunting, and reporting.
"""

import logging
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.http import JsonResponse, HttpResponse
from django.views.decorators.http import require_http_methods
from django.db.models import Q, Count
from django.utils import timezone
from datetime import timedelta

from .models import ThreatIndicator, ThreatCampaign, Alert
from .ml_services import AnomalyDetectionService, PredictiveAnalyticsService, ThreatIntelligenceAnalytics
from .reporting_service import ReportingService

logger = logging.getLogger(__name__)


@login_required
def threat_map(request):
    """
    Display global cyber threat map with Leaflet.js.
    """
    context = {
        'threat_map_center': [-19.0154, 29.1549],  # Zimbabwe
        'threat_map_zoom': 5,
    }
    return render(request, 'cti_core/threat_map.html', context)


@login_required
def users_list(request):
    """
    Display list of users with management options.
    """
    if not request.user.is_staff:
        messages.error(request, 'You do not have permission to manage users.')
        return redirect('cti_core:dashboard')
    
    users = User.objects.all().order_by('-date_joined')
    
    context = {
        'users': users,
    }
    return render(request, 'cti_core/user_management.html', context)


@login_required
@require_http_methods(["POST"])
def user_create(request):
    """
    Create a new user.
    """
    if not request.user.is_staff:
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    try:
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        is_staff = request.POST.get('is_staff') == 'on'
        
        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists.')
            return redirect('cti_core:users_list')
        
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
            is_staff=is_staff
        )
        
        messages.success(request, f'User {username} created successfully.')
        logger.info(f"User {username} created by {request.user.username}")
        
        return redirect('cti_core:users_list')
    
    except Exception as e:
        logger.error(f"Error creating user: {str(e)}")
        messages.error(request, f'Error creating user: {str(e)}')
        return redirect('cti_core:users_list')


@login_required
@require_http_methods(["POST"])
def user_edit(request, pk):
    """
    Edit an existing user.
    """
    if not request.user.is_staff:
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    try:
        user = get_object_or_404(User, pk=pk)
        
        user.email = request.POST.get('email', user.email)
        user.first_name = request.POST.get('first_name', user.first_name)
        user.last_name = request.POST.get('last_name', user.last_name)
        user.is_staff = request.POST.get('is_staff') == 'on'
        user.is_active = request.POST.get('is_active') == 'on'
        
        user.save()
        
        messages.success(request, f'User {user.username} updated successfully.')
        logger.info(f"User {user.username} updated by {request.user.username}")
        
        return redirect('cti_core:users_list')
    
    except Exception as e:
        logger.error(f"Error editing user: {str(e)}")
        messages.error(request, f'Error editing user: {str(e)}')
        return redirect('cti_core:users_list')


@login_required
@require_http_methods(["POST"])
def user_delete(request, pk):
    """
    Delete a user.
    """
    if not request.user.is_staff:
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    try:
        user = get_object_or_404(User, pk=pk)
        
        if user == request.user:
            messages.error(request, 'You cannot delete your own account.')
            return redirect('cti_core:users_list')
        
        username = user.username
        user.delete()
        
        messages.success(request, f'User {username} deleted successfully.')
        logger.info(f"User {username} deleted by {request.user.username}")
        
        return redirect('cti_core:users_list')
    
    except Exception as e:
        logger.error(f"Error deleting user: {str(e)}")
        messages.error(request, f'Error deleting user: {str(e)}')
        return redirect('cti_core:users_list')


@login_required
def threat_hunting(request):
    """
    Display threat hunting interface.
    """
    context = {}
    return render(request, 'cti_core/threat_hunting.html', context)


@login_required
@require_http_methods(["POST"])
def threat_hunting_search(request):
    """
    Execute threat hunting search query.
    """
    try:
        query = request.POST.get('query', '')
        indicator_type = request.POST.get('indicator_type', '')
        severity = request.POST.get('severity', '')
        time_range = int(request.POST.get('time_range', 7))
        
        # Build query
        search_query = Q(indicator_value__icontains=query) | Q(context__icontains=query) | Q(tags__icontains=query)
        
        indicators = ThreatIndicator.objects.filter(search_query).filter(
            Q(context__icontains='zimbabwe') | Q(tags__icontains='zimbabwe') | Q(indicator_value__icontains='.zw') | Q(indicator_value__iendswith='.zw')
        )
        
        # Apply filters
        if indicator_type:
            indicators = indicators.filter(indicator_type=indicator_type)
        if severity:
            indicators = indicators.filter(severity=severity)
        
        # Apply time range
        cutoff_date = timezone.now() - timedelta(days=time_range)
        indicators = indicators.filter(last_seen__gte=cutoff_date)
        
        # Get related campaigns
        campaigns = ThreatCampaign.objects.filter(
            threatindicator__in=indicators
        ).distinct()
        
        context = {
            'query': query,
            'indicators': indicators[:50],
            'campaigns': campaigns[:10],
            'results_count': indicators.count(),
        }
        
        return render(request, 'cti_core/partials/hunting_results.html', context)
    
    except Exception as e:
        logger.error(f"Threat hunting error: {str(e)}")
        return JsonResponse({'error': str(e)}, status=400)


@login_required
def reports_list(request):
    """
    Display available reports.
    """
    context = {
        'report_types': [
            {'name': 'Daily Report', 'description': 'Summary of last 24 hours', 'type': 'daily'},
            {'name': 'Weekly Report', 'description': 'Summary of last 7 days', 'type': 'weekly'},
            {'name': 'Campaign Report', 'description': 'Detailed campaign analysis', 'type': 'campaign'},
            {'name': 'Threat Actor Profile', 'description': 'Threat actor analysis', 'type': 'threat_actor'},
        ]
    }
    return render(request, 'cti_core/reports.html', context)


@login_required
@require_http_methods(["POST"])
def generate_report(request):
    """
    Generate a threat report.
    """
    try:
        report_type = request.POST.get('report_type', 'daily')
        report_format = request.POST.get('format', 'pdf')
        
        if report_type == 'daily':
            result = ReportingService.generate_daily_report(report_format)
        elif report_type == 'campaign':
            campaign_id = request.POST.get('campaign_id')
            campaign = get_object_or_404(ThreatCampaign, id=campaign_id)
            result = ReportingService.generate_campaign_report(campaign, report_format)
        else:
            result = {'status': 'error', 'message': 'Unknown report type'}
        
        if result.get('status') == 'success':
            messages.success(request, f'Report generated successfully.')
            if report_format == 'pdf' and 'filepath' in result:
                # Return PDF file
                with open(result['filepath'], 'rb') as f:
                    response = HttpResponse(f.read(), content_type='application/pdf')
                    response['Content-Disposition'] = f'attachment; filename="{result["filename"]}"'
                    return response
        
        messages.error(request, result.get('message', 'Error generating report'))
        return redirect('cti_core:reports_list')
    
    except Exception as e:
        logger.error(f"Report generation error: {str(e)}")
        messages.error(request, f'Error generating report: {str(e)}')
        return redirect('cti_core:reports_list')


@login_required
def anomalies_list(request):
    """
    Display detected anomalies.
    """
    try:
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
        context = {
            'error': str(e),
        }
        return render(request, 'cti_core/anomalies.html', context)
