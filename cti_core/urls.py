"""
URL routing for the CTI core application.
Enhanced with additional endpoints for commercial-grade functionality.
"""

from django.urls import path
from . import views

app_name = 'cti_core'

urlpatterns = [
    # Dashboard
    path('', views.dashboard, name='dashboard'),
    path('stats/', views.dashboard_stats, name='dashboard_stats'),
    path('stats/health/', views.system_health, name='system_health'),
    path('threat-landscape/', views.threat_landscape, name='threat_landscape'),
    
    # Threat Map (Enhanced)
    path('threat-map/', views.threat_map, name='threat_map'),
    path('threat-map/data/', views.threat_map_data, name='threat_map_data'),
    path('threat-map/anomalies/', views.threat_map_anomalies, name='threat_map_anomalies'),
    
    # Indicators
    path('indicators/', views.indicators_list, name='indicators_list'),
    path('indicators/export/', views.indicators_export, name='indicators_export'),
    path('indicators/bulk-delete/', views.indicators_bulk_delete, name='indicators_bulk_delete'),
    path('indicators/<uuid:pk>/', views.indicator_detail, name='indicator_detail'),
    path('indicators/<uuid:pk>/update-severity/', views.update_indicator_severity, name='update_indicator_severity'),
    
    # Campaigns
    path('campaigns/', views.campaigns_list, name='campaigns_list'),
    path('campaigns/export/', views.campaigns_export, name='campaigns_export'),
    path('campaigns/<uuid:pk>/', views.campaign_detail, name='campaign_detail'),
    path('campaigns/<uuid:pk>/merge/', views.merge_campaigns, name='merge_campaigns'),
    path('campaigns/<uuid:pk>/timeline/', views.campaign_timeline, name='campaign_timeline'),
    
    # Alerts
    path('alerts/', views.alerts_list, name='alerts_list'),
    path('alerts/export/', views.alerts_export, name='alerts_export'),
    path('alerts/bulk-acknowledge/', views.alerts_bulk_acknowledge, name='alerts_bulk_acknowledge'),
    path('alerts/<uuid:pk>/', views.alert_detail, name='alert_detail'),
    path('alerts/<uuid:pk>/acknowledge/', views.acknowledge_alert, name='acknowledge_alert'),
    path('alerts/<uuid:pk>/resolve/', views.resolve_alert, name='resolve_alert'),
    path('alerts/<uuid:pk>/escalate/', views.escalate_alert, name='escalate_alert'),
    
    # Feeds
    path('feeds/', views.feeds_list, name='feeds_list'),
    path('feeds/test/', views.test_feed, name='test_feed'),
    path('feeds/<uuid:pk>/toggle/', views.toggle_feed, name='toggle_feed'),
    path('feeds/<uuid:pk>/ingest/', views.manual_ingest, name='manual_ingest'),
    
    # Correlation
    path('correlation/run/', views.run_correlation, name='run_correlation'),
    path('correlation/status/', views.correlation_status, name='correlation_status'),
    path('correlation/logs/', views.correlation_logs, name='correlation_logs'),
    path('correlation/retrain/', views.retrain_models, name='retrain_models'),
    
    # User Management (FIXED - no 'user_create_form' error)
    path('users/', views.users_list, name='users_list'),
    path('users/create/', views.user_create, name='user_create'),  # Correct name
    path('users/<int:pk>/edit/', views.user_edit, name='user_edit'),
    path('users/<int:pk>/delete/', views.user_delete, name='user_delete'),
    path('users/<int:pk>/reset-password/', views.user_reset_password, name='user_reset_password'),
    path('users/activity/', views.user_activity, name='user_activity'),

    # Add to cti_core/urls.py
    path('profile/', views.profile, name='profile'),
    path('profile/update/', views.update_profile, name='update_profile'),
    path('change-password/', views.change_password, name='change_password'),

    # Add to cti_core/urls.py
    path('users/activity/<int:pk>/', views.user_activity, name='user_activity'),
    path('users/export/', views.users_export, name='users_export'),
    
    # Threat Hunting (Enhanced)
  
    path('threat-hunting/', views.threat_hunting, name='threat_hunting'),
    path('threat-hunting/search/', views.threat_hunting_search, name='threat_hunting_search'),
    path('threat-hunting/save-query/', views.save_hunting_query, name='save_hunting_query'),
    path('threat-hunting/saved-queries/', views.saved_queries, name='saved_queries'),
    path('threat-hunting/delete-query/<int:query_id>/', views.delete_saved_query, name='delete_saved_query'),
    path('threat-hunting/load-query/<int:query_id>/', views.load_saved_query, name='load_saved_query'),
    path('threat-hunting/suggestions/', views.threat_hunting_suggestions, name='threat_hunting_suggestions'),
    path('threat-hunting/export/', views.threat_hunting_export, name='threat_hunting_export'),

    
    # Reporting (Enhanced)
  
    # Reports URLs
    path('reports/', views.reports_list, name='reports_list'),
    path('reports/generate/', views.generate_report, name='generate_report'),
    path('reports/schedule/', views.schedule_report, name='schedule_report'),
    path('reports/templates/', views.report_templates, name='report_templates'),
    path('reports/history/', views.report_history, name='report_history'),
    path('reports/preview/<str:report_type>/', views.report_preview, name='report_preview'),
    path('reports/download/<int:report_id>/', views.download_report, name='download_report'),
    
    # API endpoints
    path('api/reports/list/', views.get_recent_reports, name='api_reports_list'),
    path('api/reports/schedules/', views.get_scheduled_reports, name='api_scheduled_reports'),
    path('api/reports/schedule/', views.schedule_report, name='api_schedule_report'),
    path('api/reports/<str:schedule_id>/delete/', views.delete_scheduled_report, name='api_delete_schedule'),
    path('api/reports/analytics/', views.report_analytics, name='api_report_analytics'),

    
    # Anomaly Detection (Enhanced)
    path('anomalies/', views.anomalies_list, name='anomalies_list'),
    path('anomalies/details/', views.anomaly_details, name='anomaly_details'),
    path('anomalies/ignore/', views.ignore_anomaly, name='ignore_anomaly'),
    
    # API Keys (New)
    path('api-keys/', views.api_keys_list, name='api_keys_list'),
    path('api-keys/create/', views.api_key_create, name='api_key_create'),
    path('api-keys/<int:pk>/revoke/', views.api_key_revoke, name='api_key_revoke'),
    
    # WebSocket status endpoint
    path('ws-status/', views.websocket_status, name='websocket_status'),
    
    # Activity Logs
    path('activity-logs/', views.activity_logs, name='activity_logs'),
    path('activity-logs/export/', views.export_activity_logs, name='export_activity_logs'),

     # Analyst Dashboard
    path('analyst/', views.analyst_dashboard, name='analyst_dashboard'),
    path('analyst/<int:user_id>/', views.analyst_dashboard, name='analyst_dashboard_detail'),
    path('analysts/list/', views.analyst_list, name='analyst_list'),

    # Add to cti_core/urls.py
    path('analyst/report/pdf/<int:user_id>/', views.analyst_report_pdf, name='analyst_report_pdf'),
    path('analyst/report/pdf/', views.analyst_report_pdf, name='analyst_report_pdf_self'),
]