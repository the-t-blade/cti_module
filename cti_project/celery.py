"""
Celery configuration for CTI project.
"""

import os
from celery import Celery
from celery.schedules import crontab

# Set the default Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cti_project.settings')

app = Celery('cti_project')

# Load configuration from Django settings
app.config_from_object('django.conf:settings', namespace='CELERY')

# Auto-discover tasks from all registered Django apps
app.autodiscover_tasks()

@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')


# ============================================================
# CELERY BEAT SCHEDULE - Scheduled Tasks
# ============================================================

app.conf.beat_schedule = {
    # Generate simulated threat alerts every 3 minutes (keeps system alive)
    'generate-simulated-alerts-every-3-minutes': {
        'task': 'cti_core.tasks.generate_simulated_alerts',
        'schedule': crontab(minute='*/3'),  # Every 3 minutes
        'options': {'expires': 120}  # Task expires after 2 minutes
    },
    
    # Ingest external threat feeds every hour
    'ingest-external-feeds-every-hour': {
        'task': 'cti_core.tasks.ingest_threat_feeds',
        'schedule': crontab(minute=0),  # At minute 0 of every hour
        'options': {'expires': 300}  # Task expires after 5 minutes
    },
    
    # Run AI correlation every 4 hours
    'run-correlation-every-4-hours': {
        'task': 'cti_core.tasks.run_correlation_task',
        'schedule': crontab(minute=0, hour='*/4'),  # Every 4 hours at minute 0
        'options': {'expires': 600}  # Task expires after 10 minutes
    },
    
    # Detect anomalies every 6 hours
    'detect-anomalies-every-6-hours': {
        'task': 'cti_core.tasks.detect_anomalies',
        'schedule': crontab(minute=0, hour='*/6'),  # Every 6 hours at minute 0
        'options': {'expires': 900}  # Task expires after 15 minutes
    },
    
    # Generate daily report at 8 AM every day
    'generate-daily-report-every-morning': {
        'task': 'cti_core.tasks.generate_daily_report',
        'schedule': crontab(hour=8, minute=0),  # 8:00 AM daily
        'options': {'expires': 3600}  # Task expires after 1 hour
    },
    
    # Clean up old data every Sunday at 2 AM
    'cleanup-old-data-every-week': {
        'task': 'cti_core.tasks.cleanup_old_data',
        'schedule': crontab(hour=2, minute=0, day_of_week='sunday'),  # Sunday 2 AM
        'options': {'expires': 7200}  # Task expires after 2 hours
    },
    
    # Enrich geolocation every 12 hours
    'enrich-geolocation-every-12-hours': {
        'task': 'cti_core.tasks.enrich_indicator_geolocation',
        'schedule': crontab(hour='*/12', minute=30),  # At 00:30 and 12:30
        'options': {'expires': 1800}  # Task expires after 30 minutes
    },
    
    # Update threat severity scores every 6 hours
    'update-severity-scores-every-6-hours': {
        'task': 'cti_core.tasks.update_threat_severity_scores',
        'schedule': crontab(minute=15, hour='*/6'),  # At 15 minutes past every 6th hour
        'options': {'expires': 600}
    },
}


# Optional: Configure task routing (send specific tasks to specific queues)
app.conf.task_routes = {
    'cti_core.tasks.generate_simulated_alerts': {'queue': 'alerts'},
    'cti_core.tasks.ingest_threat_feeds': {'queue': 'ingestion'},
    'cti_core.tasks.run_correlation_task': {'queue': 'ml'},
    'cti_core.tasks.detect_anomalies': {'queue': 'ml'},
    'cti_core.tasks.generate_daily_report': {'queue': 'reports'},
    'cti_core.tasks.cleanup_old_data': {'queue': 'maintenance'},
}


# Optional: Task timeout defaults (in seconds)
app.conf.task_time_limit = 30 * 60  # 30 minutes max
app.conf.task_soft_time_limit = 25 * 60  # 25 minutes soft limit


# Optional: Result backend configuration
# Store task results for 7 days
app.conf.result_expires = 60 * 60 * 24 * 7  # 7 days


# Optional: Task tracking
app.conf.task_track_started = True
app.conf.task_send_sent_event = True


# For development: Run tasks synchronously (disable for production)
app.conf.task_always_eager = True
app.conf.task_eager_propagates = True