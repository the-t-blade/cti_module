# Installation Guide - CTI Module Enhanced

## Quick Start (Development)

### Prerequisites
- Python 3.11+
- pip and virtualenv
- Redis (for Celery)
- PostgreSQL (optional, SQLite works for dev)

### Steps

1. **Extract the archive**:
```bash
unzip cti_module_enhanced.zip
cd cti_module
```

2. **Create virtual environment**:
```bash
python3.11 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**:
```bash
pip install -r requirements.txt
```

4. **Run migrations**:
```bash
python manage.py migrate
```

5. **Seed sample data**:
```bash
python manage.py seed_data
```

6. **Start development server**:
```bash
python manage.py runserver
```

7. **Access the application**:
- Web Interface: http://localhost:8000/cti/
- Admin Panel: http://localhost:8000/admin/
- API: http://localhost:8000/api/
- Demo Credentials: `admin` / `admin123`

## Production Deployment

### Option 1: Docker Compose (Recommended)

1. **Install Docker and Docker Compose**:
```bash
# Ubuntu/Debian
sudo apt-get install docker.io docker-compose

# macOS
brew install docker docker-compose
```

2. **Build and run**:
```bash
docker-compose up -d
```

3. **Initialize database**:
```bash
docker-compose exec web python manage.py migrate
docker-compose exec web python manage.py seed_data
```

4. **Access services**:
- Web: http://localhost:80
- PostgreSQL: localhost:5432
- Redis: localhost:6379
- Elasticsearch: localhost:9200

### Option 2: Manual Deployment

#### 1. Server Setup
```bash
# Update system
sudo apt-get update && sudo apt-get upgrade -y

# Install dependencies
sudo apt-get install -y python3.11 python3-pip python3-venv \
    postgresql postgresql-contrib redis-server nginx supervisor
```

#### 2. PostgreSQL Setup
```bash
sudo -u postgres psql
CREATE DATABASE cti_db;
CREATE USER cti_user WITH PASSWORD 'secure_password';
ALTER ROLE cti_user SET client_encoding TO 'utf8';
ALTER ROLE cti_user SET default_transaction_isolation TO 'read committed';
ALTER ROLE cti_user SET default_transaction_deferrable TO on;
ALTER ROLE cti_user SET timezone TO 'UTC';
GRANT ALL PRIVILEGES ON DATABASE cti_db TO cti_user;
\q
```

#### 3. Application Setup
```bash
# Clone repository
git clone <repo-url> /opt/cti_module
cd /opt/cti_module

# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure settings
cp cti_project/settings.py cti_project/settings.py.backup
# Edit settings.py with production values

# Run migrations
python manage.py migrate

# Collect static files
python manage.py collectstatic --noinput

# Create superuser
python manage.py createsuperuser
```

#### 4. Gunicorn Setup
```bash
# Create systemd service
sudo tee /etc/systemd/system/cti-gunicorn.service > /dev/null <<EOF
[Unit]
Description=CTI Gunicorn Application Server
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/cti_module
Environment="PATH=/opt/cti_module/venv/bin"
ExecStart=/opt/cti_module/venv/bin/gunicorn \
    --workers 4 \
    --bind unix:/opt/cti_module/gunicorn.sock \
    cti_project.wsgi:application

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl start cti-gunicorn
sudo systemctl enable cti-gunicorn
```

#### 5. Celery Setup
```bash
# Create Celery worker service
sudo tee /etc/systemd/system/cti-celery.service > /dev/null <<EOF
[Unit]
Description=CTI Celery Worker
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/cti_module
Environment="PATH=/opt/cti_module/venv/bin"
ExecStart=/opt/cti_module/venv/bin/celery -A cti_project worker -l info

[Install]
WantedBy=multi-user.target
EOF

# Create Celery Beat service
sudo tee /etc/systemd/system/cti-celery-beat.service > /dev/null <<EOF
[Unit]
Description=CTI Celery Beat Scheduler
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/cti_module
Environment="PATH=/opt/cti_module/venv/bin"
ExecStart=/opt/cti_module/venv/bin/celery -A cti_project beat -l info

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl start cti-celery cti-celery-beat
sudo systemctl enable cti-celery cti-celery-beat
```

#### 6. Nginx Configuration
```bash
# Create Nginx config
sudo tee /etc/nginx/sites-available/cti > /dev/null <<EOF
upstream cti_app {
    server unix:/opt/cti_module/gunicorn.sock fail_timeout=0;
}

server {
    listen 80;
    server_name your-domain.com;
    client_max_body_size 100M;

    location /static/ {
        alias /opt/cti_module/staticfiles/;
    }

    location /media/ {
        alias /opt/cti_module/media/;
    }

    location / {
        proxy_pass http://cti_app;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

# Enable site
sudo ln -s /etc/nginx/sites-available/cti /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

#### 7. SSL/TLS Setup (Let's Encrypt)
```bash
sudo apt-get install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```

## Configuration

### Environment Variables
Create `.env` file:
```bash
# Database
DATABASE_URL=postgresql://cti_user:password@localhost/cti_db

# Redis
REDIS_URL=redis://localhost:6379/0

# Django
SECRET_KEY=your-secret-key-here
DEBUG=False
ALLOWED_HOSTS=your-domain.com,www.your-domain.com

# Email
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password

# Elasticsearch (optional)
ELASTICSEARCH_HOSTS=localhost:9200
```

### Load Environment Variables
```bash
# In manage.py or settings.py
from decouple import config

SECRET_KEY = config('SECRET_KEY')
DEBUG = config('DEBUG', default=False, cast=bool)
DATABASE_URL = config('DATABASE_URL')
```

## Monitoring & Maintenance

### Check Service Status
```bash
# Docker
docker-compose ps

# Systemd
sudo systemctl status cti-gunicorn
sudo systemctl status cti-celery
sudo systemctl status cti-celery-beat
```

### View Logs
```bash
# Docker
docker-compose logs -f web

# Systemd
sudo journalctl -u cti-gunicorn -f
sudo journalctl -u cti-celery -f
```

### Database Backups
```bash
# PostgreSQL backup
pg_dump -U cti_user -h localhost cti_db > backup.sql

# Restore
psql -U cti_user -h localhost cti_db < backup.sql
```

### Performance Tuning
```python
# In settings.py
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'CONN_MAX_AGE': 600,  # Connection pooling
        'OPTIONS': {
            'connect_timeout': 10,
        }
    }
}

# Caching
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': 'redis://127.0.0.1:6379/1',
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        }
    }
}
```

## Troubleshooting

### Database Connection Issues
```bash
# Check PostgreSQL
sudo systemctl status postgresql
sudo -u postgres psql -c "SELECT 1"

# Check Redis
redis-cli ping
```

### Celery Not Processing Tasks
```bash
# Check Celery worker
celery -A cti_project inspect active

# Purge queue
celery -A cti_project purge

# Restart worker
sudo systemctl restart cti-celery
```

### Static Files Not Loading
```bash
python manage.py collectstatic --clear --noinput
sudo systemctl restart nginx
```

### Permission Issues
```bash
# Fix ownership
sudo chown -R www-data:www-data /opt/cti_module

# Fix permissions
sudo chmod -R 755 /opt/cti_module
sudo chmod -R 775 /opt/cti_module/media
```

## Security Checklist

- [ ] Set `DEBUG = False` in production
- [ ] Use strong `SECRET_KEY`
- [ ] Configure `ALLOWED_HOSTS`
- [ ] Use HTTPS/SSL certificates
- [ ] Set up firewall rules
- [ ] Configure CORS for trusted origins
- [ ] Enable CSRF protection
- [ ] Use environment variables for secrets
- [ ] Regular security updates
- [ ] Database backups
- [ ] Log monitoring
- [ ] Rate limiting on API

## Support

For issues or questions, please refer to:
- README_ENHANCED.md - Feature documentation
- Django Documentation: https://docs.djangoproject.com/
- Celery Documentation: https://docs.celeryproject.org/
- PostgreSQL Documentation: https://www.postgresql.org/docs/
