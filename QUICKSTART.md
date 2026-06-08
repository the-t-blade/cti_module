# CTI Module - Quick Start Guide 🚀

**A complete, self-contained guide to run the Cyber Threat Intelligence platform independently.**

---

## 📋 Table of Contents
1. [Quick Start (5 minutes)](#quick-start-5-minutes)
2. [Full Development Setup](#full-development-setup)
3. [Production with Docker](#production-with-docker)
4. [Key Services & Ports](#key-services--ports)
5. [Troubleshooting](#troubleshooting)
6. [Project Structure](#project-structure)

---

## ⚡ Quick Start (5 minutes)

### Windows (PowerShell)

```powershell
# 1. Activate virtual environment


# 2. Install dependencies
pip install -r requirements.txt

# 3. Run migrations
python manage.py migrate

# 4. Seed sample data (optional)
python manage.py seed_data

# 5. Start development server
python manage.py runserver

# 6. Open browser
# Web Interface: http://localhost:8000/cti/
# Admin Panel: http://localhost:8000/admin/
# API Docs: http://localhost:8000/api/
# Login: admin / admin123
```

### macOS / Linux (Bash)

```bash
# 1. Activate virtual environment
source venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run migrations
python manage.py migrate

# 4. Seed sample data (optional)
python manage.py seed_data

# 5. Start development server
python manage.py runserver

# 6. Open browser
# Web Interface: http://localhost:8000/cti/
# Admin Panel: http://localhost:8000/admin/
# API Docs: http://localhost:8000/api/
# Login: admin / admin123
```

---

## 🛠️ Full Development Setup

### Prerequisites
- **Python 3.11+** → [Download](https://www.python.org/downloads/)
- **pip** (comes with Python)
- **Git** (optional, for version control)
- **Redis** (optional, needed for Celery tasks) → [Download](https://redis.io/download)

### Step 1: Create Virtual Environment

**Windows:**
```powershell
python -m venv venv
.\.venv\Scripts\Activate.ps1
```

**macOS/Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

**What gets installed:**
- Django 5.2 (web framework)
- Django REST Framework (API)
- Celery (task queue - optional for dev)
- scikit-learn (machine learning)
- PostgreSQL driver (optional)
- And ~20 more packages

### Step 3: Database Setup

```bash
# Create tables and schema
python manage.py migrate

# Create superuser (admin account)
python manage.py createsuperuser
# Follow prompts: username, email, password

# (Optional) Load sample data
python manage.py seed_data

# (Optional) Geolocation data for threat map
python manage.py geolocate_indicators
```.\.venv\Scripts\Activate.ps1

### Step 4: Start Development Server

```bash
python manage.py runserver
```

**Expected output:**
```
Starting development server at http://127.0.0.1:8000/
Quit the server with CONTROL-C.
```

### Step 5: Access the Application

| URL | Purpose | Login |
|-----|---------|-------|
| http://localhost:8000/cti/ | Main dashboard | admin / password |
| http://localhost:8000/admin/ | Admin panel | admin / password |
| http://localhost:8000/api/ | REST API | Same credentials |

---

## 🐳 Production with Docker

### Prerequisites
- **Docker** → [Install](https://docs.docker.com/get-docker/)
- **Docker Compose** → [Install](https://docs.docker.com/compose/install/)

### Step 1: Build and Run

```bash
# Start all services (PostgreSQL, Redis, Elasticsearch, Django)
docker-compose up -d

# Verify services are running
docker-compose ps
```

**Expected output:**
```
NAME              SERVICE   STATUS
cti_db            db        Up (healthy)
cti_redis         redis     Up (healthy)
cti_elasticsearch elasticsearch Up
web               web       Up
nginx             nginx     Up
```

### Step 2: Initialize Database

```bash
# Run migrations
docker-compose exec web python manage.py migrate

# Load sample data
docker-compose exec web python manage.py seed_data

# Create admin account
docker-compose exec web python manage.py createsuperuser
```

### Step 3: Access Services

| Service | URL | Port |
|---------|-----|------|
| Web Interface | http://localhost | 80 |
| API | http://localhost/api/ | 80 |
| PostgreSQL | localhost:5432 | 5432 |
| Redis | localhost:6379 | 6379 |
| Elasticsearch | localhost:9200 | 9200 |

### Useful Docker Commands

```bash
# View logs
docker-compose logs -f web

# Stop all services
docker-compose down

# Stop and remove all data
docker-compose down -v

# Restart a service
docker-compose restart web

# Execute command in running container
docker-compose exec web python manage.py shell
```

---

## 🔧 Key Services & Ports

### Running Services Checklist

#### For Development (Minimal)
- ✅ Django dev server (port 8000)
- ❌ Redis (optional - only if using background tasks)
- ❌ PostgreSQL (optional - SQLite works fine for dev)

#### For Production (Docker)
- ✅ PostgreSQL (port 5432)
- ✅ Redis (port 6379)
- ✅ Elasticsearch (port 9200)
- ✅ Nginx (port 80/443)
- ✅ Daphne/Django (internal)

### Start Background Services (Optional, Linux/macOS)

**Redis (for Celery tasks):**
```bash
redis-server
# Or with Homebrew (macOS): brew services start redis
```

**Celery Worker (for async tasks):**
```bash
celery -A cti_project worker -l info
```

**Celery Beat (for scheduled tasks):**
```bash
celery -A cti_project beat -l info
```

---

## 🐛 Troubleshooting

### Problem: "Port 8000 already in use"

**Solution:**
```bash
# Use different port
python manage.py runserver 8001

# Or kill process using port 8000
# Windows PowerShell:
Get-Process -Id (Get-NetTCPConnection -LocalPort 8000).OwningProcess | Stop-Process

# macOS/Linux:
sudo lsof -ti:8000 | xargs kill -9
```

### Problem: "ModuleNotFoundError: No module named 'django'"

**Solution:** Ensure virtual environment is activated
```bash
# Windows
.\.venv\Scripts\Activate.ps1

# macOS/Linux
source venv/bin/activate
```

### Problem: "No such table" database error

**Solution:** Run migrations
```bash
python manage.py migrate
```

### Problem: "Redis connection refused" (if using Celery)

**Solution:** Start Redis
```bash
redis-server
# Or if installed via package manager:
# Ubuntu: sudo systemctl start redis-server
# macOS: brew services start redis
```

### Problem: Migrations not found

**Solution:**
```bash
# Reset migrations (development only!)
rm -rf cti_core/migrations/00*.py
python manage.py makemigrations cti_core
python manage.py migrate
```

### Problem: Docker containers won't start

**Solution:**
```bash
# Check logs
docker-compose logs

# Rebuild images
docker-compose down -v
docker-compose up -d --build
```

---

## 🏗️ Project Structure

```
cti_module/
├── cti_project/              # Django configuration
│   ├── settings.py          # Main settings (databases, apps, etc.)
│   ├── urls.py              # Main URL routing
│   ├── celery.py            # Celery configuration
│   ├── asgi.py              # ASGI server config
│   └── wsgi.py              # WSGI server config
│
├── cti_core/                # Main application logic
│   ├── models.py            # Database models (Threat, Indicator, Campaign)
│   ├── views.py             # Web interface views
│   ├── api_views.py         # REST API endpoints
│   ├── serializers.py       # Data serializers for API
│   ├── services.py          # Business logic
│   ├── ml_services.py       # ML/anomaly detection
│   ├── reporting_service.py # PDF/report generation
│   ├── tasks.py             # Celery background tasks
│   ├── consumers.py         # WebSocket handlers
│   └── migrations/          # Database migrations
│
├── templates/               # HTML templates
│   ├── base.html            # Base template
│   ├── index.html           # Homepage
│   ├── login.html           # Login page
│   └── cti_core/            # App-specific templates
│       ├── dashboard.html   # Main dashboard
│       ├── threat_map.html  # Cyber threat map
│       ├── indicators.html  # Threat indicators
│       ├── campaigns.html   # Threat campaigns
│       ├── reports.html     # Report generation
│       └── ...
│
├── static/                  # Static files
│   ├── css/                 # Stylesheets
│   ├── js/                  # JavaScript
│   └── images/              # Images
│
├── logs/                    # Application logs
├── reports/                 # Generated reports
│
├── manage.py                # Django management script
├── requirements.txt         # Python dependencies
├── docker-compose.yml       # Docker configuration
├── Dockerfile               # Docker image definition
├── nginx.conf               # Nginx web server config
└── README_ENHANCED.md       # Full documentation
```

---

## 📱 Main Features to Explore

### 1. **Dashboard** (`/cti/dashboard/`)
- Overview of threats and alerts
- Real-time statistics
- Recent activities

### 2. **Threat Map** (`/cti/threat-map/`)
- Interactive world map of threat origins
- Click markers for details
- Filter by severity

### 3. **Threat Hunting** (`/cti/threat-hunting/`)
- Search across all threat data
- Filter by type, severity, date
- Export results

### 4. **Campaigns** (`/cti/campaigns/`)
- View threat campaigns
- See associated indicators
- Track campaign progress

### 5. **Indicators** (`/cti/indicators/`)
- IP addresses, domains, file hashes
- Threat severity levels
- Correlation analysis

### 6. **Anomalies** (`/cti/anomalies/`)
- AI-detected anomalies
- Unusual threat patterns
- Recommendations

### 7. **Reports** (`/cti/reports/`)
- Generate PDF/HTML reports
- Schedule automatic reports
- Historical reports

### 8. **User Management** (`/cti/users/`)
- Create/edit users
- Assign roles
- Activity logging

---

## 🎯 Common Commands Reference

### Django Management

```bash
# Create new user
python manage.py createsuperuser

# Interactive shell
python manage.py shell

# Check for issues
python manage.py check

# Collect static files (production)
python manage.py collectstatic --noinput

# Run tests
python manage.py test

# Custom data loading
python manage.py populate_analyst_data
python manage.py geolocate_indicators
python manage.py add_global_threats
```

### Development

```bash
# Runserver with different host/port
python manage.py runserver 0.0.0.0:8000

# Create migrations
python manage.py makemigrations cti_core

# View migration status
python manage.py showmigrations

# Flush database (WARNING: deletes all data)
python manage.py flush
```

---

## 💡 Tips for Success

1. **Always activate the virtual environment** before running commands
2. **Check logs** when something goes wrong: `docker-compose logs -f`
3. **Use sample data** for testing: `python manage.py seed_data`
4. **Save reports** generated to the `reports/` folder for review
5. **Monitor background tasks** in development: Start Celery worker
6. **Use the admin panel** to verify data is being created correctly
7. **API testing**: Use PostMan or `curl` to test endpoints
8. **Check ports**: Ensure no other apps use ports 8000, 5432, 6379, 9200

---

## 📚 Next Steps

1. ✅ Run the quick start above
2. ✅ Login to http://localhost:8000/cti/ with admin credentials
3. ✅ Load sample data: `python manage.py seed_data`
4. ✅ Explore the threat map and dashboard
5. ✅ Generate a report
6. ✅ Test the REST API at `/api/`
7. ✅ Create additional users in `/admin/`

---

## 🆘 Getting Help

If you encounter issues:

1. **Check logs**: `python manage.py runserver` shows debug output
2. **Check migrations**: `python manage.py migrate`
3. **Reset database** (dev only): `rm db.sqlite3; python manage.py migrate`
4. **Read full docs**: See `README_ENHANCED.md` and `INSTALLATION.md`
5. **Check requirements**: Run `pip list` to verify all packages installed

---

**Last Updated:** May 2026
**Python Version:** 3.11+
**Django Version:** 5.2+
