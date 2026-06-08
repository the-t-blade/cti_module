# CTI Module - Command Cheat Sheet 🚀

**Copy & paste these commands - no thinking required!**

---

## ⚡ QUICKEST START (Copy & Run These)

### Windows PowerShell
```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python manage.py migrate
python manage.py seed_data
python manage.py runserver
```
Then visit: **http://localhost:8000/cti/**  
Login: `admin` / `admin123`

### macOS / Linux
```bash
source venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
python manage.py seed_data
python manage.py runserver
```
Then visit: **http://localhost:8000/cti/**  
Login: `admin` / `admin123`

---

## 🐳 DOCKER (Production)

```bash
# Start everything
docker-compose up -d

# Setup database
docker-compose exec web python manage.py migrate
docker-compose exec web python manage.py seed_data

# View logs
docker-compose logs -f web

# Stop everything
docker-compose down
```

---

## 📊 Common Tasks

| Task | Command |
|------|---------|
| **Start dev server** | `python manage.py runserver` |
| **Create admin user** | `python manage.py createsuperuser` |
| **Load sample data** | `python manage.py seed_data` |
| **Run migrations** | `python manage.py migrate` |
| **Create migrations** | `python manage.py makemigrations cti_core` |
| **Reset database** | `rm db.sqlite3` then `python manage.py migrate` |
| **Interactive shell** | `python manage.py shell` |
| **Check for errors** | `python manage.py check` |
| **Run tests** | `python manage.py test` |
| **Activate virtual env (Windows)** | `.\.venv\Scripts\Activate.ps1` |
| **Activate virtual env (Mac/Linux)** | `source venv/bin/activate` |

---

## 🌐 Access URLs

| Feature | URL |
|---------|-----|
| Dashboard | http://localhost:8000/cti/ |
| Admin Panel | http://localhost:8000/admin/ |
| REST API | http://localhost:8000/api/ |
| Threat Map | http://localhost:8000/cti/threat-map/ |
| Threat Hunting | http://localhost:8000/cti/threat-hunting/ |
| Campaigns | http://localhost:8000/cti/campaigns/ |
| Indicators | http://localhost:8000/cti/indicators/ |
| Reports | http://localhost:8000/cti/reports/ |
| Users | http://localhost:8000/cti/users/ |

---

## 🔄 Background Services (Optional)

```bash
# Start Redis (for Celery)
redis-server

# Start Celery worker (async tasks)
celery -A cti_project worker -l info

# Start Celery beat (scheduled tasks)
celery -A cti_project beat -l info
```

---

## 🐛 Quick Fixes

| Problem | Solution |
|---------|----------|
| Port 8000 in use | `python manage.py runserver 8001` |
| Module not found | Ensure venv is activated |
| "No such table" | Run `python manage.py migrate` |
| Django not found | Run `pip install -r requirements.txt` |
| PostgreSQL error | Use SQLite (default) or start PostgreSQL |
| Migrations missing | Run `python manage.py migrate` |

---

## 📁 Key Files

| File | Purpose |
|------|---------|
| `manage.py` | Django control center |
| `requirements.txt` | All Python packages needed |
| `db.sqlite3` | Default database (SQLite) |
| `cti_project/settings.py` | Main configuration |
| `cti_core/models.py` | Data structure definitions |
| `templates/` | HTML pages |
| `static/` | CSS, JavaScript, images |
| `docker-compose.yml` | Docker production setup |

---

## 🎯 Database Management

```bash
# Backup database
cp db.sqlite3 db.sqlite3.backup

# Restore from backup
cp db.sqlite3.backup db.sqlite3

# View database in shell
python manage.py shell
>>> from cti_core.models import Threat
>>> Threat.objects.count()
>>> Threat.objects.all()[:5]
>>> exit()

# Raw SQL query
python manage.py dbshell
```

---

## 📦 Useful Packages (Already Installed)

- **Django** - Web framework
- **djangorestframework** - REST API
- **celery** - Background tasks
- **redis** - Caching & task queue
- **scikit-learn** - Machine learning
- **pandas** - Data analysis
- **elasticsearch** - Search engine
- **reportlab** - PDF generation

---

## ✅ Quick Checklist

- [ ] Virtual environment activated
- [ ] `requirements.txt` installed (`pip install -r requirements.txt`)
- [ ] Database migrated (`python manage.py migrate`)
- [ ] Server running (`python manage.py runserver`)
- [ ] Can access http://localhost:8000/cti/
- [ ] Can login with admin credentials
- [ ] Sample data loaded (`python manage.py seed_data`)

---

**Print this sheet and keep it on your desk!** 📋
