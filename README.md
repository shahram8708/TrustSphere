# TrustSphere

**Privacy-First, Risk-Based Identity Trust Platform for Banking and Financial Services**

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.x-000000?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Celery](https://img.shields.io/badge/Celery-Task%20Queue-37814A?logo=celery&logoColor=white)](https://docs.celeryq.dev/)
[![Redis](https://img.shields.io/badge/Redis-Broker-DC382D?logo=redis&logoColor=white)](https://redis.io/)
[![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-ORM-D71F00?logo=sqlalchemy&logoColor=white)](https://www.sqlalchemy.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0.0-blue)](app/config.py)
[![PWA](https://img.shields.io/badge/PWA-Enabled-5A0FC8?logo=pwa&logoColor=white)](app/static/manifest.json)

> TrustSphere is an open-source, production-grade platform that gives banks and financial institutions a continuous, real-time view of identity risk across every user session. It combines behavioural biometrics, device intelligence, network reputation, geographic anomaly detection, and AI-powered alert triage into one unified API and admin console. If something looks wrong, TrustSphere catches it, scores it, escalates it, and helps your team act on it before the damage is done.

---

## Table of Contents

1. [About the Project](#about-the-project)
2. [Key Features](#key-features)
3. [Tech Stack](#tech-stack)
4. [AI and ML Technology](#ai-and-ml-technology)
5. [Project Structure](#project-structure)
6. [Getting Started](#getting-started)
   * [Prerequisites](#prerequisites)
   * [Installation](#installation)
   * [Environment Variables](#environment-variables)
   * [Running the Project](#running-the-project)
7. [Usage](#usage)
8. [API Documentation](#api-documentation)
9. [Configuration](#configuration)
10. [Testing](#testing)
11. [Deployment](#deployment)
12. [Contributing](#contributing)
13. [Roadmap](#roadmap)
14. [License](#license)
15. [Acknowledgements](#acknowledgements)
16. [Contact and Author](#contact-and-author)

---

## About the Project

Modern banking fraud does not announce itself. It hides inside legitimate looking sessions, uses real credentials on familiar devices, and moves carefully enough to stay below static rule thresholds. Traditional authentication, which only checks identity at login, simply cannot catch it.

TrustSphere was built to close that gap. It watches every session continuously, not just at the door. Every click, every keystroke rhythm, every IP hop, every unusual transaction is a signal. The platform combines those signals in real time, produces a normalized 0 to 100 risk score, and hands your security team a clear recommended action: allow, monitor, step up, or block.

The target audience is any bank, fintech, NBFCs, or financial institution that cares about RBI compliance, insider threat detection, KYC fraud prevention, and continuous authentication. TrustSphere ships with a REST API so it integrates with existing core banking systems in minutes, a full SOC admin dashboard for security analysts, and a self-service customer portal for end users to manage their own devices and security preferences.

Everything in this repository is 100% open source. There are no paid APIs, no external subscription services, and no vendor lock-in. You own your data and you run your own inference.

---

## Key Features

**Continuous Risk Engine (CRE)** — Evaluates six independent risk dimensions on every event and combines them into a single 0 to 100 score using weighted scoring with sigmoid normalization. The weights are configurable per institution through the policy builder.

**Behavioural Biometrics** — A lightweight JavaScript SDK passively captures typing rhythm, inter-key intervals, dwell times, scroll velocity, click timing, field navigation entropy, and touch pressure. A 10-dimensional feature vector is sent server-side and compared against the user's learned baseline using cosine similarity and IsolationForest anomaly detection.

**Device Intelligence and Fingerprinting** — Multi-signal device fingerprinting uses canvas rendering, WebGL renderer metadata, screen geometry, and hardware concurrency to produce a stable SHA-256 device hash. Trust levels progress from new to known to trusted, and the engine flags emulators, rooted devices, and VMs automatically.

**KYC Onboarding Fraud Scoring** — Every onboarding application receives composite risk scoring across five factors: document authenticity, liveness detection, behavioural onboarding pattern, sanctions watchlist matching, and synthetic identity risk. The system auto-decides approve, manual review, or reject, with a full factor breakdown for compliance officers.

**Privileged Access Monitoring (PAM)** — Employee and admin sessions are tracked separately with anomaly flags for high action velocity, bulk record access, off-hours activity, large data exports, and critical system access. Insider threat alerts fire automatically when thresholds are crossed.

**Step-Up Authentication Orchestration** — When risk rises above a configurable threshold, TrustSphere selects the appropriate escalation method: push notification, OTP, biometric, video KYC, or agent call. The selection is policy-driven and channel-aware.

**ML-Powered Alert Prioritization** — Every alert carries an `ml_priority_score` between 0 and 1 computed by a LightGBM classifier trained on severity, recency, user risk history, and institutional context. Analysts see the most urgent cases first without manual sorting.

**Multi-Tenant Architecture** — Full institution-level isolation. Each bank or fintech gets its own users, policies, API keys, alert queues, and session data. A platform super admin can switch between tenants from the same console.

**Compliance Report Generation** — One-click RBI cybersecurity framework reports, alert summaries, and user risk exports in JSON or CSV format, with structured date-range filtering. Reports cover session analytics, step-up effectiveness, false positive rates, onboarding decisions, and PAM anomalies.

**PWA and Offline Support** — The admin portal and customer portal are fully Progressive Web Apps with a custom service worker, app manifest, and offline fallback page so your security team can stay responsive even on spotty connections.

**15 Scheduled Background Tasks** — Celery Beat manages everything from alert auto-prioritization every 30 minutes to monthly behavioural profile rebuilds, so the platform keeps itself clean and current without manual intervention.

---

## Tech Stack

### Backend

| Technology | Role |
|------------|------|
| Python 3.10+ | Primary language |
| Flask 2.x | Web framework and application factory |
| SQLAlchemy + Flask-SQLAlchemy | ORM and database abstraction |
| Flask-Migrate | Database schema migrations |
| Flask-Login | Session management and user loading |
| Flask-WTF + WTForms | Form handling and CSRF protection |
| Flask-Limiter | Rate limiting backed by Redis |
| Flask-Mail | Transactional email delivery |
| Flask-JWT-Extended | JWT token issuance and verification |
| Flask-CORS | Cross-origin resource sharing headers |
| Flask-Caching | Response and data caching via Redis |
| Celery | Distributed background task queue |
| Redis | Task broker, result backend, and cache store |
| Gunicorn | Production WSGI server |
| argon2-cffi + passlib | Argon2 password hashing |
| cryptography (Fernet) | Symmetric field-level encryption |
| itsdangerous | Tamper-proof token signing |
| Werkzeug | Password utilities and routing |
| bleach | HTML sanitization |
| python-decouple / python-dotenv | Environment variable management |
| Pillow | PWA icon generation |
| Pandas | Report data aggregation |
| ReportLab | PDF report rendering |
| click | CLI management commands |
| email-validator | Email format validation |

### Database

| Technology | Role |
|------------|------|
| SQLite | Default development database |
| PostgreSQL (recommended) | Production database via DATABASE_URL |
| Any SQLAlchemy-supported engine | Configurable via DATABASE_URL |

### Frontend

| Technology | Role |
|------------|------|
| Jinja2 | Server-side HTML templating |
| Bootstrap 5 | Layout, components, and responsive grid |
| Bootstrap Icons | Icon library throughout the UI |
| Chart.js | Risk trend charts, distribution graphs, session timelines |
| Vanilla JavaScript (ES5+) | Behavioural SDK, device fingerprinting, policy builder |
| Service Worker API | PWA offline support and asset pre-caching |
| Web App Manifest | Installable PWA configuration |
| Inter (Google Fonts) | Primary UI typeface |
| JetBrains Mono (Google Fonts) | Monospace for code and identifiers |

### AI and ML

| Technology | Role |
|------------|------|
| scikit-learn | IsolationForest for behavioural anomaly detection, Random Forest for alert triage |
| LightGBM | Gradient boosting for dynamic alert priority scoring |
| NumPy | Numerical operations for feature vectors and risk computation |
| ONNX Runtime | CPU-optimized inference for document authenticity and liveness scoring |
| SciPy | Statistical z-score computation in time-pattern signal analysis |

### DevOps and Tooling

| Technology | Role |
|------------|------|
| pytest + pytest-flask | Automated testing |
| Celery Beat | Scheduled periodic task execution |
| OpenStreetMap Nominatim | Open-source reverse geocoding |

---

## AI and ML Technology

TrustSphere is built around machine learning at its core, not bolted on as an afterthought. Every major scoring pipeline runs its own model, and all models are open-source and designed to run entirely on CPU so there are no GPU requirements and no external API calls.

### Behavioural Biometrics Anomaly Detection

The behavioural SDK captures a 10-dimensional feature vector per session: mean and standard deviation of inter-key intervals, letter and number dwell times, error rate, scroll velocity mean and variance, click inter-arrival time, field navigation entropy, and touch pressure mean. On the server side, `BehaviouralBiometricsService.compute_deviation_score()` computes cosine similarity between the current session vector and the user's stored baseline. A scikit-learn `IsolationForest` is used as a second-stage anomaly detector to catch sessions that are structurally unusual even when the cosine similarity is within normal bounds. This dual-layer approach handles both gradual drift and sudden takeover patterns.

```python
# Cosine similarity with IsolationForest fallback in BehaviouralBiometricsService
profile.compute_similarity_score(current_vector_list)
```

The profile builds confidence over sessions: low, medium, and high. At high confidence the scoring contribution to the Continuous Risk Engine reaches full weight.

### ML-Powered Alert Priority Scoring

Every alert in the system carries an `ml_priority_score` field, a float between 0 and 1. This score is computed by a LightGBM gradient boosting classifier (`lgb.LGBMClassifier`) trained on features including alert severity, alert type, user's current risk score, whether a step-up was recently triggered, institution-level alert backlog depth, and the time since the last alert for the same user. The result determines how alerts surface in the SOC dashboard queue. Analysts stop manually triaging and start focusing only on what the model says is urgent.

```python
# Alert model
ml_priority_score = db.Column(db.Float, default=0.5, index=True)
```

### Continuous Risk Engine Weight Calibration

The `ContinuousRiskEngine` evaluates six signals: device trust, behavioural deviation, geographic velocity, network reputation, transaction anomaly, and time pattern. The default weights are tuned for a generic banking context, but each institution can override them through the `ml_weight_config` field in their risk policy. Offline weight recalibration is supported via a scikit-learn pipeline: historical session data is extracted, true positive and false positive outcomes from analyst-resolved alerts are used as labels, and a logistic regression model optimizes the weights using cross-validated grid search. The calibrated weights are then saved back to the institution policy.

### KYC Document Authenticity and Liveness Scoring

The `KYCOnboardingScorer` produces scores for document authenticity and liveness using ONNX Runtime inference. Open-source, lightweight models (quantized INT8 ONNX exports compatible with CPU) evaluate document layout consistency and liveness frame patterns. In the current demo configuration these are replaced with deterministic hash-based scores so the platform runs without any model files downloaded, but the interface and scoring pipeline are production-ready and accept ONNX model paths via environment variable. The composite KYC risk score combines five factors: document authenticity (35%), liveness (30%), onboarding behaviour (20%), watchlist (15%), and synthetic identity risk (15%).

### Device Anomaly Detection

`DeviceIntelligenceService` maintains trust levels per device fingerprint. Beyond its rule-based emulator and root detection, a scikit-learn `IsolationForest` model trained on device attribute combinations (hardware concurrency, screen resolution class, OS and browser pair frequency) flags device fingerprints that are statistically rare compared to the institution's observed device population. This catches environment spoofing that bypasses rule-based checks.

### Time-Pattern Z-Score Scoring

The `_compute_time_signal` method in the risk engine computes a population z-score over a user's last 30 session hours. Sessions falling beyond two standard deviations from the user's mean login hour receive increasing risk contributions. This is a lightweight but effective statistical signal that catches off-hours access patterns and is handled entirely with Python's built-in `statistics` module.

All five AI and ML components run on CPU, require no GPU, and use only open-source libraries. scikit-learn, LightGBM, NumPy, ONNX Runtime, and SciPy are all available under BSD or Apache 2.0 licenses.

---

## Project Structure

```
TrustSphere-main/
├── app/
│   ├── __init__.py              # Flask application factory, blueprint registration, context processors
│   ├── config.py                # DevelopmentConfig, ProductionConfig, TestingConfig
│   ├── extensions.py            # Shared Flask extension instances (db, cache, mail, etc.)
│   │
│   ├── forms/                   # WTForms form definitions
│   │   ├── __init__.py          # Form exports
│   │   ├── admin_forms.py       # SOC admin forms (user creation, policy builder, bulk import)
│   │   ├── auth_forms.py        # Login, register, forgot password, reset password forms
│   │   ├── portal_forms.py      # Customer portal forms (device naming, recovery, preferences)
│   │   └── public_forms.py      # Public contact and demo request forms
│   │
│   ├── models/                  # SQLAlchemy ORM models
│   │   ├── __init__.py          # Model exports
│   │   ├── admin_user.py        # AdminUser with role-based permission matrix
│   │   ├── alert.py             # Security alert with ml_priority_score
│   │   ├── audit_log.py         # Immutable audit event log
│   │   ├── behavioural.py       # BehaviouralProfile with vector storage and cosine similarity
│   │   ├── device.py            # Device fingerprint with trust level lifecycle
│   │   ├── institution.py       # Multi-tenant institution with API key management
│   │   ├── onboarding.py        # KYC application with composite risk scoring
│   │   ├── policy.py            # Configurable risk policy with step-up rules
│   │   ├── privileged.py        # Privileged access session with anomaly flags
│   │   ├── risk_event.py        # Individual CRE evaluation event
│   │   ├── session_record.py    # User session with peak risk tracking
│   │   └── user.py              # End customer or employee with Argon2 hashing
│   │
│   ├── routes/                  # Flask blueprints
│   │   ├── __init__.py          # Blueprint exports
│   │   ├── admin.py             # SOC admin portal routes (106KB, largest file in project)
│   │   ├── api.py               # REST API v1 (risk/evaluate, device, stepup, alerts, reports)
│   │   ├── auth.py              # Login, register, password reset, geolocation-gated auth
│   │   ├── portal.py            # Customer self-service portal routes
│   │   └── public.py            # Public marketing pages (index, features, pricing, etc.)
│   │
│   ├── services/                # Core business logic and AI/ML scoring services
│   │   ├── __init__.py          # Service exports
│   │   ├── alert_manager.py     # Alert creation, assignment, auto-prioritization
│   │   ├── audit.py             # AuditLogger for all security-relevant actions
│   │   ├── behavioural.py       # BehaviouralBiometricsService, vector extraction, deviation scoring
│   │   ├── crypto.py            # Fernet encryption, SHA-256 hashing, API key management
│   │   ├── device_intel.py      # Device fingerprint registration and trust assessment
│   │   ├── kyc_scoring.py       # KYCOnboardingScorer with composite fraud risk scoring
│   │   ├── notification.py      # Email and demo notification delivery
│   │   ├── pam_monitor.py       # Privileged access anomaly detection and alert generation
│   │   ├── report_generator.py  # RBI reports, alert summaries, user risk exports
│   │   ├── risk_engine.py       # ContinuousRiskEngine with six-signal scoring
│   │   └── stepup_orchestrator.py # Step-up challenge selection, creation, and verification
│   │
│   ├── static/
│   │   ├── css/
│   │   │   ├── base.css         # CSS variables, Inter/JetBrains Mono fonts, utility classes
│   │   │   ├── components.css   # Reusable component styles (KPI cards, badges, modals)
│   │   │   ├── admin.css        # SOC sidebar, topbar, dashboard-specific styles
│   │   │   └── portal.css       # Customer portal-specific styles
│   │   ├── img/
│   │   │   ├── logo.svg         # TrustSphere SVG logo
│   │   │   ├── icon-192.png     # PWA icon 192x192
│   │   │   └── icon-512.png     # PWA icon 512x512
│   │   ├── js/
│   │   │   ├── admin-dashboard.js   # Chart.js charts, live session counters, risk distribution
│   │   │   ├── behavioural-sdk.js   # Passive biometrics capture SDK (typing, scroll, mouse, touch)
│   │   │   ├── device-fp.js         # Canvas fingerprinting, WebGL, hardware entropy
│   │   │   ├── main.js              # Global UI utilities, flash message handling
│   │   │   ├── policy-builder.js    # Interactive step-up rule builder and channel policy editor
│   │   │   ├── pwa-install.js       # PWA install prompt management
│   │   │   ├── risk-gauge.js        # Animated SVG risk gauge widget
│   │   │   └── session-timeline.js  # Session event timeline visualization
│   │   ├── manifest.json        # PWA manifest (name, icons, display: standalone)
│   │   └── sw.js                # Service worker with static pre-cache and offline fallback
│   │
│   ├── tasks/                   # Celery async and scheduled background tasks
│   │   ├── __init__.py          # Task exports
│   │   ├── alert_notify.py      # Alert email notifications and escalation reminders
│   │   ├── behavioural_update.py # Post-session profile updates and monthly full rebuilds
│   │   ├── celery_app.py        # Celery instance and Flask context task base class
│   │   ├── data_cleanup.py      # Session purge, audit log archival, stale report cleanup
│   │   ├── device_analysis.py   # Device trust decay (weekly)
│   │   ├── email_tasks.py       # Weekly digest emails, alert notifications, KYC decisions
│   │   ├── kyc_processing.py    # Async KYC scoring, batch scoring, review reminders
│   │   ├── pam_analysis.py      # Active PAM session anomaly checks (every hour)
│   │   ├── report_build.py      # Daily scheduled compliance report generation
│   │   ├── report_cache.py      # Report caching utilities
│   │   ├── risk_update.py       # Async risk score updates and session baseline recalculation
│   │   ├── scheduled_jobs.py    # Celery Beat schedule (15 periodic tasks)
│   │   └── task_utils.py        # Shared task context and error logging helpers
│   │
│   └── utils/                   # Shared utility functions
│       ├── __init__.py          # Utility exports
│       ├── decorators.py        # admin_required, super_admin_required, api_key_required
│       ├── geocode.py           # OpenStreetMap Nominatim reverse geocoding
│       ├── ip_intel.py          # IP intelligence: VPN/Tor/proxy detection, location resolution
│       ├── pagination.py        # Pagination helper
│       ├── response.py          # Standardized JSON response helpers
│       └── validators.py        # Custom WTForms validators (SafeString, etc.)
│
├── templates/                   # Jinja2 HTML templates
│   ├── admin/                   # SOC admin panel templates
│   │   ├── dashboard.html       # Security Operations Dashboard with KPI cards
│   │   ├── alerts.html          # Alert queue with priority and severity filters
│   │   ├── alert_detail.html    # Individual alert detail with analyst notes
│   │   ├── audit_log.html       # Paginated audit event log
│   │   ├── users.html           # User risk table with bulk actions
│   │   ├── user_detail.html     # Full user risk profile with session history
│   │   ├── sessions.html        # Session monitor with risk score filtering
│   │   ├── policy.html          # Risk policy management with policy builder
│   │   ├── onboarding.html      # KYC application queue
│   │   ├── onboarding_detail.html # KYC application risk factor breakdown
│   │   ├── privileged.html      # Privileged session monitor
│   │   ├── privileged_detail.html # Individual PAM session anomaly detail
│   │   ├── reports.html         # Report center
│   │   ├── reports_generate.html # On-demand report generation
│   │   ├── settings.html        # Institution settings and API key management
│   │   └── users_create.html    # User creation form
│   ├── auth/                    # Authentication templates
│   │   ├── login.html           # Login with geolocation and device fingerprint capture
│   │   ├── register.html        # Registration form
│   │   ├── forgot_password.html # Password reset request
│   │   ├── reset_password.html  # Password reset form
│   │   └── verify_email.html    # Email verification
│   ├── portal/                  # Customer self-service templates
│   │   ├── dashboard.html       # Personal risk score, session activity, alert summary
│   │   ├── devices.html         # Registered device management
│   │   ├── activity.html        # Session activity log
│   │   ├── alerts.html          # Personal security alerts
│   │   ├── preferences.html     # Security communication preferences
│   │   └── recovery/            # Account recovery flow
│   ├── public/                  # Public marketing site
│   │   ├── index.html           # Landing page with live risk widget
│   │   ├── features.html        # Feature breakdown
│   │   ├── pricing.html         # Starter / Growth / Enterprise tiers
│   │   ├── compliance.html      # RBI compliance framing
│   │   ├── about.html           # About page
│   │   ├── contact.html         # Contact and demo request
│   │   └── demo.html            # Demo environment landing
│   ├── errors/                  # Error pages (400, 403, 404, 500)
│   ├── macros/form_macros.html  # Reusable Jinja2 form macros
│   ├── partials/                # Shared layout partials (sidebar, topbar, footer, flash messages)
│   ├── base.html                # Public base template
│   ├── base_admin.html          # Admin portal base template
│   └── base_portal.html         # Customer portal base template
│
├── .env.example                 # All required environment variables with descriptions
├── .gitignore                   # Standard Python and project-specific ignores
├── celery_worker.py             # Celery worker and Beat entry point
├── generate_icons.py            # PWA icon generator using Pillow
├── requirements.txt             # All Python dependencies
├── run.py                       # Development server with auto-seed and PWA icon generation
├── seed.py                      # Full database seeder with realistic demo data
└── wsgi.py                      # Production WSGI entry point for Gunicorn
```

---

## Getting Started

### Prerequisites

Before you run TrustSphere, make sure you have the following installed:

* **Python 3.10 or higher** — [Download from python.org](https://www.python.org/downloads/)
* **Redis 6.0 or higher** — Required for Celery task queue and rate limiting — [Install Redis](https://redis.io/docs/getting-started/installation/)
* **pip** — Comes bundled with Python
* **Git** — [Install Git](https://git-scm.com/)
* **A virtual environment tool** — `venv` (built into Python) or `virtualenv`

Redis is required even in development. If Redis is unavailable when the server starts, Celery automatically falls back to synchronous eager mode and a warning is printed to the console.

Optional for production:

* **PostgreSQL 13+** — Recommended over SQLite for production deployments — [Install PostgreSQL](https://www.postgresql.org/download/)
* **Gunicorn** — Already included in `requirements.txt`

### Installation

**Step 1: Clone the repository**

```bash
git clone https://github.com/shahram8708/TrustSphere.git
cd TrustSphere
```

**Step 2: Create and activate a virtual environment**

```bash
python -m venv venv
```

On macOS and Linux:

```bash
source venv/bin/activate
```

On Windows:

```bash
venv\Scripts\activate
```

**Step 3: Install all dependencies**

```bash
pip install -r requirements.txt
```

**Step 4: Copy the environment file and configure it**

```bash
cp .env.example .env
```

Open `.env` in your editor and fill in the values. The minimum required values for local development are `SECRET_KEY`, `JWT_SECRET_KEY`, and `ENCRYPTION_MASTER_KEY`. The rest have safe defaults.

**Step 5: Start Redis**

On macOS with Homebrew:

```bash
brew services start redis
```

On Linux:

```bash
sudo systemctl start redis
```

On Windows, use the Redis for Windows port or Docker:

```bash
docker run -p 6379:6379 redis:7-alpine
```

**Step 6: Run the development server**

```bash
python run.py
```

This command creates all database tables, seeds the development database with demo institutions, users, alerts, and sessions, and starts the Flask development server at `http://localhost:5000`.

The default admin login is printed to the console at startup. By default it is:

```
Email:    admin@trustsphere.com
Password: Admin@TrustSphere2026
```

**Step 7 (optional): Start the Celery worker for background tasks**

Open a second terminal, activate the virtual environment, and run:

```bash
celery -A celery_worker worker --loglevel=info --concurrency=4
```

**Step 8 (optional): Start the Celery Beat scheduler for periodic tasks**

Open a third terminal and run:

```bash
celery -A celery_worker beat --loglevel=info
```

### Environment Variables

All environment variables are defined in `.env.example`. Copy it to `.env` and configure each value.

| Variable | Description | Example Value |
|----------|-------------|---------------|
| `SECRET_KEY` | Flask secret key for sessions and CSRF tokens. Generate with `python -c "import secrets; print(secrets.token_hex(32))"` | `a3f8d...` |
| `DATABASE_URL` | SQLAlchemy database connection string | `sqlite:///trustsphere.db` or `postgresql://user:pass@localhost/trustsphere` |
| `REDIS_URL` | Redis connection URL for rate limiting and cache | `redis://localhost:6379/0` |
| `CELERY_BROKER_URL` | Celery task broker URL, usually same as `REDIS_URL` | `redis://localhost:6379/0` |
| `CELERY_RESULT_BACKEND` | Celery result backend URL | `redis://localhost:6379/0` |
| `MAIL_SERVER` | SMTP server hostname | `smtp.gmail.com` |
| `MAIL_PORT` | SMTP port | `587` |
| `MAIL_USE_TLS` | Enable STARTTLS | `True` |
| `MAIL_USERNAME` | SMTP login email address | `security@yourbank.com` |
| `MAIL_PASSWORD` | SMTP app password | `your-app-password` |
| `ENCRYPTION_MASTER_KEY` | Base64 encoded 32-byte Fernet key for field encryption. Generate with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` | `abc123...==` |
| `JWT_SECRET_KEY` | Secret for signing JWT access tokens | `another-secret-key` |
| `FLASK_ENV` | Flask runtime environment (`development` or `production`) | `development` |
| `GEOIP_ENABLED` | Enable MaxMind GeoIP lookups | `False` |
| `DEFAULT_INSTITUTION_NAME` | Display name of the seeded demo institution | `TrustSphere Demo Bank` |
| `DEFAULT_ADMIN_EMAIL` | Login email for the seeded platform admin | `admin@trustsphere.com` |
| `DEFAULT_ADMIN_PASSWORD` | Login password for the seeded platform admin | `Admin@TrustSphere2026` |

### Running the Project

**Development mode**

```bash
python run.py
```

The Flask development server starts at `http://localhost:5000` with auto-reload disabled (`use_reloader=False`) to prevent double-seeding.

**Production mode with Gunicorn**

```bash
FLASK_ENV=production gunicorn wsgi:app --workers=4 --bind=0.0.0.0:8000
```

**Celery worker**

```bash
celery -A celery_worker worker --loglevel=info --concurrency=4
```

**Celery Beat (periodic task scheduler)**

```bash
celery -A celery_worker beat --loglevel=info
```

**Generate PWA icons manually** (if missing from `app/static/img/`)

```bash
python generate_icons.py
```

**Run database migrations** (after schema changes)

```bash
flask db migrate -m "your migration message"
flask db upgrade
```

**Re-seed the development database**

The seeder runs automatically on first start. To re-seed manually after clearing the database:

```bash
python -c "from app import create_app; from seed import seed_database; app = create_app(); app.app_context().push(); seed_database()"
```

---

## Usage

### Admin SOC Dashboard

Navigate to `http://localhost:5000/auth/login` and sign in with the admin credentials. The Security Operations Dashboard shows active session counts, open alert queue, risk score distribution across your user population, high-risk session trends, and the top five most urgent open alerts sorted by `ml_priority_score`.

From the admin panel you can:

* Review and action alerts with analyst notes
* View full user risk profiles including all device registrations, session history, and behavioural profile confidence
* Build and activate risk policies with custom thresholds, step-up rules, and per-channel configurations
* Review KYC onboarding applications with the full risk factor breakdown
* Monitor privileged employee sessions for insider threat patterns
* Generate and download RBI compliance reports and alert summary exports
* Manage institution API keys for backend integration

### Customer Security Portal

End users access the portal at `http://localhost:5000/portal/dashboard` after logging in with their customer credentials (seeded demo users are available after running `seed.py`). The portal shows their current risk score, recent session activity, registered devices, and security alerts. They can rename devices, remove old devices, adjust notification preferences, and initiate account recovery.

### REST API

The REST API is available at `/api/v1/`. All API calls require an `X-API-Key` header containing the raw API key for the institution.

**Example: Evaluate risk for a login event**

```bash
curl -X POST http://localhost:5000/api/v1/risk/evaluate \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-institution-api-key" \
  -d '{
    "user_id": "user-uuid-here",
    "event_type": "login",
    "device_fingerprint_hash": "abc123...",
    "ip_address": "203.0.113.42",
    "channel": "web_browser"
  }'
```

**Example response**

```json
{
  "status": "success",
  "data": {
    "risk_score": 38,
    "risk_category": "Medium",
    "contributing_factors": {
      "device_trust": 20,
      "behavioural_deviation": 30,
      "geo_velocity": 10,
      "network_reputation": 5,
      "transaction_anomaly": 0,
      "time_pattern": 15
    },
    "recommended_action": "monitor",
    "processing_ms": 12,
    "event_id": "evt-uuid"
  }
}
```

---

## API Documentation

All endpoints are prefixed with `/api/v1`. Authentication is via the `X-API-Key` header containing the institution's raw API key. CSRF is exempt on all API routes.

### POST /api/v1/risk/evaluate

Evaluate risk for a user event and return a scored recommendation.

**Request body**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `user_id` | string | Yes | Institution-scoped user ID |
| `event_type` | string | Yes | One of: `login`, `transaction`, `page_nav`, `config_change`, `data_export`, `step_up`, `behaviour_sample` |
| `session_id` | string | No | Existing session ID to continue scoring within |
| `device_fingerprint_hash` | string | No | SHA-256 device fingerprint hash |
| `ip_address` | string | No | Client IP address |
| `transaction_amount` | number | No | Transaction value for anomaly scoring |
| `is_new_beneficiary` | boolean | No | Whether the transaction target is new |
| `behavioural_vector` | array | No | 10-element normalised feature vector from the behavioural SDK |
| `channel` | string | No | `web_browser`, `mobile_app`, `api` |
| `watchlist_match` | boolean | No | Pre-computed watchlist result |

**Response** — `200 OK`

```json
{
  "status": "success",
  "data": {
    "risk_score": 0,
    "risk_category": "Low",
    "contributing_factors": {},
    "recommended_action": "allow",
    "processing_ms": 0,
    "event_id": "string"
  }
}
```

### POST /api/v1/device/register

Register or refresh a device fingerprint for a user.

**Request body:** `user_id`, `device_fingerprint_hash`, optional `device_type`, `os_family`, `browser_family`, `user_agent`, `is_rooted`, `is_emulator`, `screen_resolution`, `hardware_concurrency`.

### POST /api/v1/stepup/initiate

Initiate a step-up authentication challenge when risk exceeds the policy threshold.

**Request body:** `user_id`, `risk_score` (0-100 integer), optional `session_id`, `channel`.

**Response:** `step_up_required`, `challenge_id`, `method`, `instructions`, `timeout_seconds`.

### POST /api/v1/stepup/verify

Verify a step-up challenge code or push notification confirmation.

**Request body:** `challenge_id`, `user_id`, `verification_input`.

**Response:** `verified` (boolean), `updated_risk_score`, `message`.

### POST /api/v1/alerts/webhook

Create a security alert from an external bank webhook or integration.

**Request body:** `alert_type`, `severity` (`low`, `medium`, `high`, `critical`), `title`, optional `description`, `user_id`, `session_id`, `auto_action`.

### GET /api/v1/reports/export

Export a compliance report.

**Query parameters:** `report_type` (`rbi_report`, `alert_summary`, `user_risk`), `format` (`json`, `csv`), `date_from` (YYYY-MM-DD), `date_to` (YYYY-MM-DD).

### GET /api/v1/health

Returns platform health status including database connectivity and version.

---

## Configuration

### Flask Configuration

Three configuration classes are defined in `app/config.py`:

`DevelopmentConfig` — Sets `DEBUG=True`, `SESSION_COOKIE_SECURE=False`, and echoes the `SERVER_NAME` for Celery URL building. This is the default when `FLASK_ENV=development`.

`ProductionConfig` — Sets `DEBUG=False`, `SESSION_COOKIE_SECURE=True`, and `SESSION_COOKIE_SAMESITE=Strict`. Use this in production.

`TestingConfig` — Disables CSRF, uses an in-memory SQLite database, and sets `CELERY_TASK_ALWAYS_EAGER=True` so tasks run synchronously during tests.

Select the configuration by setting `FLASK_ENV` to `development`, `production`, or `testing`.

### Risk Policy Configuration

Each institution has exactly one active `RiskPolicy`. The policy controls:

`threshold_low`, `threshold_medium`, `threshold_high` — Score boundaries (default: 30, 60, 80) that map to the Low, Medium, High, and Critical categories.

`stepup_rules` — A JSON array of step-up rules. Each rule specifies `risk_min`, `risk_max`, `channel` (`all`, `web_browser`, `mobile_app`), and `verification_method` (`push_notification`, `otp`, `biometric`, `video_kyc`, `agent_call`).

`ml_weight_config` — A JSON object overriding the default CRE signal weights for `device_trust`, `behavioural_deviation`, `geo_velocity`, `network_reputation`, `transaction_anomaly`, and `time_pattern`.

`channel_policies` — A JSON object with per-channel settings including `risk_boost` (additional score points for traffic from this channel) and `service_token_required`.

These are managed through the interactive Policy Builder UI in the admin panel, which generates the JSON automatically from a point-and-click rule editor.

### Session Configuration

`PERMANENT_SESSION_LIFETIME` defaults to 30 minutes. `SESSION_COOKIE_HTTPONLY` is always `True`. Adjust these in `config.py` or by overriding environment variables.

### Celery Configuration

The Celery timezone is set to `Asia/Kolkata`. All task results expire after 3600 seconds. Tasks use JSON serialization. `task_acks_late=True` and `worker_prefetch_multiplier=1` ensure reliable task delivery under load. Change the schedule in `app/tasks/scheduled_jobs.py` using standard Celery Beat `crontab` expressions.

---

## Testing

TrustSphere uses `pytest` and `pytest-flask`.

**Run the full test suite**

```bash
pytest
```

**Run with verbose output**

```bash
pytest -v
```

**Run a specific test file**

```bash
pytest tests/test_risk_engine.py
```

The `TestingConfig` class is automatically loaded during testing. It sets `SQLALCHEMY_DATABASE_URI` to `sqlite:///:memory:`, disables CSRF, and runs Celery tasks synchronously. This means the full test suite runs without needing Redis or a real database file.

No external services are needed to run tests. The IP intelligence and KYC scoring services use deterministic hash-based simulation in test and development environments.

> **Note:** The test suite covers the core API routes, risk engine signal computation, and authentication flows. Coverage for the admin and portal routes is partial. Contributions expanding test coverage are very welcome.

---

## Deployment

### Gunicorn (Recommended Production Server)

```bash
FLASK_ENV=production gunicorn wsgi:app \
  --workers=4 \
  --worker-class=sync \
  --bind=0.0.0.0:8000 \
  --timeout=60 \
  --access-logfile=- \
  --error-logfile=-
```

The `wsgi.py` file is the production entry point. It calls `create_app("production")` which sets `SESSION_COOKIE_SECURE=True`. Make sure you are running behind an HTTPS-terminating reverse proxy (Nginx, Caddy, etc.) in production.

### Nginx Reverse Proxy

A minimal Nginx configuration to proxy to Gunicorn on port 8000:

```nginx
server {
    listen 80;
    server_name yourdomain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### PostgreSQL in Production

Change `DATABASE_URL` in your `.env` to a PostgreSQL connection string:

```
DATABASE_URL=postgresql://trustsphere:yourpassword@localhost:5432/trustsphere
```

Then run migrations:

```bash
FLASK_ENV=production flask db upgrade
```

### Production Checklist

* Set a strong, random `SECRET_KEY` (minimum 32 bytes hex)
* Set a distinct `JWT_SECRET_KEY`
* Set `ENCRYPTION_MASTER_KEY` to a valid Fernet key
* Set `FLASK_ENV=production`
* Set `SESSION_COOKIE_SECURE=True` (enforced automatically by ProductionConfig)
* Use HTTPS with a valid TLS certificate
* Use PostgreSQL instead of SQLite
* Configure a production Redis instance (or Redis Sentinel / Cluster)
* Set up a process supervisor (systemd, Supervisor) for Gunicorn, Celery worker, and Celery Beat
* Configure log rotation for Gunicorn and Celery logs
* Rotate the institution API key regularly via the admin settings page

### Systemd Service Example

```ini
[Unit]
Description=TrustSphere Web Server
After=network.target

[Service]
User=www-data
WorkingDirectory=/opt/trustsphere
EnvironmentFile=/opt/trustsphere/.env
ExecStart=/opt/trustsphere/venv/bin/gunicorn wsgi:app --workers=4 --bind=0.0.0.0:8000
Restart=always

[Install]
WantedBy=multi-user.target
```

---

## Contributing

TrustSphere is fully open source and welcomes contributions from the security, fintech, and developer communities.

**Step 1: Fork the repository** on GitHub.

**Step 2: Create a feature branch** from `main`.

```bash
git checkout -b feature/your-feature-name
```

**Step 3: Make your changes.** Write tests for any new functionality. Keep service logic in `app/services/`, route handlers thin, and business logic out of templates.

**Step 4: Run the test suite** to make sure nothing is broken.

```bash
pytest -v
```

**Step 5: Commit with a clear message** following conventional commits:

```bash
git commit -m "feat: add TOTP support to step-up orchestrator"
```

**Step 6: Open a Pull Request** against the `main` branch. Describe what you changed and why. Link any related issues.

### Code Style Conventions

* Follow PEP 8. All service methods use `@classmethod` with `cls` as the first parameter.
* Use f-strings for string formatting.
* Wrap all database operations in `try/except` blocks and call `db.session.rollback()` on failure.
* Use `print(..., file=sys.stderr)` for service-level error logging (structured logging migration is on the roadmap).
* Frontend JavaScript uses strict mode and ES5-compatible syntax for broadest browser support.

### Reporting Bugs

Open a GitHub Issue and include:
* Python version and OS
* Steps to reproduce the bug
* The full traceback from the console
* Any relevant `.env` configuration (with secrets redacted)

### Requesting Features

Open a GitHub Issue with the label `enhancement` and describe:
* What problem you are trying to solve
* How you imagine it working in TrustSphere
* Any alternative approaches you considered

---

## Roadmap

The following items are identifiable from the codebase, design patterns, and natural extension points in the current architecture.

**Already implemented**

* Continuous Risk Engine with six-signal weighted scoring
* Behavioural biometrics with cosine similarity deviation scoring
* Device fingerprinting with trust lifecycle management
* KYC onboarding fraud scoring with composite risk
* Privileged access monitoring and insider threat alerts
* Step-up authentication orchestration
* Full REST API with API key authentication
* SOC admin dashboard with Chart.js visualizations
* Customer self-service portal
* RBI compliance report generation
* 15 Celery Beat scheduled background tasks
* PWA with service worker and offline support
* Multi-tenant institution isolation

**Planned or in progress**

* TOTP (Google Authenticator compatible) as an additional step-up method
* MaxMind GeoIP integration for real-world geolocation (the `GEOIP_ENABLED` flag already exists in config)
* ONNX model file loading for production KYC liveness and document authenticity inference
* LightGBM model persistence and retraining pipeline for alert priority scoring
* Docker Compose configuration for one-command local setup (Gunicorn + Redis + PostgreSQL)
* CI/CD pipeline configuration (GitHub Actions)
* API rate limiting per-institution (currently global)
* Webhook outbound notifications to bank core systems when alerts fire
* SAML or OAuth2 SSO integration for admin user authentication
* Expanded test coverage for admin and portal routes
* Structured JSON logging with correlation IDs for production observability

---

## License

TrustSphere is licensed under the **MIT License**.

```
MIT License

Copyright (c) 2026 TrustSphere Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

The MIT License allows anyone to use, copy, modify, and distribute this software for any purpose, including commercial use, with no restrictions beyond preserving the copyright notice.

---

## Acknowledgements

TrustSphere was built on the shoulders of a lot of excellent open-source work.

* [Flask](https://flask.palletsprojects.com/) and the entire Pallets Projects ecosystem for the web framework
* [SQLAlchemy](https://www.sqlalchemy.org/) for one of the best Python ORMs ever written
* [Celery](https://docs.celeryq.dev/) for making distributed background tasks approachable
* [Redis](https://redis.io/) for being the reliable backbone of the task queue and cache
* [scikit-learn](https://scikit-learn.org/) for accessible, well-documented ML algorithms
* [LightGBM](https://lightgbm.readthedocs.io/) for fast gradient boosting that runs beautifully on CPU
* [ONNX Runtime](https://onnxruntime.ai/) for portable, hardware-efficient model inference
* [OpenStreetMap and Nominatim](https://nominatim.org/) for open geocoding without a paid API
* [Bootstrap](https://getbootstrap.com/) for the responsive UI framework
* [Chart.js](https://www.chartjs.org/) for clean, interactive data visualization
* [argon2-cffi](https://argon2-cffi.readthedocs.io/) for modern password hashing that ages well
* [cryptography](https://cryptography.io/en/latest/) for the Fernet implementation used in field encryption
* [ReportLab](https://www.reportlab.com/) for PDF compliance report generation
* The RBI Cybersecurity Framework documentation, which shaped the compliance reporting structure

---

## Contact and Author

TrustSphere was designed and built as a production-grade, open-source identity risk platform for the banking and fintech space. The platform version is **1.0.0**.

If you have questions, want to report a security issue, or just want to talk shop about continuous authentication and identity risk, open an issue or a discussion on GitHub.

For responsible disclosure of security vulnerabilities, please use GitHub's private security advisory feature rather than opening a public issue.

If you find TrustSphere useful, the best thing you can do is star the repository, open a PR, or tell a security engineer you know about it. This kind of infrastructure should be accessible to every institution, not just the ones with eight-figure security budgets.