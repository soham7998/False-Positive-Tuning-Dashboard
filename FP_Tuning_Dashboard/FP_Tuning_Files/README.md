# FP Tuning Dashboard

**Automated false-positive reduction for Security Operations Centers.**

[![Backend](https://img.shields.io/badge/Backend-Railway-9333ea)](https://railway.app)
[![Frontend](https://img.shields.io/badge/Frontend-Vercel-000)](https://vercel.com)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

**Live App:** https://false-positive-tuning-dashboard.vercel.app
**API:** https://false-positive-tuning-dashboard-production.up.railway.app

---

## What Is This?

The **FP Tuning Dashboard** is a full-stack SOC tool that helps security analysts eliminate alert fatigue. Analysts triage incoming security alerts — marking each as a True Positive or False Positive. The backend engine automatically detects recurring FP patterns and surfaces suppression/whitelist rule suggestions with confidence scores and estimated time savings.

The project ships with 41 realistic sample alerts containing embedded FP patterns so the full workflow is demonstrable out of the box, no setup required.

---

## The Problem It Solves

| Problem | Impact | How This Helps |
|---|---|---|
| Analysts repeatedly triage the same benign alerts | Hours wasted per shift | Detects recurring FP patterns after every decision |
| No visibility into which rules generate the most noise | Hard to prioritize tuning | Overview ranks top FP-generating rules with counts |
| Tuning rules are created manually and inconsistently | Rules are missed or wrong | Engine auto-generates suppress/whitelist rules with confidence scores |
| Can't prove ROI of tuning work | Budget pressure | Each rule shows estimated weekly FP reduction and analyst time saved |
| Decisions aren't tracked between shifts | Context lost | All decisions persist with analyst ID, notes, and timestamps |
| Alert fatigue causes real threats to be missed | Serious security risk | Reducing FP volume lets analysts focus on genuine threats |

---

## How It Works

```
Analyst triages alert  →  marks True Positive or False Positive
               │
               ▼
     Flask API stores decision on the Alert object
               │
               ▼
     FPDetectionEngine.detect_patterns() runs automatically
               │
               ▼
     Engine groups all FP alerts by 4 pattern types:
       • rule_name + source_ip
       • rule_name + user
       • rule_name + process
       • rule_name + host
               │
               ▼
     Patterns with ≥ 3 FPs generate a TuningRule:
       confidence  = min(0.95,  0.5 + fp_count × 0.05)
       weekly_fps  = fp_count × 2   (projection)
       time_saved  = weekly_fps × 8 min/alert
       action      = suppress (fp_count ≥ 5) or lower_severity
               │
               ▼
     Analyst reviews suggested rules → Apply or Reject
```

### Dashboard Tabs

| Tab | What You See | What You Can Do |
|---|---|---|
| **Overview** | KPI cards — time saved, FP rate, suggested rules, true positives | View decision pie chart and top FP-rule bar chart |
| **Alert Triage** | All alerts with severity, rule name, IP, user, host, process | Mark individual alerts as True Positive or False Positive |
| **Tuning Rules** | Auto-generated suppression/whitelist suggestions with confidence, FP count, estimated time saved, pattern | Apply or Reject each rule |

---

## Architecture

```
┌──────────────────────────┐         ┌──────────────────────────┐
│    Frontend (Vercel)     │  HTTPS  │    Backend (Railway)     │
│                          │         │                          │
│  Next.js 14 + TypeScript │ ──────► │  Flask REST API          │
│  Tailwind CSS            │         │  FPDetectionEngine       │
│  Recharts                │ ◄────── │  In-memory alert store   │
│  Lucide React icons      │   JSON  │  Pattern clustering      │
└──────────────────────────┘         └──────────────────────────┘
```

---

## Frontend

| Technology | Version | Role |
|---|---|---|
| Next.js | 14.2.5 | React framework — App Router |
| TypeScript | 5.5 | Static typing across all components |
| Tailwind CSS | 3.4 | Utility-first styling, responsive layout |
| Recharts | 2.12 | PieChart (decision distribution) + BarChart (top FP rules) |
| Lucide React | 0.408 | Icon set |
| Vercel | — | Deployment, CDN, environment variables |

### Frontend Setup

```bash
cd FP_Tuning_Dashboard/FP_Tuning_Files/frontend

npm install

cp .env.example .env.local
# Edit .env.local:
# NEXT_PUBLIC_API_URL=http://localhost:5000

npm run dev
# Dashboard at http://localhost:3000
```

### Frontend File Map

| File | Description |
|---|---|
| `src/app/page.tsx` | Entire dashboard — all three tabs, data fetching, decision and rule actions |
| `src/app/layout.tsx` | Root layout, global font, HTML metadata |
| `src/app/globals.css` | Tailwind base styles |
| `.env.example` | `NEXT_PUBLIC_API_URL` template |
| `next.config.js` | Next.js build config with env var fallback |
| `vercel.json` | Vercel deployment config |

---

## Backend

| Technology | Version | Role |
|---|---|---|
| Python | 3.11 | Runtime |
| Flask | 2.3.3 | REST API framework |
| Flask-CORS | 4.0.0 | Cross-origin requests from the Vercel frontend |
| Gunicorn | 21.2.0 | Production WSGI server |
| Railway | — | Deployment, auto-deploy on push |

### Backend Setup

```bash
cd FP_Tuning_Dashboard/FP_Tuning_Files/backend

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt

python app.py
# API at http://localhost:5000
```

### Backend File Map

| File | Description |
|---|---|
| `app.py` | Flask application — all API routes, CORS config, sample data loading |
| `src/fp_engine.py` | `FPDetectionEngine` — core pattern detection, rule generation, metrics |
| `src/sample_data.py` | Generates realistic SOC alerts with embedded FP patterns |
| `Procfile` | `web: gunicorn app:app` — Railway start command |
| `runtime.txt` | Python version pin |
| `railway.json` | Railway service configuration |

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Service info and endpoint listing |
| `GET` | `/api/health` | Health check — returns alert count and rule count |
| `GET` | `/api/metrics` | Full dashboard metrics (FP rate, time saved, top rules, distributions) |
| `GET` | `/api/alerts` | List alerts — filter by `?status=pending\|fp\|tp\|all` |
| `POST` | `/api/alerts/<id>/decision` | Submit analyst decision (`true_positive` / `false_positive`) |
| `GET` | `/api/rules` | List tuning rules — filter by `?status=pending\|applied\|rejected\|all` |
| `POST` | `/api/rules/<id>/apply` | Apply a tuning rule |
| `POST` | `/api/rules/<id>/reject` | Reject a tuning rule |
| `POST` | `/api/analyze` | Re-run pattern detection manually |
| `POST` | `/api/seed` | Reset all data back to the sample state |

---

## Project Structure

```
FP_Tuning_Dashboard/
└── FP_Tuning_Files/
    ├── backend/
    │   ├── app.py                   # Flask API entry point
    │   ├── Procfile                 # Gunicorn start command (Railway)
    │   ├── requirements.txt         # Python dependencies
    │   ├── runtime.txt              # Python version pin
    │   ├── railway.json             # Railway deployment config
    │   └── src/
    │       ├── fp_engine.py         # Core FP detection engine
    │       └── sample_data.py       # Alert data generator
    └── frontend/
        ├── package.json
        ├── next.config.js
        ├── tailwind.config.js
        ├── tsconfig.json
        ├── vercel.json
        ├── .env.example
        └── src/
            └── app/
                ├── layout.tsx
                ├── page.tsx         # Main dashboard UI
                └── globals.css
```

---

## Deployment

### Backend → Railway

1. Push the repo to GitHub.
2. Go to [railway.app](https://railway.app) → New Project → Deploy from GitHub repo.
3. Set **Root Directory** to `FP_Tuning_Dashboard/FP_Tuning_Files/backend`.
4. Under Networking → Generate Domain. Copy the URL.

### Frontend → Vercel

1. Go to [vercel.com/new](https://vercel.com/new) → Import the same GitHub repo.
2. Set **Root Directory** to `FP_Tuning_Dashboard/FP_Tuning_Files/frontend`.
3. Add environment variable:
   ```
   NEXT_PUBLIC_API_URL = https://your-app.up.railway.app
   ```
4. Deploy.

The backend CORS config uses `r"https://.*\.vercel\.app"` regex to allow all Vercel deployment URLs automatically — no manual update needed.

---

## Sample Data Patterns

The demo pre-loads 41 alerts with these embedded FP patterns:

| Detection Rule | FP Source Field | Value | Description |
|---|---|---|---|
| Suspicious PowerShell Execution | user | `admin_it_01` | IT admin running legitimate admin scripts |
| Unusual Outbound Traffic | process | `backup_agent.exe` | Backup agent doing scheduled transfers |
| Process Injection Detected | user | `dev_team` | Developers running a debugger |
| Multiple Failed Login Attempts | source_ip | `10.0.2.10` | Monitoring service login probes |

Each pattern repeats 4–6 times, crossing the engine's minimum threshold of 3 FPs, so tuning rule suggestions appear immediately on load.

---

## Core Engine Classes

| Class | Purpose |
|---|---|
| `Alert` | Single SOC alert — stores rule name, severity, IP, user, host, process, analyst decision, notes, timestamps |
| `TuningRule` | Auto-generated rule suggestion — pattern, confidence, fp_count, estimated weekly FP reduction, time saved, action, status |
| `FPDetectionEngine` | Stateful engine — holds all alerts and rules; exposes `detect_patterns()`, `apply_rule()`, `reject_rule()`, `get_metrics()` |

**Confidence formula:** `min(0.95, 0.5 + fp_count × 0.05)`

**Suggested action:** `suppress` when `fp_count >= 5`, otherwise `lower_severity`
