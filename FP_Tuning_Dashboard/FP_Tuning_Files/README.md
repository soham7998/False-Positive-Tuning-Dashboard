# FP Tuning Dashboard

[![Backend](https://img.shields.io/badge/Backend-Railway-9333ea)](https://false-positive-tuning-dashboard-production.up.railway.app)
[![Frontend](https://img.shields.io/badge/Frontend-Vercel-000)](https://false-positive-tuning-dashboard.vercel.app)
[![GitHub](https://img.shields.io/badge/GitHub-soham7998%2FFalse--Positive--Tuning--Dashboard-181717?logo=github)](https://github.com/soham7998/False-Positive-Tuning-Dashboard)

**Live:** https://false-positive-tuning-dashboard.vercel.app  
**Repo:** https://github.com/soham7998/False-Positive-Tuning-Dashboard  
**API:** https://false-positive-tuning-dashboard-production.up.railway.app

SOC analysts spend a significant chunk of each shift triaging alerts they've already seen before — the same rule firing on the same backup process, the same IT admin account, the same monitoring IP. This tool tracks those decisions and automatically surfaces suppression rule suggestions when a pattern repeats enough times to be worth acting on.

---

## How It Works

Analysts triage alerts through the dashboard, marking each one as a True Positive or False Positive. After every decision, the detection engine re-runs and groups all FP alerts by four pattern types:

- `rule_name + source_ip`
- `rule_name + user`
- `rule_name + process`
- `rule_name + host`

Any combination that appears 3 or more times becomes a suggested tuning rule. The rule includes:

- **Confidence score** — `min(0.95, 0.5 + fp_count × 0.05)`, grows with each additional FP
- **Suggested action** — `suppress` if fp_count ≥ 5, otherwise `lower_severity`
- **Estimated weekly FP reduction** — fp_count × 2 (rough forward projection)
- **Estimated time saved** — weekly FPs × 8 min/alert

Rules stay in `pending` state until an analyst applies or rejects them.

---

## Tuning Rules — What They Contain

Each rule is a structured object the engine generates:

```json
{
  "rule_id": "TUN-0001",
  "name": "Suppress: Suspicious PowerShell Execution from User=admin_it_01",
  "description": "Detected 6 false positives for rule 'Suspicious PowerShell Execution' with user 'admin_it_01'. Recommend suppressing or whitelisting this combination.",
  "pattern": {
    "rule_name": "Suspicious PowerShell Execution",
    "user": "admin_it_01"
  },
  "fp_count": 6,
  "confidence": 0.8,
  "estimated_fp_reduction": 12,
  "estimated_time_saved_minutes": 96,
  "suggested_action": "suppress",
  "status": "pending"
}
```

The `pattern` field is deliberately simple — a flat key/value map that's easy to translate into any SIEM's suppression syntax.

---

## Applying Rules to Your SIEM

The dashboard itself marks rules as applied or rejected, but doesn't push changes to a SIEM directly. The API returns structured rule data that can be piped into whichever platform you use.

**Splunk** — translate the pattern into a `NOT` filter in your search:
```spl
index=soc_alerts rule_name="Suspicious PowerShell Execution" NOT user="admin_it_01"
```

**Elastic / OpenSearch** — add a `must_not` clause to your detection query:
```json
{
  "must_not": [
    { "term": { "rule_name": "Suspicious PowerShell Execution" } },
    { "term": { "user": "admin_it_01" } }
  ]
}
```

**Sigma** — translate to a condition filter:
```yaml
filter:
  rule_name: 'Suspicious PowerShell Execution'
  user: 'admin_it_01'
condition: selection and not filter
```

To pull all pending rules from the API:
```bash
curl https://false-positive-tuning-dashboard-production.up.railway.app/api/rules?status=pending
```

A webhook or scheduled script can poll this endpoint and apply rules programmatically once they're approved in the dashboard.

---

## Stack

**Backend** — Python 3.11, Flask, Flask-CORS, Gunicorn, deployed on Railway  
**Frontend** — Next.js 14, TypeScript, Tailwind CSS, Recharts, deployed on Vercel

---

## Running Locally

**Backend:**
```bash
cd FP_Tuning_Dashboard/FP_Tuning_Files/backend

python -m venv venv
source venv/bin/activate

pip install -r requirements.txt
python app.py
# running on http://localhost:5000
```

**Frontend:**
```bash
cd FP_Tuning_Dashboard/FP_Tuning_Files/frontend

npm install

cp .env.example .env.local
# set NEXT_PUBLIC_API_URL=http://localhost:5000

npm run dev
# running on http://localhost:3000
```

---

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Health check |
| `GET` | `/api/metrics` | FP rate, time saved, top rules, distributions |
| `GET` | `/api/alerts` | List alerts — `?status=pending\|fp\|tp\|all` |
| `POST` | `/api/alerts/<id>/decision` | Submit `true_positive` or `false_positive` |
| `GET` | `/api/rules` | List tuning rules — `?status=pending\|applied\|rejected\|all` |
| `POST` | `/api/rules/<id>/apply` | Mark rule as applied |
| `POST` | `/api/rules/<id>/reject` | Mark rule as rejected |
| `POST` | `/api/analyze` | Re-run pattern detection |
| `POST` | `/api/seed` | Reset to sample data |

---

## Deployment

**Backend → Railway**
1. New Project → Deploy from GitHub ([soham7998/False-Positive-Tuning-Dashboard](https://github.com/soham7998/False-Positive-Tuning-Dashboard))
2. Root Directory: `FP_Tuning_Dashboard/FP_Tuning_Files/backend`
3. Networking → Generate Domain

**Frontend → Vercel**
1. Import [soham7998/False-Positive-Tuning-Dashboard](https://github.com/soham7998/False-Positive-Tuning-Dashboard), Root Directory: `FP_Tuning_Dashboard/FP_Tuning_Files/frontend`
2. Add env var: `NEXT_PUBLIC_API_URL=https://false-positive-tuning-dashboard-production.up.railway.app`
3. Deploy → https://false-positive-tuning-dashboard.vercel.app

---

## Sample Data

Ships with 41 pre-loaded alerts containing four embedded FP patterns (4–6 repeats each) so rule suggestions appear immediately without any triaging:

| Rule | Field | Value |
|------|-------|-------|
| Suspicious PowerShell Execution | user | `admin_it_01` |
| Unusual Outbound Traffic | process | `backup_agent.exe` |
| Process Injection Detected | user | `dev_team` |
| Multiple Failed Login Attempts | source_ip | `10.0.2.10` |

---

## Project Structure

```
FP_Tuning_Dashboard/FP_Tuning_Files/
├── backend/
│   ├── app.py              # Flask routes
│   ├── src/
│   │   ├── fp_engine.py    # detection engine, rule generation, metrics
│   │   └── sample_data.py  # alert generator
│   ├── Procfile
│   └── requirements.txt
└── frontend/
    └── src/app/
        ├── page.tsx        # full dashboard UI
        └── layout.tsx
```
