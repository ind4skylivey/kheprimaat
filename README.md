# 🦂⚖️ KhepriMaat — Offensive Recon & Vuln Automation  
![Build](https://img.shields.io/github/actions/workflow/status/ind4skylivey/kheprimaat/ci.yml?label=CI&logo=github) ![Coverage](https://img.shields.io/badge/coverage-80%25%2B-blue) ![License](https://img.shields.io/badge/license-Private-red) ![Rust](https://img.shields.io/badge/rust-2021-orange) ![DB](https://img.shields.io/badge/db-SQLite%20%7C%20Postgres-informational) ![Status](https://img.shields.io/badge/status-Lab%20use%20only-purple)

![KhepriMaat Banner](assets/banner.png)

![KhepriMaat Logo](assets/logo.png)

> Key Hunting & Exploration Platform for Reconnaissance Intelligence. Built for fast, scoped, auditable bug bounty automation.

## About KhepriMaat
KhepriMaat blends continual transformation (Khepri) with balance and truth (Maat). It was born to give our red-team lab a reproducible, evidence-first pipeline for recon, probing, and verification—without losing auditability. Every subsystem (control API, parsers, reporting, notifications) keeps findings explainable, replayable, and safe to validate in the lab before they ever touch production.

![About KhepriMaat](assets/about.png)

**Why it exists**
- Replace brittle one-off scripts with a cohesive, testable automation spine.
- Preserve ground truth: store requests/responses, confidence, and provenance per finding.
- Enable remote control: bearer-protected API + rate limits + SSE events for live status.
- Stay tool-agnostic: wrap subfinder/httpx/nuclei/sqlmap/ffuf with structured parsers and confidence scoring.

**How it’s built (lab view)**
- Rust async stack (Tokio, Axum, SQLx AnyPool for SQLite/Postgres).
- Evidence-first parsers with truncation and export-safe reporting (HTML/JSON/CSV).
- Notification fan-out (SMTP, Slack/Discord/webhooks) with optional XOAUTH2.
- CI: fmt + clippy + tests + coverage; fixtures for parsers and SMTP config.

**Control surface (today)**
- CLI & control API server (Bearer + rate limits).
- Endpoints: POST /scans, GET /scans, GET /scans/:id/findings, status, cancel, SSE /events.
- Defaults scoped to local lab: bind 127.0.0.1, token required, sqlite://data/kheprimaat.db.

**Road ahead**
- ✅ **Worker/queue for scans with live progress push** (IMPLEMENTED)
- ✅ **Secret-aware redaction in stored evidence** (IMPLEMENTED)
- Container/packaging for isolated lab deploys.

## ⚡ Why KhepriMaat
- End-to-end pipeline: Subfinder → HTTPX → Nuclei → SQLMap/FFUF.
- Hard scope enforcement + rate limits; fails soft, logs everything.
- Dedup + confidence scoring to cut noise; JSON/HTML reports ready to ship.
- SQLite by default; Postgres-ready via `DATABASE_URL`.
- Proprietary. Exclusive use by ind4skylivey.

## 🚀 Quick Start (5-minute lab spin-up)
```bash
cd /media/il1v3y/HD2/HDfiles/shenanigans/Repos/Personal/kheprimaat
mkdir -p data reports logs
cargo build
# initialize DB + defaults
cargo run -- --database-url sqlite://data/kheprimaat.db db-init
# add a target
cargo run -- target-add example.com --scope "*.api.example.com,app.example.com"
# launch the control API (bearer token)
cargo run -- server --bind 127.0.0.1:8080 --token mytoken
# trigger a scan via CLI or API
cargo run -- scan-start example.com --config templates/config/default-scan.yaml
curl -H "Authorization: Bearer mytoken" -H "Content-Type: application/json" \
  -d '{"target":"example.com"}' http://127.0.0.1:8080/scans
# inspect findings
cargo run -- findings-list
```

## ⚡ Power User Moves
- One-liner scan+report: `cargo run -- scan-start $TARGET && xdg-open reports/$(ls -t reports | head -1)`
- API blast: `http --auth-type bearer --auth mytoken POST :8080/scans target=$TARGET`
- Tail live status: `curl -N -H 'Authorization: Bearer mytoken' http://127.0.0.1:8080/events`
- Batch targets: `for d in $(cat scope.txt); do cargo run -- scan-start $d; done`
- Fast diff of findings: `jq '.findings[]|[.severity,.endpoint,.tool_source]' reports/scan-*.json | sort | uniq -c`

## 🔌 Control API (Bearer + rate-limit)
| Method | Path | What it does | Notes |
| --- | --- | --- | --- |
| POST | /scans | Queue a scan for `target`, optional `scope`/`config` | Returns `scan_id`, status=queued |
| GET | /scans | List recent scans | Summaries only |
| GET | /scans/:id/findings | Findings for a scan | Query: severity, verified, limit |
| GET | /status/:id | Status + sample evidence | |
| POST | /cancel/:id | Cancel a running scan | Sets cancel flag + status |
| GET | /events | SSE stream of scan status | Keep-alive for dashboards |

## 🛡️ Parsers & Evidence
- **httpx**: status/title/headers/body (truncated), server tag
- **nuclei**: matched-at, response-body (truncated), severity mapping
- **sqlmap**: payload + technique into evidence
- **ffuf**: discovered paths with status/length, confidence tag
- All findings store request/response bodies/headers (for reports/exports)
- **🆕 Automatic secret redaction** applied to all evidence before storage/export

## 🧩 Commands (CLI surface)
- `server --bind <addr> --token <token>` start control API
- `target-add|list|show|delete`
- `scan-start|list|status|cancel`
- `findings-list|verify|export|report`
- `config-webhook|config-slack|config-discord|config-create`
- `db-init`

## 🛠️ Stack (at a glance)
- Rust 2021 async: Tokio, Axum, Tower HTTP, Clap
- SQLx AnyPool (SQLite/Postgres), UUID/chrono
- HTTP: Reqwest/Hyper; Templates/Reports: Handlebars/CSV/JSON
- Notifications: Lettre (SMTP LOGIN/PLAIN/XOAUTH2), Slack/Discord/Webhooks
- CI: fmt + clippy + tests + coverage fixtures

## 🔐 Safety Defaults
- Scope validation before tool runs; rate limits per API token/IP
- Bearer-protected control API bound to 127.0.0.1 by default
- Timeouts + soft-fail paths in adapters; dedup + confidence scoring
- Evidence persisted (requests/responses) and exported to reports
- **🆕 Automatic secret redaction** in DB storage and reports (30+ patterns: AWS, GitHub, JWT, private keys, etc.)

## 📂 Layout
- `src/` core (models, orchestrator, tools, DB, reporting, notifications, control API)
- `templates/config/` scan profiles (`default-scan.yaml`)
- `tests/` fixtures for parsers/SMTP/cancellation
- `assets/` branding (banner, logo, about)

## ▶️ Roadmap (concise)
1) ✅ **Queue/worker for scans + live progress (SSE/push)** (COMPLETED - see `docs/QUEUE_WORKER_SYSTEM.md`)  
2) ✅ **Secret-aware redaction across stored evidence** (COMPLETED - see `docs/SECRET_REDACTION.md`)  
3) ✅ **Metrics/Stats endpoint for operational visibility** (COMPLETED - see `docs/METRICS_ENDPOINT.md`)
4) Packaging: container image + lab bootstrap.  
5) Red-team UX: richer reports, timeline view, and webhook templating.

## 🚀 Async Queue/Worker System (NEW!)

KhepriMaat now features a robust asynchronous queue/worker system for background scan execution with real-time progress updates.

**Features:**
- **Async execution**: API returns immediately with scan ID
- **Worker pool**: 3 concurrent workers by default (configurable)
- **Real-time events**: SSE streaming with 8 event types
- **Per-scan filtering**: Subscribe to events for specific scans
- **Connection tracking**: Monitor active SSE clients
- **Retry logic**: Automatic retry with exponential backoff (3 attempts)
- **Graceful shutdown**: Clean termination of in-flight scans
- **Bounded queue**: 100 job capacity (prevents resource exhaustion)

**Event Types:**
- `queued`, `started`, `stage_changed`, `progress`, `finding_discovered`, `completed`, `failed`, `cancelled`

**Quick Example:**
```bash
# Create scan (returns immediately)
curl -X POST http://localhost:3000/scans \
  -d '{"target":"example.com"}' | jq
# {"scan_id":"abc-123","status":"queued"}

# Stream ALL events (unfiltered)
curl -N http://localhost:3000/events

# Stream events for SPECIFIC scan (filtered)
curl -N "http://localhost:3000/events?scan_id=abc-123"
# data: {"type":"started","scan_id":"abc-123","worker_id":0,...}
# data: {"type":"stage_changed","stage":"subfinder","progress":0.0,...}
# data: {"type":"finding_discovered","severity":"high",...}
# data: {"type":"completed","duration_secs":120,"findings_count":8,...}
```

📖 **Full documentation:** [`docs/QUEUE_WORKER_SYSTEM.md`](docs/QUEUE_WORKER_SYSTEM.md)  
📖 **SSE filtering guide:** [`docs/ENHANCED_SSE.md`](docs/ENHANCED_SSE.md)

---

## 🔒 Secret Redaction (NEW!)

KhepriMaat includes comprehensive automatic secret redaction to protect sensitive data in findings and reports.

**Features:**
- 30+ built-in patterns (AWS, GitHub, Google, Azure, JWT, private keys, etc.)
- Automatic redaction at DB storage and report generation
- Configurable patterns via YAML
- Zero configuration required - works out of the box
- Performance optimized (< 5% overhead)

**Redacted Fields:**
- Evidence, payloads, request/response bodies, headers, remediation text

**Quick Example:**
```bash
# Before: "AWS_KEY=AKIAIOSFODNN7EXAMPLE"
# After:  "AWS_KEY=***REDACTED-AWS-ACCESS-KEY***"
```

📖 **Full documentation:** [`docs/SECRET_REDACTION.md`](docs/SECRET_REDACTION.md)  
⚙️ **Pattern configuration:** [`templates/config/redaction-patterns.yaml`](templates/config/redaction-patterns.yaml)

---

## 📊 Metrics & Monitoring (NEW!)

KhepriMaat provides comprehensive system metrics for operational visibility.

**Endpoints:**
- `GET /metrics` - System metrics with 30s cache
- `GET /stats` - Alias for /metrics

**Features:**
- **Scan metrics**: Total, success rate, avg duration, by status
- **Finding metrics**: By severity/tool, verified rate
- **System health**: Queue, workers, SSE connections, uptime
- **Auto-caching**: 30-second TTL for performance
- **Dashboard-ready**: JSON format for easy integration

**Quick Example:**
```bash
curl http://localhost:3000/metrics | jq
```

**Response:**
```json
{
  "scans": {
    "total": 1523,
    "success_rate": 94.5,
    "avg_duration_secs": 312.5,
    "by_status": {"Completed": 1432, "Failed": 91}
  },
  "findings": {
    "total": 8945,
    "by_severity": {"Critical": 23, "High": 187},
    "verified_rate": 90.0
  },
  "system": {
    "sse_connections": 15,
    "uptime_secs": 864000,
    "database_healthy": true
  }
}
```

📖 **Full documentation:** [`docs/METRICS_ENDPOINT.md`](docs/METRICS_ENDPOINT.md)

