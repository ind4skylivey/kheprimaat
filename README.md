# 🦂⚖️ KhepriMaat

<div align="center">

[![CI](https://img.shields.io/github/actions/workflow/status/ind4skylivey/kheprimaat/ci.yml?label=CI&logo=github&style=for-the-badge)](https://github.com/ind4skylivey/kheprimaat/actions)
[![Coverage](https://img.shields.io/badge/coverage-80%25+-success?style=for-the-badge&logo=codecov)](https://github.com/ind4skylivey/kheprimaat)
[![License](https://img.shields.io/badge/license-Proprietary-critical?style=for-the-badge)](LICENSE.txt)
[![Rust](https://img.shields.io/badge/rust-2021-orange?style=for-the-badge&logo=rust)](https://www.rust-lang.org)
[![Database](https://img.shields.io/badge/DB-SQLite%20%7C%20Postgres-blue?style=for-the-badge&logo=postgresql)](https://www.postgresql.org)
[![Status](https://img.shields.io/badge/status-Production%20Ready-9cf?style=for-the-badge)](https://github.com/ind4skylivey/kheprimaat)

</div>

![KhepriMaat Banner](assets/banner.png)

<div align="center">

### **Key Hunting & Exploration Platform for Reconnaissance Intelligence**

*Evidence-first bug bounty automation with audit-grade traceability*

[![API](https://img.shields.io/badge/API-REST-ff69b4?style=flat-square&logo=fastapi)](docs/API.md)
[![Security](https://img.shields.io/badge/Security-Audited-success?style=flat-square&logo=security)](docs/SECURITY.md)
[![Performance](https://img.shields.io/badge/Performance-Async%20%7C%20Parallel-blueviolet?style=flat-square)](docs/ARCHITECTURE.md)

</div>

![KhepriMaat Logo](assets/logo.png)

---

## 🎯 What is KhepriMaat?

Named after the Egyptian gods of transformation (**Khepri**) and truth/justice (**Maat**), KhepriMaat is a **battle-tested, evidence-first automation platform** designed for serious security researchers and red teams.

It transforms chaotic reconnaissance workflows into **structured, auditable, and reproducible** security assessments—without losing the agility that makes bug hunting effective.

> *"Every finding tells a story. We make sure that story is complete, verifiable, and court-ready."*

![About KhepriMaat](assets/about.png)

---

## ⚡ Why KhepriMaat Stands Out

| Feature | KhepriMaat | Traditional Tools |
|---------|-----------|------------------|
| **Evidence Preservation** | ✅ Full request/response storage | ❌ Often lost |
| **Audit Trail** | ✅ Immutable logs per finding | ❌ Manual documentation |
| **Scope Enforcement** | ✅ Hard boundaries with soft-fail | ❌ Easy to exceed |
| **Real-time Visibility** | ✅ SSE streaming + metrics | ❌ Polling or blind |
| **Secret Protection** | ✅ Automatic redaction (30+ patterns) | ❌ Manual cleanup |
| **Queue Management** | ✅ Priority-based async workers | ❌ Sequential only |
| **Scheduled Scans** | ✅ Cron-like recurring automation | ❌ Manual triggers |

---

## 🚀 Features at a Glance

### 🔍 **Intelligent Reconnaissance Pipeline**
```
Target Input → Scope Validation → Async Queue → Worker Pool
                    ↓
Subfinder → HTTPX → Nuclei → SQLMap/FFUF → Correlation Engine
                    ↓
Deduplication → Confidence Scoring → Evidence Storage → Reports
```

### 🎛️ **Advanced Control API**
- **Bearer-authenticated** REST endpoints
- **Rate limiting** (per IP + per token)
- **SSE event streaming** with multi-scan filtering
- **Priority queue** (High/Normal/Low with quotas)
- **Cron scheduling** for recurring assessments
- **Real-time metrics** endpoint

### 🛡️ **Security-First Architecture**
- **30+ secret patterns** automatically redacted
- **SSRF protection** on all targets
- **Command injection prevention** in scheduler
- **RBAC** (Admin/Operator/Viewer roles)
- **Comprehensive audit logging**
- **Security audit framework** for pre-deployment checks

---

## 🎬 Quick Start

### Prerequisites
```bash
# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Or update existing
rustup update
```

### Installation
```bash
# Clone repository
git clone https://github.com/ind4skylivey/kheprimaat.git
cd kheprimaat

# Build optimized release
cargo build --release

# Initialize database
mkdir -p data reports logs
./target/release/kheprimaat db-init
```

### First Scan
```bash
# Start control API
./target/release/kheprimaat server \
  --bind 127.0.0.1:8080 \
  --token your-secure-token

# Add target
./target/release/kheprimaat target-add example.com \
  --scope "*.api.example.com,app.example.com"

# Queue scan with high priority
curl -X POST http://127.0.0.1:8080/scans \
  -H "Authorization: Bearer your-secure-token" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "priority": "high",
    "config": "default-scan"
  }'

# Watch real-time progress
curl -N -H "Authorization: Bearer your-secure-token" \
  http://127.0.0.1:8080/events
```

---

## 📡 API Reference

### Core Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/scans` | Queue new scan | ✅ Bearer |
| `GET` | `/scans` | List recent scans | ✅ Bearer |
| `GET` | `/scans/:id/findings` | Get findings with filters | ✅ Bearer |
| `GET` | `/status/:id` | Scan status + evidence samples | ✅ Bearer |
| `POST` | `/cancel/:id` | Cancel running scan | ✅ Bearer |
| `GET` | `/events` | SSE stream (all scans) | ✅ Bearer |
| `GET` | `/events?scan_id=id1,id2` | SSE stream (filtered) | ✅ Bearer |
| `GET` | `/metrics` | System metrics | ✅ Bearer |

### Priority Queue API

```bash
# High priority (max 5/hour per user)
curl -X POST /scans -d '{"target":"x.com","priority":"high"}'

# Normal priority (default)
curl -X POST /scans -d '{"target":"x.com","priority":"normal"}'

# Low priority (background)
curl -X POST /scans -d '{"target":"x.com","priority":"low"}'
```

### Cron Scheduling API

```bash
# Create daily scan at 2 AM UTC
curl -X POST /schedules \
  -d '{
    "target": "example.com",
    "cron": "0 2 * * *",
    "timezone": "UTC",
    "priority": "normal"
  }'

# Pause schedule
curl -X POST /schedules/:id/pause

# Resume schedule  
curl -X POST /schedules/:id/resume

# Delete schedule
curl -X DELETE /schedules/:id
```

---

## 🏗️ Architecture

### System Components

```
┌─────────────────────────────────────────────────────────────┐
│                    Control API (Axum)                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   Scans     │  │  Schedules  │  │   SSE /events       │ │
│  │  Endpoint   │  │  Endpoints  │  │   Streaming         │ │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘ │
└─────────┼────────────────┼────────────────────┼────────────┘
          │                │                    │
          ▼                ▼                    ▼
┌─────────────────────────────────────────────────────────────┐
│                  Priority Queue System                      │
│     High Priority Queue (max 5/user/hr)                     │
│     Normal Priority Queue                                   │
│     Low Priority Queue (with aging)                         │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                   Worker Pool (3 workers)                   │
│  Worker 0: Subfinder → HTTPX → Nuclei                       │
│  Worker 1: SQLMap (conditional)                             │
│  Worker 2: FFUF (conditional)                               │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                  Evidence Pipeline                          │
│  Parsing → Deduplication → Confidence → Redaction → DB      │
└─────────────────────────────────────────────────────────────┘
```

### Tech Stack

| Layer | Technology |
|-------|------------|
| **Runtime** | Rust 2021, Tokio async |
| **Web Framework** | Axum, Tower HTTP |
| **Database** | SQLx (SQLite/PostgreSQL) |
| **Serialization** | Serde (JSON/YAML) |
| **CLI** | Clap v4 |
| **Templating** | Handlebars, Askama |
| **HTTP Client** | Reqwest, Hyper |
| **Security** | cron, chrono-tz |

---

## 🔐 Security Features

### Automatic Secret Redaction

30+ patterns including:
- AWS Access Keys
- GitHub Tokens  
- JWT Secrets
- Private Keys (RSA, EC, DSA)
- Database Connection Strings
- API Keys (Google, Azure, Slack)

```yaml
# Before storage:
"Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."

# After redaction:
"Authorization: Bearer ***REDACTED-JWT***"
```

### SSRF Protection

Blocked targets:
- `localhost`, `127.0.0.1`, `::1`
- `169.254.169.254` (AWS metadata)
- `metadata.google.internal` (GCP)
- RFC1918 private ranges

### RBAC (Role-Based Access Control)

| Role | Create Scans | Delete Own | Delete Any | View All | Admin |
|------|-------------|------------|------------|----------|-------|
| **Admin** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Operator** | ✅ | ✅ | ❌ | ✅ | ❌ |
| **Viewer** | ❌ | ❌ | ❌ | ✅ | ❌ |

---

## 📊 Monitoring & Observability

### Metrics Endpoint

```bash
curl http://localhost:8080/metrics | jq
```

```json
{
  "scans": {
    "total": 1523,
    "success_rate": 94.5,
    "avg_duration_secs": 312.5,
    "by_priority": {"High": 145, "Normal": 876, "Low": 502}
  },
  "findings": {
    "total": 8945,
    "by_severity": {"Critical": 23, "High": 187, "Medium": 1243},
    "verified_rate": 90.0
  },
  "system": {
    "queue_depth": 12,
    "active_workers": 3,
    "sse_connections": 15,
    "schedules_active": 8
  }
}
```

### Audit Logging

All security events logged to `data/audit/audit-YYYY-MM-DD.log`:
- Authentication attempts
- Permission denials
- Schedule operations
- Quota violations
- Invalid target blocks

---

## 🛠️ Advanced Usage

### Power User Commands

```bash
# One-liner scan + open report
./kheprimaat scan-start $TARGET && \
  xdg-open reports/$(ls -t reports | head -1)

# Batch scan with priority
for target in $(cat scope.txt); do
  curl -X POST /scans -d "{\"target\":\"$target\",\"priority\":\"low\"}"
done

# Fast finding analysis
jq -r '.findings[] | "[\(.severity)] \(.endpoint)"' \
  reports/scan-*.json | sort | uniq -c | sort -rn

# Real-time dashboard
watch -n 1 'curl -s /metrics | jq .system'
```

### Docker Deployment

```bash
# Production deployment
docker-compose up -d

# Scale workers
docker-compose up -d --scale kheprimaat=3
```

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [API.md](docs/API.md) | Complete API reference |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design & components |
| [SECURITY.md](docs/SECURITY.md) | Security hardening guide |
| [CONTRIBUTING.md](docs/CONTRIBUTING.md) | Development guidelines |
| [INSTALLATION.md](docs/INSTALLATION.md) | Detailed setup instructions |

---

## 🗺️ Roadmap

### ✅ Completed
- [x] Async queue/worker system with SSE
- [x] Secret redaction (30+ patterns)
- [x] Metrics endpoint with caching
- [x] Docker containerization
- [x] Priority queue with quotas
- [x] Cron scheduling system
- [x] Multi-scan SSE filtering
- [x] RBAC & audit logging

### 🚧 In Progress
- [ ] Kubernetes Helm charts
- [ ] Distributed scanning (multi-node)
- [ ] Web UI dashboard
- [ ] Plugin system for custom tools

### 📅 Planned
- [ ] Machine learning for false-positive reduction
- [ ] Integration with CI/CD pipelines
- [ ] Compliance reporting (SOC2, ISO27001)

---

## ⚠️ Safety & Legal

**IMPORTANT**: KhepriMaat is designed for:
- ✅ Authorized penetration testing
- ✅ Bug bounty programs with explicit scope
- ✅ Internal security assessments
- ✅ Educational purposes in isolated environments

**NOT for**:
- ❌ Unauthorized access to systems
- ❌ Attacking targets without permission
- ❌ Any illegal activities

Always ensure you have **explicit written authorization** before scanning any target.

---

## 📄 License

**Proprietary Software** - All rights reserved.

This software is the exclusive property of the author. Unauthorized use, distribution, or modification is strictly prohibited.

For licensing inquiries: [Contact Author](mailto:ind4skylivey@proton.me)

---

<div align="center">

### Built with ⚡ by Security Engineers, for Security Engineers

**[⬆ Back to Top](#-kheprimaat)**

</div>
