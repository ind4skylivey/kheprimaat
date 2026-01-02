# 🔮 Khepri — Offensive Recon & Vuln Automation

![Khepri Banner](assets/banner.png)

> Key Hunting & Exploration Platform for Reconnaissance Intelligence. Built for fast, scoped, auditable bug bounty automation.

## ⚡ Why Khepri
- End-to-end pipeline: Subfinder → HTTPX → Nuclei → SQLMap/FFUF.
- Hard scope enforcement + rate limits; fails soft, logs everything.
- Dedup + confidence scoring to cut noise; JSON/HTML reports ready to ship.
- SQLite by default; Postgres-ready via `DATABASE_URL`.
- Proprietary. Exclusive use by ind4skylivey.

## 🚀 Quick Start (MVP scaffold)
```bash
cd /home/il1v3y/shenanigans/Repos/Personal/Khepri
mkdir -p data reports logs
cargo build
cargo run -- --database-url sqlite://data/khepri.db db-init
cargo run -- target-add example.com --scope "*.api.example.com,app.example.com"
cargo run -- scan-start example.com --config templates/config/default-scan.yaml
cargo run -- findings-list
```

## 🧩 Commands (current CLI)
- `target-add <domain> [--scope LIST] [--notes]`
- `target-list`
- `scan-start <domain> [--config path.yaml]`
- `findings-list [--domain <domain>]`
- `db-init`

## 🛠️ Stack
- Rust 2021, Tokio, Clap
- SQLx (Any driver: SQLite/Postgres)
- Reqwest/Hyper, Tracing
- Handlebars reporting, serde_yaml config

## 🔐 Safety Defaults
- Scope validation before tools run.
- Timeouts + rate hints in each adapter.
- Deduplication to suppress duplicate findings.
- Reports drop into `reports/`; findings persisted to DB.

## 📂 Layout
- `src/` core (models, orchestrator, tools, DB, reporting, notifications)
- `templates/config/default-scan.yaml` sample profile
- `tests/basic.rs` smoke tests (config + dedup)

## ▶️ Next Up
1) Replace placeholder parsers with full JSON ingestion for nuclei/httpx/sqlmap/ffuf.  
2) Expand `ScanConfig` coverage (notifications, filters, limits).  
3) Add stats/export commands and CI (fmt/clippy/tests).  
4) Optional container image + tool bootstrap installer.
