# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - 2026-02-03

### Added

#### Issue #9: Multiple scan_id Filtering in SSE
- Added support for comma-separated scan IDs in SSE endpoint (`/events?scan_id=id1,id2,id3`)
- Security: Limited to max 10 scan IDs and 400 chars input length (DoS prevention)
- Updated `ConnectionMetadata` to track multiple scan IDs
- Maintains backward compatibility with single scan ID parameter
- **Files**: `src/queue.rs`, `src/control.rs`

#### Issue #10: Priority Queue for Scans
- Implemented priority-based scan queue with High/Normal/Low levels
- Added user quotas (5 high priority scans per hour per user)
- Implemented aging algorithm to prevent starvation of low-priority jobs
- Weighted round-robin: 70% high, 25% normal, 5% low priority
- Added `Priority` enum and `PriorityScanJob` struct
- Full test coverage for priority ordering and quota enforcement
- **Files**: `src/priority_queue.rs` (new), `src/lib.rs`, `src/control.rs`

#### Issue #11: Cron Scheduling for Recurring Scans
- Full cron scheduling system using safe `cron` crate parsing (no shell execution)
- Comprehensive SSRF protection blocking internal IPs and metadata endpoints
- Resource quotas: 10 schedules per user, 1000 total system-wide
- Minimum 5-minute interval between executions
- Full REST API with CRUD operations:
  - `POST /schedules` - Create schedule
  - `GET /schedules` - List schedules
  - `GET /schedules/:id` - Get schedule
  - `POST /schedules/:id/pause` - Pause schedule
  - `POST /schedules/:id/resume` - Resume schedule
  - `DELETE /schedules/:id` - Delete schedule
- Database schema for schedules with migrations
- Exponential backoff for failed schedule retries
- Duplicate schedule detection
- Timezone support for cron expressions
- **Files**: `src/scheduler.rs` (new), `src/lib.rs`, `src/database.rs`, `src/control.rs`

#### Security Enhancements
- **Security Audit Framework** (`src/security_audit.rs`):
  - Pre-deployment security audit for Cron scheduling
  - 8 security check categories
  - Risk level assessment (Low/Medium/High/Critical)
  - Detailed recommendations
  
- **RBAC System** (`src/rbac.rs`):
  - Role-based access control (Admin, Operator, Viewer)
  - JWT-based authentication with claims and expiration
  - Permission-based authorization
  - API key support for service-to-service authentication
  
- **Audit Logging** (`src/audit.rs`):
  - Comprehensive audit trail for all security events
  - Async backend for log processing
  - Structured JSON logging to `data/audit/audit-YYYY-MM-DD.log`
  - Critical event alerting
  - Convenience methods for common events

### Security

#### Command Injection Prevention
- All cron expressions parsed using safe `cron` crate
- No shell execution or system calls with user input
- Input validation before parsing

#### SSRF Prevention
- Blocked internal IP ranges (localhost, 127.0.0.1, ::1, etc.)
- Blocked cloud metadata endpoints (169.254.169.254, metadata.google.internal)
- RFC1918 private IP ranges blocked (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- URL scheme validation (HTTP/HTTPS only)
- Target length limits

#### Resource Protection
- Rate limiting: 60 req/min per IP, 300 req/min per token (production)
- Schedule quotas to prevent resource exhaustion
- Queue capacity limits with graceful handling

### Documentation

- Added comprehensive `docs/SECURITY.md` with:
  - Security deployment checklist
  - RBAC configuration guide
  - Audit logging documentation
  - Rate limiting configuration
  - Penetration testing commands
  - Incident response procedures
- Added `IMPLEMENTATION_SUMMARY.md` with complete feature overview
- Inline code documentation for all public APIs

### Technical Details

#### Dependencies Added
```toml
cron = "0.12"          # Safe cron parsing
chrono-tz = "0.9"      # Timezone support
rand = "0.8"           # Randomization for tests
```

#### Database Migrations
- Added `schedules` table with fields:
  - id, target_domain, target_scope, config_name
  - cron_expression, timezone, enabled
  - last_run, next_run, created_by, created_at
  - retry_count, priority

#### API Changes
- `POST /scans` - Now accepts optional `priority` field (high/normal/low)
- `GET /events` - Now accepts comma-separated `scan_id` parameter
- New endpoints for schedule management (see Issue #11)

### Testing

- Comprehensive unit tests for all new features
- Security-focused tests for:
  - Command injection prevention
  - SSRF prevention
  - Authentication and authorization
  - Rate limiting
  - Quota enforcement

---

## [0.1.0-alpha] - Previous Release

### Features
- Initial release with basic scan functionality
- CLI interface for target management
- Basic REST API
- Database support (SQLite/PostgreSQL)
- SSE event streaming
- Report generation

---

## Migration Guide

### Upgrading to Latest Version

1. **Database Migration**:
   ```bash
   cargo run -- db-init
   ```
   This will automatically create the new `schedules` table.

2. **Environment Variables**:
   Add new required environment variables (see docs/SECURITY.md)

3. **Authentication** (Optional):
   Enable RBAC by setting `ENABLE_RBAC=true`

4. **Audit Logging** (Optional):
   Create audit directory: `mkdir -p data/audit`

---

## Contributors

- Security audit and implementation by development team
- Special thanks to security reviewers

---

## License

See LICENSE.txt for details.
