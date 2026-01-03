use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::any::{AnyPoolOptions, AnyRow};
use sqlx::{AnyPool, Row};
use uuid::Uuid;

use crate::models::{
    Finding, ScanResult, ScanSummary, Severity, Target, TargetStatus, VulnerabilityType,
};

#[derive(Clone)]
pub struct Database {
    pool: AnyPool,
}

impl Database {
    pub async fn new(database_url: &str) -> Result<Self> {
        // Register compiled drivers for AnyPool (sqlite/postgres) to avoid runtime panic.
        sqlx::any::install_default_drivers();

        let pool = AnyPoolOptions::new()
            .max_connections(20)
            .connect(database_url)
            .await?;

        let db = Self { pool };
        db.migrate().await?;
        Ok(db)
    }

    async fn migrate(&self) -> Result<()> {
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS targets (
                id TEXT PRIMARY KEY,
                domain TEXT NOT NULL UNIQUE,
                scope TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_scan TEXT,
                notes TEXT
            );"#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS scan_results (
                id TEXT PRIMARY KEY,
                target_id TEXT NOT NULL,
                config_id TEXT NOT NULL,
                started_at TEXT NOT NULL,
                ended_at TEXT,
                status TEXT NOT NULL,
                error_message TEXT,
                total_subdomains_discovered INTEGER,
                total_endpoints_probed INTEGER,
                request_body TEXT,
                response_body TEXT,
                response_headers TEXT
            );"#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                target_id TEXT NOT NULL,
                scan_id TEXT,
                tool_source TEXT NOT NULL,
                vulnerability_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                payload TEXT,
                evidence TEXT NOT NULL,
                verified INTEGER NOT NULL,
                cvss_score REAL,
                confidence_score REAL,
                owasp_category TEXT,
                remediation TEXT,
                created_at TEXT NOT NULL,
                tags TEXT,
                request_body TEXT,
                response_body TEXT,
                response_headers TEXT
            );"#,
        )
        .execute(&self.pool)
        .await?;

        // best-effort migrations for existing DBs
        let _ = sqlx::query("ALTER TABLE findings ADD COLUMN confidence_score REAL;")
            .execute(&self.pool)
            .await;
        let _ = sqlx::query("ALTER TABLE findings ADD COLUMN request_body TEXT;")
            .execute(&self.pool)
            .await;
        let _ = sqlx::query("ALTER TABLE findings ADD COLUMN response_body TEXT;")
            .execute(&self.pool)
            .await;
        let _ = sqlx::query("ALTER TABLE findings ADD COLUMN response_headers TEXT;")
            .execute(&self.pool)
            .await;

        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS scan_control (
                scan_id TEXT PRIMARY KEY,
                cancel INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );"#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn upsert_target(&self, target: &Target) -> Result<Target> {
        let id = target.id.unwrap_or_else(Uuid::new_v4);
        let scope_json = serde_json::to_string(&target.scope)?;

        sqlx::query(
            r#"INSERT INTO targets (id, domain, scope, status, created_at, last_scan, notes)
               VALUES ($1, $2, $3, $4, $5, $6, $7)
               ON CONFLICT(domain) DO UPDATE SET scope = EXCLUDED.scope, notes = EXCLUDED.notes;"#,
        )
        .bind(id.to_string())
        .bind(&target.domain)
        .bind(scope_json)
        .bind(format!("{:?}", target.status))
        .bind(target.created_at.to_rfc3339())
        .bind(target.last_scan.map(|d| d.to_rfc3339()))
        .bind(&target.notes)
        .execute(&self.pool)
        .await?;

        Ok(Target {
            id: Some(id),
            domain: target.domain.clone(),
            scope: target.scope.clone(),
            status: target.status,
            created_at: target.created_at,
            last_scan: target.last_scan,
            notes: target.notes.clone(),
        })
    }

    pub async fn list_targets(&self) -> Result<Vec<Target>> {
        let rows: Vec<AnyRow> = sqlx::query("SELECT * FROM targets ORDER BY created_at DESC")
            .fetch_all(&self.pool)
            .await?;

        let mut targets = Vec::new();
        for row in rows {
            let scope_json: String = row.try_get("scope")?;
            let scope: Vec<String> = serde_json::from_str(&scope_json).unwrap_or_default();
            let status_str: String = row.try_get("status")?;
            targets.push(Target {
                id: Some(Uuid::parse_str(row.try_get::<String, _>("id")?.as_str())?),
                domain: row.try_get("domain")?,
                scope,
                status: parse_target_status(&status_str),
                created_at: parse_datetime(row.try_get::<String, _>("created_at")?),
                last_scan: row
                    .try_get::<Option<String>, _>("last_scan")?
                    .map(|s| parse_datetime(s)),
                notes: row.try_get("notes")?,
            });
        }

        Ok(targets)
    }

    pub async fn save_scan(&self, scan: &ScanResult) -> Result<()> {
        sqlx::query(
            r#"INSERT INTO scan_results
                (id, target_id, config_id, started_at, ended_at, status, error_message, total_subdomains_discovered, total_endpoints_probed, request_body, response_body)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
               ON CONFLICT(id) DO UPDATE SET status = EXCLUDED.status, ended_at = EXCLUDED.ended_at, error_message = EXCLUDED.error_message, request_body = EXCLUDED.request_body, response_body = EXCLUDED.response_body;"#,
        )
        .bind(scan.id.to_string())
        .bind(scan.target_id.to_string())
        .bind(scan.config_id.to_string())
        .bind(scan.started_at.to_rfc3339())
        .bind(scan.ended_at.map(|d| d.to_rfc3339()))
        .bind(format!("{:?}", scan.status))
        .bind(scan.error_message.clone())
        .bind(scan.total_subdomains_discovered as i64)
        .bind(scan.total_endpoints_probed as i64)
        .bind(&scan.request_body)
        .bind(&scan.response_body)
        .execute(&self.pool)
        .await?;

        self.insert_findings(&scan.findings, Some(scan.id)).await?;
        Ok(())
    }

    pub async fn insert_findings(&self, findings: &[Finding], scan_id: Option<Uuid>) -> Result<()> {
        for finding in findings {
            sqlx::query(
            r#"INSERT OR REPLACE INTO findings
                   (id, target_id, scan_id, tool_source, vulnerability_type, severity, endpoint, payload, evidence, verified, cvss_score, confidence_score, owasp_category, remediation, created_at, tags, request_body, response_body, response_headers)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19);"#,
            )
            .bind(finding.id.unwrap_or_else(Uuid::new_v4).to_string())
            .bind(finding.target_id.to_string())
            .bind(scan_id.map(|s| s.to_string()))
            .bind(&finding.tool_source)
            .bind(format!("{:?}", finding.vulnerability_type))
            .bind(format!("{:?}", finding.severity))
            .bind(&finding.endpoint)
            .bind(&finding.payload)
            .bind(&finding.evidence)
            .bind(finding.verified as i64)
            .bind(finding.cvss_score)
            .bind(finding.confidence_score)
            .bind(&finding.owasp_category)
            .bind(&finding.remediation)
            .bind(finding.created_at.to_rfc3339())
            .bind(serde_json::to_string(&finding.tags)?)
            .bind(&finding.request_body)
            .bind(&finding.response_body)
            .bind(&finding.response_headers)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    pub async fn list_findings(&self, domain: Option<String>) -> Result<Vec<Finding>> {
        let rows: Vec<AnyRow> = if let Some(domain) = domain {
            sqlx::query(
                r#"SELECT f.* FROM findings f
                   JOIN targets t ON f.target_id = t.id
                   WHERE t.domain = $1
                   ORDER BY f.created_at DESC"#,
            )
            .bind(domain)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query("SELECT * FROM findings ORDER BY created_at DESC")
                .fetch_all(&self.pool)
                .await?
        };

        let mut findings = Vec::new();
        for row in rows {
            findings.push(row_to_finding(&row)?);
        }
        Ok(findings)
    }

    pub async fn verify_finding(&self, finding_id: &Uuid, verified: bool) -> Result<()> {
        sqlx::query("UPDATE findings SET verified = $1 WHERE id = $2")
            .bind(if verified { 1 } else { 0 })
            .bind(finding_id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn delete_target(&self, id_or_domain: &str) -> Result<u64> {
        let res = if let Ok(uuid) = Uuid::parse_str(id_or_domain) {
            sqlx::query("DELETE FROM targets WHERE id = $1")
                .bind(uuid.to_string())
                .execute(&self.pool)
                .await?
        } else {
            sqlx::query("DELETE FROM targets WHERE domain = $1")
                .bind(id_or_domain)
                .execute(&self.pool)
                .await?
        };
        Ok(res.rows_affected())
    }

    pub async fn get_target(&self, id_or_domain: &str) -> Result<Option<Target>> {
        let row_opt = if let Ok(uuid) = Uuid::parse_str(id_or_domain) {
            sqlx::query("SELECT * FROM targets WHERE id = $1")
                .bind(uuid.to_string())
                .fetch_optional(&self.pool)
                .await?
        } else {
            sqlx::query("SELECT * FROM targets WHERE domain = $1")
                .bind(id_or_domain)
                .fetch_optional(&self.pool)
                .await?
        };

        if let Some(row) = row_opt {
            let scope_json: String = row.try_get("scope")?;
            let scope: Vec<String> = serde_json::from_str(&scope_json).unwrap_or_default();
            let status_str: String = row.try_get("status")?;
            Ok(Some(Target {
                id: Some(Uuid::parse_str(row.try_get::<String, _>("id")?.as_str())?),
                domain: row.try_get("domain")?,
                scope,
                status: parse_target_status(&status_str),
                created_at: parse_datetime(row.try_get::<String, _>("created_at")?),
                last_scan: row
                    .try_get::<Option<String>, _>("last_scan")?
                    .map(|s| parse_datetime(s)),
                notes: row.try_get("notes")?,
            }))
        } else {
            Ok(None)
        }
    }

    pub async fn list_scans(&self, target: Option<String>) -> Result<Vec<ScanResult>> {
        let rows: Vec<AnyRow> = if let Some(domain) = target {
            sqlx::query(
                r#"SELECT sr.* FROM scan_results sr
                   JOIN targets t ON sr.target_id = t.id
                   WHERE t.domain = $1
                   ORDER BY sr.started_at DESC"#,
            )
            .bind(domain)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query("SELECT * FROM scan_results ORDER BY started_at DESC")
                .fetch_all(&self.pool)
                .await?
        };

        let mut scans = Vec::new();
        for row in rows {
            scans.push(ScanResult {
                id: Uuid::parse_str(row.try_get::<String, _>("id")?.as_str())?,
                target_id: Uuid::parse_str(row.try_get::<String, _>("target_id")?.as_str())?,
                config_id: Uuid::parse_str(row.try_get::<String, _>("config_id")?.as_str())?,
                findings: Vec::new(),
                started_at: parse_datetime(row.try_get::<String, _>("started_at")?),
                ended_at: row
                    .try_get::<Option<String>, _>("ended_at")?
                    .map(|s| parse_datetime(s)),
                status: parse_scan_status(row.try_get::<String, _>("status")?),
                error_message: row.try_get("error_message")?,
                total_subdomains_discovered: row
                    .try_get::<Option<i64>, _>("total_subdomains_discovered")?
                    .unwrap_or(0) as u32,
                total_endpoints_probed: row
                    .try_get::<Option<i64>, _>("total_endpoints_probed")?
                    .unwrap_or(0) as u32,
                request_body: row.try_get("request_body")?,
                response_body: row.try_get("response_body")?,
                response_headers: row.try_get("response_headers")?,
            });
        }
        Ok(scans)
    }

    pub async fn list_scan_summaries(&self, limit: i64) -> Result<Vec<ScanSummary>> {
        let rows: Vec<AnyRow> = sqlx::query(
            r#"SELECT sr.id, sr.target_id, sr.status, sr.started_at, sr.ended_at,
                       (SELECT COUNT(*) FROM findings f WHERE f.scan_id = sr.id) as findings_count
               FROM scan_results sr
               ORDER BY sr.started_at DESC
               LIMIT $1"#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        let mut items = Vec::new();
        for row in rows {
            items.push(ScanSummary {
                id: Uuid::parse_str(row.try_get::<String, _>("id")?.as_str())?,
                target_id: Uuid::parse_str(row.try_get::<String, _>("target_id")?.as_str())?,
                status: parse_scan_status(row.try_get::<String, _>("status")?),
                started_at: parse_datetime(row.try_get::<String, _>("started_at")?),
                ended_at: row
                    .try_get::<Option<String>, _>("ended_at")?
                    .map(|s| parse_datetime(s)),
                findings_count: row
                    .try_get::<Option<i64>, _>("findings_count")?
                    .unwrap_or(0) as u32,
            });
        }
        Ok(items)
    }

    pub async fn update_scan_status(
        &self,
        scan_id: &Uuid,
        status: crate::models::ScanStatus,
        message: Option<String>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE scan_results SET status = $1, error_message = $2, ended_at = $3 WHERE id = $4",
        )
        .bind(format!("{:?}", status))
        .bind(message)
        .bind(Some(chrono::Utc::now().to_rfc3339()))
        .bind(scan_id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn set_scan_cancel(&self, scan_id: &Uuid) -> Result<()> {
        sqlx::query(
            r#"INSERT INTO scan_control (scan_id, cancel, created_at)
               VALUES ($1,1,$2)
               ON CONFLICT(scan_id) DO UPDATE SET cancel=1;"#,
        )
        .bind(scan_id.to_string())
        .bind(chrono::Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn is_scan_cancelled(&self, scan_id: &Uuid) -> Result<bool> {
        let row = sqlx::query("SELECT cancel FROM scan_control WHERE scan_id=$1")
            .bind(scan_id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        Ok(row
            .and_then(|r| r.try_get::<i64, _>("cancel").ok())
            .unwrap_or(0)
            == 1)
    }
    pub async fn get_scan_with_findings(&self, scan_id: &Uuid) -> Result<ScanResult> {
        let row = sqlx::query("SELECT * FROM scan_results WHERE id = $1")
            .bind(scan_id.to_string())
            .fetch_one(&self.pool)
            .await?;

        let findings_rows: Vec<AnyRow> = sqlx::query("SELECT * FROM findings WHERE scan_id = $1")
            .bind(scan_id.to_string())
            .fetch_all(&self.pool)
            .await?;

        let mut scan = ScanResult {
            id: *scan_id,
            target_id: Uuid::parse_str(row.try_get::<String, _>("target_id")?.as_str())?,
            config_id: Uuid::parse_str(row.try_get::<String, _>("config_id")?.as_str())?,
            findings: Vec::new(),
            started_at: parse_datetime(row.try_get::<String, _>("started_at")?),
            ended_at: row
                .try_get::<Option<String>, _>("ended_at")?
                .map(|s| parse_datetime(s)),
            status: parse_scan_status(row.try_get::<String, _>("status")?),
            error_message: row.try_get("error_message")?,
            total_subdomains_discovered: row
                .try_get::<Option<i64>, _>("total_subdomains_discovered")?
                .unwrap_or(0) as u32,
            total_endpoints_probed: row
                .try_get::<Option<i64>, _>("total_endpoints_probed")?
                .unwrap_or(0) as u32,
            request_body: row.try_get("request_body")?,
            response_body: row.try_get("response_body")?,
            response_headers: row.try_get("response_headers")?,
        };

        for fr in findings_rows {
            scan.findings.push(row_to_finding(&fr)?);
        }

        Ok(scan)
    }
}

fn row_to_finding(row: &AnyRow) -> Result<Finding> {
    let tags_json: String = row.try_get("tags")?;
    let tags: Vec<String> = serde_json::from_str(&tags_json).unwrap_or_default();
    Ok(Finding {
        id: Some(Uuid::parse_str(row.try_get::<String, _>("id")?.as_str())?),
        target_id: Uuid::parse_str(row.try_get::<String, _>("target_id")?.as_str())?,
        scan_id: row
            .try_get::<Option<String>, _>("scan_id")?
            .and_then(|s| Uuid::parse_str(s.as_str()).ok()),
        tool_source: row.try_get("tool_source")?,
        vulnerability_type: parse_vuln(row.try_get::<String, _>("vulnerability_type")?),
        severity: parse_severity(row.try_get::<String, _>("severity")?),
        endpoint: row.try_get("endpoint")?,
        payload: row.try_get("payload")?,
        evidence: row.try_get("evidence")?,
        verified: row.try_get::<i64, _>("verified")? == 1,
        cvss_score: row.try_get("cvss_score")?,
        confidence_score: row.try_get("confidence_score")?,
        owasp_category: row.try_get("owasp_category")?,
        remediation: row.try_get("remediation")?,
        created_at: parse_datetime(row.try_get::<String, _>("created_at")?),
        tags,
        request_body: row.try_get("request_body")?,
        response_body: row.try_get("response_body")?,
        response_headers: row.try_get("response_headers")?,
    })
}

fn parse_datetime(value: String) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(&value)
        .map(|d| d.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

fn parse_severity(value: String) -> Severity {
    match value.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "low" => Severity::Low,
        "info" => Severity::Info,
        _ => Severity::Medium,
    }
}

fn parse_vuln(value: String) -> VulnerabilityType {
    match value.to_lowercase().as_str() {
        "sqlinjection" | "sql_injection" => VulnerabilityType::SqlInjection,
        "xss" => VulnerabilityType::Xss,
        "ssrf" => VulnerabilityType::Ssrf,
        "lfi" => VulnerabilityType::Lfi,
        "rfi" => VulnerabilityType::Rfi,
        "authbypass" | "auth_bypass" => VulnerabilityType::AuthBypass,
        "jwtvulnerability" | "jwt_vulnerability" => VulnerabilityType::JwtVulnerability,
        "commandinjection" | "command_injection" => VulnerabilityType::CommandInjection,
        "pathtraversal" | "path_traversal" => VulnerabilityType::PathTraversal,
        "openredirect" | "open_redirect" => VulnerabilityType::OpenRedirect,
        "corsmisconfiguration" | "cors_misconfiguration" => VulnerabilityType::CorsMisconfiguration,
        "informationdisclosure" | "information_disclosure" => {
            VulnerabilityType::InformationDisclosure
        }
        "brokenauthentication" | "broken_authentication" => VulnerabilityType::BrokenAuthentication,
        "subdomaintakeover" | "subdomain_takeover" => VulnerabilityType::SubdomainTakeover,
        "misconfiguredaws_s3" | "misconfiguredawss3" => VulnerabilityType::MisconfiguredAwsS3,
        _ => VulnerabilityType::Other,
    }
}

fn parse_target_status(value: &str) -> TargetStatus {
    match value.to_lowercase().as_str() {
        "active" => TargetStatus::Active,
        "completed" => TargetStatus::Completed,
        "failed" => TargetStatus::Failed,
        "paused" => TargetStatus::Paused,
        _ => TargetStatus::Pending,
    }
}

fn parse_scan_status(value: String) -> crate::models::ScanStatus {
    match value.to_lowercase().as_str() {
        "completed" => crate::models::ScanStatus::Completed,
        "failed" => crate::models::ScanStatus::Failed,
        "cancelled" => crate::models::ScanStatus::Cancelled,
        "running" => crate::models::ScanStatus::Running,
        _ => crate::models::ScanStatus::Pending,
    }
}
