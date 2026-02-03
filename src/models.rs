use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// Severity levels used across the platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
pub enum Severity {
    #[serde(rename = "info")]
    Info,
    #[serde(rename = "low")]
    Low,
    #[serde(rename = "medium")]
    Medium,
    #[serde(rename = "high")]
    High,
    #[serde(rename = "critical")]
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "Info"),
            Severity::Low => write!(f, "Low"),
            Severity::Medium => write!(f, "Medium"),
            Severity::High => write!(f, "High"),
            Severity::Critical => write!(f, "Critical"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EmailSettings {
    pub smtp_server: Option<String>,
    pub recipients: Vec<String>,
    pub from: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub xoauth2_token: Option<String>,
    pub auth_method: Option<String>, // "plain"|"login"|"none"
    pub starttls: Option<bool>,
    pub send_above: Option<Severity>,
}

/// High-level vulnerability categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VulnerabilityType {
    #[serde(rename = "sql_injection")]
    SqlInjection,
    #[serde(rename = "xss")]
    Xss,
    #[serde(rename = "ssrf")]
    Ssrf,
    #[serde(rename = "lfi")]
    Lfi,
    #[serde(rename = "rfi")]
    Rfi,
    #[serde(rename = "auth_bypass")]
    AuthBypass,
    #[serde(rename = "jwt_vulnerability")]
    JwtVulnerability,
    #[serde(rename = "command_injection")]
    CommandInjection,
    #[serde(rename = "path_traversal")]
    PathTraversal,
    #[serde(rename = "open_redirect")]
    OpenRedirect,
    #[serde(rename = "cors_misconfiguration")]
    CorsMisconfiguration,
    #[serde(rename = "information_disclosure")]
    InformationDisclosure,
    #[serde(rename = "broken_authentication")]
    BrokenAuthentication,
    #[serde(rename = "subdomain_takeover")]
    SubdomainTakeover,
    #[serde(rename = "misconfigured_aws_s3")]
    MisconfiguredAwsS3,
    #[serde(rename = "other")]
    Other,
}

impl fmt::Display for VulnerabilityType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VulnerabilityType::SqlInjection => write!(f, "SQL Injection"),
            VulnerabilityType::Xss => write!(f, "XSS"),
            VulnerabilityType::Ssrf => write!(f, "SSRF"),
            VulnerabilityType::Lfi => write!(f, "LFI"),
            VulnerabilityType::Rfi => write!(f, "RFI"),
            VulnerabilityType::AuthBypass => write!(f, "Authentication Bypass"),
            VulnerabilityType::JwtVulnerability => write!(f, "JWT Vulnerability"),
            VulnerabilityType::CommandInjection => write!(f, "Command Injection"),
            VulnerabilityType::PathTraversal => write!(f, "Path Traversal"),
            VulnerabilityType::OpenRedirect => write!(f, "Open Redirect"),
            VulnerabilityType::CorsMisconfiguration => write!(f, "CORS Misconfiguration"),
            VulnerabilityType::InformationDisclosure => write!(f, "Information Disclosure"),
            VulnerabilityType::BrokenAuthentication => write!(f, "Broken Authentication"),
            VulnerabilityType::SubdomainTakeover => write!(f, "Subdomain Takeover"),
            VulnerabilityType::MisconfiguredAwsS3 => write!(f, "Misconfigured AWS S3"),
            VulnerabilityType::Other => write!(f, "Other"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum TargetStatus {
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "active")]
    Active,
    #[serde(rename = "completed")]
    Completed,
    #[serde(rename = "failed")]
    Failed,
    #[serde(rename = "paused")]
    Paused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ScanStatus {
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "running")]
    Running,
    #[serde(rename = "completed")]
    Completed,
    #[serde(rename = "failed")]
    Failed,
    #[serde(rename = "cancelled")]
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub id: Option<Uuid>,
    pub domain: String,
    pub scope: Vec<String>,
    pub status: TargetStatus,
    pub created_at: DateTime<Utc>,
    pub last_scan: Option<DateTime<Utc>>,
    pub notes: Option<String>,
}

impl Target {
    pub fn new(domain: String, scope: Vec<String>) -> Self {
        Self {
            id: Some(Uuid::new_v4()),
            domain,
            scope,
            status: TargetStatus::Pending,
            created_at: Utc::now(),
            last_scan: None,
            notes: None,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.domain.is_empty() {
            return Err("Domain cannot be empty".to_string());
        }
        if !self.domain.contains('.') {
            return Err("Invalid domain format".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: Option<Uuid>,
    pub target_id: Uuid,
    pub scan_id: Option<Uuid>,
    pub tool_source: String,
    pub vulnerability_type: VulnerabilityType,
    pub severity: Severity,
    pub endpoint: String,
    pub payload: Option<String>,
    pub evidence: String,
    pub verified: bool,
    pub cvss_score: Option<f32>,
    pub confidence_score: Option<f32>,
    pub owasp_category: Option<String>,
    pub remediation: Option<String>,
    pub created_at: DateTime<Utc>,
    pub tags: Vec<String>,
    pub request_body: Option<String>,
    pub response_body: Option<String>,
    pub response_headers: Option<String>,
}

impl Finding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        target_id: Uuid,
        vulnerability_type: VulnerabilityType,
        severity: Severity,
        endpoint: String,
        evidence: String,
        tool_source: String,
    ) -> Self {
        Self {
            id: Some(Uuid::new_v4()),
            target_id,
            scan_id: None,
            tool_source,
            vulnerability_type,
            severity,
            endpoint,
            payload: None,
            evidence,
            verified: false,
            cvss_score: None,
            confidence_score: None,
            owasp_category: None,
            remediation: None,
            created_at: Utc::now(),
            tags: vec![],
            request_body: None,
            response_body: None,
            response_headers: None,
        }
    }

    pub fn with_payload(mut self, payload: String) -> Self {
        self.payload = Some(payload);
        self
    }

    pub fn with_cvss(mut self, score: f32) -> Self {
        self.cvss_score = Some(score);
        self
    }

    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags.extend(tags);
        self
    }

    pub fn mark_verified(mut self) -> Self {
        self.verified = true;
        self
    }

    pub fn with_confidence(mut self, score: f32) -> Self {
        self.confidence_score = Some(score);
        self
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "[{}] {} - {} (via {}) @ {}",
            self.severity,
            self.vulnerability_type,
            self.endpoint,
            self.tool_source,
            self.created_at.format("%Y-%m-%d %H:%M:%S")
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub id: Option<Uuid>,
    pub name: String,
    pub description: Option<String>,
    pub tools_enabled: Vec<String>,
    pub nuclei_templates: Vec<String>,
    pub timeout_seconds: u64,
    pub concurrency: u32,
    pub retry_count: u32,
    pub exclude_endpoints: Vec<String>,
    pub exclude_status_codes: Vec<u16>,
    pub webhook_url: Option<String>,
    pub slack_webhook: Option<String>,
    pub discord_webhook: Option<String>,
    pub email: Option<EmailSettings>,
    pub rate_limit_per_sec: Option<u32>,
    pub scope_strict: bool,
    pub ffuf_wordlist: Option<String>,
    pub ffuf_extensions: Vec<String>,
    pub false_positive_patterns: Vec<String>,
    pub max_findings_per_target: Option<u32>,
    pub max_total_scan_time: Option<u64>,
    pub created_at: DateTime<Utc>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            id: Some(Uuid::new_v4()),
            name: "default-scan".to_string(),
            description: None,
            tools_enabled: vec![
                "subfinder".to_string(),
                "httpx".to_string(),
                "nuclei".to_string(),
            ],
            nuclei_templates: vec!["auth-bypass".to_string()],
            timeout_seconds: 600,
            concurrency: 10,
            retry_count: 3,
            exclude_endpoints: vec!["/health".to_string(), "/status".to_string()],
            exclude_status_codes: vec![404, 403],
            webhook_url: None,
            slack_webhook: None,
            discord_webhook: None,
            email: None,
            rate_limit_per_sec: None,
            scope_strict: true,
            ffuf_wordlist: None,
            ffuf_extensions: vec![],
            false_positive_patterns: vec![],
            max_findings_per_target: None,
            max_total_scan_time: None,
            created_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub id: Uuid,
    pub target_id: Uuid,
    pub config_id: Uuid,
    pub findings: Vec<Finding>,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub status: ScanStatus,
    pub error_message: Option<String>,
    pub total_subdomains_discovered: u32,
    pub total_endpoints_probed: u32,
    pub request_body: Option<String>,
    pub response_body: Option<String>,
    pub response_headers: Option<String>,
    pub timeline: Option<ScanTimeline>, // Issue #1: Timeline visualization
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub id: Uuid,
    pub target_id: Uuid,
    pub status: ScanStatus,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub findings_count: u32,
}

impl ScanResult {
    pub fn new(target_id: Uuid, config_id: Uuid) -> Self {
        let id = Uuid::new_v4();
        Self {
            id,
            target_id,
            config_id,
            findings: vec![],
            started_at: Utc::now(),
            ended_at: None,
            status: ScanStatus::Running,
            error_message: None,
            total_subdomains_discovered: 0,
            total_endpoints_probed: 0,
            request_body: None,
            response_body: None,
            response_headers: None,
            timeline: Some(ScanTimeline::new(id)), // Issue #1: Initialize timeline
        }
    }

    pub fn add_finding(&mut self, finding: Finding) {
        // Issue #1: Add finding to timeline
        if let Some(ref mut timeline) = self.timeline {
            timeline.add_finding_event(&finding);
        }
        self.findings.push(finding);
    }

    pub fn complete(mut self) -> Self {
        self.ended_at = Some(Utc::now());
        self.status = ScanStatus::Completed;
        if let Some(ref mut timeline) = self.timeline {
            timeline.mark_completed();
        }
        self
    }

    pub fn fail(mut self, error: String) -> Self {
        self.ended_at = Some(Utc::now());
        self.status = ScanStatus::Failed;
        self.error_message = Some(error.clone());
        if let Some(ref mut timeline) = self.timeline {
            timeline.mark_failed(error);
        }
        self
    }

    pub fn findings_by_severity(&self, severity: Severity) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| f.severity == severity)
            .collect()
    }

    pub fn critical_findings(&self) -> Vec<&Finding> {
        self.findings_by_severity(Severity::Critical)
    }

    pub fn duration_secs(&self) -> u64 {
        let end = self.ended_at.unwrap_or_else(Utc::now);
        (end - self.started_at).num_seconds() as u64
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subdomain {
    pub name: String,
    pub ip: Option<String>,
    pub http_status: Option<u16>,
    pub title: Option<String>,
    pub tech_stack: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostProbe {
    pub url: String,
    pub status_code: u16,
    pub title: Option<String>,
    pub tech: Vec<String>,
    pub webserver: Option<String>,
    pub response_headers: Option<String>,
    pub response_body: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInput {
    pub target: String,
    pub endpoints: Option<Vec<String>>,
    pub payloads: Option<Vec<String>>,
    pub wordlist: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolOutput {
    pub tool_name: String,
    pub findings: Vec<Finding>,
    pub raw_output: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatistics {
    pub total_scans: u32,
    pub total_findings: u32,
    pub critical_count: u32,
    pub high_count: u32,
    pub medium_count: u32,
    pub low_count: u32,
    pub info_count: u32,
    pub verification_rate: f32,
    pub average_scan_duration_secs: u64,
}

impl ScanStatistics {
    pub fn from_results(results: &[ScanResult]) -> Self {
        let total_findings = results.iter().map(|r| r.findings.len() as u32).sum();
        let total_scans = results.len() as u32;

        let mut critical_count = 0;
        let mut high_count = 0;
        let mut medium_count = 0;
        let mut low_count = 0;
        let mut info_count = 0;
        let mut verified_count = 0;

        for result in results {
            for finding in &result.findings {
                match finding.severity {
                    Severity::Critical => critical_count += 1,
                    Severity::High => high_count += 1,
                    Severity::Medium => medium_count += 1,
                    Severity::Low => low_count += 1,
                    Severity::Info => info_count += 1,
                }
                if finding.verified {
                    verified_count += 1;
                }
            }
        }

        let verification_rate = if total_findings > 0 {
            (verified_count as f32 / total_findings as f32) * 100.0
        } else {
            0.0
        };

        let average_scan_duration_secs = if total_scans > 0 {
            results.iter().map(|r| r.duration_secs()).sum::<u64>() / total_scans as u64
        } else {
            0
        };

        Self {
            total_scans,
            total_findings,
            critical_count,
            high_count,
            medium_count,
            low_count,
            info_count,
            verification_rate,
            average_scan_duration_secs,
        }
    }
}

/// Timeline event for scan visualization (Issue #1)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: TimelineEventType,
    pub stage: Option<String>,
    pub description: String,
    pub duration_ms: Option<u64>,
    pub metadata: Option<serde_json::Value>,
}

/// Types of timeline events
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimelineEventType {
    ScanStarted,
    StageStarted,
    StageCompleted,
    ToolStarted,
    ToolCompleted,
    FindingDiscovered,
    ScanCompleted,
    ScanFailed,
    ScanCancelled,
}

/// Scan timeline for visualization (Issue #1)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanTimeline {
    pub events: Vec<TimelineEvent>,
    pub scan_id: Uuid,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

impl ScanTimeline {
    pub fn new(scan_id: Uuid) -> Self {
        Self {
            events: Vec::new(),
            scan_id,
            started_at: Utc::now(),
            completed_at: None,
        }
    }

    pub fn add_event(
        &mut self,
        event_type: TimelineEventType,
        stage: Option<String>,
        description: String,
        duration_ms: Option<u64>,
    ) {
        self.events.push(TimelineEvent {
            timestamp: Utc::now(),
            event_type,
            stage,
            description,
            duration_ms,
            metadata: None,
        });
    }

    pub fn add_finding_event(&mut self, finding: &Finding) {
        self.events.push(TimelineEvent {
            timestamp: Utc::now(),
            event_type: TimelineEventType::FindingDiscovered,
            stage: None,
            description: format!(
                "[{}] {} - {}",
                finding.severity, finding.vulnerability_type, finding.endpoint
            ),
            duration_ms: None,
            metadata: Some(serde_json::json!({
                "severity": finding.severity,
                "vuln_type": finding.vulnerability_type,
                "endpoint": finding.endpoint,
            })),
        });
    }

    pub fn mark_completed(&mut self) {
        self.completed_at = Some(Utc::now());
        self.add_event(
            TimelineEventType::ScanCompleted,
            None,
            "Scan completed successfully".to_string(),
            Some(self.total_duration_ms()),
        );
    }

    pub fn mark_failed(&mut self, error: String) {
        self.completed_at = Some(Utc::now());
        self.add_event(
            TimelineEventType::ScanFailed,
            None,
            format!("Scan failed: {}", error),
            Some(self.total_duration_ms()),
        );
    }

    pub fn total_duration_ms(&self) -> u64 {
        let end = self.completed_at.unwrap_or_else(Utc::now);
        (end - self.started_at).num_milliseconds() as u64
    }

    pub fn get_stage_durations(&self) -> Vec<(String, u64)> {
        let mut durations = Vec::new();
        let mut current_stage: Option<(String, DateTime<Utc>)> = None;

        for event in &self.events {
            match &event.event_type {
                TimelineEventType::StageStarted => {
                    if let Some(stage) = &event.stage {
                        current_stage = Some((stage.clone(), event.timestamp));
                    }
                }
                TimelineEventType::StageCompleted => {
                    if let Some((stage_name, start_time)) = current_stage.take() {
                        let duration = (event.timestamp - start_time).num_milliseconds() as u64;
                        durations.push((stage_name, duration));
                    }
                }
                _ => {}
            }
        }

        durations
    }

    /// Generate HTML timeline data for reports
    pub fn to_html_data(&self) -> String {
        serde_json::to_string(&self.events).unwrap_or_default()
    }
}
