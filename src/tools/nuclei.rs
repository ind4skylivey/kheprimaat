use anyhow::Result;
use tokio::{
    process::Command,
    time::{timeout, Duration},
};
use tracing::{info, warn};

use super::binary_exists;
use crate::models::{Finding, ScanConfig, Severity, VulnerabilityType};
use uuid::Uuid;

pub async fn run_nuclei_scan(hosts: &[String], config: &ScanConfig) -> Result<Vec<Finding>> {
    if hosts.is_empty() || !config.tools_enabled.iter().any(|t| t == "nuclei") {
        return Ok(vec![]);
    }
    if !binary_exists("nuclei") {
        warn!("nuclei binary not found; skipping template scan");
        return Ok(vec![]);
    }

    // Prepare temporary file with hosts
    let host_list = hosts.join("\n");
    let temp_path = "/tmp/khepri-hosts.txt";
    tokio::fs::write(temp_path, host_list.as_bytes()).await?;

    let mut cmd = Command::new("nuclei");
    cmd.arg("-list")
        .arg(temp_path)
        .arg("-json")
        .arg("-silent")
        .arg("-c")
        .arg(config.concurrency.to_string());

    if !config.nuclei_templates.is_empty() {
        cmd.arg("-tags").arg(config.nuclei_templates.join(","));
    }

    let output = timeout(
        Duration::from_secs(config.timeout_seconds.max(120)),
        cmd.output(),
    )
    .await??;
    if !output.status.success() {
        warn!("nuclei returned non-zero status; continuing without findings");
        return Ok(vec![]);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut findings = Vec::new();
    for line in stdout.lines() {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
            let endpoint = value
                .get("host")
                .and_then(|h| h.as_str())
                .unwrap_or_default()
                .to_string();
            let template = value
                .get("template-id")
                .and_then(|t| t.as_str())
                .unwrap_or("unknown")
                .to_string();
            let severity = value
                .get("info")
                .and_then(|i| i.get("severity"))
                .and_then(|s| s.as_str())
                .unwrap_or("medium");
            let severity = match severity {
                "critical" => Severity::Critical,
                "high" => Severity::High,
                "low" => Severity::Low,
                "info" => Severity::Info,
                _ => Severity::Medium,
            };
            let vuln_type = map_template_to_vuln(&template);

            let finding = Finding::new(
                Uuid::nil(),
                vuln_type,
                severity,
                endpoint.clone(),
                value
                    .get("matcher-name")
                    .and_then(|m| m.as_str())
                    .unwrap_or(template.as_str())
                    .to_string(),
                "nuclei".into(),
            );
            findings.push(finding);
        }
    }

    info!("nuclei produced {} findings", findings.len());
    Ok(findings)
}

fn map_template_to_vuln(template: &str) -> VulnerabilityType {
    let t = template.to_lowercase();
    if t.contains("sqli") || t.contains("sql-injection") {
        VulnerabilityType::SqlInjection
    } else if t.contains("xss") {
        VulnerabilityType::Xss
    } else if t.contains("ssrf") {
        VulnerabilityType::Ssrf
    } else if t.contains("lfi") {
        VulnerabilityType::Lfi
    } else if t.contains("rfi") {
        VulnerabilityType::Rfi
    } else if t.contains("auth") {
        VulnerabilityType::AuthBypass
    } else if t.contains("cors") {
        VulnerabilityType::CorsMisconfiguration
    } else if t.contains("open-redirect") {
        VulnerabilityType::OpenRedirect
    } else if t.contains("takeover") {
        VulnerabilityType::SubdomainTakeover
    } else if t.contains("s3") {
        VulnerabilityType::MisconfiguredAwsS3
    } else {
        VulnerabilityType::Other
    }
}
