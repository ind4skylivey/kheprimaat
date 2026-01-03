use anyhow::Result;
use tokio::{
    process::Command,
    time::{timeout, Duration},
};
use tracing::{info, warn};

use super::binary_exists;
use crate::models::{Finding, ScanConfig, Severity, VulnerabilityType};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub async fn run_nuclei_scan(
    hosts: &[String],
    config: &ScanConfig,
    cancel: Option<&CancellationToken>,
) -> Result<Vec<Finding>> {
    if hosts.is_empty() || !config.tools_enabled.iter().any(|t| t == "nuclei") {
        return Ok(vec![]);
    }
    if !binary_exists("nuclei") {
        warn!("nuclei binary not found; skipping template scan");
        return Ok(vec![]);
    }

    // Prepare temporary file with hosts
    let host_list = hosts.join("\n");
    let temp_path = "/tmp/kheprimaat-hosts.txt";
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

    let output = tokio::select! {
        res = timeout(Duration::from_secs(config.timeout_seconds.max(120)), cmd.output()) => res??,
        _ = async {
            if let Some(token) = cancel {
                token.cancelled().await;
            }
        } => {
            return Ok(vec![]);
        }
    };
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

            let mut evidence_parts = vec![];
            if let Some(extracted) = value.get("extracted-results").and_then(|e| e.as_array()) {
                let joined = extracted
                    .iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(" | ");
                if !joined.is_empty() {
                    evidence_parts.push(format!("extracted: {joined}"));
                }
            }
            if let Some(m) = value.get("matcher-name").and_then(|m| m.as_str()) {
                evidence_parts.push(format!("matcher: {m}"));
            }
            if let Some(matched) = value.get("matched-at").and_then(|m| m.as_str()) {
                evidence_parts.push(format!("matched-at: {matched}"));
            }
            if let Some(req) = value.get("request").and_then(|r| r.as_str()) {
                evidence_parts.push(format!("request: {}", req.trim()));
            }
            let mut response_body = None;
            if let Some(resp) = value.get("response").and_then(|r| r.as_str()) {
                response_body = Some(truncate(resp, 500));
                evidence_parts.push(format!(
                    "response: {}",
                    resp.lines().take(3).collect::<Vec<_>>().join(" | ")
                ));
            }
            let evidence = if evidence_parts.is_empty() {
                template.clone()
            } else {
                evidence_parts.join(" ; ")
            };

            let finding = Finding::new(
                Uuid::nil(),
                vuln_type,
                severity,
                endpoint.clone(),
                evidence,
                "nuclei".into(),
            )
            .with_tags(vec![template.clone(), "nuclei".into()]);
            let mut finding = finding;
            finding.response_body = response_body;
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

fn truncate(text: &str, max: usize) -> String {
    if text.len() > max {
        format!("{}... (truncated {})", &text[..max], text.len() - max)
    } else {
        text.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_template_basic() {
        assert_eq!(
            map_template_to_vuln("cve-2023-sqli"),
            VulnerabilityType::SqlInjection
        );
        assert_eq!(
            map_template_to_vuln("xss-reflected"),
            VulnerabilityType::Xss
        );
    }

    #[test]
    fn truncate_short() {
        assert_eq!(truncate("hi", 10), "hi".to_string());
    }
}
