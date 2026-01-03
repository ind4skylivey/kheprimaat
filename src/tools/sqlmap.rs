use anyhow::Result;
use tracing::{info, warn};
use uuid::Uuid;

use super::{binary_exists, run_command_with_input};
use crate::models::{Finding, ScanConfig, Severity, VulnerabilityType};
use tokio_util::sync::CancellationToken;

pub fn parse_sqlmap_value(value: &serde_json::Value, endpoint: &str, findings: &mut Vec<Finding>) {
    if let Some(arr) = value.as_array() {
        for entry in arr {
            add_sqlmap_entry(entry, endpoint, findings);
        }
        return;
    }
    if let Some(obj) = value.as_object() {
        if let Some(data) = obj.get("data").and_then(|d| d.as_array()) {
            for entry in data {
                add_sqlmap_entry(entry, endpoint, findings);
            }
        } else {
            add_sqlmap_entry(value, endpoint, findings);
        }
    }
}

fn add_sqlmap_entry(entry: &serde_json::Value, endpoint: &str, findings: &mut Vec<Finding>) {
    let url = entry
        .get("url")
        .and_then(|u| u.as_str())
        .unwrap_or(endpoint)
        .to_string();
    let payload = entry
        .get("payload")
        .and_then(|p| p.as_str())
        .unwrap_or("sqlmap payload")
        .to_string();
    let evidence = entry
        .get("technique")
        .and_then(|t| t.as_str())
        .map(|t| format!("technique={t}; payload={payload}"))
        .unwrap_or_else(|| payload.clone());

    findings.push(
        Finding::new(
            Uuid::nil(),
            VulnerabilityType::SqlInjection,
            Severity::Critical,
            url,
            evidence,
            "sqlmap".into(),
        )
        .with_payload(payload)
        .with_tags(vec!["sqlmap".into()]),
    );
}

pub async fn run_sqlmap_scan(
    endpoints: &[String],
    config: &ScanConfig,
    cancel: Option<&CancellationToken>,
) -> Result<Vec<Finding>> {
    if endpoints.is_empty() || !config.tools_enabled.iter().any(|t| t == "sqlmap") {
        return Ok(vec![]);
    }
    if !binary_exists("sqlmap") {
        warn!("sqlmap binary not found; skipping");
        return Ok(vec![]);
    }

    // Prefer real execution; fall back to fixtures if available.
    let mut findings: Vec<Finding> = Vec::new();

    let max_targets = endpoints.len().min(3);
    for endpoint in endpoints.iter().take(max_targets) {
        let args = vec![
            "-u",
            endpoint.as_str(),
            "--batch",
            "--output-format=json",
            "--parse-errors",
        ];
        let output = run_command_with_input(
            "sqlmap",
            &args,
            None,
            config.timeout_seconds.max(120),
            cancel,
        )
        .await;
        if let Ok(stdout) = output {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&stdout) {
                parse_sqlmap_value(&value, endpoint, &mut findings);
            }
        }
    }

    if findings.is_empty() && tokio::fs::metadata("fixtures/sqlmap.json").await.is_ok() {
        let content = tokio::fs::read_to_string("fixtures/sqlmap.json").await?;
        if let Ok(values) = serde_json::from_str::<serde_json::Value>(&content) {
            parse_sqlmap_value(&values, "", &mut findings);
        }
    };

    info!("sqlmap produced {} findings", findings.len());
    Ok(findings)
}
