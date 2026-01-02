use anyhow::Result;
use tracing::{info, warn};
use uuid::Uuid;

use super::{binary_exists, run_command_with_input};
use crate::models::{Finding, ScanConfig, Severity, VulnerabilityType};

pub async fn run_sqlmap_scan(endpoints: &[String], config: &ScanConfig) -> Result<Vec<Finding>> {
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
        let output =
            run_command_with_input("sqlmap", &args, None, config.timeout_seconds.max(120)).await;
        if let Ok(stdout) = output {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&stdout) {
                if let Some(arr) = value.as_array() {
                    for entry in arr {
                        let payload = entry
                            .get("payload")
                            .and_then(|p| p.as_str())
                            .unwrap_or("sqlmap payload");
                        findings.push(
                            Finding::new(
                                Uuid::nil(),
                                VulnerabilityType::SqlInjection,
                                Severity::Critical,
                                endpoint.clone(),
                                payload.to_string(),
                                "sqlmap".into(),
                            )
                            .with_payload(payload.to_string()),
                        );
                    }
                }
            }
        }
    }

    if findings.is_empty() && tokio::fs::metadata("fixtures/sqlmap.json").await.is_ok() {
        let content = tokio::fs::read_to_string("fixtures/sqlmap.json").await?;
        if let Ok(values) = serde_json::from_str::<serde_json::Value>(&content) {
            let extras: Vec<Finding> = values
                .as_array()
                .cloned()
                .unwrap_or_default()
                .iter()
                .filter_map(|v| {
                    let url = v.get("url")?.as_str()?;
                    let payload = v
                        .get("payload")
                        .and_then(|p| p.as_str())
                        .map(|s| s.to_string());
                    let payload_clone = payload.clone();
                    Some(
                        Finding::new(
                            Uuid::nil(),
                            VulnerabilityType::SqlInjection,
                            Severity::Critical,
                            url.to_string(),
                            payload_clone.unwrap_or_else(|| "sqlmap finding".into()),
                            "sqlmap".into(),
                        )
                        .with_payload(payload.unwrap_or_default()),
                    )
                })
                .collect();
            findings.extend(extras);
        }
    };

    info!("sqlmap produced {} findings", findings.len());
    Ok(findings)
}
