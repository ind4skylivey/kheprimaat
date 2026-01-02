use anyhow::Result;
use tracing::{info, warn};
use uuid::Uuid;

use super::binary_exists;
use crate::models::{Finding, ScanConfig, Severity, VulnerabilityType};

pub async fn run_sqlmap_scan(endpoints: &[String], config: &ScanConfig) -> Result<Vec<Finding>> {
    if endpoints.is_empty() || !config.tools_enabled.iter().any(|t| t == "sqlmap") {
        return Ok(vec![]);
    }
    if !binary_exists("sqlmap") {
        warn!("sqlmap binary not found; skipping");
        return Ok(vec![]);
    }

    // TODO: integrate real sqlmap JSON output. For now use mock file if present.
    let findings = if tokio::fs::metadata("fixtures/sqlmap.json").await.is_ok() {
        let content = tokio::fs::read_to_string("fixtures/sqlmap.json").await?;
        if let Ok(values) = serde_json::from_str::<serde_json::Value>(&content) {
            values
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
                .collect()
        } else {
            Vec::new()
        }
    } else {
        endpoints
            .iter()
            .take(3)
            .map(|endpoint| {
                Finding::new(
                    Uuid::nil(),
                    VulnerabilityType::SqlInjection,
                    Severity::Medium,
                    endpoint.clone(),
                    "Potential SQLi detected by sqlmap placeholder".to_string(),
                    "sqlmap".to_string(),
                )
            })
            .collect::<Vec<_>>()
    };

    info!("sqlmap placeholder produced {} findings", findings.len());
    Ok(findings)
}
