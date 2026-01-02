use anyhow::Result;
use tracing::{info, warn};
use uuid::Uuid;

use super::binary_exists;
use crate::models::{Finding, ScanConfig, Severity, VulnerabilityType};

pub async fn run_ffuf_scan(endpoints: &[String], config: &ScanConfig) -> Result<Vec<Finding>> {
    if endpoints.is_empty() || !config.tools_enabled.iter().any(|t| t == "ffuf") {
        return Ok(vec![]);
    }
    if !binary_exists("ffuf") {
        warn!("ffuf binary not found; skipping fuzzing");
        return Ok(vec![]);
    }

    let findings = if tokio::fs::metadata("fixtures/ffuf.json").await.is_ok() {
        let content = tokio::fs::read_to_string("fixtures/ffuf.json").await?;
        if let Ok(values) = serde_json::from_str::<serde_json::Value>(&content) {
            values
                .as_array()
                .cloned()
                .unwrap_or_default()
                .iter()
                .map(|v| {
                    let url = v.get("url").and_then(|u| u.as_str()).unwrap_or_default();
                    let status = v.get("status").and_then(|s| s.as_u64()).unwrap_or(0) as u16;
                    let evidence = format!(
                        "status={} len={} words={}",
                        status,
                        v.get("length").and_then(|l| l.as_u64()).unwrap_or(0),
                        v.get("words").and_then(|w| w.as_u64()).unwrap_or(0)
                    );
                    Finding::new(
                        Uuid::nil(),
                        if url.contains(".git/") {
                            VulnerabilityType::InformationDisclosure
                        } else {
                            VulnerabilityType::Other
                        },
                        if status == 200 {
                            Severity::High
                        } else {
                            Severity::Low
                        },
                        url.to_string(),
                        evidence,
                        "ffuf".into(),
                    )
                })
                .collect()
        } else {
            Vec::new()
        }
    } else {
        endpoints
            .iter()
            .take(2)
            .map(|endpoint| {
                Finding::new(
                    Uuid::nil(),
                    VulnerabilityType::InformationDisclosure,
                    Severity::Low,
                    format!("{endpoint}/FUZZ"),
                    "ffuf placeholder finding".to_string(),
                    "ffuf".to_string(),
                )
            })
            .collect::<Vec<_>>()
    };

    info!("ffuf placeholder produced {} findings", findings.len());
    Ok(findings)
}
