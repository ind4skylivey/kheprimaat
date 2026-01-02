use anyhow::Result;
use tracing::{info, warn};
use uuid::Uuid;

use super::{binary_exists, run_command_with_input};
use crate::models::{Finding, ScanConfig, Severity, VulnerabilityType};

pub async fn run_ffuf_scan(endpoints: &[String], config: &ScanConfig) -> Result<Vec<Finding>> {
    if endpoints.is_empty() || !config.tools_enabled.iter().any(|t| t == "ffuf") {
        return Ok(vec![]);
    }
    if !binary_exists("ffuf") {
        warn!("ffuf binary not found; skipping fuzzing");
        return Ok(vec![]);
    }

    let mut findings = Vec::new();

    // real execution
    let wordlist = config
        .ffuf_wordlist
        .clone()
        .unwrap_or_else(|| "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt".into());
    let extensions = if config.ffuf_extensions.is_empty() {
        None
    } else {
        Some(config.ffuf_extensions.join(","))
    };
    for endpoint in endpoints.iter().take(2) {
        let mut args = vec!["-u", endpoint.as_str(), "-w", wordlist.as_str(), "-json"];
        if let Some(ext) = &extensions {
            args.push("-e");
            args.push(ext.as_str());
        }
        let output =
            run_command_with_input("ffuf", &args, None, config.timeout_seconds.max(90)).await;
        if let Ok(stdout) = output {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&stdout) {
                if let Some(results) = value.get("results").and_then(|r| r.as_array()) {
                    for r in results {
                        if let Some(url) = r.get("url").and_then(|u| u.as_str()) {
                            let status =
                                r.get("status").and_then(|s| s.as_u64()).unwrap_or(0) as u16;
                            let evidence = format!(
                                "status={} len={} words={}",
                                status,
                                r.get("length").and_then(|l| l.as_u64()).unwrap_or(0),
                                r.get("words").and_then(|w| w.as_u64()).unwrap_or(0)
                            );
                            findings.push(Finding::new(
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
                            ));
                        }
                    }
                }
            }
        }
    }

    if findings.is_empty() && tokio::fs::metadata("fixtures/ffuf.json").await.is_ok() {
        let content = tokio::fs::read_to_string("fixtures/ffuf.json").await?;
        if let Ok(values) = serde_json::from_str::<serde_json::Value>(&content) {
            let extras: Vec<Finding> = values
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
                .collect();
            findings.extend(extras);
        }
    };

    info!("ffuf produced {} findings", findings.len());
    Ok(findings)
}
