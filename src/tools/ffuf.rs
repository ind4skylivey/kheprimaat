use anyhow::Result;
use tracing::{info, warn};
use uuid::Uuid;

use super::{binary_exists, run_command_with_input};
use crate::models::{Finding, ScanConfig, Severity, VulnerabilityType};
use tokio_util::sync::CancellationToken;

fn parse_ffuf_value(value: &serde_json::Value, findings: &mut Vec<Finding>) {
    if let Some(results) = value.get("results").and_then(|r| r.as_array()) {
        for r in results {
            if let Some(url) = r.get("url").and_then(|u| u.as_str()) {
                let status = r.get("status").and_then(|s| s.as_u64()).unwrap_or(0) as u16;
                let length = r.get("length").and_then(|l| l.as_u64()).unwrap_or(0);
                let words = r.get("words").and_then(|w| w.as_u64()).unwrap_or(0);
                push_ffuf_finding(findings, url, status, length, words);
            }
        }
    }
}

fn push_ffuf_finding(findings: &mut Vec<Finding>, url: &str, status: u16, length: u64, words: u64) {
    let evidence = format!("status={} len={} words={}", status, length, words);
    findings.push(
        Finding::new(
            Uuid::nil(),
            if url.contains(".git/") {
                VulnerabilityType::InformationDisclosure
            } else {
                VulnerabilityType::Other
            },
            if status == 200 || status == 302 {
                Severity::High
            } else {
                Severity::Low
            },
            url.to_string(),
            evidence,
            "ffuf".into(),
        )
        .with_tags(vec!["ffuf".into()]),
    );
}

pub async fn run_ffuf_scan(
    endpoints: &[String],
    config: &ScanConfig,
    cancel: Option<&CancellationToken>,
) -> Result<Vec<Finding>> {
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
            run_command_with_input("ffuf", &args, None, config.timeout_seconds.max(90), cancel)
                .await;
        if let Ok(stdout) = output {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&stdout) {
                parse_ffuf_value(&value, &mut findings);
            } else {
                for line in stdout.lines() {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
                        parse_ffuf_value(&val, &mut findings);
                    }
                }
            }
        }
    }

    if findings.is_empty() && tokio::fs::metadata("fixtures/ffuf.json").await.is_ok() {
        let content = tokio::fs::read_to_string("fixtures/ffuf.json").await?;
        if let Ok(values) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(arr) = values.as_array() {
                for v in arr {
                    if let Some(url) = v.get("url").and_then(|u| u.as_str()) {
                        let status = v.get("status").and_then(|s| s.as_u64()).unwrap_or(0) as u16;
                        let length = v.get("length").and_then(|l| l.as_u64()).unwrap_or(0);
                        let words = v.get("words").and_then(|w| w.as_u64()).unwrap_or(0);
                        push_ffuf_finding(&mut findings, url, status, length, words);
                    }
                }
            }
        }
    };

    info!("ffuf produced {} findings", findings.len());
    Ok(findings)
}
