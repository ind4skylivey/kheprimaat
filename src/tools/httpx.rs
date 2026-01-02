use anyhow::Result;
use tracing::{info, warn};

use super::{binary_exists, run_command_with_input};
use crate::models::{HostProbe, ScanConfig};

pub async fn run_httpx(hosts: &[String], config: &ScanConfig) -> Result<Vec<HostProbe>> {
    if hosts.is_empty() {
        return Ok(vec![]);
    }
    if !config.tools_enabled.iter().any(|t| t == "httpx") {
        return Ok(vec![]);
    }
    if !binary_exists("httpx") {
        warn!("httpx binary not found; skipping probing");
        return Ok(vec![]);
    }

    let timeout_s = config.timeout_seconds.to_string();
    let threads_s = config.concurrency.to_string();
    let mut args = vec![
        "-json",
        "-silent",
        "-follow-redirects",
        "-nc",
        "-timeout",
        timeout_s.as_str(),
        "-threads",
        threads_s.as_str(),
    ];
    if let Some(rl) = config.rate_limit_per_sec {
        args.push("-rate-limit");
        args.push(Box::leak(rl.to_string().into_boxed_str()));
    }

    let stdout = run_command_with_input(
        "httpx",
        &args,
        Some(hosts.join("\n")),
        config.timeout_seconds.max(60),
    )
    .await?;
    let mut live = Vec::new();
    for line in stdout.lines() {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
            if let Some(url) = value.get("url").and_then(|u| u.as_str()) {
                let status = value
                    .get("status_code")
                    .and_then(|s| s.as_u64())
                    .unwrap_or(0) as u16;
                let tech = value
                    .get("tech")
                    .and_then(|t| t.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|s| s.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
                let title = value
                    .get("title")
                    .and_then(|t| t.as_str())
                    .map(|s| s.to_string());
                let webserver = value
                    .get("webserver")
                    .and_then(|t| t.as_str())
                    .map(|s| s.to_string());
                live.push(HostProbe {
                    url: url.to_string(),
                    status_code: status,
                    title,
                    tech,
                    webserver,
                });
            }
        }
    }

    info!("httpx validated {} live hosts", live.len());
    Ok(live)
}
