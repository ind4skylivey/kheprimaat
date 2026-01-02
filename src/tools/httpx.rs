use anyhow::{anyhow, Result};
use tokio::{
    process::Command,
    time::{timeout, Duration},
};
use tracing::{info, warn};

use super::binary_exists;
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

    let mut child = Command::new("httpx")
        .arg("-json")
        .arg("-silent")
        .arg("-follow-redirects")
        .arg("-nc")
        .arg("-timeout")
        .arg(config.timeout_seconds.to_string())
        .arg("-threads")
        .arg(config.concurrency.to_string())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()?;

    {
        use tokio::io::AsyncWriteExt;
        let mut stdin = child.stdin.take().ok_or_else(|| anyhow!("missing stdin"))?;
        let joined = hosts.join("\n");
        stdin.write_all(joined.as_bytes()).await?;
    }

    let output = timeout(
        Duration::from_secs(config.timeout_seconds.max(60)),
        child.wait_with_output(),
    )
    .await??;
    if !output.status.success() {
        warn!("httpx returned non-zero status");
        return Ok(vec![]);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
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
