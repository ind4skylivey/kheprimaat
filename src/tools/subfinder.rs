use anyhow::Result;
use tokio::{
    process::Command,
    time::{timeout, Duration},
};
use tracing::{info, warn};

use super::binary_exists;
use crate::models::{ScanConfig, Target};
use tokio_util::sync::CancellationToken;

pub async fn run_subfinder(
    target: &Target,
    config: &ScanConfig,
    cancel: Option<&CancellationToken>,
) -> Result<Vec<String>> {
    if !config.tools_enabled.iter().any(|t| t == "subfinder") {
        return Ok(vec![]);
    }

    if !binary_exists("subfinder") {
        warn!("subfinder binary not found in PATH; skipping");
        return Ok(vec![]);
    }

    let cmd = Command::new("subfinder")
        .arg("-d")
        .arg(&target.domain)
        .arg("-silent")
        .arg("-all")
        .stdout(std::process::Stdio::piped())
        .spawn()?;

    let output = tokio::select! {
        res = timeout(Duration::from_secs(config.timeout_seconds.max(60)), cmd.wait_with_output()) => res??,
        _ = async {
            if let Some(token) = cancel {
                token.cancelled().await;
            }
        } => {
            return Ok(vec![]);
        }
    };
    if !output.status.success() {
        warn!("subfinder returned non-zero status");
        return Ok(vec![]);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut hosts = Vec::new();
    for line in stdout.lines() {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
            if let Some(host) = value.get("host").and_then(|h| h.as_str()) {
                hosts.push(host.to_string());
            }
        } else if !line.trim().is_empty() {
            hosts.push(line.trim().to_string());
        }
    }

    info!("subfinder discovered {} candidates", hosts.len());
    Ok(hosts)
}
