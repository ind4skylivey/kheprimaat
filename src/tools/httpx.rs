use anyhow::Result;
use tracing::{info, warn};

use super::{binary_exists, run_command_with_input};
use crate::models::{HostProbe, ScanConfig};
use tokio_util::sync::CancellationToken;

pub async fn run_httpx(
    hosts: &[String],
    config: &ScanConfig,
    cancel: Option<&CancellationToken>,
) -> Result<Vec<HostProbe>> {
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

    let mut owned_args: Vec<String> = vec![
        "-json".into(),
        "-silent".into(),
        "-follow-redirects".into(),
        "-nc".into(),
        "-timeout".into(),
        config.timeout_seconds.to_string(),
        "-threads".into(),
        config.concurrency.to_string(),
    ];
    if let Some(rl) = config.rate_limit_per_sec {
        owned_args.push("-rate-limit".into());
        owned_args.push(rl.to_string());
    }
    let args: Vec<&str> = owned_args.iter().map(|s| s.as_str()).collect();

    let stdout = run_command_with_input(
        "httpx",
        &args,
        Some(hosts.join("\n")),
        config.timeout_seconds.max(60),
        cancel,
    )
    .await?;
    let mut live = Vec::new();
    for line in stdout.lines() {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
            if let Some(probe) = parse_httpx_line(&value) {
                live.push(probe);
            }
        }
    }

    info!("httpx validated {} live hosts", live.len());
    Ok(live)
}

fn parse_httpx_line(value: &serde_json::Value) -> Option<HostProbe> {
    let url = value.get("url").and_then(|u| u.as_str())?;
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
    let server = value
        .get("server")
        .and_then(|t| t.as_str())
        .map(|s| s.to_string())
        .or(webserver.clone());
    let response_headers = value
        .get("response")
        .and_then(|r| r.get("headers"))
        .map(|h| h.to_string())
        .or_else(|| value.get("headers").map(|h| h.to_string()));
    let response_body = value
        .get("response")
        .and_then(|r| r.get("body"))
        .and_then(|b| b.as_str())
        .map(|b| truncate(b, 500));
    Some(HostProbe {
        url: url.to_string(),
        status_code: status,
        title,
        tech,
        webserver: server,
        response_headers,
        response_body,
    })
}

pub fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}... (truncated {})", &s[..max], s.len() - max)
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_httpx() {
        let v = serde_json::json!({
            "url":"https://x.test",
            "status_code":200,
            "title":"hello",
            "tech":["nginx"],
            "headers":{"Server":"nginx"},
            "response":{"body":"abc", "headers":{"X":"y"}}
        });
        let p = parse_httpx_line(&v).unwrap();
        assert_eq!(p.status_code, 200);
        assert!(p.response_body.is_some());
        assert!(p.response_headers.is_some());
    }
}
