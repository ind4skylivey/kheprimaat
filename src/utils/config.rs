use anyhow::{anyhow, Result};
use serde_yaml::Value;
use std::fs;

use crate::models::{EmailSettings, ScanConfig, Severity};
use crate::utils::config_store::ConfigOverrides;

pub struct ConfigParser;

impl ConfigParser {
    pub fn load_from_file(path: &str) -> Result<ScanConfig> {
        let file = fs::read_to_string(path)?;
        Self::load_from_string(&file)
    }

    pub fn load_from_string(yaml: &str) -> Result<ScanConfig> {
        let value: Value = serde_yaml::from_str(yaml)?;
        let scan = value
            .get("scan_config")
            .ok_or_else(|| anyhow!("scan_config section missing"))?;

        let name = scan
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("default-scan")
            .to_string();

        let timeout_seconds = scan
            .get("limits")
            .and_then(|l| l.get("max_total_scan_time"))
            .and_then(|v| v.as_u64())
            .unwrap_or(600);

        let concurrency = scan
            .get("tools")
            .and_then(|t| t.get("httpx"))
            .and_then(|h| h.get("concurrency"))
            .and_then(|v| v.as_u64())
            .unwrap_or(10) as u32;

        let tools_enabled = gather_tools(scan);
        let nuclei_templates = scan
            .get("tools")
            .and_then(|t| t.get("nuclei"))
            .and_then(|n| n.get("templates"))
            .and_then(|v| v.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|s| s.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_else(|| vec!["auth-bypass".to_string()]);

        let webhook_url = scan
            .get("notifications")
            .and_then(|n| n.get("webhook"))
            .and_then(|w| w.get("url"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let slack_webhook = scan
            .get("notifications")
            .and_then(|n| n.get("slack"))
            .and_then(|w| w.get("webhook_url"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let discord_webhook = scan
            .get("notifications")
            .and_then(|n| n.get("discord"))
            .and_then(|w| w.get("webhook_url"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let email = scan
            .get("notifications")
            .and_then(|n| n.get("email"))
            .map(parse_email_settings);

        let rate_limit_per_sec = scan
            .get("security")
            .and_then(|s| s.get("rate_limit_requests_per_second"))
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);

        let scope_strict = scan
            .get("security")
            .and_then(|s| s.get("scope_strict"))
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let ffuf_wordlist = scan
            .get("tools")
            .and_then(|t| t.get("ffuf"))
            .and_then(|f| f.get("wordlist"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let ffuf_extensions = scan
            .get("tools")
            .and_then(|t| t.get("ffuf"))
            .and_then(|f| f.get("extensions"))
            .and_then(|v| v.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|s| s.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let false_positive_patterns = scan
            .get("filters")
            .and_then(|f| f.get("false_positive_filter"))
            .and_then(|f| f.get("patterns"))
            .and_then(|v| v.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|s| s.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let max_findings_per_target = scan
            .get("limits")
            .and_then(|l| l.get("max_findings_per_target"))
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);

        let max_total_scan_time = scan
            .get("limits")
            .and_then(|l| l.get("max_total_scan_time"))
            .and_then(|v| v.as_u64());

        let mut config = ScanConfig {
            id: None,
            name,
            description: scan
                .get("description")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            tools_enabled,
            nuclei_templates,
            timeout_seconds,
            concurrency,
            retry_count: 3,
            exclude_endpoints: vec![],
            exclude_status_codes: vec![404, 403],
            webhook_url,
            slack_webhook,
            discord_webhook,
            email,
            rate_limit_per_sec,
            scope_strict,
            ffuf_wordlist,
            ffuf_extensions,
            false_positive_patterns,
            max_findings_per_target,
            max_total_scan_time,
            created_at: chrono::Utc::now(),
        };

        apply_overrides(&mut config);
        config.validate_basic()?;
        Ok(config)
    }
}

fn parse_email_settings(value: &Value) -> EmailSettings {
    let send_above = value
        .get("send_above")
        .and_then(|v| v.as_str())
        .map(|sev| match sev {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "low" => Severity::Low,
            "info" => Severity::Info,
            _ => Severity::Medium,
        });
    EmailSettings {
        smtp_server: value
            .get("smtp_server")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        recipients: value
            .get("recipients")
            .and_then(|v| v.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|s| s.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default(),
        from: value
            .get("from")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        username: value
            .get("username")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        password: value
            .get("password")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        xoauth2_token: value
            .get("xoauth2_token")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        auth_method: value
            .get("auth_method")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        starttls: value.get("starttls").and_then(|v| v.as_bool()),
        send_above,
    }
}

fn apply_overrides(config: &mut ScanConfig) {
    let overrides = ConfigOverrides::load();
    if config.webhook_url.is_none() {
        config.webhook_url = overrides.webhook_url;
    }
    if config.slack_webhook.is_none() {
        config.slack_webhook = overrides.slack_webhook;
    }
    if config.discord_webhook.is_none() {
        config.discord_webhook = overrides.discord_webhook;
    }
}

fn gather_tools(scan: &Value) -> Vec<String> {
    let mut tools = vec![];
    if let Some(map) = scan.get("tools").and_then(|v| v.as_mapping()) {
        for (key, value) in map {
            if let (Some(name), Some(enabled)) = (key.as_str(), value.get("enabled")) {
                if enabled.as_bool().unwrap_or(false) {
                    tools.push(name.to_string());
                }
            }
        }
    }
    if tools.is_empty() {
        tools.extend(
            ["subfinder", "httpx", "nuclei"]
                .iter()
                .map(|s| s.to_string()),
        );
    }
    tools
}

impl ScanConfig {
    pub fn validate_basic(&self) -> Result<()> {
        if self.tools_enabled.is_empty() {
            return Err(anyhow!("At least one tool must be enabled"));
        }
        if self.timeout_seconds == 0 {
            return Err(anyhow!("timeout_seconds must be > 0"));
        }
        if self.concurrency == 0 {
            return Err(anyhow!("concurrency must be > 0"));
        }
        if let Some(url) = &self.webhook_url {
            if !url.starts_with("http") {
                return Err(anyhow!("webhook_url must be http/https"));
            }
        }
        if let Some(url) = &self.slack_webhook {
            if !url.starts_with("http") {
                return Err(anyhow!("slack_webhook must be http/https"));
            }
        }
        if let Some(url) = &self.discord_webhook {
            if !url.starts_with("http") {
                return Err(anyhow!("discord_webhook must be http/https"));
            }
        }
        Ok(())
    }
}
