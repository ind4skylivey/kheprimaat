use anyhow::{anyhow, Result};
use serde_yaml::Value;
use std::fs;

use crate::models::ScanConfig;

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

        let config = ScanConfig {
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
            created_at: chrono::Utc::now(),
        };

        config.validate_basic()?;
        Ok(config)
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
        Ok(())
    }
}
