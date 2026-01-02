use anyhow::Result;
use reqwest::Client;
use serde::Serialize;
use tracing::{info, warn};

use crate::models::{ScanResult, Severity};

#[derive(Clone, Debug, Default)]
pub struct NotificationManager {
    pub webhook_url: Option<String>,
    pub slack_webhook: Option<String>,
    pub email: Option<EmailConfig>,
    client: Client,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct EmailConfig {
    pub smtp_server: Option<String>,
    pub recipients: Vec<String>,
    pub from: Option<String>,
    pub send_above: Option<Severity>,
}

impl NotificationManager {
    pub fn new(webhook_url: Option<String>, slack_webhook: Option<String>) -> Self {
        Self {
            webhook_url,
            slack_webhook,
            email: None,
            client: Client::new(),
        }
    }

    pub async fn notify_findings(&self, result: &ScanResult) -> Result<()> {
        if self.webhook_url.is_none() && self.slack_webhook.is_none() {
            return Ok(());
        }

        let summary = WebhookPayload::from_result(result);

        if let Some(url) = &self.webhook_url {
            let res = self.client.post(url).json(&summary).send().await;
            if let Err(err) = res {
                warn!("webhook notification failed: {err}");
            } else {
                info!("webhook notification sent");
            }
        }

        if let Some(url) = &self.slack_webhook {
            let blocks = summary.to_slack_blocks();
            let res = self
                .client
                .post(url)
                .json(&serde_json::json!({ "blocks": blocks }))
                .send()
                .await;
            if let Err(err) = res {
                warn!("slack notification failed: {err}");
            } else {
                info!("slack notification sent");
            }
        }

        Ok(())
    }
}

#[derive(Serialize, Debug)]
struct WebhookPayload {
    timestamp: String,
    target: String,
    scan_id: String,
    total_findings: usize,
    by_severity: SeverityBreakdown,
}

#[derive(Serialize, Debug, Default)]
struct SeverityBreakdown {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
}

impl WebhookPayload {
    fn from_result(result: &ScanResult) -> Self {
        let mut breakdown = SeverityBreakdown::default();
        for finding in &result.findings {
            match finding.severity {
                Severity::Critical => breakdown.critical += 1,
                Severity::High => breakdown.high += 1,
                Severity::Medium => breakdown.medium += 1,
                Severity::Low => breakdown.low += 1,
                Severity::Info => breakdown.info += 1,
            }
        }

        Self {
            timestamp: result.started_at.to_rfc3339(),
            target: result.target_id.to_string(),
            scan_id: result.id.to_string(),
            total_findings: result.findings.len(),
            by_severity: breakdown,
        }
    }

    fn to_slack_blocks(&self) -> serde_json::Value {
        serde_json::json!([
            {
                "type": "header",
                "text": { "type": "plain_text", "text": "Khepri Scan Summary" }
            },
            {
                "type": "section",
                "fields": [
                    { "type": "mrkdwn", "text": format!("*Scan ID*\n{}", self.scan_id) },
                    { "type": "mrkdwn", "text": format!("*Findings*\n{}", self.total_findings) }
                ]
            },
            {
                "type": "context",
                "elements": [
                    { "type": "mrkdwn", "text": format!("Critical: {}, High: {}, Medium: {}, Low: {}, Info: {}", self.by_severity.critical, self.by_severity.high, self.by_severity.medium, self.by_severity.low, self.by_severity.info) }
                ]
            }
        ])
    }
}
