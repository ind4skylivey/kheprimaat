use anyhow::{anyhow, Result};
use lettre::transport::smtp::authentication::Mechanism;
use lettre::{
    message::Mailbox, transport::smtp::authentication::Credentials, AsyncSmtpTransport,
    AsyncTransport, Message, Tokio1Executor,
};
use reqwest::Client;
use serde::Serialize;
use tracing::{info, warn};
use url::Url;

use crate::models::{EmailSettings, ScanResult, Severity};

#[derive(Clone, Debug, Default)]
pub struct NotificationManager {
    pub webhook_url: Option<String>,
    pub slack_webhook: Option<String>,
    pub discord_webhook: Option<String>,
    pub email: Option<EmailSettings>,
    client: Client,
}

impl NotificationManager {
    pub fn new(
        webhook_url: Option<String>,
        slack_webhook: Option<String>,
        discord_webhook: Option<String>,
        email: Option<EmailSettings>,
    ) -> Self {
        Self {
            webhook_url,
            slack_webhook,
            discord_webhook,
            email,
            client: Client::new(),
        }
    }

    pub async fn notify_findings(&self, result: &ScanResult) -> Result<()> {
        if self.webhook_url.is_none()
            && self.slack_webhook.is_none()
            && self.discord_webhook.is_none()
            && self.email.is_none()
        {
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

        if let Some(url) = &self.discord_webhook {
            let res = self
                .client
                .post(url)
                .json(&summary.to_discord_embed())
                .send()
                .await;
            if let Err(err) = res {
                warn!("discord notification failed: {err}");
            } else {
                info!("discord notification sent");
            }
        }

        if let Some(email) = &self.email {
            if let Some(threshold) = email.send_above {
                let should_send = result.findings.iter().any(|f| f.severity >= threshold);
                if should_send {
                    if let Err(err) = send_email(email, &summary).await {
                        warn!("email notification failed: {err}");
                    } else {
                        info!("email notification sent");
                    }
                }
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
    findings: Vec<FindingSnippet>,
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
        let mut snippets = Vec::new();
        for finding in &result.findings {
            match finding.severity {
                Severity::Critical => breakdown.critical += 1,
                Severity::High => breakdown.high += 1,
                Severity::Medium => breakdown.medium += 1,
                Severity::Low => breakdown.low += 1,
                Severity::Info => breakdown.info += 1,
            }
            if snippets.len() < 5 {
                snippets.push(FindingSnippet {
                    severity: finding.severity.to_string(),
                    vuln_type: finding.vulnerability_type.to_string(),
                    endpoint: finding.endpoint.clone(),
                    evidence: finding.evidence.clone(),
                });
            }
        }

        Self {
            timestamp: result.started_at.to_rfc3339(),
            target: result.target_id.to_string(),
            scan_id: result.id.to_string(),
            total_findings: result.findings.len(),
            by_severity: breakdown,
            findings: snippets,
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
            },
            {
                "type": "divider"
            }
            ,
            {
                "type": "section",
                "text": { "type": "mrkdwn", "text": format!("Top findings:\\n{}", self.findings.iter().map(|f| format!("• *{}* {} - {}", f.severity, f.vuln_type, f.endpoint)).collect::<Vec<_>>().join("\\n")) }
            }
        ])
    }

    fn to_discord_message(&self) -> String {
        let mut lines = vec![
            format!(
                "**Scan {}** on target {}",
                self.scan_id.chars().take(8).collect::<String>(),
                self.target
            ),
            format!(
                "Findings: {} (C:{} H:{} M:{} L:{} I:{})",
                self.total_findings,
                self.by_severity.critical,
                self.by_severity.high,
                self.by_severity.medium,
                self.by_severity.low,
                self.by_severity.info
            ),
        ];
        for f in self.findings.iter().take(5) {
            lines.push(format!("[{}] {} - {}", f.severity, f.vuln_type, f.endpoint));
        }
        lines.join("\n")
    }

    fn to_discord_embed(&self) -> serde_json::Value {
        serde_json::json!({
            "embeds": [{
                "title": format!("Khepri Scan {}", self.scan_id.chars().take(8).collect::<String>()),
                "description": format!("Findings: {} (C:{} H:{} M:{} L:{} I:{})",
                    self.total_findings,
                    self.by_severity.critical,
                    self.by_severity.high,
                    self.by_severity.medium,
                    self.by_severity.low,
                    self.by_severity.info),
                "fields": self.findings.iter().take(5).map(|f| serde_json::json!({
                    "name": format!("[{}] {}", f.severity, f.vuln_type),
                    "value": f.endpoint
                })).collect::<Vec<_>>(),
                "color": 0x9c27b0u32,
                "timestamp": self.timestamp
            }]
        })
    }
}

#[derive(Serialize, Debug)]
struct FindingSnippet {
    severity: String,
    vuln_type: String,
    endpoint: String,
    evidence: String,
}

async fn send_email(settings: &EmailSettings, payload: &WebhookPayload) -> Result<()> {
    let smtp = settings
        .smtp_server
        .as_ref()
        .ok_or_else(|| anyhow!("smtp_server missing"))?;
    let url = Url::parse(smtp).map_err(|e| anyhow!(e))?;
    let host = url.host_str().ok_or_else(|| anyhow!("smtp host missing"))?;
    let port = url
        .port()
        .unwrap_or_else(|| if url.scheme() == "smtps" { 465 } else { 587 });

    let creds = if let Some(user) = settings.username.clone().or_else(|| {
        if url.username().is_empty() {
            None
        } else {
            Some(url.username().to_string())
        }
    }) {
        Some(Credentials::new(
            user,
            settings
                .password
                .clone()
                .or_else(|| url.password().map(|p| p.to_string()))
                .unwrap_or_default(),
        ))
    } else {
        None
    };

    let mut transport = if url.scheme() == "smtps" {
        AsyncSmtpTransport::<Tokio1Executor>::relay(host)?
    } else if settings.starttls.unwrap_or(true) {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)?
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host)
    }
    .port(port);

    if let Some(c) = creds.clone() {
        transport = transport.credentials(c);
    }

    if let Some(method) = settings.auth_method.as_deref() {
        let mech = match method.to_lowercase().as_str() {
            "login" => Mechanism::Login,
            "plain" => Mechanism::Plain,
            "xoauth2" => Mechanism::Xoauth2,
            _ => Mechanism::Plain,
        };
        transport = transport.authentication(vec![mech]);
    }

    // If XOAUTH2 token provided, set credentials accordingly.
    if settings
        .auth_method
        .as_deref()
        .map(|m| m.eq_ignore_ascii_case("xoauth2"))
        .unwrap_or(false)
    {
        if let Some(user) = settings
            .username
            .clone()
            .or_else(|| url.username().is_empty().then(|| None).flatten())
        {
            if let Some(token) = settings
                .xoauth2_token
                .clone()
                .or_else(|| settings.password.clone())
            {
                transport = transport.credentials(Credentials::new(user, token));
            } else {
                warn!("XOAUTH2 selected but token missing");
            }
        }
    }

    let mailer = transport.build();

    let from_addr = settings
        .from
        .as_ref()
        .and_then(|f| f.parse::<Mailbox>().ok())
        .unwrap_or_else(|| "kheprimaat@localhost".parse().unwrap());

    let recipients = if settings.recipients.is_empty() {
        vec!["security@example.com".to_string()]
    } else {
        settings.recipients.clone()
    };

    let body = payload.to_discord_message();
    for rcpt in recipients {
        if let Ok(to_mail) = rcpt.parse::<Mailbox>() {
            let email = Message::builder()
                .from(from_addr.clone())
                .to(to_mail)
                .subject(format!(
                    "[Khepri] Scan {} findings ({})",
                    payload.scan_id.chars().take(8).collect::<String>(),
                    payload.total_findings
                ))
                .body(body.clone())?;
            mailer.send(email).await?;
        }
    }

    Ok(())
}
