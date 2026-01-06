use std::sync::Arc;
use std::time::Instant;

use anyhow::{anyhow, Result};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use uuid::Uuid;

use crate::{
    database::Database,
    filters::deduplication::{deduplicate_findings, filter_false_positives},
    models::{Finding, HostProbe, ScanConfig, ScanResult, ScanStatus, Target},
    notifications::NotificationManager,
    reporting::ReportGenerator,
    tools::ToolsManager,
    queue::{EventBus, ScanEvent},
};

#[derive(Clone)]
pub struct BugHunterOrchestrator {
    pub config: Arc<ScanConfig>,
    pub target: Target,
    pub db: Arc<Database>,
    pub tools_manager: ToolsManager,
    pub notification_manager: NotificationManager,
    pub reporter: ReportGenerator,
    pub cancel_token: CancellationToken,
    forced_scan_id: Option<Uuid>,
    event_bus: Option<EventBus>,
}

impl BugHunterOrchestrator {
    pub fn new(config: ScanConfig, target: Target, db: Database) -> Self {
        let tools_manager = ToolsManager::new(config.clone());
        let notification_manager = NotificationManager::new(
            config.webhook_url.clone(),
            config.slack_webhook.clone(),
            config.discord_webhook.clone(),
            config.email.clone(),
        );
        let reporter = ReportGenerator::new();

        let cancel_token = CancellationToken::new();

        Self {
            config: Arc::new(config),
            target,
            db: Arc::new(db),
            tools_manager,
            notification_manager,
            reporter,
            cancel_token,
            forced_scan_id: None,
            event_bus: None,
        }
    }

    pub fn with_scan_id(config: ScanConfig, target: Target, db: Database, scan_id: Uuid) -> Self {
        let mut s = Self::new(config, target, db);
        s.forced_scan_id = Some(scan_id);
        s
    }

    pub fn with_event_bus(mut self, event_bus: EventBus) -> Self {
        self.event_bus = Some(event_bus);
        self
    }

    pub async fn run_full_scan(&self) -> Result<ScanResult> {
        self.validate_target().await?;
        let start = Instant::now();
        let max_time = self.config.max_total_scan_time;

        let mut result = ScanResult::new(
            self.target.id.unwrap_or_else(Uuid::new_v4),
            self.config.id.unwrap_or_else(Uuid::new_v4),
        );
        if let Some(id) = self.forced_scan_id {
            result.id = id;
        }

        start_cancel_watcher(self.db.clone(), result.id, self.cancel_token.clone());

        macro_rules! check_deadline {
            () => {
                if let Some(limit) = max_time {
                    if start.elapsed().as_secs() > limit {
                        result.status = ScanStatus::Failed;
                        result.error_message =
                            Some(format!("max_total_scan_time {}s exceeded", limit));
                        result.ended_at = Some(chrono::Utc::now());
                        self.db.save_scan(&result).await?;
                        return Ok(result);
                    }
                }
                if self.cancel_token.is_cancelled() {
                    result.status = ScanStatus::Cancelled;
                    result.error_message = Some("cancelled by user".into());
                    result.ended_at = Some(chrono::Utc::now());
                    self.db.save_scan(&result).await?;
                    return Ok(result);
                }
            };
        }

        // Emit stage change event
        self.emit_stage_event("subfinder", 0.0).await;
        
        info!("running subfinder for {}", self.target.domain);
        let subdomains = self
            .tools_manager
            .run_subfinder(&self.target, Some(&self.cancel_token))
            .await?;
        check_deadline!();

        // Emit progress event
        self.emit_progress_event("subfinder", subdomains.len(), subdomains.len()).await;

        // Emit stage change event
        self.emit_stage_event("httpx", 0.25).await;
        
        info!("running httpx probing");
        let probes: Vec<HostProbe> = self
            .tools_manager
            .run_httpx(&subdomains, Some(&self.cancel_token))
            .await
            .unwrap_or_default();
        let probes = if self.config.scope_strict {
            probes
                .into_iter()
                .filter(|p| in_scope(&self.target.scope, &p.url))
                .collect::<Vec<_>>()
        } else {
            probes
        };
        let live_hosts: Vec<String> = probes.iter().map(|p| p.url.clone()).collect();

        let mut findings: Vec<Finding> = Vec::new();

        // Emit stage change event
        self.emit_stage_event("nuclei", 0.5).await;
        
        info!("running nuclei");
        let nuclei_findings = self
            .tools_manager
            .run_nuclei(&live_hosts, Some(&self.cancel_token))
            .await
            .unwrap_or_default();
        findings.extend(self.attach_target(nuclei_findings.clone()));
        
        // Emit findings discovered
        for finding in &nuclei_findings {
            self.emit_finding_event(finding).await;
        }
        check_deadline!();

        // Emit stage change event
        self.emit_stage_event("sqlmap", 0.7).await;
        
        info!("running sqlmap");
        let sqlmap_findings = self
            .tools_manager
            .run_sqlmap(&live_hosts, Some(&self.cancel_token))
            .await
            .unwrap_or_default();
        findings.extend(self.attach_target(sqlmap_findings.clone()));
        
        // Emit findings discovered
        for finding in &sqlmap_findings {
            self.emit_finding_event(finding).await;
        }
        check_deadline!();

        // Emit stage change event
        self.emit_stage_event("ffuf", 0.85).await;
        
        info!("running ffuf");
        let ffuf_findings = self
            .tools_manager
            .run_ffuf(&live_hosts, Some(&self.cancel_token))
            .await
            .unwrap_or_default();
        findings.extend(self.attach_target(ffuf_findings.clone()));
        
        // Emit findings discovered
        for finding in &ffuf_findings {
            self.emit_finding_event(finding).await;
        }

        let filtered = filter_false_positives(findings, &self.config.false_positive_patterns);

        let mut deduped = deduplicate_findings(filtered);
        for f in deduped.iter_mut() {
            if f.cvss_score.is_none() {
                f.cvss_score = Some(map_severity_to_cvss(f.severity));
            }
        }
        if let Some(max) = self.config.max_findings_per_target {
            if deduped.len() > max as usize {
                deduped.truncate(max as usize);
            }
        }
        for f in result.findings.iter_mut() {
            if f.confidence_score.is_none() {
                if let Some(tag) = f.tags.iter().find(|t| t.starts_with("confidence:")) {
                    if let Some(val) = tag.split(':').nth(1) {
                        f.confidence_score = val.parse::<f32>().ok();
                    }
                }
            }
        }

        result.findings = deduped;
        result.total_subdomains_discovered = subdomains.len() as u32;
        result.total_endpoints_probed = live_hosts.len() as u32;
        result.status = ScanStatus::Completed;
        result.ended_at = Some(chrono::Utc::now());

        self.db.save_scan(&result).await?;
        self.notification_manager.notify_findings(&result).await?;

        if let Err(err) = tokio::fs::create_dir_all("reports").await {
            warn!("could not create reports directory: {err}");
        }

        let report_path = format!("reports/scan-{}.html", result.id);
        if let Err(err) = self.reporter.generate_html_report(&result, &report_path) {
            warn!("failed to generate report: {err}");
        }
        let json_path = format!("reports/scan-{}.json", result.id);
        if let Err(err) = self.reporter.generate_json_report(&result, &json_path) {
            warn!("failed to generate json report: {err}");
        }
        let csv_path = format!("reports/scan-{}.csv", result.id);
        if let Err(err) = self.reporter.generate_csv_report(&result, &csv_path) {
            warn!("failed to generate csv report: {err}");
        }

        Ok(result)
    }

    async fn validate_target(&self) -> Result<()> {
        self.target.validate().map_err(|e| anyhow!(e))?;
        if !self.target.scope.iter().any(|s| {
            self.target
                .domain
                .ends_with(s.trim_start_matches('*').trim_start_matches('.'))
        }) {
            return Err(anyhow!("target domain is outside provided scope"));
        }
        Ok(())
    }

    fn attach_target(&self, findings: Vec<Finding>) -> Vec<Finding> {
        let target_id = self.target.id.unwrap_or_else(Uuid::new_v4);
        findings
            .into_iter()
            .map(|mut f| {
                if f.target_id.is_nil() {
                    f.target_id = target_id;
                }
                f
            })
            .collect()
    }

    async fn emit_stage_event(&self, stage: &str, progress: f32) {
        if let Some(ref bus) = self.event_bus {
            let scan_id = self.forced_scan_id.unwrap_or_else(Uuid::new_v4);
            bus.publish(ScanEvent::StageChanged {
                scan_id,
                stage: stage.to_string(),
                progress,
                timestamp: chrono::Utc::now(),
            }).await;
        }
    }

    async fn emit_progress_event(&self, stage: &str, current: usize, total: usize) {
        if let Some(ref bus) = self.event_bus {
            let scan_id = self.forced_scan_id.unwrap_or_else(Uuid::new_v4);
            bus.publish(ScanEvent::Progress {
                scan_id,
                stage: stage.to_string(),
                current,
                total,
                timestamp: chrono::Utc::now(),
            }).await;
        }
    }

    async fn emit_finding_event(&self, finding: &Finding) {
        if let Some(ref bus) = self.event_bus {
            let scan_id = self.forced_scan_id.unwrap_or_else(Uuid::new_v4);
            bus.publish(ScanEvent::FindingDiscovered {
                scan_id,
                severity: finding.severity.to_string(),
                vulnerability_type: finding.vulnerability_type.to_string(),
                endpoint: finding.endpoint.clone(),
                timestamp: chrono::Utc::now(),
            }).await;
        }
    }
}

fn in_scope(scope: &[String], url: &str) -> bool {
    if let Ok(parsed) = url::Url::parse(url) {
        if let Some(host) = parsed.host_str() {
            return scope.iter().any(|s| {
                let trimmed = s.trim_start_matches('*').trim_start_matches('.');
                host == trimmed || host.ends_with(&format!(".{}", trimmed))
            });
        }
    }
    false
}

fn map_severity_to_cvss(sev: crate::models::Severity) -> f32 {
    match sev {
        crate::models::Severity::Critical => 9.0,
        crate::models::Severity::High => 7.5,
        crate::models::Severity::Medium => 5.0,
        crate::models::Severity::Low => 3.0,
        crate::models::Severity::Info => 0.0,
    }
}

fn start_cancel_watcher(db: Arc<Database>, scan_id: Uuid, token: CancellationToken) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            interval.tick().await;
            if token.is_cancelled() {
                break;
            }
            if let Ok(true) = db.is_scan_cancelled(&scan_id).await {
                token.cancel();
                break;
            }
        }
    });
}
