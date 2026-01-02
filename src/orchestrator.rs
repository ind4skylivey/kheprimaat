use std::sync::Arc;

use anyhow::{anyhow, Result};
use tracing::{info, warn};
use uuid::Uuid;

use crate::{
    database::Database,
    filters::deduplication::deduplicate_findings,
    models::{Finding, HostProbe, ScanConfig, ScanResult, ScanStatus, Target},
    notifications::NotificationManager,
    reporting::ReportGenerator,
    tools::ToolsManager,
};

#[derive(Clone)]
pub struct BugHunterOrchestrator {
    pub config: Arc<ScanConfig>,
    pub target: Target,
    pub db: Arc<Database>,
    pub tools_manager: ToolsManager,
    pub notification_manager: NotificationManager,
    pub reporter: ReportGenerator,
}

impl BugHunterOrchestrator {
    pub fn new(config: ScanConfig, target: Target, db: Database) -> Self {
        let tools_manager = ToolsManager::new(config.clone());
        let notification_manager = NotificationManager::new(config.webhook_url.clone(), None);
        let reporter = ReportGenerator::new();

        Self {
            config: Arc::new(config),
            target,
            db: Arc::new(db),
            tools_manager,
            notification_manager,
            reporter,
        }
    }

    pub async fn run_full_scan(&self) -> Result<ScanResult> {
        self.validate_target().await?;

        let mut result = ScanResult::new(
            self.target.id.unwrap_or_else(Uuid::new_v4),
            self.config.id.unwrap_or_else(Uuid::new_v4),
        );

        info!("running subfinder for {}", self.target.domain);
        let subdomains = self.tools_manager.run_subfinder(&self.target).await?;

        info!("running httpx probing");
        let probes: Vec<HostProbe> = self
            .tools_manager
            .run_httpx(&subdomains)
            .await
            .unwrap_or_default();
        let live_hosts: Vec<String> = probes.iter().map(|p| p.url.clone()).collect();

        let mut findings: Vec<Finding> = Vec::new();

        info!("running nuclei");
        let nuclei_findings = self
            .tools_manager
            .run_nuclei(&live_hosts)
            .await
            .unwrap_or_default();
        findings.extend(self.attach_target(nuclei_findings));

        info!("running sqlmap");
        let sqlmap_findings = self
            .tools_manager
            .run_sqlmap(&live_hosts)
            .await
            .unwrap_or_default();
        findings.extend(self.attach_target(sqlmap_findings));

        info!("running ffuf");
        let ffuf_findings = self
            .tools_manager
            .run_ffuf(&live_hosts)
            .await
            .unwrap_or_default();
        findings.extend(self.attach_target(ffuf_findings));

        let deduped = deduplicate_findings(findings);
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
}
