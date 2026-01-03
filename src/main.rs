use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use kheprimaat::{
    control,
    database::Database,
    models::{ScanConfig, ScanStatus, Target, TargetStatus},
    orchestrator::BugHunterOrchestrator,
    reporting::ReportGenerator,
    utils::{config::ConfigParser, config_store::ConfigOverrides},
};

#[derive(Parser, Debug)]
#[command(
    name = "kheprimaat",
    version,
    about = "KhepriMaat bug bounty hunting framework"
)]
struct Cli {
    /// Database URL (sqlite:// or postgres://)
    #[arg(long, default_value = "sqlite://data/kheprimaat.db", global = true)]
    database_url: String,

    /// Enable control API server (default: off)
    #[arg(long, default_value_t = false)]
    control_enable: bool,

    /// Control server bind address (host:port)
    #[arg(long, default_value = "127.0.0.1:8080")]
    control_bind: String,

    /// Control server bearer token
    #[arg(long)]
    control_token: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Add a new target
    TargetAdd {
        domain: String,
        #[arg(long)]
        scope: Option<String>,
        #[arg(long)]
        notes: Option<String>,
    },
    /// List targets
    TargetList,
    /// Show a single target by id or domain
    TargetShow { id_or_domain: String },
    /// Delete a target by id or domain
    TargetDelete { id_or_domain: String },
    /// Start a scan
    ScanStart {
        domain: String,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        concurrency: Option<u32>,
        #[arg(long)]
        rate_limit: Option<u32>,
        #[arg(long, default_value_t = true)]
        scope_strict: bool,
    },
    /// List scans (optionally filter by domain)
    ScanList {
        #[arg(long)]
        domain: Option<String>,
    },
    /// Show scan status/details
    ScanStatus { scan_id: String },
    /// Mark a scan as cancelled
    ScanCancel { scan_id: String },
    /// List findings (optionally by domain)
    FindingsList {
        #[arg(long)]
        domain: Option<String>,
    },
    /// Mark finding as verified
    FindingsVerify { finding_id: String },
    /// Export findings (stdout)
    FindingsExport {
        #[arg(long, default_value = "json")]
        format: String,
    },
    /// Generate a report for a scan id
    FindingsReport {
        scan_id: String,
        #[arg(long, default_value = "html")]
        format: String,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Show counts by severity
    StatsShow {
        #[arg(long, default_value = "text")]
        format: String,
    },
    /// Configure notification webhooks
    ConfigWebhook { url: String },
    /// Configure Slack webhook
    ConfigSlack { url: String },
    /// Configure Discord webhook
    ConfigDiscord { url: String },
    /// Create a named config from file
    ConfigCreate { name: String, from_file: PathBuf },
    /// Initialize database schema
    DbInit,
    /// Run control API server only
    Server {
        #[arg(long, default_value = "127.0.0.1:8080")]
        bind: String,
        #[arg(long)]
        token: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("kheprimaat=info".parse()?))
        .with_target(false)
        .init();

    let cli = Cli::parse();

    if cli.database_url.starts_with("sqlite://") {
        tokio::fs::create_dir_all("data").await?;
    }

    let db = Database::new(&cli.database_url).await?;

    if cli.control_enable {
        let db_clone = db.clone();
        let bind = cli.control_bind.clone();
        let token = cli.control_token.clone();
        tokio::spawn(async move {
            if let Err(err) =
                control::serve(db_clone.into(), &bind, control::ControlConfig { token }).await
            {
                eprintln!("control server failed: {err}");
            }
        });
    }

    match cli.command {
        Commands::TargetAdd {
            domain,
            scope,
            notes,
        } => {
            let scopes = scope
                .map(|s| s.split(',').map(|p| p.trim().to_string()).collect())
                .unwrap_or_else(|| vec![domain.clone(), format!("*.{}", domain)]);
            let target = Target {
                id: None,
                domain: domain.clone(),
                scope: scopes,
                status: TargetStatus::Active,
                created_at: chrono::Utc::now(),
                last_scan: None,
                notes,
            };
            let stored = db.upsert_target(&target).await?;
            println!("Target stored with id {}", stored.id.unwrap_or_default());
        }
        Commands::TargetList => {
            let targets = db.list_targets().await?;
            for t in targets {
                println!(
                    "{} | scope: {} | status: {:?}",
                    t.domain,
                    t.scope.join(","),
                    t.status
                );
            }
        }
        Commands::TargetShow { id_or_domain } => {
            if let Some(t) = db.get_target(&id_or_domain).await? {
                println!(
                    "Target {} | scope={} | status={:?} | created_at={} | last_scan={:?} | notes={:?}",
                    t.domain,
                    t.scope.join(","),
                    t.status,
                    t.created_at,
                    t.last_scan,
                    t.notes
                );
            } else {
                println!("Target not found");
            }
        }
        Commands::TargetDelete { id_or_domain } => {
            let removed = db.delete_target(&id_or_domain).await?;
            println!("Deleted {} target(s)", removed);
        }
        Commands::ScanStart {
            domain,
            config,
            concurrency,
            rate_limit,
            scope_strict,
        } => {
            let scopes = vec![domain.clone(), format!("*.{}", domain)];
            let target = Target {
                id: Some(uuid::Uuid::new_v4()),
                domain: domain.clone(),
                scope: scopes,
                status: TargetStatus::Active,
                created_at: chrono::Utc::now(),
                last_scan: None,
                notes: None,
            };

            let target = db.upsert_target(&target).await?;

            let mut scan_config: ScanConfig = if let Some(path) = config {
                ConfigParser::load_from_file(path.to_str().unwrap())?
            } else {
                let mut cfg = ScanConfig::default();
                let overrides = ConfigOverrides::load();
                if cfg.webhook_url.is_none() {
                    cfg.webhook_url = overrides.webhook_url;
                }
                if cfg.slack_webhook.is_none() {
                    cfg.slack_webhook = overrides.slack_webhook;
                }
                if cfg.discord_webhook.is_none() {
                    cfg.discord_webhook = overrides.discord_webhook;
                }
                cfg
            };
            if let Some(c) = concurrency {
                scan_config.concurrency = c;
            }
            if let Some(r) = rate_limit {
                scan_config.rate_limit_per_sec = Some(r);
            }
            scan_config.scope_strict = scope_strict;

            let orchestrator = BugHunterOrchestrator::new(scan_config, target, db.clone());
            let result = orchestrator.run_full_scan().await?;
            println!(
                "Scan {} completed. Findings: {}. Report saved to reports/scan-{}.html",
                result.id,
                result.findings.len(),
                result.id
            );
        }
        Commands::ScanList { domain } => {
            let scans = db.list_scans(domain).await?;
            for s in scans {
                println!(
                    "{} | target={} | status={:?} | started={} | ended={:?} | findings={}",
                    s.id,
                    s.target_id,
                    s.status,
                    s.started_at,
                    s.ended_at,
                    s.findings.len()
                );
            }
        }
        Commands::ScanStatus { scan_id } => {
            let scan_uuid = uuid::Uuid::parse_str(&scan_id)?;
            let scan = db.get_scan_with_findings(&scan_uuid).await?;
            println!(
                "Scan {} | status={:?} | started={} | ended={:?} | findings={}",
                scan.id,
                scan.status,
                scan.started_at,
                scan.ended_at,
                scan.findings.len()
            );
        }
        Commands::ScanCancel { scan_id } => {
            let scan_uuid = uuid::Uuid::parse_str(&scan_id)?;
            db.update_scan_status(
                &scan_uuid,
                ScanStatus::Cancelled,
                Some("user cancelled".into()),
            )
            .await?;
            db.set_scan_cancel(&scan_uuid).await?;
            println!("Scan {} marked as cancelled", scan_id);
        }
        Commands::FindingsList { domain } => {
            let findings = db.list_findings(domain).await?;
            for f in findings {
                println!(
                    "[{}] {} - {} ({})",
                    f.severity, f.vulnerability_type, f.endpoint, f.tool_source
                );
            }
        }
        Commands::FindingsVerify { finding_id } => {
            let fid = uuid::Uuid::parse_str(&finding_id)?;
            db.verify_finding(&fid, true).await?;
            println!("Marked finding {} as verified", finding_id);
        }
        Commands::FindingsExport { format } => {
            let findings = db.list_findings(None).await?;
            match format.as_str() {
                "csv" => {
                    let mut wtr = csv::Writer::from_writer(std::io::stdout());
                    wtr.write_record([
                        "severity",
                        "type",
                        "endpoint",
                        "payload",
                        "evidence",
                        "tool",
                        "verified",
                        "created_at",
                    ])?;
                    for f in findings {
                        wtr.write_record([
                            f.severity.to_string(),
                            f.vulnerability_type.to_string(),
                            f.endpoint,
                            f.payload.unwrap_or_default(),
                            f.evidence,
                            f.tool_source,
                            f.verified.to_string(),
                            f.created_at.to_rfc3339(),
                        ])?;
                    }
                    wtr.flush()?;
                }
                _ => {
                    println!("{}", serde_json::to_string_pretty(&findings)?);
                }
            }
        }
        Commands::FindingsReport {
            scan_id,
            format,
            output,
        } => {
            let scan_uuid = uuid::Uuid::parse_str(&scan_id)?;
            let scan = db.get_scan_with_findings(&scan_uuid).await?;
            tokio::fs::create_dir_all("reports").await?;
            let generator = ReportGenerator::new();
            let path = output
                .unwrap_or_else(|| PathBuf::from(format!("reports/scan-{}.{}", scan_id, format)));
            match format.as_str() {
                "json" => generator.generate_json_report(&scan, path.to_str().unwrap())?,
                "csv" => generator.generate_csv_report(&scan, path.to_str().unwrap())?,
                _ => generator.generate_html_report(&scan, path.to_str().unwrap())?,
            }
            println!("Report written to {}", path.display());
        }
        Commands::StatsShow { format } => {
            let findings = db.list_findings(None).await?;
            let mut counts: HashMap<String, u32> = HashMap::new();
            for f in findings {
                *counts.entry(f.severity.to_string()).or_insert(0) += 1;
            }
            match format.as_str() {
                "json" => println!("{}", serde_json::to_string_pretty(&counts)?),
                _ => {
                    for (sev, count) in counts {
                        println!("{sev}: {count}");
                    }
                }
            }
        }
        Commands::ConfigWebhook { url } => {
            let mut overrides = ConfigOverrides::load();
            overrides.webhook_url = Some(url);
            overrides.save()?;
            println!("Default webhook saved to data/config_overrides.json");
        }
        Commands::ConfigSlack { url } => {
            let mut overrides = ConfigOverrides::load();
            overrides.slack_webhook = Some(url);
            overrides.save()?;
            println!("Default Slack webhook saved to data/config_overrides.json");
        }
        Commands::ConfigDiscord { url } => {
            let mut overrides = ConfigOverrides::load();
            overrides.discord_webhook = Some(url);
            overrides.save()?;
            println!("Default Discord webhook saved to data/config_overrides.json");
        }
        Commands::ConfigCreate { name, from_file } => {
            tokio::fs::create_dir_all("templates/config").await?;
            let dest = format!("templates/config/{}.yaml", name);
            tokio::fs::copy(&from_file, &dest).await?;
            println!("Saved config as {}", dest);
        }
        Commands::DbInit => {
            println!("Database initialized at {}", cli.database_url);
        }
        Commands::Server { bind, token } => {
            let db_clone = db.clone();
            tokio::spawn(async move {
                if let Err(err) =
                    control::serve(db_clone.into(), &bind, control::ControlConfig { token }).await
                {
                    eprintln!("control server failed: {err}");
                }
            });
            // keep running until killed
            futures::future::pending::<()>().await;
        }
    }

    Ok(())
}
