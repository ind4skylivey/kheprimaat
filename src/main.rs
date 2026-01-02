use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use khepri::{
    database::Database,
    models::{ScanConfig, Target, TargetStatus},
    orchestrator::BugHunterOrchestrator,
    utils::config::ConfigParser,
};

#[derive(Parser, Debug)]
#[command(
    name = "khepri",
    version,
    about = "Automated bug bounty hunting framework"
)]
struct Cli {
    /// Database URL (sqlite:// or postgres://)
    #[arg(long, default_value = "sqlite://data/khepri.db")]
    database_url: String,

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
    /// Start a scan
    ScanStart {
        domain: String,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// List findings (optionally by domain)
    FindingsList {
        #[arg(long)]
        domain: Option<String>,
    },
    /// Initialize database schema
    DbInit,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("khepri=info".parse()?))
        .with_target(false)
        .init();

    let cli = Cli::parse();

    if cli.database_url.starts_with("sqlite://") {
        tokio::fs::create_dir_all("data").await?;
    }

    let db = Database::new(&cli.database_url).await?;

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
        Commands::ScanStart { domain, config } => {
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

            let scan_config: ScanConfig = if let Some(path) = config {
                ConfigParser::load_from_file(path.to_str().unwrap())?
            } else {
                ScanConfig::default()
            };

            let orchestrator = BugHunterOrchestrator::new(scan_config, target, db.clone());
            let result = orchestrator.run_full_scan().await?;
            println!(
                "Scan {} completed. Findings: {}. Report saved to reports/scan-{}.html",
                result.id,
                result.findings.len(),
                result.id
            );
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
        Commands::DbInit => {
            println!("Database initialized at {}", cli.database_url);
        }
    }

    Ok(())
}
