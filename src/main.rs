use std::collections::HashMap;
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
        #[arg(long)]
        concurrency: Option<u32>,
        #[arg(long)]
        rate_limit: Option<u32>,
        #[arg(long, default_value_t = true)]
        scope_strict: bool,
    },
    /// List findings (optionally by domain)
    FindingsList {
        #[arg(long)]
        domain: Option<String>,
    },
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
                ScanConfig::default()
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
        Commands::FindingsList { domain } => {
            let findings = db.list_findings(domain).await?;
            for f in findings {
                println!(
                    "[{}] {} - {} ({})",
                    f.severity, f.vulnerability_type, f.endpoint, f.tool_source
                );
            }
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
            let generator = khepri::reporting::ReportGenerator::new();
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
        Commands::DbInit => {
            println!("Database initialized at {}", cli.database_url);
        }
    }

    Ok(())
}
