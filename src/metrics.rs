use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{database::Database, models::ScanStatus, queue::EventBus};

/// System metrics aggregating scan, finding, and health data
#[derive(Debug, Clone, Serialize)]
pub struct SystemMetrics {
    pub scans: ScanMetrics,
    pub findings: FindingMetrics,
    pub system: SystemHealth,
    pub generated_at: DateTime<Utc>,
}

/// Scan-related metrics
#[derive(Debug, Clone, Serialize)]
pub struct ScanMetrics {
    pub total: usize,
    pub last_24h: usize,
    pub last_7d: usize,
    pub last_30d: usize,
    pub success_rate: f32,
    pub avg_duration_secs: f32,
    pub by_status: HashMap<String, usize>,
}

/// Finding-related metrics
#[derive(Debug, Clone, Serialize)]
pub struct FindingMetrics {
    pub total: usize,
    pub last_24h: usize,
    pub last_7d: usize,
    pub by_severity: HashMap<String, usize>,
    pub by_tool: HashMap<String, usize>,
    pub verified_count: usize,
    pub verified_rate: f32,
}

/// System health metrics
#[derive(Debug, Clone, Serialize)]
pub struct SystemHealth {
    pub queue_length: usize,
    pub active_workers: usize,
    pub sse_connections: usize,
    pub sse_filtered_connections: usize,
    pub uptime_secs: u64,
    pub database_healthy: bool,
}

/// Metrics collector with caching
pub struct MetricsCollector {
    db: Arc<Database>,
    event_bus: EventBus,
    cache: Arc<RwLock<Option<CachedMetrics>>>,
    cache_ttl_secs: u64,
    start_time: DateTime<Utc>,
}

#[derive(Debug, Clone)]
struct CachedMetrics {
    metrics: SystemMetrics,
    cached_at: DateTime<Utc>,
}

impl MetricsCollector {
    pub fn new(db: Arc<Database>, event_bus: EventBus) -> Self {
        Self {
            db,
            event_bus,
            cache: Arc::new(RwLock::new(None)),
            cache_ttl_secs: 30, // Cache for 30 seconds
            start_time: Utc::now(),
        }
    }

    /// Get metrics with caching
    pub async fn get_metrics(&self) -> anyhow::Result<SystemMetrics> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.as_ref() {
                let age = Utc::now() - cached.cached_at;
                if age.num_seconds() < self.cache_ttl_secs as i64 {
                    return Ok(cached.metrics.clone());
                }
            }
        }

        // Cache miss or expired, collect fresh metrics
        let metrics = self.collect_metrics().await?;

        // Update cache
        {
            let mut cache = self.cache.write().await;
            *cache = Some(CachedMetrics {
                metrics: metrics.clone(),
                cached_at: Utc::now(),
            });
        }

        Ok(metrics)
    }

    /// Force refresh metrics (bypass cache)
    pub async fn refresh_metrics(&self) -> anyhow::Result<SystemMetrics> {
        let metrics = self.collect_metrics().await?;
        
        // Update cache
        {
            let mut cache = self.cache.write().await;
            *cache = Some(CachedMetrics {
                metrics: metrics.clone(),
                cached_at: Utc::now(),
            });
        }

        Ok(metrics)
    }

    /// Collect fresh metrics from database and system
    async fn collect_metrics(&self) -> anyhow::Result<SystemMetrics> {
        // Collect in parallel for performance
        let (scan_metrics, finding_metrics, system_health) = tokio::join!(
            self.collect_scan_metrics(),
            self.collect_finding_metrics(),
            self.collect_system_health()
        );

        Ok(SystemMetrics {
            scans: scan_metrics?,
            findings: finding_metrics?,
            system: system_health?,
            generated_at: Utc::now(),
        })
    }

    async fn collect_scan_metrics(&self) -> anyhow::Result<ScanMetrics> {
        // Get all scans (this could be optimized with SQL aggregations)
        let scans = self.db.list_scan_summaries(10000).await?;

        let now = Utc::now();
        let day_ago = now - Duration::days(1);
        let week_ago = now - Duration::days(7);
        let month_ago = now - Duration::days(30);

        let total = scans.len();
        let last_24h = scans.iter().filter(|s| s.started_at >= day_ago).count();
        let last_7d = scans.iter().filter(|s| s.started_at >= week_ago).count();
        let last_30d = scans.iter().filter(|s| s.started_at >= month_ago).count();

        // Calculate success rate
        let completed = scans
            .iter()
            .filter(|s| matches!(s.status, ScanStatus::Completed))
            .count();
        let success_rate = if total > 0 {
            (completed as f32 / total as f32) * 100.0
        } else {
            0.0
        };

        // Calculate average duration
        let total_duration: i64 = scans
            .iter()
            .filter_map(|s| {
                s.ended_at
                    .map(|end| (end - s.started_at).num_seconds())
            })
            .sum();
        let avg_duration_secs = if completed > 0 {
            total_duration as f32 / completed as f32
        } else {
            0.0
        };

        // Count by status
        let mut by_status = HashMap::new();
        for scan in &scans {
            let status = format!("{:?}", scan.status);
            *by_status.entry(status).or_insert(0) += 1;
        }

        Ok(ScanMetrics {
            total,
            last_24h,
            last_7d,
            last_30d,
            success_rate,
            avg_duration_secs,
            by_status,
        })
    }

    async fn collect_finding_metrics(&self) -> anyhow::Result<FindingMetrics> {
        // Get all findings
        let findings = self.db.list_findings(None).await?;

        let now = Utc::now();
        let day_ago = now - Duration::days(1);
        let week_ago = now - Duration::days(7);

        let total = findings.len();
        let last_24h = findings.iter().filter(|f| f.created_at >= day_ago).count();
        let last_7d = findings.iter().filter(|f| f.created_at >= week_ago).count();

        // Count by severity
        let mut by_severity = HashMap::new();
        for finding in &findings {
            let severity = finding.severity.to_string();
            *by_severity.entry(severity).or_insert(0) += 1;
        }

        // Count by tool
        let mut by_tool = HashMap::new();
        for finding in &findings {
            *by_tool.entry(finding.tool_source.clone()).or_insert(0) += 1;
        }

        // Verified count
        let verified_count = findings.iter().filter(|f| f.verified).count();
        let verified_rate = if total > 0 {
            (verified_count as f32 / total as f32) * 100.0
        } else {
            0.0
        };

        Ok(FindingMetrics {
            total,
            last_24h,
            last_7d,
            by_severity,
            by_tool,
            verified_count,
            verified_rate,
        })
    }

    async fn collect_system_health(&self) -> anyhow::Result<SystemHealth> {
        // Queue length (approximate - channels don't expose exact length)
        let queue_length = 0; // TODO: Implement queue length tracking

        // Active workers (based on queue capacity and usage)
        let active_workers = 3; // TODO: Get from WorkerPool

        // SSE connections
        let sse_connections = self.event_bus.subscriber_count().await;
        let sse_filtered_connections = self.event_bus.filtered_connection_count().await;

        // Uptime
        let uptime_secs = (Utc::now() - self.start_time).num_seconds() as u64;

        // Database health check
        let database_healthy = self.check_database_health().await;

        Ok(SystemHealth {
            queue_length,
            active_workers,
            sse_connections,
            sse_filtered_connections,
            uptime_secs,
            database_healthy,
        })
    }

    async fn check_database_health(&self) -> bool {
        // Simple health check: try to query one scan
        self.db.list_scan_summaries(1).await.is_ok()
    }

    /// Get cache age in seconds
    pub async fn get_cache_age(&self) -> Option<i64> {
        let cache = self.cache.read().await;
        cache
            .as_ref()
            .map(|c| (Utc::now() - c.cached_at).num_seconds())
    }

    /// Clear cache
    pub async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;
        *cache = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_metrics_structure() {
        let metrics = SystemMetrics {
            scans: ScanMetrics {
                total: 100,
                last_24h: 10,
                last_7d: 50,
                last_30d: 90,
                success_rate: 95.0,
                avg_duration_secs: 300.0,
                by_status: {
                    let mut map = HashMap::new();
                    map.insert("Completed".to_string(), 95);
                    map.insert("Failed".to_string(), 5);
                    map
                },
            },
            findings: FindingMetrics {
                total: 500,
                last_24h: 50,
                last_7d: 200,
                by_severity: {
                    let mut map = HashMap::new();
                    map.insert("Critical".to_string(), 5);
                    map.insert("High".to_string(), 20);
                    map.insert("Medium".to_string(), 100);
                    map.insert("Low".to_string(), 200);
                    map.insert("Info".to_string(), 175);
                    map
                },
                by_tool: {
                    let mut map = HashMap::new();
                    map.insert("nuclei".to_string(), 300);
                    map.insert("ffuf".to_string(), 150);
                    map.insert("sqlmap".to_string(), 50);
                    map
                },
                verified_count: 450,
                verified_rate: 90.0,
            },
            system: SystemHealth {
                queue_length: 5,
                active_workers: 3,
                sse_connections: 10,
                sse_filtered_connections: 7,
                uptime_secs: 86400,
                database_healthy: true,
            },
            generated_at: Utc::now(),
        };

        // Serialize to JSON
        let json = serde_json::to_string_pretty(&metrics).unwrap();
        assert!(json.contains("\"total\":"));
        assert!(json.contains("\"success_rate\":"));
        assert!(json.contains("\"by_severity\":"));
    }

    #[tokio::test]
    async fn test_cache_age_tracking() {
        let db = Arc::new(Database::new("sqlite::memory:").await.unwrap());
        let event_bus = crate::queue::EventBus::new();
        let collector = MetricsCollector::new(db, event_bus);

        // Initially no cache
        assert!(collector.get_cache_age().await.is_none());

        // Manually set cache to test age tracking
        {
            let mut cache = collector.cache.write().await;
            *cache = Some(CachedMetrics {
                metrics: SystemMetrics {
                    scans: ScanMetrics {
                        total: 0,
                        last_24h: 0,
                        last_7d: 0,
                        last_30d: 0,
                        success_rate: 0.0,
                        avg_duration_secs: 0.0,
                        by_status: HashMap::new(),
                    },
                    findings: FindingMetrics {
                        total: 0,
                        last_24h: 0,
                        last_7d: 0,
                        by_severity: HashMap::new(),
                        by_tool: HashMap::new(),
                        verified_count: 0,
                        verified_rate: 0.0,
                    },
                    system: SystemHealth {
                        queue_length: 0,
                        active_workers: 0,
                        sse_connections: 0,
                        sse_filtered_connections: 0,
                        uptime_secs: 0,
                        database_healthy: true,
                    },
                    generated_at: Utc::now(),
                },
                cached_at: Utc::now(),
            });
        }

        // Now cache should exist
        let age = collector.get_cache_age().await;
        assert!(age.is_some(), "Cache should exist");
        assert!(age.unwrap() < 5, "Cache should be very recent");

        // Clear cache
        collector.clear_cache().await;
        assert!(collector.get_cache_age().await.is_none());
    }
    
    #[tokio::test]
    async fn test_metrics_serialization() {
        let metrics = SystemMetrics {
            scans: ScanMetrics {
                total: 100,
                last_24h: 10,
                last_7d: 50,
                last_30d: 90,
                success_rate: 95.5,
                avg_duration_secs: 300.0,
                by_status: {
                    let mut map = HashMap::new();
                    map.insert("Completed".to_string(), 90);
                    map.insert("Failed".to_string(), 10);
                    map
                },
            },
            findings: FindingMetrics {
                total: 500,
                last_24h: 50,
                last_7d: 200,
                by_severity: {
                    let mut map = HashMap::new();
                    map.insert("Critical".to_string(), 5);
                    map.insert("High".to_string(), 20);
                    map
                },
                by_tool: {
                    let mut map = HashMap::new();
                    map.insert("nuclei".to_string(), 300);
                    map.insert("ffuf".to_string(), 200);
                    map
                },
                verified_count: 450,
                verified_rate: 90.0,
            },
            system: SystemHealth {
                queue_length: 5,
                active_workers: 3,
                sse_connections: 10,
                sse_filtered_connections: 7,
                uptime_secs: 86400,
                database_healthy: true,
            },
            generated_at: Utc::now(),
        };

        // Test JSON serialization
        let json = serde_json::to_string(&metrics);
        assert!(json.is_ok());
        
        let json_str = json.unwrap();
        assert!(json_str.contains("\"total\":100"));
        assert!(json_str.contains("\"success_rate\":95.5"));
        assert!(json_str.contains("\"verified_rate\":90"));
    }
}
