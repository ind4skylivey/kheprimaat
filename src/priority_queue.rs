use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{info, warn, debug};
use uuid::Uuid;

use crate::models::{ScanConfig, Target};

/// Priority levels for scan jobs (Issue #10)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Priority {
    Low = 0,
    Normal = 1,
    High = 2,
}

impl Default for Priority {
    fn default() -> Self {
        Priority::Normal
    }
}

impl Priority {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// Scan job with priority support
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriorityScanJob {
    pub scan_id: Uuid,
    pub target: Target,
    pub config: ScanConfig,
    pub priority: Priority,
    pub created_at: DateTime<Utc>,
    pub retries: u32,
    pub max_retries: u32,
    pub user_id: Option<String>, // For quota tracking
}

impl PriorityScanJob {
    pub fn new(
        scan_id: Uuid,
        target: Target,
        config: ScanConfig,
        priority: Priority,
    ) -> Self {
        Self {
            scan_id,
            target,
            config,
            priority,
            created_at: Utc::now(),
            retries: 0,
            max_retries: 3,
            user_id: None,
        }
    }

    pub fn with_user(mut self, user_id: String) -> Self {
        self.user_id = Some(user_id);
        self
    }

    pub fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    pub fn can_retry(&self) -> bool {
        self.retries < self.max_retries
    }

    pub fn increment_retry(&mut self) {
        self.retries += 1;
    }
}

/// Wrapper for BinaryHeap ordering (higher priority = processed first)
#[derive(Debug, Clone)]
struct PrioritizedJob {
    job: PriorityScanJob,
    sequence: u64, // For FIFO ordering within same priority
}

impl PartialEq for PrioritizedJob {
    fn eq(&self, other: &Self) -> bool {
        self.sequence == other.sequence
    }
}

impl Eq for PrioritizedJob {}

impl PartialOrd for PrioritizedJob {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PrioritizedJob {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher priority first, then by sequence (FIFO)
        other
            .job
            .priority
            .as_u8()
            .cmp(&self.job.priority.as_u8())
            .then_with(|| self.sequence.cmp(&other.sequence))
    }
}

/// Priority quota tracking per user
#[derive(Debug, Clone)]
pub struct PriorityQuota {
    high_used: usize,
    high_allowed: usize,
    last_reset: Instant,
}

impl PriorityQuota {
    pub fn new(allowed: usize) -> Self {
        Self {
            high_used: 0,
            high_allowed: allowed,
            last_reset: Instant::now(),
        }
    }

    pub fn can_use_high(&mut self) -> bool {
        // Reset counter every hour
        if self.last_reset.elapsed() > Duration::from_secs(3600) {
            self.high_used = 0;
            self.last_reset = Instant::now();
        }
        self.high_used < self.high_allowed
    }

    pub fn use_high(&mut self) {
        self.high_used += 1;
    }
}

/// Configuration for priority queue
#[derive(Debug, Clone)]
pub struct PriorityQueueConfig {
    pub max_high_priority_per_hour: usize,
    pub max_queue_size: usize,
    pub starvation_check_interval: Duration,
    pub aging_threshold: Duration, // Time before promoting low priority
}

impl Default for PriorityQueueConfig {
    fn default() -> Self {
        Self {
            max_high_priority_per_hour: 5,
            max_queue_size: 1000,
            starvation_check_interval: Duration::from_secs(300), // 5 minutes
            aging_threshold: Duration::from_secs(600),           // 10 minutes
        }
    }
}

/// Priority queue with starvation prevention (Issue #10)
pub struct PriorityQueue {
    heap: RwLock<BinaryHeap<PrioritizedJob>>,
    sequence_counter: RwLock<u64>,
    quotas: RwLock<HashMap<String, PriorityQuota>>,
    config: PriorityQueueConfig,
    last_aging: RwLock<Instant>,
    metrics: RwLock<QueueMetrics>,
}

#[derive(Debug, Default)]
struct QueueMetrics {
    enqueued: HashMap<Priority, usize>,
    dequeued: HashMap<Priority, usize>,
    demoted: usize,
    promoted: usize,
}

impl PriorityQueue {
    pub fn new(config: PriorityQueueConfig) -> Self {
        Self {
            heap: RwLock::new(BinaryHeap::new()),
            sequence_counter: RwLock::new(0),
            quotas: RwLock::new(HashMap::new()),
            config,
            last_aging: RwLock::new(Instant::now()),
            metrics: RwLock::new(QueueMetrics::default()),
        }
    }

    /// Enqueue a job with priority validation
    /// 
    /// Security features:
    /// - Validates user quota for high priority
    /// - Demotes to normal if quota exceeded
    /// - Prevents queue overflow
    pub async fn enqueue(&self, mut job: PriorityScanJob) -> Result<(), QueueError> {
        // Check queue capacity
        {
            let heap = self.heap.read().await;
            if heap.len() >= self.config.max_queue_size {
                return Err(QueueError::QueueFull);
            }
        }

        // Validate priority based on user quota
        if job.priority == Priority::High {
            if let Some(ref user_id) = job.user_id {
                let mut quotas = self.quotas.write().await;
                let quota = quotas
                    .entry(user_id.clone())
                    .or_insert_with(|| PriorityQuota::new(self.config.max_high_priority_per_hour));

                if !quota.can_use_high() {
                    warn!(
                        "User {} exceeded high priority quota, demoting job {}",
                        user_id, job.scan_id
                    );
                    job.priority = Priority::Normal;

                    let mut metrics = self.metrics.write().await;
                    metrics.demoted += 1;
                } else {
                    quota.use_high();
                }
            }
        }

        // Apply aging to prevent starvation
        self.apply_aging().await;

        // Get sequence number for FIFO ordering
        let sequence = {
            let mut counter = self.sequence_counter.write().await;
            *counter += 1;
            *counter
        };

        // Update metrics before moving job
        let priority = job.priority;
        let scan_id = job.scan_id;
        {
            let mut metrics = self.metrics.write().await;
            *metrics.enqueued.entry(priority).or_insert(0) += 1;
        }

        // Add to heap
        {
            let mut heap = self.heap.write().await;
            heap.push(PrioritizedJob { job, sequence });
        }

        info!("Job {} enqueued with priority {:?}", scan_id, priority);
        Ok(())
    }

    /// Dequeue the highest priority job
    /// 
    /// Uses weighted random selection to prevent complete starvation:
    /// - 70% chance: High priority
    /// - 25% chance: Normal priority
    /// - 5% chance: Low priority
    pub async fn dequeue(&self) -> Option<PriorityScanJob> {
        // Apply aging periodically
        self.apply_aging().await;

        let mut heap = self.heap.write().await;

        if heap.is_empty() {
            return None;
        }

        // Weighted random selection to prevent starvation
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let roll = rng.gen_range(0..100);

        let target_priority = if roll < 70 {
            Priority::High
        } else if roll < 95 {
            Priority::Normal
        } else {
            Priority::Low
        };

        // Try to find job of target priority
        let mut temp_queue: Vec<PrioritizedJob> = Vec::new();
        let mut result = None;

        while let Some(pjob) = heap.pop() {
            if result.is_none() && pjob.job.priority == target_priority {
                result = Some(pjob.job);
            } else {
                temp_queue.push(pjob);
            }
        }

        // Put back jobs we didn't use
        for pjob in temp_queue {
            heap.push(pjob);
        }

        // If we didn't find target priority, just take highest
        if result.is_none() {
            if let Some(pjob) = heap.pop() {
                result = Some(pjob.job);
            }
        }

        // Update metrics
        if let Some(ref job) = result {
            let mut metrics = self.metrics.write().await;
            *metrics.dequeued.entry(job.priority).or_insert(0) += 1;
        }

        result
    }

    /// Apply aging to prevent starvation of low priority jobs
    async fn apply_aging(&self) {
        let should_age = {
            let last = self.last_aging.read().await;
            last.elapsed() > self.config.starvation_check_interval
        };

        if should_age {
            let mut heap = self.heap.write().await;
            let mut temp_queue: Vec<PrioritizedJob> = Vec::new();
            let mut promoted = 0;

            while let Some(mut pjob) = heap.pop() {
                // Promote low priority jobs that have been waiting too long
                if pjob.job.priority == Priority::Low
                    && pjob.job.created_at + chrono::Duration::from_std(self.config.aging_threshold).unwrap()
                        < Utc::now()
                {
                    debug!("Promoting job {} from Low to Normal", pjob.job.scan_id);
                    pjob.job.priority = Priority::Normal;
                    promoted += 1;
                }
                temp_queue.push(pjob);
            }

            // Put back all jobs
            for pjob in temp_queue {
                heap.push(pjob);
            }

            if promoted > 0 {
                let mut metrics = self.metrics.write().await;
                metrics.promoted += promoted;
                info!("Aging: promoted {} jobs from Low to Normal priority", promoted);
            }

            let mut last_aging = self.last_aging.write().await;
            *last_aging = Instant::now();
        }
    }

    /// Get current queue size
    pub async fn len(&self) -> usize {
        let heap = self.heap.read().await;
        heap.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    /// Get metrics snapshot
    pub async fn get_metrics(&self) -> QueueMetricsSnapshot {
        let metrics = self.metrics.read().await;
        QueueMetricsSnapshot {
            enqueued_high: *metrics.enqueued.get(&Priority::High).unwrap_or(&0),
            enqueued_normal: *metrics.enqueued.get(&Priority::Normal).unwrap_or(&0),
            enqueued_low: *metrics.enqueued.get(&Priority::Low).unwrap_or(&0),
            dequeued_high: *metrics.dequeued.get(&Priority::High).unwrap_or(&0),
            dequeued_normal: *metrics.dequeued.get(&Priority::Normal).unwrap_or(&0),
            dequeued_low: *metrics.dequeued.get(&Priority::Low).unwrap_or(&0),
            demoted: metrics.demoted,
            promoted: metrics.promoted,
            current_size: self.len().await,
        }
    }

    /// Peek at highest priority job without removing
    pub async fn peek(&self) -> Option<PriorityScanJob> {
        let heap = self.heap.read().await;
        heap.peek().map(|pjob| pjob.job.clone())
    }
}

#[derive(Debug, Serialize)]
pub struct QueueMetricsSnapshot {
    pub enqueued_high: usize,
    pub enqueued_normal: usize,
    pub enqueued_low: usize,
    pub dequeued_high: usize,
    pub dequeued_normal: usize,
    pub dequeued_low: usize,
    pub demoted: usize,
    pub promoted: usize,
    pub current_size: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum QueueError {
    #[error("Queue is full")]
    QueueFull,
    #[error("Invalid priority")]
    InvalidPriority,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_job(priority: Priority) -> PriorityScanJob {
        PriorityScanJob::new(
            Uuid::new_v4(),
            Target::new("example.com".to_string(), vec![]),
            ScanConfig::default(),
            priority,
        )
    }

    #[tokio::test]
    async fn test_priority_ordering() {
        let queue = PriorityQueue::new(PriorityQueueConfig::default());

        let low = create_test_job(Priority::Low);
        let high = create_test_job(Priority::High);
        let normal = create_test_job(Priority::Normal);

        queue.enqueue(low).await.unwrap();
        queue.enqueue(high).await.unwrap();
        queue.enqueue(normal).await.unwrap();

        // Should dequeue high first
        let first = queue.dequeue().await.unwrap();
        assert_eq!(first.priority, Priority::High);

        // Then normal
        let second = queue.dequeue().await.unwrap();
        assert_eq!(second.priority, Priority::Normal);

        // Then low
        let third = queue.dequeue().await.unwrap();
        assert_eq!(third.priority, Priority::Low);
    }

    #[tokio::test]
    async fn test_queue_full() {
        let config = PriorityQueueConfig {
            max_queue_size: 2,
            ..Default::default()
        };
        let queue = PriorityQueue::new(config);

        queue.enqueue(create_test_job(Priority::Normal)).await.unwrap();
        queue.enqueue(create_test_job(Priority::Normal)).await.unwrap();

        // Third should fail
        let result = queue.enqueue(create_test_job(Priority::Normal)).await;
        assert!(matches!(result, Err(QueueError::QueueFull)));
    }

    #[tokio::test]
    async fn test_priority_quota() {
        let config = PriorityQueueConfig {
            max_high_priority_per_hour: 2,
            ..Default::default()
        };
        let queue = PriorityQueue::new(config);

        let user_id = "test_user".to_string();

        // First two high priority should succeed
        let job1 = create_test_job(Priority::High).with_user(user_id.clone());
        let job2 = create_test_job(Priority::High).with_user(user_id.clone());

        queue.enqueue(job1).await.unwrap();
        queue.enqueue(job2).await.unwrap();

        // Third should be demoted to normal
        let job3 = create_test_job(Priority::High).with_user(user_id.clone());
        queue.enqueue(job3).await.unwrap();

        let dequeued = queue.dequeue().await.unwrap();
        assert_eq!(dequeued.priority, Priority::High);

        let dequeued = queue.dequeue().await.unwrap();
        assert_eq!(dequeued.priority, Priority::High);

        // Third was demoted
        let dequeued = queue.dequeue().await.unwrap();
        assert_eq!(dequeued.priority, Priority::Normal);
    }

    #[tokio::test]
    async fn test_fifo_within_priority() {
        let queue = PriorityQueue::new(PriorityQueueConfig::default());

        let job1 = create_test_job(Priority::Normal);
        let job2 = create_test_job(Priority::Normal);
        let id1 = job1.scan_id;
        let id2 = job2.scan_id;

        queue.enqueue(job1).await.unwrap();
        queue.enqueue(job2).await.unwrap();

        let first = queue.dequeue().await.unwrap();
        let second = queue.dequeue().await.unwrap();

        assert_eq!(first.scan_id, id1);
        assert_eq!(second.scan_id, id2);
    }
}
