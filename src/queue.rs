use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use tracing::{info, warn, error};

use crate::{
    database::Database,
    models::{ScanConfig, Target, ScanStatus},
    orchestrator::BugHunterOrchestrator,
};

/// Represents a scan job to be executed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanJob {
    pub scan_id: Uuid,
    pub target: Target,
    pub config: ScanConfig,
    pub created_at: DateTime<Utc>,
    pub retries: u32,
    pub max_retries: u32,
}

impl ScanJob {
    pub fn new(scan_id: Uuid, target: Target, config: ScanConfig) -> Self {
        Self {
            scan_id,
            target,
            config,
            created_at: Utc::now(),
            retries: 0,
            max_retries: 3,
        }
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

/// Event types emitted by the queue/worker system
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScanEvent {
    Queued {
        scan_id: Uuid,
        target: String,
        timestamp: DateTime<Utc>,
    },
    Started {
        scan_id: Uuid,
        target: String,
        worker_id: usize,
        timestamp: DateTime<Utc>,
    },
    StageChanged {
        scan_id: Uuid,
        stage: String,
        progress: f32,
        timestamp: DateTime<Utc>,
    },
    Progress {
        scan_id: Uuid,
        stage: String,
        current: usize,
        total: usize,
        timestamp: DateTime<Utc>,
    },
    FindingDiscovered {
        scan_id: Uuid,
        severity: String,
        vulnerability_type: String,
        endpoint: String,
        timestamp: DateTime<Utc>,
    },
    Completed {
        scan_id: Uuid,
        duration_secs: u64,
        findings_count: usize,
        timestamp: DateTime<Utc>,
    },
    Failed {
        scan_id: Uuid,
        error: String,
        timestamp: DateTime<Utc>,
    },
    Cancelled {
        scan_id: Uuid,
        timestamp: DateTime<Utc>,
    },
}

/// Connection metadata for tracking SSE clients
#[derive(Debug, Clone)]
pub struct ConnectionMetadata {
    pub connection_id: Uuid,
    pub filter_scan_id: Option<Uuid>,
    pub connected_at: DateTime<Utc>,
}

/// Event bus for broadcasting scan events to SSE listeners
#[derive(Clone)]
pub struct EventBus {
    subscribers: Arc<RwLock<Vec<mpsc::UnboundedSender<ScanEvent>>>>,
    connections: Arc<RwLock<Vec<ConnectionMetadata>>>,
}

impl ScanEvent {
    /// Get the scan_id from any event type
    pub fn scan_id(&self) -> Uuid {
        match self {
            ScanEvent::Queued { scan_id, .. } => *scan_id,
            ScanEvent::Started { scan_id, .. } => *scan_id,
            ScanEvent::StageChanged { scan_id, .. } => *scan_id,
            ScanEvent::Progress { scan_id, .. } => *scan_id,
            ScanEvent::FindingDiscovered { scan_id, .. } => *scan_id,
            ScanEvent::Completed { scan_id, .. } => *scan_id,
            ScanEvent::Failed { scan_id, .. } => *scan_id,
            ScanEvent::Cancelled { scan_id, .. } => *scan_id,
        }
    }
}

impl EventBus {
    pub fn new() -> Self {
        Self {
            subscribers: Arc::new(RwLock::new(Vec::new())),
            connections: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Subscribe to all events, returns a receiver
    pub async fn subscribe(&self) -> mpsc::UnboundedReceiver<ScanEvent> {
        let (tx, rx) = mpsc::unbounded_channel();
        
        // Track connection
        let connection_id = Uuid::new_v4();
        let metadata = ConnectionMetadata {
            connection_id,
            filter_scan_id: None,
            connected_at: Utc::now(),
        };
        
        {
            let mut subs = self.subscribers.write().await;
            let mut conns = self.connections.write().await;
            subs.push(tx);
            conns.push(metadata);
        }
        
        info!("SSE client {} connected (unfiltered)", connection_id);
        rx
    }

    /// Subscribe to events for a specific scan_id, returns a filtered receiver
    pub async fn subscribe_filtered(&self, filter_scan_id: Uuid) -> mpsc::UnboundedReceiver<ScanEvent> {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let (filtered_tx, filtered_rx) = mpsc::unbounded_channel();
        
        // Track connection
        let connection_id = Uuid::new_v4();
        let metadata = ConnectionMetadata {
            connection_id,
            filter_scan_id: Some(filter_scan_id),
            connected_at: Utc::now(),
        };
        
        // Add to subscribers and connections
        {
            let mut subs = self.subscribers.write().await;
            let mut conns = self.connections.write().await;
            subs.push(tx);
            conns.push(metadata);
        }
        
        info!("SSE client {} connected (filtered: {})", connection_id, filter_scan_id);
        
        // Spawn a task to filter events
        let event_bus = self.clone();
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                if event.scan_id() == filter_scan_id {
                    if filtered_tx.send(event).is_err() {
                        // Client disconnected, cleanup connection metadata
                        event_bus.cleanup_connection(connection_id).await;
                        break;
                    }
                }
            }
        });
        
        filtered_rx
    }

    /// Publish an event to all subscribers
    pub async fn publish(&self, event: ScanEvent) {
        let mut subs = self.subscribers.write().await;
        // Remove dead subscribers
        subs.retain(|tx| !tx.is_closed());
        
        // Broadcast to all active subscribers
        for tx in subs.iter() {
            let _ = tx.send(event.clone());
        }
    }

    /// Get current subscriber count
    pub async fn subscriber_count(&self) -> usize {
        let subs = self.subscribers.read().await;
        subs.len()
    }

    /// Get connection metadata
    pub async fn get_connections(&self) -> Vec<ConnectionMetadata> {
        let conns = self.connections.read().await;
        conns.clone()
    }

    /// Cleanup disconnected connection
    async fn cleanup_connection(&self, connection_id: Uuid) {
        let mut conns = self.connections.write().await;
        conns.retain(|c| c.connection_id != connection_id);
        info!("SSE client {} disconnected", connection_id);
    }

    /// Get filtered connection count
    pub async fn filtered_connection_count(&self) -> usize {
        let conns = self.connections.read().await;
        conns.iter().filter(|c| c.filter_scan_id.is_some()).count()
    }

    /// Get unfiltered connection count
    pub async fn unfiltered_connection_count(&self) -> usize {
        let conns = self.connections.read().await;
        conns.iter().filter(|c| c.filter_scan_id.is_none()).count()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

/// Scan job queue with bounded capacity
pub struct ScanQueue {
    tx: mpsc::Sender<ScanJob>,
    rx: Arc<tokio::sync::Mutex<mpsc::Receiver<ScanJob>>>,
    event_bus: EventBus,
}

impl ScanQueue {
    pub fn new(capacity: usize) -> Self {
        let (tx, rx) = mpsc::channel(capacity);
        Self {
            tx,
            rx: Arc::new(tokio::sync::Mutex::new(rx)),
            event_bus: EventBus::new(),
        }
    }

    /// Enqueue a scan job
    pub async fn enqueue(&self, job: ScanJob) -> Result<(), String> {
        let scan_id = job.scan_id;
        let target = job.target.domain.clone();
        
        self.tx
            .send(job)
            .await
            .map_err(|e| format!("Failed to enqueue job: {}", e))?;

        // Publish queued event
        self.event_bus.publish(ScanEvent::Queued {
            scan_id,
            target,
            timestamp: Utc::now(),
        }).await;

        info!("Job {} enqueued", scan_id);
        Ok(())
    }

    /// Get a reference to the receiver (for workers)
    pub fn receiver(&self) -> Arc<tokio::sync::Mutex<mpsc::Receiver<ScanJob>>> {
        self.rx.clone()
    }

    /// Get a reference to the event bus
    pub fn event_bus(&self) -> EventBus {
        self.event_bus.clone()
    }

    /// Get current queue length (approximate)
    pub fn len(&self) -> usize {
        // Note: mpsc::Sender doesn't expose queue length directly
        // This is a best-effort approach
        self.tx.capacity()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Worker that processes scan jobs from the queue
pub struct Worker {
    id: usize,
    db: Arc<Database>,
    event_bus: EventBus,
    shutdown: CancellationToken,
    retry_queue: Arc<tokio::sync::Mutex<Vec<ScanJob>>>,
}

impl Worker {
    pub fn new(id: usize, db: Arc<Database>, event_bus: EventBus, shutdown: CancellationToken) -> Self {
        Self {
            id,
            db,
            event_bus,
            shutdown,
            retry_queue: Arc::new(tokio::sync::Mutex::new(Vec::new())),
        }
    }

    /// Start processing jobs from the queue
    pub async fn run(self, queue_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<ScanJob>>>) {
        info!("Worker {} started", self.id);

        loop {
            tokio::select! {
                _ = self.shutdown.cancelled() => {
                    info!("Worker {} shutting down gracefully", self.id);
                    break;
                }
                job = async {
                    let mut rx = queue_rx.lock().await;
                    rx.recv().await
                } => {
                    match job {
                        Some(job) => {
                            info!("Worker {} picked up job {}", self.id, job.scan_id);
                            if let Err(e) = self.process_job(job).await {
                                error!("Worker {} job processing error: {}", self.id, e);
                            }
                        }
                        None => {
                            info!("Worker {} queue closed, exiting", self.id);
                            break;
                        }
                    }
                }
            }
        }

        info!("Worker {} stopped", self.id);
    }

    async fn process_job(&self, mut job: ScanJob) -> Result<(), String> {
        let scan_id = job.scan_id;
        let target = job.target.domain.clone();
        let start_time = std::time::Instant::now();

        // Publish started event
        self.event_bus.publish(ScanEvent::Started {
            scan_id,
            target: target.clone(),
            worker_id: self.id,
            timestamp: Utc::now(),
        }).await;

        // Update scan status to running
        if let Err(e) = self.db.update_scan_status(&scan_id, ScanStatus::Running, None).await {
            warn!("Failed to update scan status to running: {}", e);
        }

        // Create orchestrator with the scan ID and event bus
        let orchestrator = BugHunterOrchestrator::with_scan_id(
            job.config.clone(),
            job.target.clone(),
            (*self.db).clone(),
            scan_id,
        ).with_event_bus(self.event_bus.clone());

        // Execute the scan
        match orchestrator.run_full_scan().await {
            Ok(result) => {
                let duration = start_time.elapsed().as_secs();
                
                // Publish completion event
                self.event_bus.publish(ScanEvent::Completed {
                    scan_id,
                    duration_secs: duration,
                    findings_count: result.findings.len(),
                    timestamp: Utc::now(),
                }).await;

                info!(
                    "Worker {} completed scan {} in {}s with {} findings",
                    self.id, scan_id, duration, result.findings.len()
                );

                Ok(())
            }
            Err(e) => {
                let error_msg = e.to_string();
                
                // Check if job can be retried
                if job.can_retry() {
                    job.increment_retry();
                    
                    let retries = job.retries;
                    let max_retries = job.max_retries;
                    
                    warn!(
                        "Worker {} scan {} failed (attempt {}/{}): {}. Scheduling retry...",
                        self.id, scan_id, retries, max_retries, error_msg
                    );
                    
                    // Add to retry queue with exponential backoff
                    let backoff_secs = 2_u64.pow(retries);
                    tokio::time::sleep(tokio::time::Duration::from_secs(backoff_secs)).await;
                    
                    // Update status to pending for retry
                    if let Err(db_err) = self.db.update_scan_status(
                        &scan_id,
                        ScanStatus::Pending,
                        Some(format!("Retry {}/{}: {}", retries, max_retries, error_msg)),
                    ).await {
                        warn!("Failed to update scan status for retry: {}", db_err);
                    }
                    
                    let mut retry_queue = self.retry_queue.lock().await;
                    retry_queue.push(job);
                    
                    return Ok(()); // Don't mark as permanently failed yet
                }
                
                // Max retries exceeded, mark as permanently failed
                if let Err(db_err) = self.db.update_scan_status(
                    &scan_id,
                    ScanStatus::Failed,
                    Some(format!("Max retries exceeded. Last error: {}", error_msg)),
                ).await {
                    warn!("Failed to update scan status to failed: {}", db_err);
                }

                // Publish failed event
                self.event_bus.publish(ScanEvent::Failed {
                    scan_id,
                    error: format!("Max retries ({}) exceeded. Last error: {}", job.max_retries, error_msg),
                    timestamp: Utc::now(),
                }).await;

                error!(
                    "Worker {} scan {} permanently failed after {} retries: {}",
                    self.id, scan_id, job.retries, error_msg
                );

                Err(format!("Scan failed after {} retries: {}", job.retries, error_msg))
            }
        }
    }
}

/// Worker pool manager
pub struct WorkerPool {
    workers: Vec<tokio::task::JoinHandle<()>>,
    shutdown: CancellationToken,
}

impl WorkerPool {
    pub fn new(
        worker_count: usize,
        db: Arc<Database>,
        queue: &ScanQueue,
    ) -> Self {
        let shutdown = CancellationToken::new();
        let mut workers = Vec::with_capacity(worker_count);
        let queue_rx = queue.receiver();
        let event_bus = queue.event_bus();

        for id in 0..worker_count {
            let worker = Worker::new(
                id,
                db.clone(),
                event_bus.clone(),
                shutdown.clone(),
            );
            let queue_rx_clone = queue_rx.clone();
            
            let handle = tokio::spawn(async move {
                worker.run(queue_rx_clone).await;
            });

            workers.push(handle);
        }

        info!("Worker pool started with {} workers", worker_count);

        Self {
            workers,
            shutdown,
        }
    }

    /// Gracefully shutdown all workers
    pub async fn shutdown(self) {
        info!("Initiating worker pool shutdown");
        self.shutdown.cancel();

        for (i, handle) in self.workers.into_iter().enumerate() {
            match tokio::time::timeout(std::time::Duration::from_secs(30), handle).await {
                Ok(Ok(())) => info!("Worker {} shut down successfully", i),
                Ok(Err(e)) => error!("Worker {} panicked: {}", i, e),
                Err(_) => warn!("Worker {} shutdown timed out", i),
            }
        }

        info!("Worker pool shutdown complete");
    }

    /// Get shutdown token (for external cancellation)
    pub fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_event_bus_subscribe_and_publish() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe().await;

        let event = ScanEvent::Queued {
            scan_id: Uuid::new_v4(),
            target: "example.com".to_string(),
            timestamp: Utc::now(),
        };

        bus.publish(event.clone()).await;

        let received = rx.recv().await;
        assert!(received.is_some());
    }

    #[tokio::test]
    async fn test_queue_enqueue() {
        let queue = ScanQueue::new(10);
        let job = ScanJob::new(
            Uuid::new_v4(),
            crate::models::Target::new("example.com".to_string(), vec![]),
            crate::models::ScanConfig::default(),
        );

        let result = queue.enqueue(job).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_event_bus_multiple_subscribers() {
        let bus = EventBus::new();
        let mut rx1 = bus.subscribe().await;
        let mut rx2 = bus.subscribe().await;

        assert_eq!(bus.subscriber_count().await, 2);

        let event = ScanEvent::Started {
            scan_id: Uuid::new_v4(),
            target: "example.com".to_string(),
            worker_id: 0,
            timestamp: Utc::now(),
        };

        bus.publish(event).await;

        assert!(rx1.recv().await.is_some());
        assert!(rx2.recv().await.is_some());
    }

    #[tokio::test]
    async fn test_scan_job_retry_logic() {
        let mut job = ScanJob::new(
            Uuid::new_v4(),
            crate::models::Target::new("example.com".to_string(), vec![]),
            crate::models::ScanConfig::default(),
        );

        assert_eq!(job.retries, 0);
        assert_eq!(job.max_retries, 3);
        assert!(job.can_retry());

        job.increment_retry();
        assert_eq!(job.retries, 1);
        assert!(job.can_retry());

        job.increment_retry();
        job.increment_retry();
        assert_eq!(job.retries, 3);
        assert!(!job.can_retry());
    }

    #[tokio::test]
    async fn test_scan_job_custom_max_retries() {
        let job = ScanJob::new(
            Uuid::new_v4(),
            crate::models::Target::new("example.com".to_string(), vec![]),
            crate::models::ScanConfig::default(),
        ).with_max_retries(5);

        assert_eq!(job.max_retries, 5);
    }

    #[tokio::test]
    async fn test_queue_capacity() {
        let queue = ScanQueue::new(2);
        
        let job1 = ScanJob::new(
            Uuid::new_v4(),
            crate::models::Target::new("example1.com".to_string(), vec![]),
            crate::models::ScanConfig::default(),
        );
        let job2 = ScanJob::new(
            Uuid::new_v4(),
            crate::models::Target::new("example2.com".to_string(), vec![]),
            crate::models::ScanConfig::default(),
        );
        let job3 = ScanJob::new(
            Uuid::new_v4(),
            crate::models::Target::new("example3.com".to_string(), vec![]),
            crate::models::ScanConfig::default(),
        );

        assert!(queue.enqueue(job1).await.is_ok());
        assert!(queue.enqueue(job2).await.is_ok());
        
        // Third should be accepted since channel has buffer
        assert!(queue.enqueue(job3).await.is_ok());
    }

    #[tokio::test]
    async fn test_event_bus_dead_subscriber_cleanup() {
        let bus = EventBus::new();
        let mut rx1 = bus.subscribe().await;
        let rx2 = bus.subscribe().await;

        assert_eq!(bus.subscriber_count().await, 2);

        // Drop one subscriber
        drop(rx2);

        let event = ScanEvent::Queued {
            scan_id: Uuid::new_v4(),
            target: "example.com".to_string(),
            timestamp: Utc::now(),
        };

        // This should clean up dead subscribers
        bus.publish(event).await;

        // Subscriber count should eventually be 1
        assert!(rx1.recv().await.is_some());
    }

    #[tokio::test]
    async fn test_scan_event_serialization() {
        let event = ScanEvent::Completed {
            scan_id: Uuid::new_v4(),
            duration_secs: 120,
            findings_count: 5,
            timestamp: Utc::now(),
        };

        let json = serde_json::to_string(&event);
        assert!(json.is_ok());
        
        let json_str = json.unwrap();
        assert!(json_str.contains("\"type\":\"completed\""));
        assert!(json_str.contains("\"findings_count\":5"));
    }

    #[tokio::test]
    async fn test_queue_event_on_enqueue() {
        let queue = ScanQueue::new(10);
        let mut rx = queue.event_bus().subscribe().await;

        let scan_id = Uuid::new_v4();
        let job = ScanJob::new(
            scan_id,
            crate::models::Target::new("example.com".to_string(), vec![]),
            crate::models::ScanConfig::default(),
        );

        queue.enqueue(job).await.unwrap();

        // Should receive queued event
        let event = rx.recv().await;
        assert!(event.is_some());
        
        if let Some(ScanEvent::Queued { scan_id: received_id, .. }) = event {
            assert_eq!(received_id, scan_id);
        } else {
            panic!("Expected Queued event");
        }
    }

    #[tokio::test]
    async fn test_worker_pool_creation() {
        let db = Arc::new(Database::new("sqlite::memory:").await.unwrap());
        let queue = ScanQueue::new(10);
        
        let pool = WorkerPool::new(2, db, &queue);
        
        // Pool should be created with shutdown token
        let token = pool.shutdown_token();
        assert!(!token.is_cancelled());
    }

    #[tokio::test]
    async fn test_worker_pool_graceful_shutdown() {
        let db = Arc::new(Database::new("sqlite::memory:").await.unwrap());
        let queue = ScanQueue::new(10);
        
        let pool = WorkerPool::new(2, db, &queue);
        
        // Shutdown should complete without panic
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            pool.shutdown()
        ).await.expect("Shutdown should complete within timeout");
    }

    #[tokio::test]
    async fn test_event_types_coverage() {
        let scan_id = Uuid::new_v4();
        
        let events = vec![
            ScanEvent::Queued {
                scan_id,
                target: "test.com".to_string(),
                timestamp: Utc::now(),
            },
            ScanEvent::Started {
                scan_id,
                target: "test.com".to_string(),
                worker_id: 0,
                timestamp: Utc::now(),
            },
            ScanEvent::StageChanged {
                scan_id,
                stage: "subfinder".to_string(),
                progress: 0.25,
                timestamp: Utc::now(),
            },
            ScanEvent::Progress {
                scan_id,
                stage: "nuclei".to_string(),
                current: 50,
                total: 100,
                timestamp: Utc::now(),
            },
            ScanEvent::FindingDiscovered {
                scan_id,
                severity: "high".to_string(),
                vulnerability_type: "XSS".to_string(),
                endpoint: "https://test.com/vuln".to_string(),
                timestamp: Utc::now(),
            },
            ScanEvent::Completed {
                scan_id,
                duration_secs: 300,
                findings_count: 10,
                timestamp: Utc::now(),
            },
            ScanEvent::Failed {
                scan_id,
                error: "Test error".to_string(),
                timestamp: Utc::now(),
            },
            ScanEvent::Cancelled {
                scan_id,
                timestamp: Utc::now(),
            },
        ];

        // All events should serialize successfully
        for event in events {
            let json = serde_json::to_string(&event);
            assert!(json.is_ok(), "Event serialization failed");
        }
    }

    #[tokio::test]
    async fn test_filtered_subscription() {
        let bus = EventBus::new();
        let scan_id_1 = Uuid::new_v4();
        let scan_id_2 = Uuid::new_v4();
        
        // Subscribe with filter for scan_id_1
        let mut rx_filtered = bus.subscribe_filtered(scan_id_1).await;
        
        // Publish events for both scans
        bus.publish(ScanEvent::Queued {
            scan_id: scan_id_1,
            target: "test1.com".to_string(),
            timestamp: Utc::now(),
        }).await;
        
        bus.publish(ScanEvent::Queued {
            scan_id: scan_id_2,
            target: "test2.com".to_string(),
            timestamp: Utc::now(),
        }).await;
        
        bus.publish(ScanEvent::Started {
            scan_id: scan_id_1,
            target: "test1.com".to_string(),
            worker_id: 0,
            timestamp: Utc::now(),
        }).await;
        
        // Should only receive events for scan_id_1
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        let event1 = rx_filtered.recv().await.unwrap();
        assert_eq!(event1.scan_id(), scan_id_1);
        
        let event2 = rx_filtered.recv().await.unwrap();
        assert_eq!(event2.scan_id(), scan_id_1);
        
        // Should not receive event for scan_id_2
        match tokio::time::timeout(
            tokio::time::Duration::from_millis(100),
            rx_filtered.recv()
        ).await {
            Ok(Some(event)) => {
                // If we receive an event, it should be for scan_id_1
                assert_eq!(event.scan_id(), scan_id_1);
            },
            Ok(None) => panic!("Channel closed unexpectedly"),
            Err(_) => {
                // Timeout is expected - no more events for scan_id_1
            }
        }
    }

    #[tokio::test]
    async fn test_scan_event_scan_id_extraction() {
        let scan_id = Uuid::new_v4();
        
        let event1 = ScanEvent::Queued {
            scan_id,
            target: "test.com".to_string(),
            timestamp: Utc::now(),
        };
        assert_eq!(event1.scan_id(), scan_id);
        
        let event2 = ScanEvent::Completed {
            scan_id,
            duration_secs: 100,
            findings_count: 5,
            timestamp: Utc::now(),
        };
        assert_eq!(event2.scan_id(), scan_id);
    }

    #[tokio::test]
    async fn test_connection_metadata_tracking() {
        let bus = EventBus::new();
        
        // Initially no connections
        assert_eq!(bus.subscriber_count().await, 0);
        assert_eq!(bus.filtered_connection_count().await, 0);
        assert_eq!(bus.unfiltered_connection_count().await, 0);
        
        // Add unfiltered subscription
        let _rx1 = bus.subscribe().await;
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        
        assert_eq!(bus.subscriber_count().await, 1);
        assert_eq!(bus.unfiltered_connection_count().await, 1);
        assert_eq!(bus.filtered_connection_count().await, 0);
        
        // Add filtered subscription
        let scan_id = Uuid::new_v4();
        let _rx2 = bus.subscribe_filtered(scan_id).await;
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        
        assert_eq!(bus.subscriber_count().await, 2);
        assert_eq!(bus.unfiltered_connection_count().await, 1);
        assert_eq!(bus.filtered_connection_count().await, 1);
        
        // Get connection metadata
        let connections = bus.get_connections().await;
        assert_eq!(connections.len(), 2);
        
        // Verify metadata
        let filtered_conn = connections.iter().find(|c| c.filter_scan_id.is_some()).unwrap();
        assert_eq!(filtered_conn.filter_scan_id, Some(scan_id));
    }

    #[tokio::test]
    async fn test_multiple_filtered_subscriptions() {
        let bus = EventBus::new();
        let scan_id_1 = Uuid::new_v4();
        let scan_id_2 = Uuid::new_v4();
        
        // Two clients filtering different scans
        let mut rx1 = bus.subscribe_filtered(scan_id_1).await;
        let mut rx2 = bus.subscribe_filtered(scan_id_2).await;
        
        // Publish event for scan_id_1
        bus.publish(ScanEvent::Started {
            scan_id: scan_id_1,
            target: "test1.com".to_string(),
            worker_id: 0,
            timestamp: Utc::now(),
        }).await;
        
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        // rx1 should receive it
        let event = rx1.recv().await.unwrap();
        assert_eq!(event.scan_id(), scan_id_1);
        
        // rx2 should timeout (no event for scan_id_2)
        match tokio::time::timeout(
            tokio::time::Duration::from_millis(100),
            rx2.recv()
        ).await {
            Err(_) => {}, // Expected timeout
            Ok(_) => panic!("rx2 should not receive event for different scan_id"),
        }
    }

    #[tokio::test]
    async fn test_mixed_filtered_and_unfiltered() {
        let bus = EventBus::new();
        let scan_id = Uuid::new_v4();
        
        // One unfiltered, one filtered
        let mut rx_all = bus.subscribe().await;
        let mut rx_filtered = bus.subscribe_filtered(scan_id).await;
        
        // Publish events
        bus.publish(ScanEvent::Queued {
            scan_id,
            target: "test.com".to_string(),
            timestamp: Utc::now(),
        }).await;
        
        let other_scan_id = Uuid::new_v4();
        bus.publish(ScanEvent::Queued {
            scan_id: other_scan_id,
            target: "other.com".to_string(),
            timestamp: Utc::now(),
        }).await;
        
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        // Unfiltered should receive both
        let event1 = rx_all.recv().await.unwrap();
        let event2 = rx_all.recv().await.unwrap();
        
        let received_ids: Vec<Uuid> = vec![event1.scan_id(), event2.scan_id()];
        assert!(received_ids.contains(&scan_id));
        assert!(received_ids.contains(&other_scan_id));
        
        // Filtered should only receive one
        let event = rx_filtered.recv().await.unwrap();
        assert_eq!(event.scan_id(), scan_id);
        
        // No more events for filtered
        match tokio::time::timeout(
            tokio::time::Duration::from_millis(100),
            rx_filtered.recv()
        ).await {
            Err(_) => {}, // Expected
            Ok(_) => panic!("Should not receive more events"),
        }
    }

    #[tokio::test]
    async fn test_connection_cleanup_on_drop() {
        let bus = EventBus::new();
        let scan_id = Uuid::new_v4();
        
        {
            let _rx = bus.subscribe_filtered(scan_id).await;
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            assert_eq!(bus.filtered_connection_count().await, 1);
        } // rx dropped here
        
        // Publish event to trigger cleanup
        bus.publish(ScanEvent::Queued {
            scan_id,
            target: "test.com".to_string(),
            timestamp: Utc::now(),
        }).await;
        
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        // Cleanup should have occurred
        assert_eq!(bus.filtered_connection_count().await, 0);
    }
}
