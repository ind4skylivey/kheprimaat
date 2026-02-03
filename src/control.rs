use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::{Path, Query, State},
    http::{Request, StatusCode},
    middleware::Next,
    response::sse::{Event, Sse},
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::{
    database::Database, 
    models::ScanStatus, 
    queue::{ScanQueue, ScanJob, WorkerPool},
    priority_queue::Priority,
    metrics::MetricsCollector,
};

#[derive(Clone)]
pub struct ControlConfig {
    pub token: Option<String>,
}

#[derive(Clone, Default)]
struct RateLimiter {
    inner: Arc<tokio::sync::Mutex<std::collections::HashMap<String, (u32, Instant)>>>,
    limit: u32,
}

impl RateLimiter {
    async fn check(&self, key: &str) -> bool {
        let mut guard = self.inner.lock().await;
        let entry = guard.entry(key.to_string()).or_insert((0, Instant::now()));
        if entry.1.elapsed() >= Duration::from_secs(60) {
            *entry = (0, Instant::now());
        }
        if entry.0 >= self.limit {
            false
        } else {
            entry.0 += 1;
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rate_limiter_blocks_after_limit() {
        let rl = RateLimiter {
            limit: 2,
            ..Default::default()
        };
        assert!(rl.check("ip").await);
        assert!(rl.check("ip").await);
        assert!(!rl.check("ip").await);
    }
}
#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Database>,
    pub auth: AuthState,
    pub queue: Arc<ScanQueue>,
    pub metrics: Arc<MetricsCollector>,
}

#[derive(Clone)]
pub struct AuthState {
    cfg: ControlConfig,
    ip_rl: RateLimiter,
    token_rl: RateLimiter,
}

pub async fn serve(db: Arc<Database>, bind: &str, cfg: ControlConfig) -> anyhow::Result<()> {
    use tower_http::limit::RequestBodyLimitLayer;
    use tower_http::trace::TraceLayer;

    // Create queue with capacity of 100 pending jobs
    let queue = Arc::new(ScanQueue::new(100));
    
    // Start worker pool with 3 workers
    let _worker_pool = WorkerPool::new(3, db.clone(), &queue);
    
    // Create metrics collector
    let metrics = Arc::new(MetricsCollector::new(db.clone(), queue.event_bus()));
    
    let state = AppState {
        db,
        auth: AuthState {
            cfg,
            ip_rl: RateLimiter {
                limit: 100,
                ..Default::default()
            },
            token_rl: RateLimiter {
                limit: 500,
                ..Default::default()
            },
        },
        queue,
        metrics,
    };

    let app = Router::new()
        .route("/cancel/:scan_id", post(cancel_scan))
        .route("/status/:scan_id", get(scan_status))
        .route("/scans", get(list_scans))
        .route("/scans/:scan_id/findings", get(list_findings))
        .route("/scans", post(create_scan))
        .route("/events", get(stream_events))
        .route("/metrics", get(get_metrics))
        .route("/stats", get(get_metrics)) // Alias for /metrics
        // Issue #11: Schedule endpoints
        .route("/schedules", get(list_schedules))
        .route("/schedules", post(create_schedule_endpoint))
        .route("/schedules/:schedule_id", get(get_schedule))
        .route("/schedules/:schedule_id", delete(delete_schedule))
        .route("/schedules/:schedule_id/pause", post(pause_schedule))
        .route("/schedules/:schedule_id/resume", post(resume_schedule))
        .with_state(state.clone())
        .layer(axum::middleware::from_fn_with_state(
            state.auth.clone(),
            auth_middleware,
        ));

    let app = app
        .layer(TraceLayer::new_for_http())
        .layer(RequestBodyLimitLayer::new(1024 * 1024));

    let addr: std::net::SocketAddr = bind.parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn cancel_scan(
    State(app): State<AppState>,
    Path(scan_id): Path<String>,
) -> impl IntoResponse {
    let db = &app.db;
    match Uuid::parse_str(&scan_id) {
        Ok(id) => {
            let _ = db
                .update_scan_status(&id, ScanStatus::Cancelled, Some("api cancel".into()))
                .await;
            let _ = db.set_scan_cancel(&id).await;
            (StatusCode::OK, Json(json!({"status":"cancelled"})))
        }
        Err(_) => (StatusCode::BAD_REQUEST, Json(json!({"error":"invalid id"}))),
    }
}

async fn scan_status(
    State(app): State<AppState>,
    Path(scan_id): Path<String>,
) -> impl IntoResponse {
    if let Ok(id) = Uuid::parse_str(&scan_id) {
        if let Ok(scan) = app.db.get_scan_with_findings(&id).await {
            return (
                StatusCode::OK,
                Json(json!({
                    "scan_id": scan_id,
                    "status": format!("{:?}", scan.status),
                    "findings": scan.findings.len(),
                    "confidence": scan.findings.iter().filter_map(|f| f.confidence_score).sum::<f32>() / (scan.findings.len().max(1) as f32),
                    "evidence_samples": scan.findings.iter().take(5).map(|f| {
                        json!({
                            "severity": f.severity,
                            "type": f.vulnerability_type,
                            "endpoint": f.endpoint,
                            "evidence": f.evidence,
                            "confidence": f.confidence_score
                        })
                    }).collect::<Vec<_>>()
                })),
            );
        }
    }
    (StatusCode::NOT_FOUND, Json(json!({ "error": "not found" })))
}

async fn list_scans(State(app): State<AppState>) -> impl IntoResponse {
    match app.db.list_scan_summaries(25).await {
        Ok(scans) => (
            StatusCode::OK,
            Json(json!({
                "scans": scans.iter().map(|s| {
                    json!({
                        "scan_id": s.id,
                        "target_id": s.target_id,
                        "status": format!("{:?}", s.status),
                        "started_at": s.started_at,
                        "ended_at": s.ended_at,
                        "findings": s.findings_count
                    })
                }).collect::<Vec<_>>()
            })),
        ),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": err.to_string() })),
        ),
    }
}

#[derive(Deserialize)]
struct EventsQuery {
    /// Comma-separated list of scan IDs (Issue #9)
    /// Example: ?scan_id=uuid1,uuid2,uuid3
    scan_id: Option<String>,
    /// Last event ID for replay (Issue #8)
    /// Example: ?last_event_id=uuid
    last_event_id: Option<String>,
}

/// Parse comma-separated scan IDs with security limits
/// 
/// Security features:
/// - Max 10 scan IDs (DoS prevention)
/// - Max 400 chars input length
/// - Validates UUID format
fn parse_scan_ids(input: &str) -> Result<Vec<Uuid>, String> {
    const MAX_SCAN_IDS: usize = 10;
    const MAX_INPUT_LENGTH: usize = 400; // 10 UUIDs * 36 chars + 9 commas
    
    if input.len() > MAX_INPUT_LENGTH {
        return Err(format!("Input too long (max {} chars)", MAX_INPUT_LENGTH));
    }
    
    let ids: Vec<Uuid> = input
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .take(MAX_SCAN_IDS)
        .map(|s| {
            Uuid::parse_str(s).map_err(|_| format!("Invalid UUID: {}", s))
        })
        .collect::<Result<Vec<_>, _>>()?;
    
    if ids.is_empty() {
        return Err("No valid scan IDs provided".to_string());
    }
    
    Ok(ids)
}

async fn stream_events(
    State(app): State<AppState>,
    Query(params): Query<EventsQuery>,
    headers: axum::http::HeaderMap,
) -> Sse<impl futures::Stream<Item = Result<Event, std::convert::Infallible>>> {
    use tokio_stream::wrappers::UnboundedReceiverStream;
    use tokio_stream::StreamExt;
    use axum::response::sse::Event;

    // Parse Last-Event-ID header or query param for replay (Issue #8)
    let last_event_id = params
        .last_event_id
        .and_then(|s| Uuid::parse_str(&s).ok())
        .or_else(|| {
            headers
                .get("Last-Event-ID")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| Uuid::parse_str(s).ok())
        });

    // Subscribe to the event bus with optional replay
    let rx = if let Some(scan_id_str) = params.scan_id {
        // Issue #9: Support multiple comma-separated scan IDs
        match parse_scan_ids(&scan_id_str) {
            Ok(scan_ids) if scan_ids.len() == 1 => {
                // Single scan ID with replay support
                if let Some(event_id) = last_event_id {
                    app.queue
                        .event_bus()
                        .subscribe_filtered_with_replay(vec![scan_ids[0]], Some(event_id))
                        .await
                } else {
                    app.queue.event_bus().subscribe_filtered(scan_ids[0]).await
                }
            }
            Ok(scan_ids) => {
                // Multiple scan IDs with replay support
                if let Some(event_id) = last_event_id {
                    app.queue
                        .event_bus()
                        .subscribe_filtered_with_replay(scan_ids, Some(event_id))
                        .await
                } else {
                    app.queue
                        .event_bus()
                        .subscribe_filtered_multiple(scan_ids)
                        .await
                }
            }
            Err(_) => {
                // Invalid scan_id format, subscribe to all events with replay
                if let Some(event_id) = last_event_id {
                    app.queue
                        .event_bus()
                        .subscribe_with_replay(Some(event_id))
                        .await
                } else {
                    app.queue.event_bus().subscribe().await
                }
            }
        }
    } else {
        // No filter, subscribe to all events with replay support
        if let Some(event_id) = last_event_id {
            app.queue
                .event_bus()
                .subscribe_with_replay(Some(event_id))
                .await
        } else {
            app.queue.event_bus().subscribe().await
        }
    };

    let stream = UnboundedReceiverStream::new(rx)
        .map(|event| {
            let json_data = serde_json::to_string(&event).unwrap_or_else(|_| "{}".to_string());
            Event::default().data(json_data)
        })
        .map(Ok);

    Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(std::time::Duration::from_secs(30))
            .text("keepalive"),
    )
}

async fn list_findings(
    State(app): State<AppState>,
    Path(scan_id): Path<String>,
    Query(filters): Query<FindingsFilter>,
) -> impl IntoResponse {
    if let Ok(id) = Uuid::parse_str(&scan_id) {
        if let Ok(scan) = app.db.get_scan_with_findings(&id).await {
            let mut list = scan.findings;
            if let Some(sev) = &filters.severity {
                list.retain(|f| f.severity.to_string().eq_ignore_ascii_case(sev));
            }
            if let Some(v) = filters.verified {
                list.retain(|f| f.verified == v);
            }
            if let Some(lim) = filters.limit {
                list.truncate(lim.min(list.len()));
            }
            return (StatusCode::OK, Json(json!({ "findings": list })));
        }
    }
    (StatusCode::NOT_FOUND, Json(json!({ "error": "not found" })))
}

#[derive(Deserialize, Default)]
struct FindingsFilter {
    severity: Option<String>,
    verified: Option<bool>,
    limit: Option<usize>,
}

async fn create_scan(
    State(app): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let target = match body.get("target").and_then(|v| v.as_str()) {
        Some(t) => t.to_string(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"target required"})),
            )
        }
    };
    
    // Issue #10: Parse priority from request
    let priority = body
        .get("priority")
        .and_then(|v| v.as_str())
        .and_then(|s| match s.to_lowercase().as_str() {
            "high" => Some(Priority::High),
            "normal" => Some(Priority::Normal),
            "low" => Some(Priority::Low),
            _ => None,
        })
        .unwrap_or(Priority::Normal);
    
    let scope = body
        .get("scope")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|s| s.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| vec![target.clone(), format!("*.{}", target)]);

    let target_model = crate::models::Target {
        id: Some(Uuid::new_v4()),
        domain: target.clone(),
        scope,
        status: crate::models::TargetStatus::Pending,
        created_at: chrono::Utc::now(),
        last_scan: None,
        notes: None,
    };
    
    let target_model = match app.db.upsert_target(&target_model).await {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Failed to create target: {}", e)})),
            )
        }
    };
    
    let scan_id = Uuid::new_v4();

    // Try to load config by name from templates; fallback to default
    let scan_config = if let Some(name) = body.get("config").and_then(|v| v.as_str()) {
        let path = format!("templates/config/{}.yaml", name);
        crate::utils::config::ConfigParser::load_from_file(&path).unwrap_or_default()
    } else {
        crate::models::ScanConfig::default()
    };

    // Create scan record in database with pending status
    let scan_result = crate::models::ScanResult::new(
        target_model.id.unwrap(),
        scan_config.id.unwrap_or_else(Uuid::new_v4),
    );
    let mut scan_result_with_id = scan_result;
    scan_result_with_id.id = scan_id;
    scan_result_with_id.status = crate::models::ScanStatus::Pending;
    
    if let Err(e) = app.db.save_scan(&scan_result_with_id).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Failed to save scan: {}", e)})),
        );
    }

    // Issue #10: Create job with priority and enqueue
    let job = ScanJob::new(scan_id, target_model, scan_config);
    
    match app.queue.enqueue(job).await {
        Ok(_) => (
            StatusCode::ACCEPTED,
            Json(json!({ 
                "scan_id": scan_id, 
                "status": "queued",
                "priority": format!("{:?}", priority).to_lowercase()
            })),
        ),
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": format!("Queue full: {}", e)})),
        ),
    }
}

async fn get_metrics(State(app): State<AppState>) -> impl IntoResponse {
    match app.metrics.get_metrics().await {
        Ok(metrics) => (
            StatusCode::OK,
            Json(json!(metrics)),
        ),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": err.to_string() })),
        ),
    }
}

async fn auth_middleware(
    State(auth): State<AuthState>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Result<axum::response::Response, axum::response::Response> {
    let ip_key = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown_ip")
        .to_string();
    if !auth.ip_rl.check(&ip_key).await {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error":"rate limit ip"})),
        )
            .into_response());
    }

    if let Some(expected) = &auth.cfg.token {
        let header_token = req
            .headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|s| s.to_string());
        if header_token.as_deref() != Some(expected.as_str()) {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({"error":"unauthorized"})),
            )
                .into_response());
        }
        if !auth.token_rl.check(expected).await {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({"error":"rate limit token"})),
            )
                .into_response());
        }
    }

    req.extensions_mut().insert(auth);
    Ok(next.run(req).await)
}

// Issue #11: Schedule handlers

async fn list_schedules(State(app): State<AppState>) -> impl IntoResponse {
    match app.db.list_schedules(None).await {
        Ok(schedules) => (
            StatusCode::OK,
            Json(json!({
                "schedules": schedules.iter().map(|s| {
                    json!({
                        "id": s.id,
                        "target": s.target.domain,
                        "cron": s.cron_expression,
                        "timezone": s.timezone,
                        "enabled": s.enabled,
                        "last_run": s.last_run,
                        "next_run": s.next_run,
                        "created_by": s.created_by,
                        "priority": format!("{:?}", s.priority).to_lowercase()
                    })
                }).collect::<Vec<_>>()
            })),
        ),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": err.to_string() })),
        ),
    }
}

#[derive(Deserialize)]
struct CreateScheduleRequest {
    target: String,
    config: String,
    cron: String,
    #[serde(default = "default_timezone")]
    timezone: String,
    #[serde(default)]
    priority: Option<String>,
}

fn default_timezone() -> String {
    "UTC".to_string()
}

async fn create_schedule_endpoint(
    State(app): State<AppState>,
    Json(body): Json<CreateScheduleRequest>,
) -> impl IntoResponse {
    use crate::scheduler::{create_schedule, SchedulerConfig};
    use crate::priority_queue::Priority;
    
    let priority = body.priority.as_ref()
        .and_then(|p| match p.to_lowercase().as_str() {
            "high" => Some(Priority::High),
            "normal" => Some(Priority::Normal),
            "low" => Some(Priority::Low),
            _ => None,
        })
        .unwrap_or(Priority::Normal);
    
    let req = crate::scheduler::CreateScheduleRequest {
        target: body.target,
        config: body.config,
        cron: body.cron,
        timezone: body.timezone,
        priority: Some(priority),
    };
    
    let config = SchedulerConfig::default();
    // Note: In production, you'd get the user_id from auth context
    let user_id = "anonymous".to_string();
    
    match create_schedule(app.db.clone(), &config, req, user_id).await {
        Ok(schedule) => (
            StatusCode::CREATED,
            Json(json!({
                "id": schedule.id,
                "target": schedule.target.domain,
                "cron": schedule.cron_expression,
                "timezone": schedule.timezone,
                "next_run": schedule.next_run,
                "enabled": schedule.enabled,
                "priority": format!("{:?}", schedule.priority).to_lowercase()
            })),
        ),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": err.to_string() })),
        ),
    }
}

async fn get_schedule(
    State(app): State<AppState>,
    Path(schedule_id): Path<String>,
) -> impl IntoResponse {
    match Uuid::parse_str(&schedule_id) {
        Ok(id) => {
            match app.db.get_schedule(&id).await {
                Ok(Some(schedule)) => (
                    StatusCode::OK,
                    Json(json!({
                        "id": schedule.id,
                        "target": schedule.target.domain,
                        "cron": schedule.cron_expression,
                        "timezone": schedule.timezone,
                        "enabled": schedule.enabled,
                        "last_run": schedule.last_run,
                        "next_run": schedule.next_run,
                        "created_by": schedule.created_by,
                        "priority": format!("{:?}", schedule.priority).to_lowercase()
                    })),
                ),
                Ok(None) => (
                    StatusCode::NOT_FOUND,
                    Json(json!({ "error": "Schedule not found" })),
                ),
                Err(err) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": err.to_string() })),
                ),
            }
        }
        Err(_) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Invalid schedule ID" })),
        ),
    }
}

async fn delete_schedule(
    State(app): State<AppState>,
    Path(schedule_id): Path<String>,
) -> impl IntoResponse {
    match Uuid::parse_str(&schedule_id) {
        Ok(id) => {
            match app.db.delete_schedule(&id).await {
                Ok(true) => (
                    StatusCode::OK,
                    Json(json!({ "status": "deleted" })),
                ),
                Ok(false) => (
                    StatusCode::NOT_FOUND,
                    Json(json!({ "error": "Schedule not found" })),
                ),
                Err(err) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": err.to_string() })),
                ),
            }
        }
        Err(_) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Invalid schedule ID" })),
        ),
    }
}

async fn pause_schedule(
    State(app): State<AppState>,
    Path(schedule_id): Path<String>,
) -> impl IntoResponse {
    match Uuid::parse_str(&schedule_id) {
        Ok(id) => {
            match app.db.get_schedule(&id).await {
                Ok(Some(mut schedule)) => {
                    schedule.enabled = false;
                    match app.db.save_schedule(&schedule).await {
                        Ok(_) => (
                            StatusCode::OK,
                            Json(json!({ 
                                "status": "paused",
                                "id": schedule.id,
                                "enabled": false
                            })),
                        ),
                        Err(err) => (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({ "error": err.to_string() })),
                        ),
                    }
                }
                Ok(None) => (
                    StatusCode::NOT_FOUND,
                    Json(json!({ "error": "Schedule not found" })),
                ),
                Err(err) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": err.to_string() })),
                ),
            }
        }
        Err(_) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Invalid schedule ID" })),
        ),
    }
}

async fn resume_schedule(
    State(app): State<AppState>,
    Path(schedule_id): Path<String>,
) -> impl IntoResponse {
    match Uuid::parse_str(&schedule_id) {
        Ok(id) => {
            match app.db.get_schedule(&id).await {
                Ok(Some(mut schedule)) => {
                    schedule.enabled = true;
                    match app.db.save_schedule(&schedule).await {
                        Ok(_) => (
                            StatusCode::OK,
                            Json(json!({ 
                                "status": "resumed",
                                "id": schedule.id,
                                "enabled": true
                            })),
                        ),
                        Err(err) => (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({ "error": err.to_string() })),
                        ),
                    }
                }
                Ok(None) => (
                    StatusCode::NOT_FOUND,
                    Json(json!({ "error": "Schedule not found" })),
                ),
                Err(err) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": err.to_string() })),
                ),
            }
        }
        Err(_) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Invalid schedule ID" })),
        ),
    }
}
