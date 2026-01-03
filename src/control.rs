use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::{Path, Query, State},
    http::{Request, StatusCode},
    middleware::Next,
    response::sse::{Event, Sse},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::{database::Database, models::ScanStatus};

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
    };

    let app = Router::new()
        .route("/cancel/:scan_id", post(cancel_scan))
        .route("/status/:scan_id", get(scan_status))
        .route("/scans", get(list_scans))
        .route("/scans/:scan_id/findings", get(list_findings))
        .route("/scans", post(create_scan))
        .route("/events", get(stream_events))
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

async fn stream_events(
    State(app): State<AppState>,
) -> Sse<impl futures::Stream<Item = Result<Event, std::convert::Infallible>>> {
    use tokio_stream::{wrappers::IntervalStream, StreamExt};
    let stream = IntervalStream::new(tokio::time::interval(std::time::Duration::from_secs(2)))
        .then(move |_| {
            let db = app.db.clone();
            async move {
                let scans = db.list_scan_summaries(10).await.unwrap_or_default();
                let payload = json!({
                    "type": "scan_status",
                    "scans": scans.iter().map(|s| {
                        json!({
                            "scan_id": s.id,
                            "status": format!("{:?}", s.status),
                            "started_at": s.started_at,
                            "ended_at": s.ended_at,
                            "findings": s.findings_count
                        })
                    }).collect::<Vec<_>>()
                });
                Event::default().data(payload.to_string())
            }
        })
        .map(Ok);
    Sse::new(stream)
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
    let scope = body
        .get("scope")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|s| s.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| vec![target.clone(), format!("*.{}", target)]);
    let _config = body
        .get("config")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "default-scan".to_string());

    let target_model = crate::models::Target {
        id: Some(Uuid::new_v4()),
        domain: target.clone(),
        scope,
        status: crate::models::TargetStatus::Pending,
        created_at: chrono::Utc::now(),
        last_scan: None,
        notes: None,
    };
    let target_model = app.db.upsert_target(&target_model).await.unwrap();
    let scan_id = Uuid::new_v4();

    // Try to load config by name from templates; fallback to default
    let scan_config = if let Some(name) = body.get("config").and_then(|v| v.as_str()) {
        let path = format!("templates/config/{}.yaml", name);
        crate::utils::config::ConfigParser::load_from_file(&path).unwrap_or_default()
    } else {
        crate::models::ScanConfig::default()
    };

    let db_for_run = (*app.db).clone();
    let target_for_run = target_model.clone();
    tokio::spawn(async move {
        let orchestrator = crate::orchestrator::BugHunterOrchestrator::with_scan_id(
            scan_config,
            target_for_run,
            db_for_run,
            scan_id,
        );
        let _ = orchestrator.run_full_scan().await;
    });

    (
        StatusCode::ACCEPTED,
        Json(json!({ "scan_id": scan_id, "status": "queued" })),
    )
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
