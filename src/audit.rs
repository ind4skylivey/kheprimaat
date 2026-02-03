//! Comprehensive audit logging system
//! 
//! Tracks all security-relevant events:
//! - Authentication events (login, logout, failed attempts)
//! - Authorization events (permission denied, access granted)
//! - Data changes (create, update, delete)
//! - System events (schedule execution, errors)

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::rbac::AuthContext;

/// Audit event severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Audit event categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditCategory {
    Authentication,
    Authorization,
    DataAccess,
    DataModification,
    System,
    Security,
    Schedule,
}

/// Audit event types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    // Authentication
    LoginSuccess,
    LoginFailed,
    Logout,
    TokenRefreshed,
    TokenRevoked,
    MfaEnabled,
    MfaDisabled,
    
    // Authorization
    PermissionDenied,
    AccessGranted,
    RoleChanged,
    
    // Data Access
    ResourceAccessed,
    ResourceListAccessed,
    ExportRequested,
    
    // Data Modification
    ResourceCreated,
    ResourceUpdated,
    ResourceDeleted,
    
    // Schedule
    ScheduleCreated,
    ScheduleModified,
    ScheduleDeleted,
    ScheduleExecuted,
    ScheduleFailed,
    SchedulePaused,
    ScheduleResumed,
    ScheduleQuotaExceeded,
    
    // System
    SystemStartup,
    SystemShutdown,
    ConfigurationChanged,
    ErrorOccurred,
    
    // Security
    SuspiciousActivity,
    RateLimitExceeded,
    IpBlocked,
    InvalidTargetBlocked,
}

/// Complete audit event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub category: AuditCategory,
    pub event_type: AuditEventType,
    pub severity: AuditSeverity,
    
    // Actor information
    pub user_id: Option<String>,
    pub username: Option<String>,
    pub roles: Vec<String>,
    pub client_ip: String,
    pub request_id: String,
    
    // Resource information
    pub resource_type: String,
    pub resource_id: Option<String>,
    
    // Event details
    pub message: String,
    pub details: HashMap<String, Value>,
    
    // Before/After for modifications
    pub previous_state: Option<Value>,
    pub new_state: Option<Value>,
    
    // Result
    pub success: bool,
    pub error_message: Option<String>,
}

impl AuditEvent {
    /// Create new audit event builder
    pub fn builder() -> AuditEventBuilder {
        AuditEventBuilder::default()
    }
}

/// Builder for audit events
#[derive(Default)]
pub struct AuditEventBuilder {
    category: Option<AuditCategory>,
    event_type: Option<AuditEventType>,
    severity: Option<AuditSeverity>,
    auth_context: Option<AuthContext>,
    resource_type: String,
    resource_id: Option<String>,
    message: String,
    details: HashMap<String, Value>,
    previous_state: Option<Value>,
    new_state: Option<Value>,
    success: bool,
    error_message: Option<String>,
}

impl AuditEventBuilder {
    pub fn category(mut self, category: AuditCategory) -> Self {
        self.category = Some(category);
        self
    }
    
    pub fn event_type(mut self, event_type: AuditEventType) -> Self {
        self.event_type = Some(event_type);
        self
    }
    
    pub fn severity(mut self, severity: AuditSeverity) -> Self {
        self.severity = Some(severity);
        self
    }
    
    pub fn auth_context(mut self, auth: &AuthContext) -> Self {
        self.auth_context = Some(auth.clone());
        self
    }
    
    pub fn resource_type(mut self, resource_type: &str) -> Self {
        self.resource_type = resource_type.to_string();
        self
    }
    
    pub fn resource_id(mut self, resource_id: String) -> Self {
        self.resource_id = Some(resource_id);
        self
    }
    
    pub fn message(mut self, message: String) -> Self {
        self.message = message;
        self
    }
    
    pub fn detail(mut self, key: &str, value: Value) -> Self {
        self.details.insert(key.to_string(), value);
        self
    }
    
    pub fn previous_state(mut self, state: Value) -> Self {
        self.previous_state = Some(state);
        self
    }
    
    pub fn new_state(mut self, state: Value) -> Self {
        self.new_state = Some(state);
        self
    }
    
    pub fn success(mut self) -> Self {
        self.success = true;
        self
    }
    
    pub fn failure(mut self, error: &str) -> Self {
        self.success = false;
        self.error_message = Some(error.to_string());
        self
    }
    
    pub fn build(self) -> AuditEvent {
        let auth = self.auth_context.as_ref();
        
        AuditEvent {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            category: self.category.unwrap_or(AuditCategory::System),
            event_type: self.event_type.unwrap_or(AuditEventType::ErrorOccurred),
            severity: self.severity.unwrap_or(AuditSeverity::Info),
            user_id: auth.map(|a| a.user.id.clone()),
            username: auth.map(|a| a.user.username.clone()),
            roles: auth.map(|a| {
                a.user.roles.iter()
                    .map(|r| format!("{:?}", r).to_lowercase())
                    .collect()
            }).unwrap_or_default(),
            client_ip: auth.map(|a| a.client_ip.clone()).unwrap_or_default(),
            request_id: auth.map(|a| a.request_id.clone()).unwrap_or_else(|| Uuid::new_v4().to_string()),
            resource_type: self.resource_type,
            resource_id: self.resource_id,
            message: self.message,
            details: self.details,
            previous_state: self.previous_state,
            new_state: self.new_state,
            success: self.success,
            error_message: self.error_message,
        }
    }
}

/// Audit logger
pub struct AuditLogger {
    sender: mpsc::UnboundedSender<AuditEvent>,
}

impl AuditLogger {
    /// Create new audit logger with async backend
    pub fn new() -> (Self, AuditBackend) {
        let (sender, receiver) = mpsc::unbounded_channel();
        let backend = AuditBackend::new(receiver);
        
        (Self { sender }, backend)
    }
    
    /// Log an audit event
    pub fn log(&self,
        event: AuditEvent,
    ) {
        if let Err(e) = self.sender.send(event) {
            error!("Failed to send audit event: {}", e);
        }
    }
    
    /// Convenience: Log schedule creation
    pub fn log_schedule_created(
        &self,
        auth: &AuthContext,
        schedule_id: &str,
        target: &str,
        cron: &str,
    ) {
        let event = AuditEvent::builder()
            .category(AuditCategory::Schedule)
            .event_type(AuditEventType::ScheduleCreated)
            .severity(AuditSeverity::Info)
            .auth_context(auth)
            .resource_type("schedule")
            .resource_id(schedule_id.to_string())
            .message("Schedule created".to_string())
            .detail("target", target.into())
            .detail("cron_expression", cron.into())
            .success()
            .build();
        
        self.log(event);
    }
    
    /// Convenience: Log permission denied
    pub fn log_permission_denied(
        &self,
        auth: &AuthContext,
        permission: &str,
        resource: &str,
    ) {
        let event = AuditEvent::builder()
            .category(AuditCategory::Authorization)
            .event_type(AuditEventType::PermissionDenied)
            .severity(AuditSeverity::Warning)
            .auth_context(auth)
            .resource_type(resource)
            .message(format!("Permission denied: {}", permission))
            .detail("requested_permission", permission.into())
            .failure("Insufficient permissions")
            .build();
        
        self.log(event);
        
        // Also log to tracing for immediate visibility
        warn!(
            "Permission denied for user {} on {}: {}",
            auth.user.username, resource, permission
        );
    }
    
    /// Convenience: Log invalid target attempt (SSRF prevention)
    pub fn log_invalid_target(
        &self,
        auth: &AuthContext,
        target: &str,
        reason: &str,
    ) {
        let event = AuditEvent::builder()
            .category(AuditCategory::Security)
            .event_type(AuditEventType::InvalidTargetBlocked)
            .severity(AuditSeverity::Warning)
            .auth_context(auth)
            .resource_type("target")
            .message("Invalid target blocked".to_string())
            .detail("target", target.into())
            .detail("reason", reason.into())
            .failure(reason)
            .build();
        
        self.log(event);
        
        warn!(
            "Blocked invalid target '{}' for user {}: {}",
            target, auth.user.username, reason
        );
    }
    
    /// Convenience: Log schedule quota exceeded
    pub fn log_quota_exceeded(
        &self,
        auth: &AuthContext,
        quota_type: &str,
        limit: usize,
    ) {
        let event = AuditEvent::builder()
            .category(AuditCategory::Schedule)
            .event_type(AuditEventType::ScheduleQuotaExceeded)
            .severity(AuditSeverity::Warning)
            .auth_context(auth)
            .resource_type("quota")
            .message(format!("{} quota exceeded", quota_type))
            .detail("quota_type", quota_type.into())
            .detail("limit", limit.into())
            .failure("Quota exceeded")
            .build();
        
        self.log(event);
    }
}

impl Clone for AuditLogger {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

/// Backend for processing audit events
pub struct AuditBackend {
    receiver: mpsc::UnboundedReceiver<AuditEvent>,
}

impl AuditBackend {
    fn new(receiver: mpsc::UnboundedReceiver<AuditEvent>) -> Self {
        Self { receiver }
    }
    
    /// Run the backend (spawn this in a task)
    pub async fn run(mut self) {
        info!("Audit backend started");
        
        while let Some(event) = self.receiver.recv().await {
            // Store to database
            if let Err(e) = self.store_event(&event).await {
                error!("Failed to store audit event: {}", e);
            }
            
            // Log critical events immediately
            if matches!(event.severity, AuditSeverity::Critical) {
                self.alert_critical(&event).await;
            }
        }
        
        info!("Audit backend stopped");
    }
    
    async fn store_event(
        &self,
        event: &AuditEvent,
    ) -> Result<(), anyhow::Error> {
        // Serialize to JSON
        let json = serde_json::to_string(event)?;
        
        // Store to file/database
        // In production, this would write to:
        // - Immutable audit log (append-only)
        // - SIEM system
        // - Security monitoring
        
        info!(
            target: "audit",
            "[{}] {:?}: {:?} - {}",
            event.timestamp.to_rfc3339(),
            event.event_type,
            event.category,
            event.message
        );
        
        // Also write to separate audit file
        self.write_to_audit_file(&json).await?;
        
        Ok(())
    }
    
    async fn write_to_audit_file(
        &self,
        json: &str,
    ) -> Result<(), anyhow::Error> {
        use tokio::io::AsyncWriteExt;
        
        let date = Utc::now().format("%Y-%m-%d");
        let filename = format!("data/audit/audit-{}.log", date);
        
        // Ensure directory exists
        tokio::fs::create_dir_all("data/audit").await?;
        
        // Append to file
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&filename)
            .await?;
        
        file.write_all(json.as_bytes()).await?;
        file.write_all(b"\n").await?;
        file.flush().await?;
        
        Ok(())
    }
    
    async fn alert_critical(&self,
        event: &AuditEvent,
    ) {
        // Send alert for critical events
        // This could:
        // - Send email to security team
        // - Trigger PagerDuty
        // - Send Slack notification
        
        error!(
            target: "security_alert",
            "🚨 CRITICAL SECURITY EVENT: {:?} - {}",
            event.event_type,
            event.message
        );
    }
}

/// Middleware for automatic audit logging
pub struct AuditMiddleware {
    logger: AuditLogger,
}

impl AuditMiddleware {
    pub fn new(logger: AuditLogger) -> Self {
        Self { logger }
    }
    
    /// Log API request
    pub fn log_request(
        &self,
        auth: &AuthContext,
        method: &str,
        path: &str,
        status_code: u16,
    ) {
        let event = AuditEvent::builder()
            .category(AuditCategory::DataAccess)
            .event_type(AuditEventType::ResourceAccessed)
            .severity(if status_code >= 400 {
                AuditSeverity::Warning
            } else {
                AuditSeverity::Info
            })
            .auth_context(auth)
            .resource_type("api")
            .message(format!("{} {}", method, path))
            .detail("method", method.into())
            .detail("path", path.into())
            .detail("status_code", (status_code as i64).into())
            .success()
            .build();
        
        self.logger.log(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rbac::{Role, User};

    fn create_test_auth() -> AuthContext {
        let user = User::new(
            "user123".to_string(),
            "testuser".to_string(),
            "test@example.com".to_string(),
        );
        let claims = crate::rbac::Claims::new(&user, 24);
        AuthContext::new(user, claims, "127.0.0.1".to_string())
    }

    #[tokio::test]
    async fn test_audit_event_builder() {
        let auth = create_test_auth();
        
        let event = AuditEvent::builder()
            .category(AuditCategory::Schedule)
            .event_type(AuditEventType::ScheduleCreated)
            .severity(AuditSeverity::Info)
            .auth_context(&auth)
            .resource_type("schedule")
            .resource_id("sched-123".to_string())
            .message("Test schedule created".to_string())
            .detail("target", "example.com".into())
            .success()
            .build();
        
        assert_eq!(event.user_id, Some("user123".to_string()));
        assert_eq!(event.resource_type, "schedule");
        assert!(event.success);
    }

    #[tokio::test]
    async fn test_audit_logger() {
        let (logger, backend) = AuditLogger::new();
        
        // Spawn backend
        tokio::spawn(async move {
            backend.run().await;
        });
        
        let auth = create_test_auth();
        
        // Log event
        logger.log_schedule_created(
            &auth,
            "sched-123",
            "example.com",
            "0 2 * * *",
        );
        
        // Give time to process
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    #[test]
    fn test_permission_denied_logging() {
        let (logger, _backend) = AuditLogger::new();
        let auth = create_test_auth();
        
        logger.log_permission_denied(
            &auth,
            "create_schedule",
            "schedule",
        );
        
        // Should not panic
    }
}
