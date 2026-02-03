//! Role-Based Access Control (RBAC) and enhanced authentication
//!
//! Provides:
//! - JWT-based authentication
//! - Role-based authorization (Admin, Operator, Viewer)
//! - Permission-based access control
//! - Session management

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// User roles in the system
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Full system access
    Admin,
    /// Can create/modify scans and schedules, view all data
    Operator,
    /// Read-only access
    Viewer,
}

impl Role {
    /// Check if role has a specific permission
    pub fn has_permission(&self, permission: Permission) -> bool {
        match (self, permission) {
            // Admin can do everything
            (Role::Admin, _) => true,

            // Operator permissions
            (Role::Operator, Permission::CreateScan) => true,
            (Role::Operator, Permission::DeleteOwnScan) => true,
            (Role::Operator, Permission::ViewScan) => true,
            (Role::Operator, Permission::CreateSchedule) => true,
            (Role::Operator, Permission::DeleteOwnSchedule) => true,
            (Role::Operator, Permission::PauseResumeSchedule) => true,
            (Role::Operator, Permission::ViewSchedule) => true,
            (Role::Operator, Permission::ViewFindings) => true,
            (Role::Operator, Permission::ExportReport) => true,
            (Role::Operator, _) => false,

            // Viewer permissions (read-only)
            (Role::Viewer, Permission::ViewScan) => true,
            (Role::Viewer, Permission::ViewSchedule) => true,
            (Role::Viewer, Permission::ViewFindings) => true,
            (Role::Viewer, Permission::ExportReport) => true,
            (Role::Viewer, _) => false,
        }
    }

    /// Get all permissions for this role
    pub fn permissions(&self) -> Vec<Permission> {
        match self {
            Role::Admin => vec![
                Permission::CreateScan,
                Permission::DeleteOwnScan,
                Permission::DeleteAnyScan,
                Permission::ViewScan,
                Permission::CreateSchedule,
                Permission::DeleteOwnSchedule,
                Permission::DeleteAnySchedule,
                Permission::PauseResumeSchedule,
                Permission::ViewSchedule,
                Permission::ViewFindings,
                Permission::ExportReport,
                Permission::ManageUsers,
                Permission::ManageSystem,
                Permission::ViewAuditLogs,
            ],
            Role::Operator => vec![
                Permission::CreateScan,
                Permission::DeleteOwnScan,
                Permission::ViewScan,
                Permission::CreateSchedule,
                Permission::DeleteOwnSchedule,
                Permission::PauseResumeSchedule,
                Permission::ViewSchedule,
                Permission::ViewFindings,
                Permission::ExportReport,
            ],
            Role::Viewer => vec![
                Permission::ViewScan,
                Permission::ViewSchedule,
                Permission::ViewFindings,
                Permission::ExportReport,
            ],
        }
    }
}

/// Permissions in the system
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Permission {
    // Scan permissions
    CreateScan,
    DeleteOwnScan,
    DeleteAnyScan,
    ViewScan,

    // Schedule permissions
    CreateSchedule,
    DeleteOwnSchedule,
    DeleteAnySchedule,
    PauseResumeSchedule,
    ViewSchedule,

    // Finding permissions
    ViewFindings,
    VerifyFinding,
    ExportReport,

    // Administrative permissions
    ManageUsers,
    ManageSystem,
    ViewAuditLogs,
}

/// User information with roles
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    pub roles: HashSet<Role>,
    pub created_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub enabled: bool,
    pub mfa_enabled: bool,
}

impl User {
    pub fn new(id: String, username: String, email: String) -> Self {
        let mut roles = HashSet::new();
        roles.insert(Role::Viewer); // Default role

        Self {
            id,
            username,
            email,
            roles,
            created_at: Utc::now(),
            last_login: None,
            enabled: true,
            mfa_enabled: false,
        }
    }

    /// Check if user has a specific role
    pub fn has_role(&self, role: Role) -> bool {
        self.roles.contains(&role)
    }

    /// Check if user has a specific permission (through any role)
    pub fn has_permission(&self, permission: Permission) -> bool {
        if !self.enabled {
            return false;
        }

        self.roles
            .iter()
            .any(|role| role.has_permission(permission))
    }

    /// Add role to user
    pub fn add_role(&mut self, role: Role) {
        self.roles.insert(role);
    }

    /// Remove role from user
    pub fn remove_role(&mut self, role: Role) {
        self.roles.remove(&role);
    }

    /// Get highest role (for UI display)
    pub fn primary_role(&self) -> Role {
        if self.has_role(Role::Admin) {
            Role::Admin
        } else if self.has_role(Role::Operator) {
            Role::Operator
        } else {
            Role::Viewer
        }
    }
}

/// JWT Claims structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,        // User ID
    pub username: String,   // Username
    pub roles: Vec<String>, // Role names
    pub iat: u64,           // Issued at
    pub exp: u64,           // Expiration
    pub jti: String,        // JWT ID (for revocation)
}

impl Claims {
    /// Create new claims for a user
    pub fn new(user: &User, ttl_hours: u64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            sub: user.id.clone(),
            username: user.username.clone(),
            roles: user
                .roles
                .iter()
                .map(|r| format!("{:?}", r).to_lowercase())
                .collect(),
            iat: now,
            exp: now + (ttl_hours * 3600),
            jti: Uuid::new_v4().to_string(),
        }
    }

    /// Check if token is expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.exp <= now
    }

    /// Get remaining time in seconds
    pub fn remaining_seconds(&self) -> i64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        self.exp as i64 - now
    }
}

/// Authentication context for requests
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub user: User,
    pub claims: Claims,
    pub client_ip: String,
    pub request_id: String,
}

impl AuthContext {
    pub fn new(user: User, claims: Claims, client_ip: String) -> Self {
        Self {
            user,
            claims,
            client_ip,
            request_id: Uuid::new_v4().to_string(),
        }
    }

    /// Check if authenticated user can access a resource
    pub fn can_access_scan(&self, scan_owner_id: &str) -> bool {
        // Admin can access any scan
        if self.user.has_role(Role::Admin) {
            return true;
        }

        // Users can access their own scans
        if self.user.id == scan_owner_id {
            return true;
        }

        // Viewer/Operator can view but not modify others' scans
        false
    }

    /// Check if can modify scan
    pub fn can_modify_scan(&self, scan_owner_id: &str) -> bool {
        // Admin can modify any scan
        if self.user.has_role(Role::Admin) {
            return true;
        }

        // Users can modify their own scans
        self.user.id == scan_owner_id
    }

    /// Check if can access schedule
    pub fn can_access_schedule(&self, schedule_owner_id: &str) -> bool {
        self.can_access_scan(schedule_owner_id) // Same logic
    }

    /// Check if can modify schedule
    pub fn can_modify_schedule(&self, schedule_owner_id: &str) -> bool {
        self.can_modify_scan(schedule_owner_id) // Same logic
    }
}

/// RBAC enforcement helper
pub struct RbacEnforcer;

impl RbacEnforcer {
    /// Enforce permission check
    pub fn enforce(auth: &AuthContext, permission: Permission) -> Result<(), RbacError> {
        if !auth.user.has_permission(permission) {
            return Err(RbacError::PermissionDenied {
                user: auth.user.username.clone(),
                permission: format!("{:?}", permission),
            });
        }
        Ok(())
    }

    /// Enforce ownership or admin
    pub fn enforce_owner_or_admin(
        auth: &AuthContext,
        owner_id: &str,
        resource_type: &str,
    ) -> Result<(), RbacError> {
        if auth.user.has_role(Role::Admin) || auth.user.id == owner_id {
            Ok(())
        } else {
            Err(RbacError::OwnershipRequired {
                resource: resource_type.to_string(),
            })
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RbacError {
    #[error("Permission denied: user '{user}' lacks permission '{permission}'")]
    PermissionDenied { user: String, permission: String },

    #[error("Ownership required for resource: {resource}")]
    OwnershipRequired { resource: String },

    #[error("User account is disabled")]
    AccountDisabled,

    #[error("Token expired")]
    TokenExpired,

    #[error("Token revoked")]
    TokenRevoked,
}

/// API Keys for service-to-service authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: String,
    pub name: String,
    pub key_hash: String, // Store only hash, never plaintext
    pub scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used: Option<DateTime<Utc>>,
    pub enabled: bool,
}

impl ApiKey {
    /// Generate new API key
    pub fn generate(name: String, scopes: Vec<String>) -> (Self, String) {
        let key = format!("km_{}", Uuid::new_v4().to_string().replace("-", ""));
        let key_hash = sha256::digest(&key);

        let api_key = Self {
            id: Uuid::new_v4().to_string(),
            name,
            key_hash,
            scopes,
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + chrono::Duration::days(365)),
            last_used: None,
            enabled: true,
        };

        (api_key, key) // Return both the stored object and the plaintext key
    }

    /// Verify a provided key
    pub fn verify(&self, provided_key: &str) -> bool {
        if !self.enabled {
            return false;
        }

        // Check expiration
        if let Some(exp) = self.expires_at {
            if Utc::now() > exp {
                return false;
            }
        }

        let provided_hash = sha256::digest(provided_key);
        self.key_hash == provided_hash
    }
}

// Simple SHA256 implementation for API key hashing
mod sha256 {
    pub fn digest(input: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        // Note: In production, use a proper cryptographic hash like SHA256
        // This is a placeholder - use ring::digest or similar in production
        let mut hasher = DefaultHasher::new();
        input.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_user() -> User {
        let mut user = User::new(
            "user123".to_string(),
            "testuser".to_string(),
            "test@example.com".to_string(),
        );
        user.add_role(Role::Operator);
        user
    }

    #[test]
    fn test_role_permissions() {
        assert!(Role::Admin.has_permission(Permission::ManageUsers));
        assert!(!Role::Operator.has_permission(Permission::ManageUsers));
        assert!(!Role::Viewer.has_permission(Permission::CreateScan));
    }

    #[test]
    fn test_user_permissions() {
        let user = create_test_user();

        assert!(user.has_permission(Permission::CreateScan));
        assert!(user.has_permission(Permission::ViewScan));
        assert!(!user.has_permission(Permission::ManageUsers));
    }

    #[test]
    fn test_disabled_user() {
        let mut user = create_test_user();
        user.enabled = false;

        assert!(!user.has_permission(Permission::ViewScan));
    }

    #[test]
    fn test_auth_context_access_control() {
        let user = create_test_user();
        let claims = Claims::new(&user, 24);
        let auth = AuthContext::new(user, claims, "127.0.0.1".to_string());

        // Can access own scans
        assert!(auth.can_access_scan("user123"));
        assert!(auth.can_modify_scan("user123"));

        // Cannot access others' scans
        assert!(!auth.can_access_scan("other_user"));
        assert!(!auth.can_modify_scan("other_user"));
    }

    #[test]
    fn test_admin_access_control() {
        let mut user = create_test_user();
        user.add_role(Role::Admin);

        let claims = Claims::new(&user, 24);
        let auth = AuthContext::new(user, claims, "127.0.0.1".to_string());

        // Admin can access any scan
        assert!(auth.can_access_scan("any_user"));
        assert!(auth.can_modify_scan("any_user"));
    }

    #[test]
    fn test_claims_expiration() {
        let user = create_test_user();

        // Create expired token
        let mut claims = Claims::new(&user, 0); // 0 hours TTL
        claims.exp = claims.iat - 1; // Set expiration in the past

        assert!(claims.is_expired());
        assert!(claims.remaining_seconds() < 0);
    }

    #[test]
    fn test_api_key_generation() {
        let (api_key, plaintext) = ApiKey::generate(
            "Test Key".to_string(),
            vec!["read".to_string(), "write".to_string()],
        );

        assert!(api_key.verify(&plaintext));
        assert!(!api_key.verify("wrong_key"));
    }

    #[test]
    fn test_enforce_permission() {
        let user = create_test_user();
        let claims = Claims::new(&user, 24);
        let auth = AuthContext::new(user, claims, "127.0.0.1".to_string());

        // Should succeed
        assert!(RbacEnforcer::enforce(&auth, Permission::CreateScan).is_ok());

        // Should fail
        assert!(RbacEnforcer::enforce(&auth, Permission::ManageUsers).is_err());
    }
}
