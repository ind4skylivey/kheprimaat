use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Secret redaction engine for sanitizing sensitive data in findings and reports
#[derive(Clone)]
pub struct SecretRedactor {
    patterns: Arc<Vec<RedactionPattern>>,
}

/// Individual redaction pattern with regex and replacement text
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionPattern {
    pub name: String,
    pub description: String,
    #[serde(with = "serde_regex")]
    pub regex: Regex,
    pub replacement: String,
    pub enabled: bool,
}

impl SecretRedactor {
    /// Create a new redactor with default patterns
    pub fn new() -> Self {
        Self {
            patterns: Arc::new(Self::default_patterns()),
        }
    }

    /// Create a redactor with custom patterns
    pub fn with_patterns(patterns: Vec<RedactionPattern>) -> Self {
        Self {
            patterns: Arc::new(patterns),
        }
    }

    /// Redact secrets from text using all enabled patterns
    pub fn redact(&self, text: &str) -> String {
        let mut result = text.to_string();
        
        for pattern in self.patterns.iter() {
            if pattern.enabled {
                result = pattern.regex.replace_all(&result, &pattern.replacement).to_string();
            }
        }
        
        result
    }

    /// Redact secrets from optional text
    pub fn redact_option(&self, text: Option<&str>) -> Option<String> {
        text.map(|t| self.redact(t))
    }

    /// Check if text contains any secrets (without redacting)
    pub fn contains_secrets(&self, text: &str) -> bool {
        self.patterns.iter()
            .filter(|p| p.enabled)
            .any(|p| p.regex.is_match(text))
    }

    /// Get default redaction patterns covering common secret types
    fn default_patterns() -> Vec<RedactionPattern> {
        vec![
            // AWS Credentials
            RedactionPattern {
                name: "aws_access_key_id".to_string(),
                description: "AWS Access Key ID".to_string(),
                regex: Regex::new(r"(?i)(AKIA[0-9A-Z]{16})").unwrap(),
                replacement: "***REDACTED-AWS-ACCESS-KEY***".to_string(),
                enabled: true,
            },
            RedactionPattern {
                name: "aws_secret_access_key".to_string(),
                description: "AWS Secret Access Key".to_string(),
                regex: Regex::new(r#"(?i)(aws_secret_access_key|secret_key)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"#).unwrap(),
                replacement: r#"$1: "***REDACTED-AWS-SECRET***""#.to_string(),
                enabled: true,
            },
            RedactionPattern {
                name: "aws_session_token".to_string(),
                description: "AWS Session Token".to_string(),
                regex: Regex::new(r#"(?i)(aws_session_token)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{100,})['"]?"#).unwrap(),
                replacement: r#"$1: "***REDACTED-AWS-SESSION-TOKEN***""#.to_string(),
                enabled: true,
            },

            // GitHub Tokens
            RedactionPattern {
                name: "github_pat".to_string(),
                description: "GitHub Personal Access Token".to_string(),
                regex: Regex::new(r"ghp_[a-zA-Z0-9]{36}").unwrap(),
                replacement: "***REDACTED-GITHUB-PAT***".to_string(),
                enabled: true,
            },
            RedactionPattern {
                name: "github_oauth".to_string(),
                description: "GitHub OAuth Token".to_string(),
                regex: Regex::new(r"gho_[a-zA-Z0-9]{36}").unwrap(),
                replacement: "***REDACTED-GITHUB-OAUTH***".to_string(),
                enabled: true,
            },
            RedactionPattern {
                name: "github_app_token".to_string(),
                description: "GitHub App Token".to_string(),
                regex: Regex::new(r"(ghu|ghs)_[a-zA-Z0-9]{36}").unwrap(),
                replacement: "***REDACTED-GITHUB-APP-TOKEN***".to_string(),
                enabled: true,
            },
            RedactionPattern {
                name: "github_refresh_token".to_string(),
                description: "GitHub Refresh Token".to_string(),
                regex: Regex::new(r"ghr_[a-zA-Z0-9]{36}").unwrap(),
                replacement: "***REDACTED-GITHUB-REFRESH-TOKEN***".to_string(),
                enabled: true,
            },

            // Generic API Keys
            RedactionPattern {
                name: "generic_api_key".to_string(),
                description: "Generic API Key patterns".to_string(),
                regex: Regex::new(r#"(?i)(api[_-]?key|apikey|api[_-]?token)\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{20,})['"]?"#).unwrap(),
                replacement: r#"$1: "***REDACTED-API-KEY***""#.to_string(),
                enabled: true,
            },

            // Bearer Tokens
            RedactionPattern {
                name: "bearer_token".to_string(),
                description: "Bearer tokens in Authorization headers".to_string(),
                regex: Regex::new(r"(?i)Bearer\s+([a-zA-Z0-9\-._~+/]+=*)").unwrap(),
                replacement: "Bearer ***REDACTED-BEARER-TOKEN***".to_string(),
                enabled: true,
            },

            // Basic Auth
            RedactionPattern {
                name: "basic_auth".to_string(),
                description: "Basic authentication credentials".to_string(),
                regex: Regex::new(r"(?i)Basic\s+([A-Za-z0-9+/=]+)").unwrap(),
                replacement: "Basic ***REDACTED-BASIC-AUTH***".to_string(),
                enabled: true,
            },

            // JWT Tokens
            RedactionPattern {
                name: "jwt_token".to_string(),
                description: "JSON Web Tokens".to_string(),
                regex: Regex::new(r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*").unwrap(),
                replacement: "***REDACTED-JWT-TOKEN***".to_string(),
                enabled: true,
            },

            // Private Keys (PEM format)
            RedactionPattern {
                name: "private_key_rsa".to_string(),
                description: "RSA Private Keys".to_string(),
                regex: Regex::new(r"-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----").unwrap(),
                replacement: "-----BEGIN RSA PRIVATE KEY-----\n***REDACTED***\n-----END RSA PRIVATE KEY-----".to_string(),
                enabled: true,
            },
            RedactionPattern {
                name: "private_key_generic".to_string(),
                description: "Generic Private Keys".to_string(),
                regex: Regex::new(r"-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----").unwrap(),
                replacement: "-----BEGIN PRIVATE KEY-----\n***REDACTED***\n-----END PRIVATE KEY-----".to_string(),
                enabled: true,
            },
            RedactionPattern {
                name: "private_key_ec".to_string(),
                description: "EC Private Keys".to_string(),
                regex: Regex::new(r"-----BEGIN EC PRIVATE KEY-----[\s\S]*?-----END EC PRIVATE KEY-----").unwrap(),
                replacement: "-----BEGIN EC PRIVATE KEY-----\n***REDACTED***\n-----END EC PRIVATE KEY-----".to_string(),
                enabled: true,
            },
            RedactionPattern {
                name: "private_key_openssh".to_string(),
                description: "OpenSSH Private Keys".to_string(),
                regex: Regex::new(r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----").unwrap(),
                replacement: "-----BEGIN OPENSSH PRIVATE KEY-----\n***REDACTED***\n-----END OPENSSH PRIVATE KEY-----".to_string(),
                enabled: true,
            },

            // Database Connection Strings
            RedactionPattern {
                name: "database_url_postgres".to_string(),
                description: "PostgreSQL connection strings".to_string(),
                regex: Regex::new(r"postgres(?:ql)?://([^:]+):([^@]+)@").unwrap(),
                replacement: "postgres://$1:***REDACTED-PASSWORD***@".to_string(),
                enabled: true,
            },
            RedactionPattern {
                name: "database_url_mysql".to_string(),
                description: "MySQL connection strings".to_string(),
                regex: Regex::new(r"mysql://([^:]+):([^@]+)@").unwrap(),
                replacement: "mysql://$1:***REDACTED-PASSWORD***@".to_string(),
                enabled: true,
            },
            RedactionPattern {
                name: "database_url_mongodb".to_string(),
                description: "MongoDB connection strings".to_string(),
                regex: Regex::new(r"mongodb(?:\+srv)?://([^:]+):([^@]+)@").unwrap(),
                replacement: "mongodb://$1:***REDACTED-PASSWORD***@".to_string(),
                enabled: true,
            },

            // Password in various formats
            RedactionPattern {
                name: "password_key_value".to_string(),
                description: "Password in key-value format".to_string(),
                regex: Regex::new(r#"(?i)(password|passwd|pwd)\s*[:=]\s*["']?([^"'\s]{6,})["']?"#).unwrap(),
                replacement: r#"$1: "***REDACTED-PASSWORD***""#.to_string(),
                enabled: true,
            },

            // Slack Tokens
            RedactionPattern {
                name: "slack_token".to_string(),
                description: "Slack API Tokens".to_string(),
                regex: Regex::new(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}").unwrap(),
                replacement: "***REDACTED-SLACK-TOKEN***".to_string(),
                enabled: true,
            },
            RedactionPattern {
                name: "slack_webhook".to_string(),
                description: "Slack Webhook URLs".to_string(),
                regex: Regex::new(r"https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[a-zA-Z0-9]+").unwrap(),
                replacement: "***REDACTED-SLACK-WEBHOOK***".to_string(),
                enabled: true,
            },

            // Discord Webhooks
            RedactionPattern {
                name: "discord_webhook".to_string(),
                description: "Discord Webhook URLs".to_string(),
                regex: Regex::new(r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+").unwrap(),
                replacement: "***REDACTED-DISCORD-WEBHOOK***".to_string(),
                enabled: true,
            },

            // Google Cloud
            RedactionPattern {
                name: "google_api_key".to_string(),
                description: "Google API Keys".to_string(),
                regex: Regex::new(r"AIza[0-9A-Za-z_-]{35}").unwrap(),
                replacement: "***REDACTED-GOOGLE-API-KEY***".to_string(),
                enabled: true,
            },
            RedactionPattern {
                name: "google_oauth".to_string(),
                description: "Google OAuth tokens".to_string(),
                regex: Regex::new(r"ya29\.[0-9A-Za-z_-]+").unwrap(),
                replacement: "***REDACTED-GOOGLE-OAUTH***".to_string(),
                enabled: true,
            },

            // Azure
            RedactionPattern {
                name: "azure_client_secret".to_string(),
                description: "Azure Client Secrets".to_string(),
                regex: Regex::new(r#"(?i)(client_secret)\s*[:=]\s*['"]?([a-zA-Z0-9~._-]{34,})['"]?"#).unwrap(),
                replacement: r#"$1: "***REDACTED-AZURE-SECRET***""#.to_string(),
                enabled: true,
            },

            // SSH Private Keys (alternative patterns)
            RedactionPattern {
                name: "ssh_key_dsa".to_string(),
                description: "DSA SSH Keys".to_string(),
                regex: Regex::new(r"-----BEGIN DSA PRIVATE KEY-----[\s\S]*?-----END DSA PRIVATE KEY-----").unwrap(),
                replacement: "-----BEGIN DSA PRIVATE KEY-----\n***REDACTED***\n-----END DSA PRIVATE KEY-----".to_string(),
                enabled: true,
            },

            // Generic Secret patterns
            RedactionPattern {
                name: "generic_secret".to_string(),
                description: "Generic secret patterns".to_string(),
                regex: Regex::new(r#"(?i)(secret|token|credential)\s*[:=]\s*['"]?([a-zA-Z0-9_\-+=/.]{20,})['"]?"#).unwrap(),
                replacement: r#"$1: "***REDACTED-SECRET***""#.to_string(),
                enabled: true,
            },

            // Credit Card Numbers (PCI compliance)
            RedactionPattern {
                name: "credit_card".to_string(),
                description: "Credit card numbers".to_string(),
                regex: Regex::new(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b").unwrap(),
                replacement: "***REDACTED-CREDIT-CARD***".to_string(),
                enabled: true,
            },

            // Email addresses (optional, disabled by default)
            RedactionPattern {
                name: "email_address".to_string(),
                description: "Email addresses (disabled by default)".to_string(),
                regex: Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap(),
                replacement: "***REDACTED-EMAIL***".to_string(),
                enabled: false, // Disabled by default as emails might be legitimate findings
            },

            // IP Addresses (optional, disabled by default)
            RedactionPattern {
                name: "ip_address".to_string(),
                description: "IPv4 addresses (disabled by default)".to_string(),
                regex: Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").unwrap(),
                replacement: "***REDACTED-IP***".to_string(),
                enabled: false, // Disabled by default as IPs are often part of findings
            },
        ]
    }

    /// Get list of all pattern names
    pub fn pattern_names(&self) -> Vec<String> {
        self.patterns.iter().map(|p| p.name.clone()).collect()
    }

    /// Get pattern by name
    pub fn get_pattern(&self, name: &str) -> Option<&RedactionPattern> {
        self.patterns.iter().find(|p| p.name == name)
    }
}

impl Default for SecretRedactor {
    fn default() -> Self {
        Self::new()
    }
}

// Helper module for serde_regex serialization
mod serde_regex {
    use regex::Regex;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(regex: &Regex, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(regex.as_str())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Regex, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Regex::new(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_aws_access_key() {
        let redactor = SecretRedactor::new();
        let text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        let redacted = redactor.redact(text);
        assert!(redacted.contains("***REDACTED-AWS-ACCESS-KEY***"));
        assert!(!redacted.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn test_redact_github_token() {
        let redactor = SecretRedactor::new();
        let text = "token: ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let redacted = redactor.redact(text);
        assert!(redacted.contains("***REDACTED-GITHUB-PAT***"));
        assert!(!redacted.contains("ghp_aaaaaa"));
    }

    #[test]
    fn test_redact_bearer_token() {
        let redactor = SecretRedactor::new();
        let text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature";
        let redacted = redactor.redact(text);
        assert!(redacted.contains("***REDACTED"));
        assert!(!redacted.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));
    }

    #[test]
    fn test_redact_basic_auth() {
        let redactor = SecretRedactor::new();
        let text = "Authorization: Basic YWRtaW46cGFzc3dvcmQ=";
        let redacted = redactor.redact(text);
        assert!(redacted.contains("***REDACTED-BASIC-AUTH***"));
        assert!(!redacted.contains("YWRtaW46cGFzc3dvcmQ="));
    }

    #[test]
    fn test_redact_jwt() {
        let redactor = SecretRedactor::new();
        let text = "JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let redacted = redactor.redact(text);
        assert!(redacted.contains("***REDACTED-JWT-TOKEN***"));
    }

    #[test]
    fn test_redact_rsa_private_key() {
        let redactor = SecretRedactor::new();
        let text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----";
        let redacted = redactor.redact(text);
        assert!(redacted.contains("***REDACTED***"));
        assert!(redacted.contains("BEGIN RSA PRIVATE KEY"));
        assert!(!redacted.contains("MIIEowIBAAKCAQEA"));
    }

    #[test]
    fn test_redact_database_url() {
        let redactor = SecretRedactor::new();
        let text = "DATABASE_URL=postgresql://user:secretpass123@localhost:5432/db";
        let redacted = redactor.redact(text);
        assert!(redacted.contains("***REDACTED-PASSWORD***"));
        assert!(!redacted.contains("secretpass123"));
        assert!(redacted.contains("user"));
    }

    #[test]
    fn test_redact_slack_webhook() {
        let redactor = SecretRedactor::new();
        let text = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX";
        let redacted = redactor.redact(text);
        assert!(redacted.contains("***REDACTED-SLACK-WEBHOOK***"));
    }

    #[test]
    fn test_redact_discord_webhook() {
        let redactor = SecretRedactor::new();
        let text = "https://discord.com/api/webhooks/123456789/abcdefghijklmnop";
        let redacted = redactor.redact(text);
        assert!(redacted.contains("***REDACTED-DISCORD-WEBHOOK***"));
    }

    #[test]
    fn test_redact_password_key_value() {
        let redactor = SecretRedactor::new();
        let text = "password: supersecret123";
        let redacted = redactor.redact(text);
        assert!(redacted.contains("***REDACTED-PASSWORD***"));
        assert!(!redacted.contains("supersecret123"));
    }

    #[test]
    fn test_contains_secrets() {
        let redactor = SecretRedactor::new();
        assert!(redactor.contains_secrets("AKIAIOSFODNN7EXAMPLE"));
        assert!(redactor.contains_secrets("ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        assert!(!redactor.contains_secrets("This is safe text with no secrets"));
    }

    #[test]
    fn test_redact_multiple_secrets() {
        let redactor = SecretRedactor::new();
        let text = "AWS_KEY=AKIAIOSFODNN7EXAMPLE and password=secret123 and token: ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let redacted = redactor.redact(text);
        assert!(redacted.contains("***REDACTED-AWS-ACCESS-KEY***"));
        assert!(redacted.contains("***REDACTED-PASSWORD***"));
        assert!(redacted.contains("***REDACTED-GITHUB-PAT***"));
    }

    #[test]
    fn test_redact_option_some() {
        let redactor = SecretRedactor::new();
        let result = redactor.redact_option(Some("password: secret123"));
        assert!(result.is_some());
        assert!(result.unwrap().contains("***REDACTED-PASSWORD***"));
    }

    #[test]
    fn test_redact_option_none() {
        let redactor = SecretRedactor::new();
        let result = redactor.redact_option(None);
        assert!(result.is_none());
    }

    #[test]
    fn test_pattern_names() {
        let redactor = SecretRedactor::new();
        let names = redactor.pattern_names();
        assert!(names.contains(&"aws_access_key_id".to_string()));
        assert!(names.contains(&"github_pat".to_string()));
        assert!(names.contains(&"bearer_token".to_string()));
    }

    #[test]
    fn test_get_pattern() {
        let redactor = SecretRedactor::new();
        let pattern = redactor.get_pattern("aws_access_key_id");
        assert!(pattern.is_some());
        assert_eq!(pattern.unwrap().name, "aws_access_key_id");
    }

    #[test]
    fn test_custom_patterns() {
        let custom_pattern = RedactionPattern {
            name: "custom".to_string(),
            description: "Custom test pattern".to_string(),
            regex: Regex::new(r"CUSTOM-\d+").unwrap(),
            replacement: "***CUSTOM-REDACTED***".to_string(),
            enabled: true,
        };
        
        let redactor = SecretRedactor::with_patterns(vec![custom_pattern]);
        let text = "Secret: CUSTOM-12345";
        let redacted = redactor.redact(text);
        assert!(redacted.contains("***CUSTOM-REDACTED***"));
    }

    #[test]
    fn test_disabled_pattern() {
        let pattern = RedactionPattern {
            name: "test".to_string(),
            description: "Test pattern".to_string(),
            regex: Regex::new(r"SECRET").unwrap(),
            replacement: "***REDACTED***".to_string(),
            enabled: false,
        };
        
        let redactor = SecretRedactor::with_patterns(vec![pattern]);
        let text = "SECRET";
        let redacted = redactor.redact(text);
        assert_eq!(text, redacted); // Should not be redacted when disabled
    }
}
