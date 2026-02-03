//! SMTP OAuth2 Flow Helper (Issue #3)
//!
//! Provides OAuth2 authentication for SMTP providers (Gmail, Outlook, Office365).
//! Handles token acquisition, refresh, and secure storage.

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use tracing::info;
use url::Url;

/// Supported OAuth2 providers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OAuthProvider {
    Gmail,
    Outlook,
    Office365,
}

impl OAuthProvider {
    pub fn client_id_env(&self) -> String {
        match self {
            OAuthProvider::Gmail => "GMAIL_CLIENT_ID".to_string(),
            OAuthProvider::Outlook => "OUTLOOK_CLIENT_ID".to_string(),
            OAuthProvider::Office365 => "OFFICE365_CLIENT_ID".to_string(),
        }
    }

    pub fn client_secret_env(&self) -> String {
        match self {
            OAuthProvider::Gmail => "GMAIL_CLIENT_SECRET".to_string(),
            OAuthProvider::Outlook => "OUTLOOK_CLIENT_SECRET".to_string(),
            OAuthProvider::Office365 => "OFFICE365_CLIENT_SECRET".to_string(),
        }
    }

    pub fn auth_url(&self) -> String {
        match self {
            OAuthProvider::Gmail => {
                "https://accounts.google.com/o/oauth2/v2/auth".to_string()
            }
            OAuthProvider::Outlook | OAuthProvider::Office365 => {
                "https://login.microsoftonline.com/common/oauth2/v2.0/authorize".to_string()
            }
        }
    }

    pub fn token_url(&self) -> String {
        match self {
            OAuthProvider::Gmail => {
                "https://oauth2.googleapis.com/token".to_string()
            }
            OAuthProvider::Outlook | OAuthProvider::Office365 => {
                "https://login.microsoftonline.com/common/oauth2/v2.0/token".to_string()
            }
        }
    }

    pub fn scopes(&self) -> Vec<String> {
        match self {
            OAuthProvider::Gmail => vec![
                "https://mail.google.com/".to_string(),
                "email".to_string(),
            ],
            OAuthProvider::Outlook | OAuthProvider::Office365 => vec![
                "https://outlook.office.com/SMTP.Send".to_string(),
                "openid".to_string(),
                "email".to_string(),
                "offline_access".to_string(),
            ],
        }
    }

    pub fn smtp_host(&self) -> String {
        match self {
            OAuthProvider::Gmail => "smtp.gmail.com".to_string(),
            OAuthProvider::Outlook | OAuthProvider::Office365 => {
                "smtp.office365.com".to_string()
            }
        }
    }

    pub fn smtp_port(&self) -> u16 {
        587
    }
}

impl std::str::FromStr for OAuthProvider {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "gmail" => Ok(OAuthProvider::Gmail),
            "outlook" => Ok(OAuthProvider::Outlook),
            "office365" => Ok(OAuthProvider::Office365),
            _ => Err(format!("Unknown provider: {}", s)),
        }
    }
}

/// OAuth2 token response
#[derive(Debug, Clone, Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: i64,
    token_type: String,
}

/// Stored OAuth2 credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthCredentials {
    pub provider: OAuthProvider,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>,
    pub email: String,
}

impl OAuthCredentials {
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    pub fn needs_refresh(&self) -> bool {
        // Refresh if expires within 5 minutes
        Utc::now() >= self.expires_at - Duration::minutes(5)
    }
}

/// OAuth2 flow helper
pub struct OAuthHelper {
    provider: OAuthProvider,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
}

impl OAuthHelper {
    pub fn new(
        provider: OAuthProvider,
        client_id: String,
        client_secret: String,
    ) -> Result<Self> {
        Ok(Self {
            provider,
            client_id,
            client_secret,
            redirect_uri: "http://localhost:8085/callback".to_string(),
        })
    }

    pub fn from_env(provider: OAuthProvider) -> Result<Self> {
        let client_id = std::env::var(provider.client_id_env())
            .with_context(|| format!("Missing {} environment variable", provider.client_id_env()))?;
        let client_secret = std::env::var(provider.client_secret_env())
            .with_context(|| format!("Missing {} environment variable", provider.client_secret_env()))?;
        
        Self::new(provider, client_id, client_secret)
    }

    /// Generate authorization URL
    pub fn get_auth_url(&self) -> String {
        let mut params = HashMap::new();
        params.insert("client_id", self.client_id.clone());
        params.insert("redirect_uri", self.redirect_uri.clone());
        params.insert("response_type", "code".to_string());
        params.insert("access_type", "offline".to_string());
        params.insert("prompt", "consent".to_string());
        params.insert(
            "scope",
            self.provider.scopes().join(" "),
        );

        let mut url = Url::parse(&self.provider.auth_url()).unwrap();
        {
            let mut pairs = url.query_pairs_mut();
            for (k, v) in &params {
                pairs.append_pair(k, v);
            }
        }

        url.to_string()
    }

    /// Start OAuth flow and wait for callback
    pub async fn start_flow(&self,
    ) -> Result<OAuthCredentials> {
        info!("Starting OAuth flow for {:?}", self.provider);

        // Generate and display auth URL
        let auth_url = self.get_auth_url();
        println!("\n🔐 OAuth Authorization Required");
        println!("================================");
        println!("Provider: {:?}", self.provider);
        println!("\nPlease open this URL in your browser:\n{}", auth_url);
        println!("\nWaiting for authorization...\n");

        // Start local server to receive callback
        let auth_code = self.wait_for_callback().await?;

        // Exchange code for tokens
        let credentials = self.exchange_code(&auth_code).await?;

        info!("OAuth flow completed successfully for {:?}", self.provider);
        Ok(credentials)
    }

    /// Wait for OAuth callback on localhost
    async fn wait_for_callback(&self,
    ) -> Result<String> {
        let listener = TcpListener::bind("127.0.0.1:8085")
            .context("Failed to bind callback server to port 8085")?;

        let (mut stream, _) = listener.accept()
            .context("Failed to accept connection")?;

        let mut buffer = [0u8; 4096];
        let bytes_read = stream.read(&mut buffer)
            .context("Failed to read request")?;

        let request = String::from_utf8_lossy(&buffer[..bytes_read]);
        
        // Extract authorization code from request
        let code = self.extract_auth_code(&request)?;

        // Send success response to browser
        let response = b"HTTP/1.1 200 OK
Content-Type: text/html

<html>
<head><title>Authorization Successful</title></head>
<body>
<h1>Authorization Successful</h1>
<p>You can close this window and return to the terminal.</p>
</body>
</html>";

        stream.write_all(response)
            .context("Failed to send response")?;

        Ok(code)
    }

    /// Extract authorization code from HTTP request
    fn extract_auth_code(&self,
        request: &str,
    ) -> Result<String> {
        // Find the request line
        let request_line = request.lines().next()
            .context("Empty request")?;

        // Extract code from query string
        if let Some(start) = request_line.find("code=") {
            let code_start = start + 5;
            let code_end = request_line[code_start..]
                .find(|c: char| c == ' ' || c == '&')
                .map(|i| code_start + i)
                .unwrap_or(request_line.len() - 9); // -9 for " HTTP/1.1"

            let code = &request_line[code_start..code_end];
            return Ok(urlencoding::decode(code)
                .context("Failed to decode auth code")?
                .to_string());
        }

        Err(anyhow::anyhow!("Authorization code not found in request"))
    }

    /// Exchange authorization code for tokens
    async fn exchange_code(
        &self,
        code: &str,
    ) -> Result<OAuthCredentials> {
        let client = reqwest::Client::new();

        let mut params = HashMap::new();
        params.insert("code", code);
        params.insert("client_id", &self.client_id);
        params.insert("client_secret", &self.client_secret);
        params.insert("redirect_uri", &self.redirect_uri);
        params.insert("grant_type", "authorization_code");

        let response = client
            .post(self.provider.token_url())
            .form(&params)
            .send()
            .await
            .context("Failed to send token request")?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("Token request failed: {}", error_text));
        }

        let token_response: TokenResponse = response
            .json()
            .await
            .context("Failed to parse token response")?;

        let refresh_token = token_response.refresh_token
            .ok_or_else(|| anyhow::anyhow!("No refresh token received"))?;

        let expires_at = Utc::now() + Duration::seconds(token_response.expires_in);

        Ok(OAuthCredentials {
            provider: self.provider.clone(),
            access_token: token_response.access_token,
            refresh_token,
            expires_at,
            email: String::new(), // Will be populated later
        })
    }

    /// Refresh access token
    pub async fn refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<OAuthCredentials> {
        info!("Refreshing OAuth token for {:?}", self.provider);

        let client = reqwest::Client::new();

        let mut params = HashMap::new();
        params.insert("refresh_token", refresh_token);
        params.insert("client_id", &self.client_id);
        params.insert("client_secret", &self.client_secret);
        params.insert("grant_type", "refresh_token");

        let response = client
            .post(self.provider.token_url())
            .form(&params)
            .send()
            .await
            .context("Failed to send refresh request")?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("Token refresh failed: {}", error_text));
        }

        let token_response: TokenResponse = response
            .json()
            .await
            .context("Failed to parse refresh response")?;

        let expires_at = Utc::now() + Duration::seconds(token_response.expires_in);

        Ok(OAuthCredentials {
            provider: self.provider.clone(),
            access_token: token_response.access_token,
            refresh_token: token_response.refresh_token.unwrap_or_else(|| refresh_token.to_string()),
            expires_at,
            email: String::new(),
        })
    }
}

/// Token storage manager
pub struct TokenStorage;

impl TokenStorage {
    /// Save credentials to file
    pub fn save_credentials(
        credentials: &OAuthCredentials,
    ) -> Result<()> {
        let config_dir = dirs::config_dir()
            .context("Failed to get config directory")?
            .join("kheprimaat");
        
        std::fs::create_dir_all(&config_dir)?;
        
        let file_path = config_dir.join(format!("oauth_{:?}.json", credentials.provider).to_lowercase());
        let json = serde_json::to_string_pretty(credentials)?;
        
        std::fs::write(&file_path, json)
            .with_context(|| format!("Failed to write credentials to {:?}", file_path))?;
        
        // Set restrictive permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&file_path)?.permissions();
            perms.set_mode(0o600); // rw-------
            std::fs::set_permissions(&file_path, perms)?;
        }
        
        info!("Credentials saved to {:?}", file_path);
        Ok(())
    }

    /// Load credentials from file
    pub fn load_credentials(provider: OAuthProvider) -> Result<OAuthCredentials> {
        let config_dir = dirs::config_dir()
            .context("Failed to get config directory")?
            .join("kheprimaat");
        
        let file_path = config_dir.join(format!("oauth_{:?}.json", provider).to_lowercase());
        
        let json = std::fs::read_to_string(&file_path)
            .with_context(|| format!("No credentials found for {:?}. Run 'kheprimaat oauth setup' first.", provider))?;
        
        let credentials: OAuthCredentials = serde_json::from_str(&json)
            .context("Failed to parse credentials")?;
        
        Ok(credentials)
    }

    /// Check if credentials exist
    pub fn credentials_exist(provider: OAuthProvider) -> bool {
        if let Some(config_dir) = dirs::config_dir() {
            let file_path = config_dir
                .join("kheprimaat")
                .join(format!("oauth_{:?}.json", provider).to_lowercase());
            return file_path.exists();
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oauth_provider_from_str() {
        assert_eq!(
            "gmail".parse::<OAuthProvider>().unwrap(),
            OAuthProvider::Gmail
        );
        assert_eq!(
            "outlook".parse::<OAuthProvider>().unwrap(),
            OAuthProvider::Outlook
        );
        assert_eq!(
            "office365".parse::<OAuthProvider>().unwrap(),
            OAuthProvider::Office365
        );
    }

    #[test]
    fn test_credentials_expiration() {
        let creds = OAuthCredentials {
            provider: OAuthProvider::Gmail,
            access_token: "test".to_string(),
            refresh_token: "refresh".to_string(),
            expires_at: Utc::now() - Duration::hours(1),
            email: "test@test.com".to_string(),
        };
        
        assert!(creds.is_expired());
    }

    #[test]
    fn test_provider_config() {
        let gmail = OAuthProvider::Gmail;
        assert_eq!(gmail.smtp_host(), "smtp.gmail.com");
        assert_eq!(gmail.smtp_port(), 587);
        assert!(!gmail.scopes().is_empty());
    }
}
