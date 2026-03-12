use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct GatewayConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub push: PushConfig,
    pub auth: AuthConfig,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    /// Address to listen on (e.g., "0.0.0.0:8080")
    pub listen: String,
    /// Public URL of this gateway (for callback URLs in push payloads)
    pub public_url: String,
}

#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    /// SQLite connection URL (e.g., "sqlite:gateway.db?mode=rwc")
    pub url: String,
}

#[derive(Debug, Deserialize)]
pub struct PushConfig {
    /// Apple Push Notification Service configuration
    pub apns: Option<ApnsConfig>,
    /// Firebase Cloud Messaging configuration
    pub fcm: Option<FcmConfig>,
}

#[derive(Debug, Deserialize)]
pub struct ApnsConfig {
    /// Path to APNs auth key (.p8 file)
    pub key_path: String,
    /// APNs Key ID
    pub key_id: String,
    /// Apple Team ID
    pub team_id: String,
    /// App bundle ID (used as APNs topic)
    pub bundle_id: String,
    /// Use APNs sandbox (development) environment
    #[serde(default)]
    pub sandbox: bool,
}

#[derive(Debug, Deserialize)]
pub struct FcmConfig {
    /// Path to Firebase service account JSON file
    pub service_account_path: String,
    /// Firebase project ID
    pub project_id: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthConfig {
    /// JWT signing secret
    pub secret: String,
    /// Token expiry in seconds (default: 30 days)
    #[serde(default = "default_token_expiry")]
    pub token_expiry_secs: u64,
}

fn default_token_expiry() -> u64 {
    30 * 24 * 3600 // 30 days
}

impl GatewayConfig {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::warn!("Config file '{}' not found, using defaults", path);
                return Ok(Self::default());
            }
            Err(e) => return Err(e.into()),
        };
        Ok(toml::from_str(&content)?)
    }

    fn default() -> Self {
        Self {
            server: ServerConfig {
                listen: "0.0.0.0:8080".to_string(),
                public_url: "http://localhost:8080".to_string(),
            },
            database: DatabaseConfig {
                url: "sqlite:gateway.db?mode=rwc".to_string(),
            },
            push: PushConfig {
                apns: None,
                fcm: None,
            },
            auth: AuthConfig {
                secret: "CHANGE-ME-IN-PRODUCTION".to_string(),
                token_expiry_secs: default_token_expiry(),
            },
        }
    }
}
