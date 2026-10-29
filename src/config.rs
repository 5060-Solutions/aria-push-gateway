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
    /// Shared key a trusted backend must present to `POST /v1/auth/token`.
    /// Overridden by the `TOKEN_ISSUER_KEY` environment variable. When unset,
    /// token minting is disabled.
    #[serde(default)]
    pub token_issuer_key: Option<String>,
}

impl AuthConfig {
    /// The effective token-issuer key: `TOKEN_ISSUER_KEY` from the
    /// environment if set, else the config value. Blank values and the old
    /// `"auto"` placeholder count as unset.
    pub fn resolve_token_issuer_key(&self) -> Option<String> {
        let from_env = std::env::var("TOKEN_ISSUER_KEY").ok();
        normalize_issuer_key(from_env.or_else(|| self.token_issuer_key.clone()))
    }
}

fn normalize_issuer_key(key: Option<String>) -> Option<String> {
    key.filter(|k| {
        let k = k.trim();
        !k.is_empty() && !k.eq_ignore_ascii_case("auto")
    })
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
                token_issuer_key: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blank_and_placeholder_issuer_keys_count_as_unset() {
        assert_eq!(normalize_issuer_key(None), None);
        assert_eq!(normalize_issuer_key(Some(String::new())), None);
        assert_eq!(normalize_issuer_key(Some("   ".into())), None);
        assert_eq!(normalize_issuer_key(Some("auto".into())), None);
        assert_eq!(normalize_issuer_key(Some("AUTO".into())), None);
        assert_eq!(normalize_issuer_key(Some("k3y".into())), Some("k3y".into()));
    }
}
