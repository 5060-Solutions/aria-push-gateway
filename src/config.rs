use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct GatewayConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub push: PushConfig,
    pub auth: AuthConfig,
    #[serde(default)]
    pub sip: SipConfig,
}

#[derive(Debug, Default, Deserialize)]
pub struct SipConfig {
    /// Extra IPs/CIDRs (comma-separated) allowed to send SIP, besides the
    /// addresses each registrar resolves to. Overridden by the
    /// `TRUSTED_SIP_SOURCES` environment variable.
    #[serde(default)]
    pub trusted_sources: Option<String>,
}

impl SipConfig {
    /// The allowlist: `TRUSTED_SIP_SOURCES` if set and non-blank, else the
    /// config value. Invalid entries are an error (refuse to start).
    pub fn resolve_trusted_sources(&self) -> anyhow::Result<crate::sip::trust::TrustedSources> {
        self.trusted_sources_from(std::env::var("TRUSTED_SIP_SOURCES").ok())
    }

    fn trusted_sources_from(
        &self,
        env: Option<String>,
    ) -> anyhow::Result<crate::sip::trust::TrustedSources> {
        let list = env
            .filter(|v| !v.trim().is_empty())
            .or_else(|| self.trusted_sources.clone())
            .unwrap_or_default();
        crate::sip::trust::TrustedSources::parse(&list)
            .map_err(|e| anyhow::anyhow!("TRUSTED_SIP_SOURCES: {e}"))
    }
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
        self.issuer_key_from(std::env::var("TOKEN_ISSUER_KEY").ok())
    }

    /// The issuer key given the environment value: a blank (or `"auto"`)
    /// environment value does not override a valid config value.
    fn issuer_key_from(&self, env: Option<String>) -> Option<String> {
        normalize_issuer_key(env).or_else(|| normalize_issuer_key(self.token_issuer_key.clone()))
    }

    /// Refuse an issuer key equal to the JWT signing secret: whoever holds
    /// one would hold the other, and the secret must never leave the gateway.
    pub fn check_issuer_key(&self, key: Option<&str>) -> anyhow::Result<()> {
        if key.is_some_and(|k| k == self.secret || k.trim() == self.secret.trim()) {
            anyhow::bail!("TOKEN_ISSUER_KEY must differ from auth.secret");
        }
        Ok(())
    }
}

/// The placeholder secret the built-in default config uses.
pub const PLACEHOLDER_JWT_SECRET: &str = "CHANGE-ME-IN-PRODUCTION";
/// Shortest JWT signing secret the gateway will start with.
pub const MIN_JWT_SECRET_LEN: usize = 32;

impl AuthConfig {
    /// Refuse a JWT signing secret that is empty, a known placeholder or
    /// shorter than [`MIN_JWT_SECRET_LEN`]. Anyone who knows the secret can
    /// mint tokens for any user, so the gateway must not run with a weak one.
    pub fn check_jwt_secret(&self) -> anyhow::Result<()> {
        let secret = self.secret.trim();
        if secret.is_empty() {
            anyhow::bail!("auth.secret is empty");
        }
        if secret.starts_with("CHANGE-ME") {
            anyhow::bail!("auth.secret is still the placeholder {:?}", self.secret);
        }
        if secret.len() < MIN_JWT_SECRET_LEN {
            anyhow::bail!(
                "auth.secret is {} characters; it must be at least {MIN_JWT_SECRET_LEN}",
                secret.len()
            );
        }
        Ok(())
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
            sip: SipConfig::default(),
            auth: AuthConfig {
                secret: PLACEHOLDER_JWT_SECRET.to_string(),
                token_expiry_secs: default_token_expiry(),
                token_issuer_key: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth(secret: &str) -> AuthConfig {
        AuthConfig {
            secret: secret.into(),
            token_expiry_secs: 60,
            token_issuer_key: None,
        }
    }

    #[test]
    fn weak_jwt_secrets_are_refused() {
        for secret in [
            "",
            "   ",
            PLACEHOLDER_JWT_SECRET,
            "CHANGE-ME-TO-A-STRONG-RANDOM-SECRET",
            "CHANGE-ME-TO-A-STRONG-RANDOM-SECRET-AND-THEN-SOME",
            "short-secret",
            &"x".repeat(MIN_JWT_SECRET_LEN - 1),
        ] {
            assert!(auth(secret).check_jwt_secret().is_err(), "{secret:?}");
        }
        assert!(auth(&"x".repeat(MIN_JWT_SECRET_LEN))
            .check_jwt_secret()
            .is_ok());
    }

    #[test]
    fn blank_env_does_not_override_the_config_key() {
        let mut a = auth(&"s".repeat(40));
        a.token_issuer_key = Some("from-config".into());
        assert_eq!(
            a.issuer_key_from(Some(String::new())).as_deref(),
            Some("from-config")
        );
        assert_eq!(
            a.issuer_key_from(Some("  ".into())).as_deref(),
            Some("from-config")
        );
        assert_eq!(
            a.issuer_key_from(Some("auto".into())).as_deref(),
            Some("from-config")
        );
        assert_eq!(
            a.issuer_key_from(Some("from-env".into())).as_deref(),
            Some("from-env")
        );
        assert_eq!(a.issuer_key_from(None).as_deref(), Some("from-config"));
        a.token_issuer_key = Some(" ".into());
        assert_eq!(a.issuer_key_from(Some(String::new())), None);
    }

    #[test]
    fn issuer_key_equal_to_the_jwt_secret_is_refused() {
        let secret = "s".repeat(40);
        let a = auth(&secret);
        assert!(a.check_issuer_key(Some(&secret)).is_err());
        assert!(a.check_issuer_key(Some(&format!(" {secret} "))).is_err());
        assert!(a.check_issuer_key(Some("different-key")).is_ok());
        assert!(a.check_issuer_key(None).is_ok());
    }

    #[test]
    fn trusted_sources_come_from_env_or_config() {
        let cfg = SipConfig {
            trusted_sources: Some("10.0.0.0/8".into()),
        };
        let ip = |s: &str| s.parse().unwrap();
        let from_cfg = cfg.trusted_sources_from(None).unwrap();
        assert!(from_cfg.contains(ip("10.1.2.3")));
        let blank_env = cfg.trusted_sources_from(Some("  ".into())).unwrap();
        assert!(blank_env.contains(ip("10.1.2.3")));
        let from_env = cfg
            .trusted_sources_from(Some("192.0.2.0/24".into()))
            .unwrap();
        assert!(from_env.contains(ip("192.0.2.9")) && !from_env.contains(ip("10.1.2.3")));
        assert!(cfg.trusted_sources_from(Some("nope".into())).is_err());
        assert!(SipConfig::default()
            .trusted_sources_from(None)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn default_config_secret_is_refused() {
        assert!(GatewayConfig::default().auth.check_jwt_secret().is_err());
    }

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
