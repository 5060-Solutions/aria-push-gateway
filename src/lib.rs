//! Aria Push Gateway — library crate for integration tests.

pub mod auth_test_helpers {
    //! Re-export auth functions for testing.

    use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Claims {
        pub sub: String,
        pub exp: u64,
        pub iat: u64,
    }

    pub fn create_token(user_id: &str, secret: &str, expiry_secs: u64) -> anyhow::Result<String> {
        let now = chrono::Utc::now().timestamp() as u64;
        let claims = Claims {
            sub: user_id.to_string(),
            exp: now + expiry_secs,
            iat: now,
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )?;
        Ok(token)
    }

    pub fn verify_token(token: &str, secret: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
        let data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &Validation::default(),
        )?;
        Ok(data.claims)
    }
}

pub mod config_test_helpers {
    //! Re-export config types for testing.

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
        pub listen: String,
        pub public_url: String,
    }

    #[derive(Debug, Deserialize)]
    pub struct DatabaseConfig {
        pub url: String,
    }

    #[derive(Debug, Deserialize)]
    pub struct PushConfig {
        pub apns: Option<serde_json::Value>,
        pub fcm: Option<serde_json::Value>,
    }

    #[derive(Debug, Deserialize)]
    pub struct AuthConfig {
        pub secret: String,
        #[serde(default = "default_expiry")]
        pub token_expiry_secs: u64,
    }

    fn default_expiry() -> u64 {
        30 * 24 * 3600
    }

    pub fn load_default() -> GatewayConfig {
        GatewayConfig {
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
                token_expiry_secs: default_expiry(),
            },
        }
    }
}
