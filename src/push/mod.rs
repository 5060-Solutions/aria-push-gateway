//! Push notification delivery for iOS (APNs) and Android (FCM).

use crate::config::PushConfig;
use crate::db::DeviceRecord;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::RwLock;

/// Push notification manager — routes to APNs or FCM based on device platform.
pub struct PushManager {
    apns: Option<ApnsClient>,
    fcm: Option<FcmClient>,
    /// Device records keyed by device_id — populated by the server when devices register.
    devices: RwLock<HashMap<String, DeviceRecord>>,
}

struct ApnsClient {
    key_id: String,
    team_id: String,
    bundle_id: String,
    sandbox: bool,
    private_key_pem: Vec<u8>,
    http: reqwest::Client,
    /// Cached JWT and its issue time (APNs JWTs are valid for 1 hour)
    cached_jwt: RwLock<Option<(String, i64)>>,
}

struct FcmClient {
    project_id: String,
    http: reqwest::Client,
    /// OAuth2 access token + expiry timestamp
    access_token: RwLock<Option<(String, i64)>>,
    /// Service account JSON fields
    client_email: String,
    private_key_pem: String,
}

#[derive(Serialize)]
struct ApnsPayload {
    aps: ApnsAps,
    #[serde(rename = "callToken")]
    call_token: String,
    #[serde(rename = "callerUri")]
    caller_uri: String,
    #[serde(rename = "callerName", skip_serializing_if = "Option::is_none")]
    caller_name: Option<String>,
}

#[derive(Serialize)]
struct ApnsAps {
    alert: ApnsAlert,
    sound: String,
    #[serde(rename = "content-available")]
    content_available: u8,
}

#[derive(Serialize)]
struct ApnsAlert {
    title: String,
    body: String,
}

/// Google OAuth2 token response.
#[derive(Deserialize)]
struct GoogleTokenResponse {
    access_token: String,
    expires_in: i64,
}

impl PushManager {
    /// Create a no-op PushManager (used for outgoing calls where we don't need push).
    pub fn new_noop() -> Self {
        Self {
            apns: None,
            fcm: None,
            devices: RwLock::new(HashMap::new()),
        }
    }

    pub fn new(config: &PushConfig) -> anyhow::Result<Self> {
        let apns = if let Some(ref apns_config) = config.apns {
            let key_data = std::fs::read(&apns_config.key_path)
                .map_err(|e| anyhow::anyhow!("Failed to read APNs key: {}", e))?;
            Some(ApnsClient {
                key_id: apns_config.key_id.clone(),
                team_id: apns_config.team_id.clone(),
                bundle_id: apns_config.bundle_id.clone(),
                sandbox: apns_config.sandbox,
                private_key_pem: key_data,
                http: reqwest::Client::builder()
                    .http2_prior_knowledge()
                    .build()?,
                cached_jwt: RwLock::new(None),
            })
        } else {
            None
        };

        let fcm = if let Some(ref fcm_config) = config.fcm {
            let sa_data = std::fs::read_to_string(&fcm_config.service_account_path)?;
            let service_account: serde_json::Value = serde_json::from_str(&sa_data)?;

            let client_email = service_account["client_email"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Missing client_email in service account JSON"))?
                .to_string();
            let private_key_pem = service_account["private_key"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Missing private_key in service account JSON"))?
                .to_string();

            Some(FcmClient {
                project_id: fcm_config.project_id.clone(),
                http: reqwest::Client::new(),
                access_token: RwLock::new(None),
                client_email,
                private_key_pem,
            })
        } else {
            None
        };

        Ok(Self {
            apns,
            fcm,
            devices: RwLock::new(HashMap::new()),
        })
    }

    /// Register a device record for push routing.
    pub async fn register_device(&self, device: DeviceRecord) {
        let mut devices = self.devices.write().await;
        devices.insert(device.id.clone(), device);
    }

    /// Remove a device.
    pub async fn unregister_device(&self, device_id: &str) {
        let mut devices = self.devices.write().await;
        devices.remove(device_id);
    }

    /// Send an incoming call push notification.
    pub async fn send_incoming_call(
        &self,
        device_id: &str,
        call_token: &str,
        caller_uri: &str,
        caller_name: Option<&str>,
    ) -> anyhow::Result<()> {
        let device = {
            let devices = self.devices.read().await;
            devices
                .get(device_id)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("Device {} not registered for push", device_id))?
        };

        match device.platform.as_str() {
            "ios" => self.send_apns(&device, call_token, caller_uri, caller_name).await,
            "android" => self.send_fcm(&device, call_token, caller_uri, caller_name).await,
            _ => Err(anyhow::anyhow!("Unknown platform: {}", device.platform)),
        }
    }

    async fn send_apns(
        &self,
        device: &DeviceRecord,
        call_token: &str,
        caller_uri: &str,
        caller_name: Option<&str>,
    ) -> anyhow::Result<()> {
        let apns = self
            .apns
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("APNs not configured"))?;

        let display = caller_name.unwrap_or(caller_uri);
        let payload = ApnsPayload {
            aps: ApnsAps {
                alert: ApnsAlert {
                    title: "Incoming Call".to_string(),
                    body: format!("{} is calling", display),
                },
                sound: "ringtone.caf".to_string(),
                content_available: 1,
            },
            call_token: call_token.to_string(),
            caller_uri: caller_uri.to_string(),
            caller_name: caller_name.map(|s| s.to_string()),
        };

        let host = if apns.sandbox {
            "https://api.sandbox.push.apple.com"
        } else {
            "https://api.push.apple.com"
        };

        let jwt = self.get_apns_jwt(apns).await?;

        let url = format!("{}/3/device/{}", host, device.push_token);
        let topic = device
            .bundle_id
            .as_deref()
            .unwrap_or(&apns.bundle_id);

        let resp = apns
            .http
            .post(&url)
            .header("authorization", format!("bearer {}", jwt))
            .header("apns-push-type", "voip")
            .header("apns-priority", "10")
            .header("apns-topic", format!("{}.voip", topic))
            .json(&payload)
            .send()
            .await?;

        if resp.status().is_success() {
            tracing::info!("APNs push sent successfully");
            Ok(())
        } else {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            Err(anyhow::anyhow!("APNs error {}: {}", status, body))
        }
    }

    async fn send_fcm(
        &self,
        device: &DeviceRecord,
        call_token: &str,
        caller_uri: &str,
        caller_name: Option<&str>,
    ) -> anyhow::Result<()> {
        let fcm = self
            .fcm
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("FCM not configured"))?;

        let mut data = serde_json::Map::new();
        data.insert("type".into(), "incoming_call".into());
        data.insert("callToken".into(), call_token.into());
        data.insert("callerUri".into(), caller_uri.into());
        if let Some(name) = caller_name {
            data.insert("callerName".into(), name.into());
        }

        let payload = serde_json::json!({
            "message": {
                "token": device.push_token,
                "data": data,
                "android": {
                    "priority": "HIGH",
                    "ttl": "30s"
                }
            }
        });

        let access_token = self.get_fcm_token(fcm).await?;
        let url = format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            fcm.project_id
        );

        let resp = fcm
            .http
            .post(&url)
            .header("Authorization", format!("Bearer {}", access_token))
            .json(&payload)
            .send()
            .await?;

        if resp.status().is_success() {
            tracing::info!("FCM push sent successfully");
            Ok(())
        } else {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            Err(anyhow::anyhow!("FCM error {}: {}", status, body))
        }
    }

    /// Get or refresh an APNs JWT (ES256, valid for 1 hour).
    async fn get_apns_jwt(&self, apns: &ApnsClient) -> anyhow::Result<String> {
        let now = chrono::Utc::now().timestamp();

        // Check cache — reuse if less than 50 minutes old
        {
            let cached = apns.cached_jwt.read().await;
            if let Some((ref token, issued_at)) = *cached {
                if now - issued_at < 3000 {
                    return Ok(token.clone());
                }
            }
        }

        // Build new JWT signed with ES256
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(apns.key_id.clone());

        #[derive(Serialize)]
        struct ApnsClaims {
            iss: String,
            iat: i64,
        }

        let claims = ApnsClaims {
            iss: apns.team_id.clone(),
            iat: now,
        };

        let key = EncodingKey::from_ec_pem(&apns.private_key_pem)
            .map_err(|e| anyhow::anyhow!("Invalid APNs .p8 key: {}", e))?;

        let token = encode(&header, &claims, &key)
            .map_err(|e| anyhow::anyhow!("Failed to sign APNs JWT: {}", e))?;

        // Cache it
        {
            let mut cached = apns.cached_jwt.write().await;
            *cached = Some((token.clone(), now));
        }

        tracing::debug!("Generated new APNs JWT");
        Ok(token)
    }

    /// Get or refresh an FCM OAuth2 access token via service account JWT.
    async fn get_fcm_token(&self, fcm: &FcmClient) -> anyhow::Result<String> {
        let now = chrono::Utc::now().timestamp();

        // Check cache
        {
            let cached = fcm.access_token.read().await;
            if let Some((ref token, expires_at)) = *cached {
                if now < expires_at - 60 {
                    return Ok(token.clone());
                }
            }
        }

        // Build a signed JWT for Google's token endpoint
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

        let header = Header::new(Algorithm::RS256);

        #[derive(Serialize)]
        struct GoogleClaims {
            iss: String,
            scope: String,
            aud: String,
            iat: i64,
            exp: i64,
        }

        let claims = GoogleClaims {
            iss: fcm.client_email.clone(),
            scope: "https://www.googleapis.com/auth/firebase.messaging".to_string(),
            aud: "https://oauth2.googleapis.com/token".to_string(),
            iat: now,
            exp: now + 3600,
        };

        let key = EncodingKey::from_rsa_pem(fcm.private_key_pem.as_bytes())
            .map_err(|e| anyhow::anyhow!("Invalid FCM service account key: {}", e))?;

        let assertion = encode(&header, &claims, &key)
            .map_err(|e| anyhow::anyhow!("Failed to sign FCM JWT: {}", e))?;

        // Exchange JWT for access token
        let resp = fcm
            .http
            .post("https://oauth2.googleapis.com/token")
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &assertion),
            ])
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("FCM token exchange failed {}: {}", status, body));
        }

        let token_resp: GoogleTokenResponse = resp.json().await?;

        // Cache with expiry
        let expires_at = now + token_resp.expires_in;
        {
            let mut cached = fcm.access_token.write().await;
            *cached = Some((token_resp.access_token.clone(), expires_at));
        }

        tracing::debug!("Obtained new FCM access token (expires in {}s)", token_resp.expires_in);
        Ok(token_resp.access_token)
    }
}
