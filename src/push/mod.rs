//! Push notification delivery for iOS (APNs) and Android (FCM).

use crate::config::PushConfig;
use crate::db::DeviceRecord;
use crate::sip::message;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Longest a push request may take, connect included. The INVITE is held
/// with no ringback while the push is in flight, so a provider that stalls
/// fails the call (480) after this rather than after the 30 s handoff
/// timeout.
pub const PUSH_TIMEOUT: Duration = Duration::from_secs(5);
/// Longest a new connection to APNs/FCM may take to establish.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// HTTP/2 PING interval that keeps an idle provider connection open, so a
/// push after a quiet period doesn't pay DNS, TCP and TLS again.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// APNs JWTs are accepted for an hour; reuse one for 50 minutes.
const APNS_JWT_REUSE_SECS: i64 = 3000;
/// The background refresh mints a new APNs JWT once one is this old, well
/// before a push would have to mint one inline.
const APNS_JWT_REFRESH_SECS: i64 = 2700;
/// A cached FCM access token is used until this close to its expiry.
const FCM_TOKEN_MARGIN_SECS: i64 = 60;
/// The background refresh fetches a new FCM token this long before expiry.
const FCM_TOKEN_REFRESH_SECS: i64 = 600;
/// Retry delay after a failed background credential refresh.
const REFRESH_RETRY: Duration = Duration::from_secs(30);

const APNS_HOST: &str = "https://api.push.apple.com";
const APNS_SANDBOX_HOST: &str = "https://api.sandbox.push.apple.com";
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

/// Why an incoming-call push was not accepted by the provider.
#[derive(Debug)]
pub enum PushError {
    /// No push registration for the device.
    NoDevice,
    /// The device's provider (`"APNs"` or `"FCM"`) is not configured.
    NotConfigured(&'static str),
    /// An iOS device with no alert token: its push token is a PushKit one,
    /// which cannot show an alert.
    NoAlertToken,
    /// The device has a platform the gateway can't push to.
    UnknownPlatform(String),
    /// The provider credential (APNs JWT, FCM access token) couldn't be had.
    Credentials(String),
    /// The provider answered with an error status.
    Rejected {
        provider: &'static str,
        status: u16,
        body: String,
    },
    /// The provider couldn't be reached, or didn't answer in time.
    Transport {
        provider: &'static str,
        error: String,
    },
}

impl std::fmt::Display for PushError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoDevice => write!(f, "device not registered for push"),
            Self::NotConfigured(p) => write!(f, "{p} not configured"),
            Self::NoAlertToken => write!(f, "device has no alert token"),
            Self::UnknownPlatform(p) => write!(f, "unknown platform: {p}"),
            Self::Credentials(e) => write!(f, "push credentials unavailable: {e}"),
            Self::Rejected {
                provider,
                status,
                body,
            } => write!(f, "{provider} error {status}: {body}"),
            Self::Transport { provider, error } => write!(f, "{provider} unreachable: {error}"),
        }
    }
}

impl std::error::Error for PushError {}

impl PushError {
    /// Text for the `Reason` header of the 480 the PBX gets.
    pub fn sip_reason_text(&self) -> &'static str {
        match self {
            Self::NoDevice => "No push device registered",
            Self::NotConfigured(_) => "Push provider not configured",
            Self::NoAlertToken => "No alert token",
            Self::UnknownPlatform(_) => "Unsupported device platform",
            Self::Credentials(_) => "Push credentials unavailable",
            Self::Rejected { .. } => "Push rejected by provider",
            Self::Transport { .. } => "Push provider unreachable",
        }
    }
}

/// An HTTP client for a push provider: bounded connect and request times,
/// and a connection that is kept open between pushes.
fn provider_client(http2_prior_knowledge: bool) -> reqwest::Result<reqwest::Client> {
    let builder = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(PUSH_TIMEOUT)
        .pool_idle_timeout(None)
        .tcp_keepalive(KEEPALIVE_INTERVAL)
        .http2_keep_alive_interval(KEEPALIVE_INTERVAL)
        .http2_keep_alive_timeout(Duration::from_secs(10))
        .http2_keep_alive_while_idle(true);
    if http2_prior_knowledge {
        builder.http2_prior_knowledge().build()
    } else {
        builder.build()
    }
}

/// Whether the background refresh should mint a new APNs JWT.
fn apns_jwt_due(issued_at: Option<i64>, now: i64) -> bool {
    issued_at.is_none_or(|at| now - at >= APNS_JWT_REFRESH_SECS)
}

/// Whether the background refresh should fetch a new FCM access token.
fn fcm_token_due(expires_at: Option<i64>, now: i64) -> bool {
    expires_at.is_none_or(|exp| now >= exp - FCM_TOKEN_REFRESH_SECS)
}

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
    /// `https://api.push.apple.com` or the sandbox host.
    host: String,
    private_key_pem: Vec<u8>,
    http: reqwest::Client,
    /// Cached JWT and its issue time (APNs JWTs are valid for 1 hour)
    cached_jwt: RwLock<Option<(String, i64)>>,
}

struct FcmClient {
    /// The project's `messages:send` URL.
    send_url: String,
    /// Google's OAuth2 token endpoint.
    token_url: String,
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
    /// The PBX's `X-Aria-Move` value, when this INVITE moves a call here.
    #[serde(rename = "moveId", skip_serializing_if = "Option::is_none")]
    move_id: Option<String>,
    /// Who the moved call is with (display name, else the caller's URI).
    #[serde(rename = "moveFrom", skip_serializing_if = "Option::is_none")]
    move_from: Option<String>,
    /// The PBX's `X-Aria-Hold-Return` value: a held call's far party is back.
    #[serde(rename = "holdReturnId", skip_serializing_if = "Option::is_none")]
    hold_return_id: Option<String>,
    /// Who is back (the business name from `X-Aria-Hold-Return-Name`).
    #[serde(rename = "holdReturnName", skip_serializing_if = "Option::is_none")]
    hold_return_name: Option<String>,
}

/// What the PBX's INVITE adds beyond the caller: the headers the gateway
/// passes on to the push and the call offer.
#[derive(Debug, Default, Clone)]
pub struct IncomingCallExtras {
    /// `X-Aria-Move`: this INVITE moves a call to the device.
    pub move_id: Option<String>,
    /// `X-Aria-Hold-Return`: the far party of a held call is back.
    pub hold_return_id: Option<String>,
    /// `X-Aria-Hold-Return-Name`, cleaned and capped.
    pub hold_return_name: Option<String>,
}

impl IncomingCallExtras {
    pub fn from_invite(raw: &str) -> Self {
        let present = |name: &str| message::extract_header(raw, name).filter(|v| !v.is_empty());
        Self {
            move_id: present("X-Aria-Move"),
            hold_return_id: present("X-Aria-Hold-Return"),
            hold_return_name: message::extract_header(raw, "X-Aria-Hold-Return-Name")
                .map(|n| message::clean_header_text(&n, message::HOLD_RETURN_NAME_MAX))
                .filter(|n| !n.is_empty()),
        }
    }
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

/// An ordinary alert notification (not a call): what a text message sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    pub title: String,
    pub body: Option<String>,
    /// Alerts with the same id are grouped (iOS `thread-id`, Android tag).
    pub thread_id: Option<String>,
    /// iOS notification category (`aps.category`), for the app's actions.
    pub category: Option<String>,
    /// Delivered beside the alert.
    pub data: std::collections::BTreeMap<String, String>,
}

/// The APNs body of an alert: a visible banner with the app's data beside
/// `aps`. The caller refuses a `data` key named `aps`.
fn apns_alert_payload(alert: &Alert) -> serde_json::Value {
    let mut aps_alert = serde_json::json!({ "title": alert.title });
    if let Some(body) = &alert.body {
        aps_alert["body"] = body.clone().into();
    }
    let mut aps = serde_json::json!({ "alert": aps_alert, "sound": "default" });
    if let Some(thread) = &alert.thread_id {
        aps["thread-id"] = thread.clone().into();
    }
    if let Some(category) = &alert.category {
        aps["category"] = category.clone().into();
    }
    let mut payload = serde_json::Map::new();
    for (k, v) in &alert.data {
        payload.insert(k.clone(), v.clone().into());
    }
    payload.insert("aps".into(), aps);
    payload.into()
}

/// The FCM message for an alert: a notification the system shows by itself,
/// with the app's data beside it.
fn fcm_alert_message(token: &str, alert: &Alert) -> serde_json::Value {
    let mut notification = serde_json::json!({ "title": alert.title });
    if let Some(body) = &alert.body {
        notification["body"] = body.clone().into();
    }
    let mut android_notification = serde_json::json!({ "channel_id": "messages" });
    if let Some(thread) = &alert.thread_id {
        android_notification["tag"] = thread.clone().into();
    }
    serde_json::json!({
        "message": {
            "token": token,
            "notification": notification,
            "data": alert.data,
            "android": {
                "priority": "HIGH",
                "ttl": "3600s",
                "notification": android_notification,
            }
        }
    })
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
                host: if apns_config.sandbox {
                    APNS_SANDBOX_HOST
                } else {
                    APNS_HOST
                }
                .to_string(),
                private_key_pem: key_data,
                http: provider_client(true)?,
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
                send_url: format!(
                    "https://fcm.googleapis.com/v1/projects/{}/messages:send",
                    fcm_config.project_id
                ),
                token_url: GOOGLE_TOKEN_URL.to_string(),
                http: provider_client(false)?,
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
        extras: &IncomingCallExtras,
    ) -> Result<(), PushError> {
        let device = {
            let devices = self.devices.read().await;
            devices.get(device_id).cloned().ok_or(PushError::NoDevice)?
        };

        match device.platform.as_str() {
            "ios" => {
                self.send_apns(&device, call_token, caller_uri, caller_name, extras)
                    .await
            }
            "android" => {
                self.send_fcm(&device, call_token, caller_uri, caller_name, extras)
                    .await
            }
            _ => Err(PushError::UnknownPlatform(device.platform.clone())),
        }
    }

    /// Send an alert notification to `device`.
    pub async fn send_alert(&self, device: &DeviceRecord, alert: &Alert) -> Result<(), PushError> {
        match device.platform.as_str() {
            "ios" => self.send_apns_alert(device, alert).await,
            "android" => self.send_fcm_alert(device, alert).await,
            _ => Err(PushError::UnknownPlatform(device.platform.clone())),
        }
    }

    async fn send_apns_alert(&self, device: &DeviceRecord, alert: &Alert) -> Result<(), PushError> {
        let token = device
            .alert_token
            .as_deref()
            .ok_or(PushError::NoAlertToken)?;
        let apns = self.apns.as_ref().ok_or(PushError::NotConfigured("APNs"))?;
        let jwt = Self::get_apns_jwt(apns)
            .await
            .map_err(|e| PushError::Credentials(e.to_string()))?;
        let topic = device.bundle_id.as_deref().unwrap_or(&apns.bundle_id);
        let resp = apns
            .http
            .post(format!("{}/3/device/{}", apns.host, token))
            .header("authorization", format!("bearer {}", jwt))
            .header("apns-push-type", "alert")
            .header("apns-priority", "10")
            .header("apns-topic", topic)
            .json(&apns_alert_payload(alert))
            .send()
            .await
            .map_err(|e| PushError::Transport {
                provider: "APNs",
                error: e.to_string(),
            })?;
        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            Err(PushError::Rejected {
                provider: "APNs",
                status,
                body,
            })
        }
    }

    async fn send_fcm_alert(&self, device: &DeviceRecord, alert: &Alert) -> Result<(), PushError> {
        let fcm = self.fcm.as_ref().ok_or(PushError::NotConfigured("FCM"))?;
        // The same FCM token serves calls and alerts.
        let token = device.alert_token.as_deref().unwrap_or(&device.push_token);
        let access_token = Self::get_fcm_token(fcm)
            .await
            .map_err(|e| PushError::Credentials(e.to_string()))?;
        let resp = fcm
            .http
            .post(&fcm.send_url)
            .header("Authorization", format!("Bearer {}", access_token))
            .json(&fcm_alert_message(token, alert))
            .send()
            .await
            .map_err(|e| PushError::Transport {
                provider: "FCM",
                error: e.to_string(),
            })?;
        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            Err(PushError::Rejected {
                provider: "FCM",
                status,
                body,
            })
        }
    }

    async fn send_apns(
        &self,
        device: &DeviceRecord,
        call_token: &str,
        caller_uri: &str,
        caller_name: Option<&str>,
        extras: &IncomingCallExtras,
    ) -> Result<(), PushError> {
        let apns = self.apns.as_ref().ok_or(PushError::NotConfigured("APNs"))?;

        let payload = apns_payload(call_token, caller_uri, caller_name, extras);

        let jwt = Self::get_apns_jwt(apns)
            .await
            .map_err(|e| PushError::Credentials(e.to_string()))?;

        let url = format!("{}/3/device/{}", apns.host, device.push_token);
        let topic = device.bundle_id.as_deref().unwrap_or(&apns.bundle_id);

        let resp = apns
            .http
            .post(&url)
            .header("authorization", format!("bearer {}", jwt))
            .header("apns-push-type", "voip")
            .header("apns-priority", "10")
            .header("apns-topic", format!("{}.voip", topic))
            .json(&payload)
            .send()
            .await
            .map_err(|e| PushError::Transport {
                provider: "APNs",
                error: e.to_string(),
            })?;

        if resp.status().is_success() {
            tracing::info!("APNs push sent successfully");
            Ok(())
        } else {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            Err(PushError::Rejected {
                provider: "APNs",
                status,
                body,
            })
        }
    }

    async fn send_fcm(
        &self,
        device: &DeviceRecord,
        call_token: &str,
        caller_uri: &str,
        caller_name: Option<&str>,
        extras: &IncomingCallExtras,
    ) -> Result<(), PushError> {
        let fcm = self.fcm.as_ref().ok_or(PushError::NotConfigured("FCM"))?;

        let data = fcm_data(call_token, caller_uri, caller_name, extras);

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

        let access_token = Self::get_fcm_token(fcm)
            .await
            .map_err(|e| PushError::Credentials(e.to_string()))?;

        let resp = fcm
            .http
            .post(&fcm.send_url)
            .header("Authorization", format!("Bearer {}", access_token))
            .json(&payload)
            .send()
            .await
            .map_err(|e| PushError::Transport {
                provider: "FCM",
                error: e.to_string(),
            })?;

        if resp.status().is_success() {
            tracing::info!("FCM push sent successfully");
            Ok(())
        } else {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            Err(PushError::Rejected {
                provider: "FCM",
                status,
                body,
            })
        }
    }

    /// Get or refresh an APNs JWT (ES256, valid for 1 hour).
    async fn get_apns_jwt(apns: &ApnsClient) -> anyhow::Result<String> {
        let now = chrono::Utc::now().timestamp();

        // Check cache — reuse if less than 50 minutes old
        {
            let cached = apns.cached_jwt.read().await;
            if let Some((ref token, issued_at)) = *cached {
                if now - issued_at < APNS_JWT_REUSE_SECS {
                    return Ok(token.clone());
                }
            }
        }
        Self::mint_apns_jwt(apns, now).await
    }

    /// Sign a new APNs JWT and cache it.
    async fn mint_apns_jwt(apns: &ApnsClient, now: i64) -> anyhow::Result<String> {
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
    async fn get_fcm_token(fcm: &FcmClient) -> anyhow::Result<String> {
        let now = chrono::Utc::now().timestamp();

        // Check cache
        {
            let cached = fcm.access_token.read().await;
            if let Some((ref token, expires_at)) = *cached {
                if now < expires_at - FCM_TOKEN_MARGIN_SECS {
                    return Ok(token.clone());
                }
            }
        }
        Self::fetch_fcm_token(fcm, now).await
    }

    /// Exchange a signed service-account JWT for a new FCM access token and
    /// cache it.
    async fn fetch_fcm_token(fcm: &FcmClient, now: i64) -> anyhow::Result<String> {
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
            .post(&fcm.token_url)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &assertion),
            ])
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "FCM token exchange failed {}: {}",
                status,
                body
            ));
        }

        let token_resp: GoogleTokenResponse = resp.json().await?;

        // Cache with expiry
        let expires_at = now + token_resp.expires_in;
        {
            let mut cached = fcm.access_token.write().await;
            *cached = Some((token_resp.access_token.clone(), expires_at));
        }

        tracing::debug!(
            "Obtained new FCM access token (expires in {}s)",
            token_resp.expires_in
        );
        Ok(token_resp.access_token)
    }
}

impl PushManager {
    /// Keep provider credentials fresh in the background, so no incoming
    /// call has to sign an APNs JWT or fetch an FCM access token (an HTTPS
    /// round trip to Google) while its INVITE waits for the push. The first
    /// refresh runs at once; the task ends when the manager is dropped.
    pub fn spawn_credential_refresh(self: &Arc<Self>) {
        if self.apns.is_none() && self.fcm.is_none() {
            return;
        }
        let manager = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                let Some(this) = manager.upgrade() else {
                    return;
                };
                let wait = this.refresh_credentials().await;
                drop(this);
                tokio::time::sleep(wait).await;
            }
        });
    }

    /// Renew whichever credentials are due; returns when to look again.
    async fn refresh_credentials(&self) -> Duration {
        let now = chrono::Utc::now().timestamp();
        // Seconds until the next credential is due.
        let mut next = i64::MAX;
        let mut failed = false;

        if let Some(apns) = &self.apns {
            let issued = apns.cached_jwt.read().await.as_ref().map(|(_, at)| *at);
            let issued = if apns_jwt_due(issued, now) {
                match Self::mint_apns_jwt(apns, now).await {
                    Ok(_) => Some(now),
                    Err(e) => {
                        tracing::error!("APNs JWT refresh failed: {e}");
                        failed = true;
                        None
                    }
                }
            } else {
                issued
            };
            if let Some(at) = issued {
                next = next.min(at + APNS_JWT_REFRESH_SECS - now);
            }
        }

        if let Some(fcm) = &self.fcm {
            let expiry = |t: &Option<(String, i64)>| t.as_ref().map(|(_, exp)| *exp);
            let mut expires_at = expiry(&*fcm.access_token.read().await);
            if fcm_token_due(expires_at, now) {
                match Self::fetch_fcm_token(fcm, now).await {
                    Ok(_) => expires_at = expiry(&*fcm.access_token.read().await),
                    Err(e) => {
                        tracing::error!("FCM access token refresh failed: {e}");
                        failed = true;
                        expires_at = None;
                    }
                }
            }
            if let Some(exp) = expires_at {
                next = next.min(exp - FCM_TOKEN_REFRESH_SECS - now);
            }
        }

        if failed {
            return REFRESH_RETRY;
        }
        Duration::from_secs(next.clamp(30, 3600) as u64)
    }
}

/// A device record for push tests.
/// The VoIP push body for an incoming call. With `extras.move_id` (the
/// INVITE's `X-Aria-Move`) the push also carries `moveId` and `moveFrom`, so
/// the app can tell a call moved here from a new one; the hold-return values
/// ride along the same way.
fn apns_payload(
    call_token: &str,
    caller_uri: &str,
    caller_name: Option<&str>,
    extras: &IncomingCallExtras,
) -> ApnsPayload {
    let display = caller_name.unwrap_or(caller_uri);
    ApnsPayload {
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
        move_id: extras.move_id.clone(),
        move_from: extras.move_id.as_ref().map(|_| display.to_string()),
        hold_return_id: extras.hold_return_id.clone(),
        hold_return_name: extras.hold_return_name.clone(),
    }
}

/// The FCM `data` map for an incoming call (same fields as the APNs body).
fn fcm_data(
    call_token: &str,
    caller_uri: &str,
    caller_name: Option<&str>,
    extras: &IncomingCallExtras,
) -> serde_json::Map<String, serde_json::Value> {
    let mut data = serde_json::Map::new();
    data.insert("type".into(), "incoming_call".into());
    data.insert("callToken".into(), call_token.into());
    data.insert("callerUri".into(), caller_uri.into());
    if let Some(name) = caller_name {
        data.insert("callerName".into(), name.into());
    }
    if let Some(id) = &extras.move_id {
        data.insert("moveId".into(), id.as_str().into());
        data.insert("moveFrom".into(), caller_name.unwrap_or(caller_uri).into());
    }
    if let Some(id) = &extras.hold_return_id {
        data.insert("holdReturnId".into(), id.as_str().into());
    }
    if let Some(name) = &extras.hold_return_name {
        data.insert("holdReturnName".into(), name.as_str().into());
    }
    data
}

#[cfg(test)]
pub(crate) fn test_device(id: &str, platform: &str) -> DeviceRecord {
    let now = chrono::Utc::now();
    DeviceRecord {
        id: id.into(),
        user_id: "user".into(),
        platform: platform.into(),
        push_token: format!("push-{id}"),
        bundle_id: None,
        alert_token: None,
        sip_username: "1001".into(),
        sip_password: "pw".into(),
        sip_domain: "pbx.example.com".into(),
        sip_registrar: None,
        sip_transport: "udp".into(),
        sip_port: 5060,
        sip_auth_username: None,
        sip_display_name: String::new(),
        active: true,
        created_at: now,
        updated_at: now,
        last_register_at: None,
    }
}

/// A stand-in for FCM: answers `messages:send` after a set latency with a
/// set status, and reports each accepted push's call token as delivered.
#[cfg(test)]
pub(crate) mod mock {
    use super::*;
    use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
    use tokio::sync::mpsc;

    struct State {
        latency_ms: AtomicU64,
        status: AtomicU16,
        delivered: mpsc::UnboundedSender<(String, std::time::Instant)>,
    }

    pub(crate) struct MockFcm {
        url: String,
        state: Arc<State>,
        /// Call tokens of accepted pushes, with when the push was accepted.
        pub(crate) delivered: mpsc::UnboundedReceiver<(String, std::time::Instant)>,
    }

    impl MockFcm {
        pub(crate) async fn start() -> Self {
            let (tx, rx) = mpsc::unbounded_channel();
            let state = Arc::new(State {
                latency_ms: AtomicU64::new(0),
                status: AtomicU16::new(200),
                delivered: tx,
            });
            let app = axum::Router::new()
                .route("/v1/projects/test/messages:send", axum::routing::post(send))
                .with_state(state.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            tokio::spawn(async move { axum::serve(listener, app).await });
            Self {
                url,
                state,
                delivered: rx,
            }
        }

        /// How long FCM takes to accept a push.
        pub(crate) fn set_latency(&self, latency: Duration) {
            self.state
                .latency_ms
                .store(latency.as_millis() as u64, Ordering::SeqCst);
        }

        /// The status FCM answers with.
        pub(crate) fn set_status(&self, status: u16) {
            self.state.status.store(status, Ordering::SeqCst);
        }

        /// An FCM-only manager pushing here, with a valid cached access
        /// token, that knows the Android device `device_id`.
        pub(crate) async fn manager(&self, device_id: &str) -> Arc<PushManager> {
            let manager = PushManager {
                apns: None,
                fcm: Some(FcmClient {
                    send_url: format!("{}/v1/projects/test/messages:send", self.url),
                    token_url: format!("{}/token", self.url),
                    http: provider_client(false).unwrap(),
                    access_token: RwLock::new(Some((
                        "test-access-token".into(),
                        chrono::Utc::now().timestamp() + 3600,
                    ))),
                    client_email: String::new(),
                    private_key_pem: String::new(),
                }),
                devices: RwLock::new(HashMap::new()),
            };
            manager
                .register_device(test_device(device_id, "android"))
                .await;
            Arc::new(manager)
        }
    }

    async fn send(
        axum::extract::State(state): axum::extract::State<Arc<State>>,
        axum::Json(body): axum::Json<serde_json::Value>,
    ) -> (axum::http::StatusCode, &'static str) {
        let latency = state.latency_ms.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(latency)).await;
        let status = state.status.load(Ordering::SeqCst);
        if status == 200 {
            let token = body["message"]["data"]["callToken"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let _ = state.delivered.send((token, std::time::Instant::now()));
        }
        (
            axum::http::StatusCode::from_u16(status).unwrap(),
            r#"{"error":"mock"}"#,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_are_refreshed_ahead_of_their_inline_expiry() {
        let now = 1_000_000;
        assert!(apns_jwt_due(None, now));
        assert!(!apns_jwt_due(Some(now - APNS_JWT_REFRESH_SECS + 1), now));
        assert!(apns_jwt_due(Some(now - APNS_JWT_REFRESH_SECS), now));
        // Background refresh happens before a push would mint inline.
        const { assert!(APNS_JWT_REFRESH_SECS < APNS_JWT_REUSE_SECS) };

        assert!(fcm_token_due(None, now));
        assert!(!fcm_token_due(Some(now + FCM_TOKEN_REFRESH_SECS + 1), now));
        assert!(fcm_token_due(Some(now + FCM_TOKEN_REFRESH_SECS), now));
        const { assert!(FCM_TOKEN_REFRESH_SECS > FCM_TOKEN_MARGIN_SECS) };
    }

    #[tokio::test]
    async fn a_fresh_fcm_token_is_not_refetched() {
        let fcm = mock::MockFcm::start().await;
        let manager = fcm.manager("dev").await;
        // The cached token is good for an hour: nothing is fetched (the
        // mock has no token endpoint) and the next look is ~50 min away.
        let wait = manager.refresh_credentials().await;
        assert!(wait > Duration::from_secs(2900), "{wait:?}");
        assert!(wait <= Duration::from_secs(3000), "{wait:?}");
    }

    fn alert() -> Alert {
        Alert {
            title: "+15551230000".into(),
            body: Some("hello".into()),
            thread_id: Some("did:+15551230000".into()),
            category: None,
            data: [("type".to_string(), "sms".to_string())].into(),
        }
    }

    #[test]
    fn an_alert_with_a_category_sets_aps_category() {
        let mut a = alert();
        a.category = Some("HOLD_WAIT".into());
        assert_eq!(apns_alert_payload(&a)["aps"]["category"], "HOLD_WAIT");
        assert!(apns_alert_payload(&alert())["aps"]
            .get("category")
            .is_none());
        // FCM is unchanged.
        assert_eq!(
            fcm_alert_message("tok", &a),
            fcm_alert_message("tok", &alert())
        );
    }

    #[test]
    fn an_apns_alert_is_a_banner_with_the_data_beside_aps() {
        let p = apns_alert_payload(&alert());
        assert_eq!(p["aps"]["alert"]["title"], "+15551230000");
        assert_eq!(p["aps"]["alert"]["body"], "hello");
        assert_eq!(p["aps"]["thread-id"], "did:+15551230000");
        assert_eq!(p["type"], "sms");
        assert!(p["aps"].get("content-available").is_none());

        let mut quiet = alert();
        quiet.body = None;
        assert!(apns_alert_payload(&quiet)["aps"]["alert"]
            .get("body")
            .is_none());
    }

    #[test]
    fn an_fcm_alert_is_a_notification_message_with_the_data() {
        let m = fcm_alert_message("tok", &alert());
        assert_eq!(m["message"]["token"], "tok");
        assert_eq!(m["message"]["notification"]["title"], "+15551230000");
        assert_eq!(m["message"]["data"]["type"], "sms");
        assert_eq!(
            m["message"]["android"]["notification"]["tag"],
            "did:+15551230000"
        );
    }

    #[tokio::test]
    async fn alerts_reach_android_and_an_ios_device_without_a_token_is_refused() {
        let fcm = mock::MockFcm::start().await;
        let manager = fcm.manager("dev").await;
        manager
            .send_alert(&test_device("dev", "android"), &alert())
            .await
            .unwrap();
        let err = manager
            .send_alert(&test_device("ios", "ios"), &alert())
            .await
            .unwrap_err();
        assert!(matches!(err, PushError::NoAlertToken), "{err}");
    }

    #[tokio::test]
    async fn push_outcomes() {
        let mut fcm = mock::MockFcm::start().await;
        let manager = fcm.manager("dev").await;

        manager
            .send_incoming_call(
                "dev",
                "tok-1",
                "2000@pbx",
                None,
                &IncomingCallExtras::default(),
            )
            .await
            .unwrap();
        assert_eq!(fcm.delivered.recv().await.unwrap().0, "tok-1");

        let err = manager
            .send_incoming_call(
                "ghost",
                "tok-2",
                "2000@pbx",
                None,
                &IncomingCallExtras::default(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, PushError::NoDevice), "{err}");

        fcm.set_status(404);
        let err = manager
            .send_incoming_call(
                "dev",
                "tok-3",
                "2000@pbx",
                None,
                &IncomingCallExtras::default(),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, PushError::Rejected { status: 404, .. }),
            "{err}"
        );
        assert_eq!(err.sip_reason_text(), "Push rejected by provider");

        manager.register_device(test_device("ios-dev", "ios")).await;
        let err = manager
            .send_incoming_call(
                "ios-dev",
                "tok-4",
                "2000@pbx",
                None,
                &IncomingCallExtras::default(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, PushError::NotConfigured("APNs")), "{err}");
    }

    #[test]
    fn push_payloads_carry_the_hold_return_only_for_a_hold_return() {
        let extras = IncomingCallExtras {
            hold_return_id: Some("hw-1".into()),
            hold_return_name: Some("Acme Bank".into()),
            ..Default::default()
        };
        let apns = serde_json::to_value(apns_payload(
            "t",
            "+18005550100@pbx",
            Some("Acme Bank"),
            &extras,
        ))
        .unwrap();
        assert_eq!(apns["holdReturnId"], "hw-1");
        assert_eq!(apns["holdReturnName"], "Acme Bank");
        assert!(apns.get("moveId").is_none());
        let fcm = fcm_data("t", "+18005550100@pbx", Some("Acme Bank"), &extras);
        assert_eq!(fcm["holdReturnId"], "hw-1");
        assert_eq!(fcm["holdReturnName"], "Acme Bank");
        let plain = serde_json::to_value(apns_payload(
            "t",
            "2000@pbx",
            None,
            &IncomingCallExtras::default(),
        ))
        .unwrap();
        assert!(plain.get("holdReturnId").is_none() && plain.get("holdReturnName").is_none());
    }

    #[test]
    fn move_and_hold_return_travel_independently() {
        let raw = "INVITE sip:a@b SIP/2.0\r\nX-Aria-Move: m-1\r\nX-Aria-Hold-Return: hw-1\r\n\r\n";
        let e = IncomingCallExtras::from_invite(raw);
        assert_eq!(
            (e.move_id.as_deref(), e.hold_return_id.as_deref()),
            (Some("m-1"), Some("hw-1"))
        );
    }

    #[test]
    fn an_empty_hold_return_header_is_absent() {
        let e = IncomingCallExtras::from_invite(
            "INVITE sip:a@b SIP/2.0\r\nX-Aria-Hold-Return: \r\n\r\n",
        );
        assert!(e.hold_return_id.is_none());
    }

    #[test]
    fn a_dirty_hold_return_name_is_cleaned_at_the_invite() {
        let raw = format!(
            "INVITE sip:a@b SIP/2.0\r\nX-Aria-Hold-Return: hw-1\r\nX-Aria-Hold-Return-Name: \"Acme\" <Bank>\\ {}\r\n\r\n",
            "\u{e9}".repeat(200)
        );
        let e = IncomingCallExtras::from_invite(&raw);
        let name = e.hold_return_name.expect("name kept");
        assert_eq!(name.chars().count(), 64);
        assert!(!name.contains(['"', '<', '>', '\\']));
        assert_eq!(
            name,
            format!("Acme Bank {}", "\u{e9}".repeat(64 - "Acme Bank ".len()))
        );

        let empty = IncomingCallExtras::from_invite(
            "INVITE sip:a@b SIP/2.0\r\nX-Aria-Hold-Return: hw-1\r\nX-Aria-Hold-Return-Name: <>\r\n\r\n",
        );
        assert_eq!(empty.hold_return_name, None);
    }

    #[test]
    fn push_payloads_carry_the_move_id_only_for_a_move() {
        let moved_extras = IncomingCallExtras {
            move_id: Some("m-1".into()),
            ..Default::default()
        };
        let plain = serde_json::to_value(apns_payload(
            "t",
            "2000@pbx",
            Some("Bob"),
            &IncomingCallExtras::default(),
        ))
        .unwrap();
        assert!(plain.get("moveId").is_none() && plain.get("moveFrom").is_none());
        let moved = serde_json::to_value(apns_payload("t", "2000@pbx", Some("Bob"), &moved_extras))
            .unwrap();
        assert_eq!(moved["moveId"], "m-1");
        assert_eq!(moved["moveFrom"], "Bob");
        assert_eq!(moved["callToken"], "t");
        let no_name =
            serde_json::to_value(apns_payload("t", "2000@pbx", None, &moved_extras)).unwrap();
        assert_eq!(no_name["moveFrom"], "2000@pbx");

        let plain = fcm_data("t", "2000@pbx", Some("Bob"), &IncomingCallExtras::default());
        assert!(!plain.contains_key("moveId") && !plain.contains_key("moveFrom"));
        let moved = fcm_data("t", "2000@pbx", Some("Bob"), &moved_extras);
        assert_eq!(moved["moveId"], "m-1");
        assert_eq!(moved["moveFrom"], "Bob");
        assert_eq!(moved["type"], "incoming_call");
    }
}
