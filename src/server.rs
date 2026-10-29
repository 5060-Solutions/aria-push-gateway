//! HTTP API server for the push gateway.

use std::sync::Arc;

use axum::{
    extract::{rejection::JsonRejection, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::auth::{self, AuthUser, JwtSecret};
use crate::db::{Database, DeviceRecord};
use crate::handoff::{self, CallOwner, HandoffManager, TransferError};
use crate::push::PushManager;
use crate::sip::proxy::{is_valid_client_ref, OriginateRefusal};
use crate::sip::SipProxyManager;

#[derive(Clone)]
struct AppState {
    db: Database,
    sip_proxy: Arc<SipProxyManager>,
    push_manager: Arc<PushManager>,
    handoff: Arc<HandoffManager>,
    jwt_secret: String,
    token_expiry_secs: u64,
    /// Key a trusted backend must present to mint tokens; `None` disables
    /// the token endpoint.
    token_issuer_key: Option<Arc<str>>,
}

pub fn build_router(
    db: Database,
    sip_proxy: Arc<SipProxyManager>,
    push_manager: Arc<PushManager>,
    handoff: Arc<HandoffManager>,
    jwt_secret: String,
    token_expiry_secs: u64,
    token_issuer_key: Option<String>,
) -> Router {
    let state = AppState {
        db,
        sip_proxy,
        push_manager,
        handoff,
        jwt_secret: jwt_secret.clone(),
        token_expiry_secs,
        token_issuer_key: token_issuer_key.map(Arc::from),
    };

    Router::new()
        // Auth
        .route("/v1/auth/token", post(create_token))
        // Device management
        .route("/v1/devices", post(register_device))
        .route("/v1/devices/{id}", get(get_device_status))
        .route("/v1/devices/{id}", delete(unregister_device))
        .route("/v1/devices/{id}/heartbeat", post(device_heartbeat))
        // Call signaling
        .route("/v1/calls", post(make_call))
        .route("/v1/calls/cancel", post(cancel_call))
        .route("/v1/calls/{token}", get(get_call_offer))
        .route("/v1/calls/{token}/accept", post(accept_call))
        .route("/v1/calls/{token}/reject", post(reject_call))
        .route("/v1/calls/{token}/hangup", post(hangup_call))
        .route("/v1/calls/{token}/transfer", post(transfer_call))
        .route("/v1/calls/{token}/status", get(get_call_status))
        // Health check
        .route("/health", get(health_check))
        .layer(axum::Extension(JwtSecret(jwt_secret)))
        .with_state(state)
}

// ── Health ───────────────────────────────────────────────────────────────────

async fn health_check() -> &'static str {
    "ok"
}

// ── Auth ─────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct TokenRequest {
    /// User identifier the token is issued for (the JWT `sub`).
    user_id: String,
    /// Must equal the configured `TOKEN_ISSUER_KEY`.
    #[serde(default)]
    api_key: Option<String>,
}

#[derive(Serialize)]
struct TokenResponse {
    token: String,
    expires_in: u64,
}

/// Whether `presented` matches the issuer key, compared in constant time.
fn issuer_key_matches(presented: &str, expected: &str) -> bool {
    use subtle::ConstantTimeEq;
    bool::from(presented.as_bytes().ct_eq(expected.as_bytes()))
}

/// Mint a JWT for `user_id`.
///
/// Only a trusted backend holding `TOKEN_ISSUER_KEY` may call this. A missing,
/// empty, `"auto"` or wrong key gets 401; if no issuer key is configured the
/// endpoint is disabled and answers 503.
async fn create_token(
    State(state): State<AppState>,
    body: Result<Json<TokenRequest>, JsonRejection>,
) -> Result<Json<TokenResponse>, StatusCode> {
    let Some(expected) = state.token_issuer_key.as_deref() else {
        tracing::warn!("token request refused: TOKEN_ISSUER_KEY is not configured");
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    };

    let Json(req) = body.map_err(|_| StatusCode::BAD_REQUEST)?;

    let presented = req.api_key.as_deref().unwrap_or_default();
    if presented.is_empty()
        || presented.eq_ignore_ascii_case("auto")
        || !issuer_key_matches(presented, expected)
    {
        tracing::warn!("token request refused: invalid api_key");
        return Err(StatusCode::UNAUTHORIZED);
    }

    if req.user_id.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let expiry = state.token_expiry_secs;
    let token = auth::create_token(&req.user_id, &state.jwt_secret, expiry)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(TokenResponse {
        token,
        expires_in: expiry,
    }))
}

// ── Ownership ────────────────────────────────────────────────────────────────
//
// Every device and call route answers 404 when the resource exists but
// belongs to someone else, so a caller can't probe for other users' IDs.

/// Load device `id` if it belongs to `user`; 404 otherwise.
async fn owned_device(
    state: &AppState,
    user: &AuthUser,
    id: &str,
) -> Result<DeviceRecord, StatusCode> {
    let device = state
        .db
        .get_device(id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    if device.user_id != user.user_id {
        tracing::warn!(device_id = %id, user = %user.user_id, "device request by non-owner");
        return Err(StatusCode::NOT_FOUND);
    }
    Ok(device)
}

/// Whether the call behind `token` belongs to `user`: an incoming call must
/// have been delivered to one of the user's devices, an outgoing call must
/// have been placed by the user. Unknown tokens are not owned.
async fn owns_call(state: &AppState, user: &AuthUser, token: &str) -> Result<bool, StatusCode> {
    let owned = match state.handoff.call_owner(token).await {
        None => false,
        Some(CallOwner::User(owner)) => owner == user.user_id,
        Some(CallOwner::Device(device_id)) => state
            .db
            .get_device(&device_id)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .is_some_and(|d| d.user_id == user.user_id),
    };
    Ok(owned)
}

/// 404 unless the call behind `token` belongs to `user`.
async fn require_call_owner(
    state: &AppState,
    user: &AuthUser,
    token: &str,
) -> Result<(), StatusCode> {
    if owns_call(state, user, token).await? {
        Ok(())
    } else {
        tracing::debug!(user = %user.user_id, "call request for a token the user does not own");
        Err(StatusCode::NOT_FOUND)
    }
}

// ── Device Registration ──────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RegisterDeviceRequest {
    platform: String,
    push_token: String,
    bundle_id: Option<String>,
    sip_username: String,
    sip_password: String,
    sip_domain: String,
    sip_registrar: Option<String>,
    #[serde(default = "default_transport")]
    sip_transport: String,
    #[serde(default = "default_port")]
    sip_port: u16,
    sip_auth_username: Option<String>,
    #[serde(default)]
    sip_display_name: String,
}

fn default_transport() -> String {
    "udp".to_string()
}
fn default_port() -> u16 {
    5060
}

#[derive(Serialize)]
struct RegisterDeviceResponse {
    device_id: String,
    status: String,
}

async fn register_device(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<RegisterDeviceRequest>,
) -> Result<Json<RegisterDeviceResponse>, StatusCode> {
    let device_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now();

    let record = DeviceRecord {
        id: device_id.clone(),
        user_id: auth.user_id,
        platform: req.platform,
        push_token: req.push_token,
        bundle_id: req.bundle_id,
        sip_username: req.sip_username,
        sip_password: req.sip_password,
        sip_domain: req.sip_domain,
        sip_registrar: req.sip_registrar,
        sip_transport: req.sip_transport,
        sip_port: req.sip_port as i64,
        sip_auth_username: req.sip_auth_username,
        sip_display_name: req.sip_display_name,
        active: true,
        created_at: now,
        updated_at: now,
        last_register_at: None,
    };

    // Replace the caller's own earlier registrations for the same SIP user or
    // the same push token (one physical device shouldn't be registered as
    // several extensions). Only the caller's devices are touched: a matching
    // username or push token on another user's device is left alone, since
    // nothing here proves the caller owns that SIP account or phone.
    if let Err(e) = state
        .db
        .deactivate_user_devices_for_sip_user(&record.user_id, &record.sip_username)
        .await
    {
        tracing::warn!(user = %record.user_id, %e, "failed to deactivate old devices by SIP user");
    }
    if let Err(e) = state
        .db
        .deactivate_user_devices_for_token(&record.user_id, &record.push_token)
        .await
    {
        tracing::warn!(user = %record.user_id, %e, "failed to deactivate old devices by token");
    }
    match state
        .db
        .count_other_users_devices_for_token(&record.user_id, &record.push_token)
        .await
    {
        Ok(0) => {}
        Ok(n) => tracing::warn!(
            user = %record.user_id,
            device_id = %record.id,
            other_devices = n,
            "push token is also registered by another user — keeping both registrations"
        ),
        Err(e) => tracing::warn!(%e, "failed to check push token reuse"),
    }

    // Save to database
    state
        .db
        .upsert_device(&record)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Register for push notifications
    state.push_manager.register_device(record.clone()).await;

    // Start SIP proxy registration
    let sip_config = record.sip_config();
    state
        .sip_proxy
        .register_device(
            device_id.clone(),
            sip_config,
            state.push_manager.clone(),
            state.handoff.clone(),
        )
        .await
        .map_err(|e| {
            tracing::error!("SIP proxy registration failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(RegisterDeviceResponse {
        device_id,
        status: "registering".to_string(),
    }))
}

// ── Device Status / Unregister ───────────────────────────────────────────────

#[derive(Serialize)]
struct DeviceStatusResponse {
    device_id: String,
    sip_status: String,
    active: bool,
}

async fn get_device_status(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<DeviceStatusResponse>, StatusCode> {
    let device = owned_device(&state, &auth, &id).await?;

    let sip_status = state
        .sip_proxy
        .get_status(&id)
        .await
        .unwrap_or_else(|| "unknown".to_string());

    Ok(Json(DeviceStatusResponse {
        device_id: device.id,
        sip_status,
        active: device.active,
    }))
}

async fn unregister_device(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    owned_device(&state, &auth, &id).await?;

    // Unregister from SIP
    let _ = state.sip_proxy.unregister_device(&id).await;

    // Remove from push
    state.push_manager.unregister_device(&id).await;

    // Deactivate in database
    state
        .db
        .deactivate_device(&id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::NO_CONTENT)
}

/// Device heartbeat — re-registers the SIP proxy connection after network change.
///
/// Called by mobile clients when they detect a network change (WiFi→cellular,
/// reconnect after sleep, etc.). Forces a fresh SIP REGISTER to the PBX so
/// the device's registration binding is updated with the new IP/port.
async fn device_heartbeat(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let device = owned_device(&state, &auth, &id).await?;

    if !device.active {
        return Err(StatusCode::GONE);
    }

    tracing::info!(device_id = %id, user = %device.sip_username, "device heartbeat — re-registering SIP");

    // Force SIP re-registration with fresh socket
    let sip_config = device.sip_config();
    if let Err(e) = state
        .sip_proxy
        .register_device(
            id.clone(),
            sip_config,
            state.push_manager.clone(),
            state.handoff.clone(),
        )
        .await
    {
        tracing::warn!(device_id = %id, %e, "heartbeat SIP re-registration failed");
        return Err(StatusCode::BAD_GATEWAY);
    }

    // Update last_register timestamp
    let _ = state.db.touch_device(&id).await;

    Ok(StatusCode::NO_CONTENT)
}

// ── Call Signaling ───────────────────────────────────────────────────────────

/// Body of `POST /v1/calls`.
///
/// Only `sip_username` and `sip_domain` select the SIP account; the call is
/// placed with the stored credentials of the caller's active device for that
/// account. Older clients also send `sip_password`, `sip_registrar`,
/// `sip_transport`, `sip_port`, `sip_auth_username` and `sip_display_name`;
/// those are accepted and ignored.
#[derive(Deserialize)]
struct MakeCallRequest {
    destination_uri: String,
    sdp_offer: String,
    sip_username: String,
    sip_domain: String,
    /// Optional client-chosen handle (1-64 of `[A-Za-z0-9_-]`) for
    /// cancelling the call while it rings via `POST /v1/calls/cancel`.
    #[serde(default)]
    client_ref: Option<String>,
}

/// An error status, optionally with a `{"error": "<code>"}` body.
struct ApiError {
    status: StatusCode,
    code: Option<&'static str>,
}

impl ApiError {
    fn coded(status: StatusCode, code: &'static str) -> Self {
        Self {
            status,
            code: Some(code),
        }
    }
}

impl From<StatusCode> for ApiError {
    fn from(status: StatusCode) -> Self {
        Self { status, code: None }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self.code {
            Some(code) => (self.status, Json(serde_json::json!({ "error": code }))).into_response(),
            None => self.status.into_response(),
        }
    }
}

#[derive(Serialize)]
struct MakeCallResponse {
    call_token: String,
    sdp_answer: String,
}

/// Initiate an outgoing call via the gateway B2BUA.
///
/// The gateway sends a SIP INVITE to the destination on behalf of the
/// mobile client, waits for a 200 OK with SDP answer, and returns both
/// the call_token (for subsequent hangup) and the SDP answer (so the
/// mobile app can set up RTP directly with the remote party).
///
/// The SIP account must belong to an active device the caller owns;
/// otherwise 404. With a `client_ref` the ringing call can be cancelled,
/// in which case this answers 409 `{"error":"cancelled"}`.
async fn make_call(
    State(state): State<AppState>,
    auth: AuthUser,
    body: Result<Json<MakeCallRequest>, JsonRejection>,
) -> Result<Json<MakeCallResponse>, ApiError> {
    let Json(req) = body.map_err(|rejection| ApiError::from(rejection.status()))?;
    if req
        .client_ref
        .as_deref()
        .is_some_and(|r| !is_valid_client_ref(r))
    {
        return Err(ApiError::coded(
            StatusCode::BAD_REQUEST,
            "invalid_client_ref",
        ));
    }

    let device = state
        .db
        .find_active_device_for_account(&auth.user_id, &req.sip_username, &req.sip_domain)
        .await
        .map_err(|_| ApiError::from(StatusCode::INTERNAL_SERVER_ERROR))?
        .ok_or_else(|| {
            tracing::warn!(
                user = %auth.user_id,
                sip_user = %req.sip_username,
                "outgoing call for a SIP account with no active device of the caller"
            );
            ApiError::from(StatusCode::NOT_FOUND)
        })?;

    let (call_token, sdp_answer) = state
        .sip_proxy
        .originate_call(
            &req.destination_uri,
            &req.sdp_offer,
            &device.sip_config(),
            &auth.user_id,
            req.client_ref.as_deref(),
            state.handoff.clone(),
        )
        .await
        .map_err(|e| match e.downcast_ref::<OriginateRefusal>() {
            Some(OriginateRefusal::Cancelled) => ApiError::coded(StatusCode::CONFLICT, "cancelled"),
            Some(OriginateRefusal::ClientRefInUse) => {
                ApiError::coded(StatusCode::CONFLICT, "client_ref_in_use")
            }
            None => {
                tracing::error!("Outgoing call failed: {}", e);
                ApiError::from(StatusCode::BAD_GATEWAY)
            }
        })?;

    Ok(Json(MakeCallResponse {
        call_token,
        sdp_answer,
    }))
}

#[derive(Deserialize)]
struct CancelCallRequest {
    client_ref: String,
}

/// Cancel the caller's own outgoing call that is still ringing, by the
/// `client_ref` given to `POST /v1/calls`. 202 once the CANCEL is under way;
/// 404 if no such call is pending (unknown ref, another user's, or already
/// answered or ended).
async fn cancel_call(
    State(state): State<AppState>,
    auth: AuthUser,
    body: Result<Json<CancelCallRequest>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let Json(req) = body.map_err(|_| ApiError::from(StatusCode::BAD_REQUEST))?;
    if !is_valid_client_ref(&req.client_ref) {
        return Err(ApiError::coded(
            StatusCode::BAD_REQUEST,
            "invalid_client_ref",
        ));
    }
    if state
        .sip_proxy
        .cancel_outgoing_call(&auth.user_id, &req.client_ref)
    {
        Ok(StatusCode::ACCEPTED)
    } else {
        Err(ApiError::from(StatusCode::NOT_FOUND))
    }
}

async fn get_call_offer(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(token): Path<String>,
) -> Result<Json<handoff::CallOffer>, StatusCode> {
    require_call_owner(&state, &auth, &token).await?;
    let offer = state
        .handoff
        .get_call_offer(&token)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    Ok(Json(offer))
}

#[derive(Deserialize)]
struct AcceptCallRequest {
    sdp_answer: String,
}

async fn accept_call(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(token): Path<String>,
    Json(req): Json<AcceptCallRequest>,
) -> Result<StatusCode, StatusCode> {
    require_call_owner(&state, &auth, &token).await?;
    state
        .handoff
        .accept_call(&token, req.sdp_answer)
        .await
        .map_err(|e| {
            tracing::error!("Accept call failed: {}", e);
            StatusCode::NOT_FOUND
        })?;

    Ok(StatusCode::OK)
}

async fn reject_call(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(token): Path<String>,
) -> Result<StatusCode, StatusCode> {
    require_call_owner(&state, &auth, &token).await?;
    state
        .handoff
        .reject_call(&token)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    Ok(StatusCode::OK)
}

async fn hangup_call(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(token): Path<String>,
) -> Result<StatusCode, StatusCode> {
    require_call_owner(&state, &auth, &token).await?;
    state.handoff.hangup_call(&token).await.map_err(|e| {
        tracing::error!("Hangup failed: {}", e);
        StatusCode::NOT_FOUND
    })?;

    Ok(StatusCode::OK)
}

/// Poll a call's state.
///
/// Unlike the other call routes this never answers 404: clients rely on
/// `{"status":"unknown"}` (200) to learn that a call is gone, so a call that
/// belongs to someone else reports `unknown` too, exactly like a token the
/// gateway has never seen.
async fn get_call_status(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(token): Path<String>,
) -> Result<Json<handoff::CallStatus>, StatusCode> {
    if !owns_call(&state, &auth, &token).await? {
        return Ok(Json(handoff::CallStatus::Unknown));
    }
    Ok(Json(state.handoff.get_call_status(&token).await))
}

#[derive(Deserialize)]
struct TransferCallRequest {
    /// Dial string / extension (`1002`) or full `sip:` URI.
    #[serde(default)]
    target: String,
}

/// Blind-transfer an active call by sending a REFER to the PBX.
///
/// Returns 202 once the PBX accepts the REFER; the call then ends through the
/// normal BYE/NOTIFY flow and `/status` reports it as ended.
async fn transfer_call(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(token): Path<String>,
    body: Result<Json<TransferCallRequest>, JsonRejection>,
) -> Result<StatusCode, StatusCode> {
    require_call_owner(&state, &auth, &token).await?;
    let Json(req) = body.map_err(|_| StatusCode::BAD_REQUEST)?;

    state
        .handoff
        .transfer_call(&token, &req.target)
        .await
        .map_err(|e| {
            tracing::warn!(token = %token, "Transfer failed: {}", e);
            match e {
                TransferError::InvalidTarget(_) => StatusCode::BAD_REQUEST,
                TransferError::NotFound => StatusCode::NOT_FOUND,
                TransferError::InProgress => StatusCode::CONFLICT,
                TransferError::Rejected(_) | TransferError::Send(_) => StatusCode::BAD_GATEWAY,
                TransferError::Timeout => StatusCode::GATEWAY_TIMEOUT,
            }
        })?;

    Ok(StatusCode::ACCEPTED)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{header, Method, Request};
    use tower::ServiceExt;

    const JWT_SECRET: &str = "test-jwt-secret";
    const ISSUER_KEY: &str = "test-issuer-key-0123456789abcdef0123";

    struct TestApp {
        router: Router,
        db: Database,
        handoff: Arc<HandoffManager>,
    }

    async fn test_app(issuer_key: Option<&str>) -> TestApp {
        let db = Database::connect_in_memory().await.unwrap();
        let handoff = Arc::new(HandoffManager::new());
        let router = build_router(
            db.clone(),
            Arc::new(SipProxyManager::new()),
            Arc::new(PushManager::new_noop()),
            handoff.clone(),
            JWT_SECRET.to_string(),
            3600,
            issuer_key.map(str::to_string),
        );
        TestApp {
            router,
            db,
            handoff,
        }
    }

    impl TestApp {
        async fn send(&self, req: Request<Body>) -> (StatusCode, String) {
            let resp = self.router.clone().oneshot(req).await.unwrap();
            let status = resp.status();
            let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
                .await
                .unwrap();
            (status, String::from_utf8(body.to_vec()).unwrap())
        }

        async fn post_json(&self, path: &str, body: serde_json::Value) -> (StatusCode, String) {
            self.send(
                Request::builder()
                    .method(Method::POST)
                    .uri(path)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
        }

        async fn call(&self, method: Method, path: &str, user: &str) -> (StatusCode, String) {
            let jwt = auth::create_token(user, JWT_SECRET, 3600).unwrap();
            let mut req = Request::builder()
                .method(method.clone())
                .uri(path)
                .header(header::AUTHORIZATION, format!("Bearer {jwt}"));
            let body = if method == Method::POST {
                req = req.header(header::CONTENT_TYPE, "application/json");
                if path.ends_with("/accept") {
                    r#"{"sdp_answer":"v=0\r\n"}"#
                } else if path.ends_with("/transfer") {
                    r#"{"target":"1002"}"#
                } else {
                    "{}"
                }
            } else {
                ""
            };
            self.send(req.body(Body::from(body)).unwrap()).await
        }

        async fn add_device(&self, id: &str, user_id: &str, active: bool) {
            self.add_device_with(
                id,
                user_id,
                &format!("sip-{id}"),
                &format!("push-{id}"),
                active,
            )
            .await;
        }

        async fn add_device_with(
            &self,
            id: &str,
            user_id: &str,
            sip_username: &str,
            push_token: &str,
            active: bool,
        ) {
            let now = chrono::Utc::now();
            self.db
                .upsert_device(&DeviceRecord {
                    id: id.into(),
                    user_id: user_id.into(),
                    platform: "android".into(),
                    push_token: push_token.into(),
                    bundle_id: None,
                    sip_username: sip_username.into(),
                    sip_password: "pw".into(),
                    sip_domain: "pbx.example.com".into(),
                    sip_registrar: None,
                    sip_transport: "udp".into(),
                    sip_port: 5060,
                    sip_auth_username: None,
                    sip_display_name: String::new(),
                    active,
                    created_at: now,
                    updated_at: now,
                    last_register_at: None,
                })
                .await
                .unwrap();
        }

        async fn device_active(&self, id: &str) -> bool {
            self.db.get_device(id).await.unwrap().unwrap().active
        }
    }

    /// A UDP socket standing in for the PBX, and a registration that sends
    /// to it from a gateway-side socket.
    async fn fake_pbx(
        handoff: &Arc<HandoffManager>,
    ) -> (
        tokio::net::UdpSocket,
        Arc<tokio::sync::RwLock<crate::sip::proxy::ProxyRegistration>>,
    ) {
        use crate::sip::proxy::ProxyRegistration;
        let pbx = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let gw = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let reg = Arc::new(tokio::sync::RwLock::new(ProxyRegistration::for_test(
            gw,
            "pbx.example.com",
            handoff.clone(),
        )));
        (pbx, reg)
    }

    async fn recv_text(sock: &tokio::net::UdpSocket) -> String {
        let mut buf = vec![0u8; 65535];
        let len = tokio::time::timeout(std::time::Duration::from_secs(2), sock.recv(&mut buf))
            .await
            .expect("timed out waiting for SIP message")
            .unwrap();
        String::from_utf8(buf[..len].to_vec()).unwrap()
    }

    const INVITE: &str = "\
INVITE sip:1001@127.0.0.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-inv\r\n\
From: \"Bob\" <sip:2000@pbx.example.com>;tag=pbxtag\r\n\
To: <sip:1001@pbx.example.com>\r\n\
Call-ID: in-call-1\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:2000@127.0.0.1:5060>\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 10\r\n\r\n\
v=0\r\no=x\r\n";

    const OK_200: &str = "\
SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP 127.0.0.1:40000;branch=z9hG4bK-out;rport\r\n\
From: <sip:1001@pbx.example.com>;tag=gwtag\r\n\
To: <sip:2000@pbx.example.com>;tag=pbxtag\r\n\
Call-ID: out-call-1\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:2000@127.0.0.1:5060>\r\n\
Content-Length: 0\r\n\r\n";

    // ── Token minting ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn token_is_issued_for_the_correct_issuer_key() {
        let app = test_app(Some(ISSUER_KEY)).await;
        let (status, body) = app
            .post_json(
                "/v1/auth/token",
                serde_json::json!({"user_id": "ext-1", "api_key": ISSUER_KEY}),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["expires_in"], 3600);
        let claims = auth::verify_token(json["token"].as_str().unwrap(), JWT_SECRET).unwrap();
        assert_eq!(claims.sub, "ext-1");
    }

    #[tokio::test]
    async fn token_is_refused_without_the_issuer_key() {
        let app = test_app(Some(ISSUER_KEY)).await;
        for body in [
            serde_json::json!({"user_id": "ext-1"}),
            serde_json::json!({"user_id": "ext-1", "api_key": null}),
            serde_json::json!({"user_id": "ext-1", "api_key": ""}),
            serde_json::json!({"user_id": "ext-1", "api_key": "auto"}),
            serde_json::json!({"user_id": "ext-1", "api_key": "wrong"}),
            serde_json::json!({"user_id": "ext-1", "api_key": &ISSUER_KEY[1..]}),
            serde_json::json!({"user_id": "ext-1", "api_key": format!("{ISSUER_KEY}x")}),
            // The JWT signing secret is no longer accepted as a key.
            serde_json::json!({"user_id": "ext-1", "api_key": JWT_SECRET}),
        ] {
            let (status, _) = app.post_json("/v1/auth/token", body.clone()).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        }
    }

    #[tokio::test]
    async fn token_endpoint_is_disabled_without_a_configured_key() {
        let app = test_app(None).await;
        for key in ["", "auto", "anything", JWT_SECRET] {
            let (status, _) = app
                .post_json(
                    "/v1/auth/token",
                    serde_json::json!({"user_id": "ext-1", "api_key": key}),
                )
                .await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{key:?}");
        }
    }

    #[tokio::test]
    async fn token_requires_a_user_id() {
        let app = test_app(Some(ISSUER_KEY)).await;
        let (status, _) = app
            .post_json(
                "/v1/auth/token",
                serde_json::json!({"user_id": "  ", "api_key": ISSUER_KEY}),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    // ── Device ownership ────────────────────────────────────────────────────

    #[tokio::test]
    async fn device_routes_hide_other_users_devices() {
        let app = test_app(Some(ISSUER_KEY)).await;
        app.add_device("bob-dev", "bob", true).await;

        for (method, path) in [
            (Method::GET, "/v1/devices/bob-dev"),
            (Method::DELETE, "/v1/devices/bob-dev"),
            (Method::POST, "/v1/devices/bob-dev/heartbeat"),
        ] {
            let (status, _) = app.call(method.clone(), path, "alice").await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}");
            // Indistinguishable from a device that doesn't exist.
            let missing = path.replace("bob-dev", "no-such-dev");
            let (status, _) = app.call(method.clone(), &missing, "alice").await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{method} {missing}");
        }
        assert!(
            app.device_active("bob-dev").await,
            "alice must not deactivate bob's device"
        );
    }

    #[tokio::test]
    async fn device_routes_work_for_the_owner() {
        let app = test_app(Some(ISSUER_KEY)).await;
        app.add_device("bob-dev", "bob", true).await;
        app.add_device("bob-old", "bob", false).await;

        let (status, body) = app.call(Method::GET, "/v1/devices/bob-dev", "bob").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["device_id"], "bob-dev");
        assert_eq!(json["active"], true);

        // Ownership passes; the inactive device is then reported gone.
        let (status, _) = app
            .call(Method::POST, "/v1/devices/bob-old/heartbeat", "bob")
            .await;
        assert_eq!(status, StatusCode::GONE);

        let (status, _) = app.call(Method::DELETE, "/v1/devices/bob-dev", "bob").await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(!app.device_active("bob-dev").await);
    }

    #[tokio::test]
    async fn device_routes_require_a_token() {
        let app = test_app(Some(ISSUER_KEY)).await;
        app.add_device("bob-dev", "bob", true).await;
        let (status, _) = app
            .send(
                Request::builder()
                    .uri("/v1/devices/bob-dev")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    // ── Call ownership ──────────────────────────────────────────────────────

    async fn pending_call_for(app: &TestApp, device_id: &str) -> (tokio::net::UdpSocket, String) {
        let (pbx, reg) = fake_pbx(&app.handoff).await;
        let token = app
            .handoff
            .create_pending_call(
                device_id.into(),
                "in-call-1".into(),
                INVITE.into(),
                pbx.local_addr().unwrap(),
                reg,
                None,
                String::new(),
                0,
                0,
            )
            .await;
        (pbx, token)
    }

    async fn outgoing_call_for(app: &TestApp, user: &str) -> (tokio::net::UdpSocket, String) {
        let (pbx, reg) = fake_pbx(&app.handoff).await;
        app.handoff
            .register_active_call(
                "out-tok".into(),
                "out-call-1".into(),
                CallOwner::User(user.into()),
                OK_200.into(),
                pbx.local_addr().unwrap(),
                reg,
                None,
            )
            .await;
        (pbx, "out-tok".into())
    }

    fn call_routes(token: &str) -> Vec<(Method, String)> {
        vec![
            (Method::GET, format!("/v1/calls/{token}")),
            (Method::POST, format!("/v1/calls/{token}/accept")),
            (Method::POST, format!("/v1/calls/{token}/reject")),
            (Method::POST, format!("/v1/calls/{token}/hangup")),
            (Method::POST, format!("/v1/calls/{token}/transfer")),
        ]
    }

    #[tokio::test]
    async fn incoming_call_is_hidden_from_other_users() {
        let app = test_app(Some(ISSUER_KEY)).await;
        app.add_device("bob-dev", "bob", true).await;
        let (_pbx, token) = pending_call_for(&app, "bob-dev").await;

        for (method, path) in call_routes(&token) {
            let (status, _) = app.call(method.clone(), &path, "alice").await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}");
        }
        let (status, body) = app
            .call(Method::GET, &format!("/v1/calls/{token}/status"), "alice")
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, r#"{"status":"unknown"}"#);

        // Alice's attempts left bob's call untouched.
        let (_, body) = app
            .call(Method::GET, &format!("/v1/calls/{token}/status"), "bob")
            .await;
        assert_eq!(body, r#"{"status":"pending"}"#);
    }

    #[tokio::test]
    async fn incoming_call_works_for_the_device_owner() {
        let app = test_app(Some(ISSUER_KEY)).await;
        app.add_device("bob-dev", "bob", true).await;
        let (pbx, token) = pending_call_for(&app, "bob-dev").await;

        let (status, body) = app
            .call(Method::GET, &format!("/v1/calls/{token}"), "bob")
            .await;
        assert_eq!(status, StatusCode::OK);
        let offer: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(offer["call_token"], token.as_str());
        assert_eq!(offer["caller_uri"], "2000@pbx.example.com");

        let (status, _) = app
            .call(Method::POST, &format!("/v1/calls/{token}/reject"), "bob")
            .await;
        assert_eq!(status, StatusCode::OK);
        assert!(recv_text(&pbx).await.starts_with("SIP/2.0 603 Decline\r\n"));
    }

    #[tokio::test]
    async fn incoming_call_can_be_accepted_by_the_owner() {
        let app = test_app(Some(ISSUER_KEY)).await;
        app.add_device("bob-dev", "bob", true).await;
        let (pbx, token) = pending_call_for(&app, "bob-dev").await;

        let (status, _) = app
            .call(Method::POST, &format!("/v1/calls/{token}/accept"), "bob")
            .await;
        assert_eq!(status, StatusCode::OK);
        assert!(recv_text(&pbx).await.starts_with("SIP/2.0 200 OK\r\n"));

        // Once active, the call is still bob's and still hidden from alice.
        let status_path = format!("/v1/calls/{token}/status");
        let (_, body) = app.call(Method::GET, &status_path, "bob").await;
        assert_eq!(body, r#"{"status":"active"}"#);
        let (status, _) = app
            .call(Method::POST, &format!("/v1/calls/{token}/hangup"), "alice")
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = app
            .call(Method::POST, &format!("/v1/calls/{token}/hangup"), "bob")
            .await;
        assert_eq!(status, StatusCode::OK);
        assert!(recv_text(&pbx).await.starts_with("BYE "));
    }

    #[tokio::test]
    async fn call_for_an_unknown_device_belongs_to_nobody() {
        let app = test_app(Some(ISSUER_KEY)).await;
        // The call names a device that isn't in the database at all.
        let (_pbx, token) = pending_call_for(&app, "ghost-dev").await;
        let (status, _) = app
            .call(Method::GET, &format!("/v1/calls/{token}"), "bob")
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn outgoing_call_is_hidden_from_other_users() {
        let app = test_app(Some(ISSUER_KEY)).await;
        let (_pbx, token) = outgoing_call_for(&app, "bob").await;

        for (method, path) in call_routes(&token) {
            let (status, _) = app.call(method.clone(), &path, "alice").await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}");
        }
        let status_path = format!("/v1/calls/{token}/status");
        let (_, body) = app.call(Method::GET, &status_path, "alice").await;
        assert_eq!(body, r#"{"status":"unknown"}"#);
        assert!(app.handoff.is_call_active("out-call-1").await);
    }

    #[tokio::test]
    async fn outgoing_call_can_be_hung_up_by_its_caller() {
        let app = test_app(Some(ISSUER_KEY)).await;
        let (pbx, token) = outgoing_call_for(&app, "bob").await;

        let status_path = format!("/v1/calls/{token}/status");
        let (_, body) = app.call(Method::GET, &status_path, "bob").await;
        assert_eq!(body, r#"{"status":"active"}"#);

        let (status, _) = app
            .call(Method::POST, &format!("/v1/calls/{token}/hangup"), "bob")
            .await;
        assert_eq!(status, StatusCode::OK);
        assert!(recv_text(&pbx).await.starts_with("BYE "));
        assert!(!app.handoff.is_call_active("out-call-1").await);
    }

    #[tokio::test]
    async fn ended_call_status_stays_owner_only() {
        let app = test_app(Some(ISSUER_KEY)).await;
        app.add_device("bob-dev", "bob", true).await;
        let (pbx, token) = pending_call_for(&app, "bob-dev").await;
        app.handoff.handle_cancel("in-call-1").await;
        drop(pbx);

        let status_path = format!("/v1/calls/{token}/status");
        let (_, body) = app.call(Method::GET, &status_path, "bob").await;
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["status"], "ended");
        assert_eq!(json["reason"], "cancelled");
        assert!(json.get("owner").is_none());

        let (_, body) = app.call(Method::GET, &status_path, "alice").await;
        assert_eq!(body, r#"{"status":"unknown"}"#);
    }

    #[tokio::test]
    async fn concurrent_transfer_answers_409() {
        let app = test_app(Some(ISSUER_KEY)).await;
        let (pbx, token) = outgoing_call_for(&app, "bob").await;
        let first = {
            let handoff = app.handoff.clone();
            let token = token.clone();
            tokio::spawn(async move { handoff.transfer_call(&token, "1002").await })
        };
        let refer = recv_text(&pbx).await;
        assert!(refer.starts_with("REFER "));

        let (status, _) = app
            .call(Method::POST, &format!("/v1/calls/{token}/transfer"), "bob")
            .await;
        assert_eq!(status, StatusCode::CONFLICT);

        first.abort();
    }

    // ── Device registration ─────────────────────────────────────────────────

    async fn register_as(
        app: &TestApp,
        user: &str,
        sip_username: &str,
        push_token: &str,
        pbx: &tokio::net::UdpSocket,
    ) -> String {
        let jwt = auth::create_token(user, JWT_SECRET, 3600).unwrap();
        let body = serde_json::json!({
            "platform": "android",
            "push_token": push_token,
            "sip_username": sip_username,
            "sip_password": "pw",
            "sip_domain": "pbx.example.com",
            "sip_registrar": "127.0.0.1",
            "sip_port": pbx.local_addr().unwrap().port(),
        });
        let (status, resp) = app
            .send(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/devices")
                    .header(header::AUTHORIZATION, format!("Bearer {jwt}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{resp}");
        assert!(recv_text(pbx).await.starts_with("REGISTER "));
        let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
        json["device_id"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn registering_never_deactivates_another_users_devices() {
        let app = test_app(Some(ISSUER_KEY)).await;
        let pbx = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // Alice's device shares bob's SIP username and push token.
        app.add_device_with("alice-dev", "alice", "1001", "shared-token", true)
            .await;

        let new_dev = register_as(&app, "bob", "1001", "shared-token", &pbx).await;

        assert!(
            app.device_active("alice-dev").await,
            "alice's device must survive"
        );
        assert!(app.device_active(&new_dev).await);
    }

    #[tokio::test]
    async fn registering_replaces_the_callers_own_stale_devices() {
        let app = test_app(Some(ISSUER_KEY)).await;
        let pbx = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        app.add_device_with("bob-same-sip", "bob", "1001", "old-token", true)
            .await;
        app.add_device_with("bob-same-phone", "bob", "1002", "phone-token", true)
            .await;
        app.add_device_with("bob-other", "bob", "1003", "other-token", true)
            .await;

        let new_dev = register_as(&app, "bob", "1001", "phone-token", &pbx).await;

        assert!(!app.device_active("bob-same-sip").await);
        assert!(!app.device_active("bob-same-phone").await);
        assert!(app.device_active("bob-other").await);
        assert!(app.device_active(&new_dev).await);
    }

    // ── Outgoing calls ──────────────────────────────────────────────────────

    /// A device for SIP account `1001@pbx.example.com` whose registrar is
    /// the fake PBX on `pbx_port`, with stored password `stored-pw`.
    async fn add_sip_device(app: &TestApp, id: &str, user_id: &str, pbx_port: u16, active: bool) {
        let now = chrono::Utc::now();
        app.db
            .upsert_device(&DeviceRecord {
                id: id.into(),
                user_id: user_id.into(),
                platform: "android".into(),
                push_token: format!("push-{id}"),
                bundle_id: None,
                sip_username: "1001".into(),
                sip_password: "stored-pw".into(),
                sip_domain: "pbx.example.com".into(),
                sip_registrar: Some("127.0.0.1".into()),
                sip_transport: "udp".into(),
                sip_port: pbx_port as i64,
                sip_auth_username: None,
                sip_display_name: "Bob".into(),
                active,
                created_at: now,
                updated_at: now,
                last_register_at: None,
            })
            .await
            .unwrap();
    }

    /// The body today's mobile clients send, credentials included.
    fn make_call_body(extra: serde_json::Value) -> serde_json::Value {
        let mut body = serde_json::json!({
            "destination_uri": "sip:2000@pbx.example.com",
            "sdp_offer": "v=0\r\n",
            "sip_username": "1001",
            "sip_password": "whatever-the-client-sent",
            "sip_domain": "PBX.example.com",
            "sip_registrar": "203.0.113.9",
            "sip_transport": "udp",
            "sip_port": 5999,
            "sip_auth_username": "someone-else",
            "sip_display_name": "Bob",
        });
        if let (Some(b), Some(e)) = (body.as_object_mut(), extra.as_object()) {
            b.extend(e.clone());
        }
        body
    }

    fn post_as(user: &str, path: &str, body: &serde_json::Value) -> Request<Body> {
        let jwt = auth::create_token(user, JWT_SECRET, 3600).unwrap();
        Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {jwt}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    /// A response to `req` from the fake PBX.
    fn pbx_reply(req: &str, status: &str, extra: &str, body: &str) -> String {
        let h = |n: &str| crate::sip::message::extract_header(req, n).unwrap_or_default();
        format!(
            "SIP/2.0 {status}\r\nVia: {}\r\nFrom: {}\r\nTo: {};tag=pbxtag\r\n\
             Call-ID: {}\r\nCSeq: {}\r\nContact: <sip:2000@127.0.0.1>\r\n{extra}\
             Content-Length: {}\r\n\r\n{body}",
            h("Via"),
            h("From"),
            h("To"),
            h("Call-ID"),
            h("CSeq"),
            body.len()
        )
    }

    async fn recv_from(sock: &tokio::net::UdpSocket) -> (String, std::net::SocketAddr) {
        let mut buf = vec![0u8; 65535];
        let (len, from) =
            tokio::time::timeout(std::time::Duration::from_secs(2), sock.recv_from(&mut buf))
                .await
                .expect("timed out waiting for SIP message")
                .unwrap();
        (String::from_utf8(buf[..len].to_vec()).unwrap(), from)
    }

    #[tokio::test]
    async fn outgoing_call_uses_the_callers_stored_device_credentials() {
        let app = test_app(Some(ISSUER_KEY)).await;
        let pbx = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        add_sip_device(
            &app,
            "bob-dev",
            "bob",
            pbx.local_addr().unwrap().port(),
            true,
        )
        .await;

        let req = post_as("bob", "/v1/calls", &make_call_body(serde_json::json!({})));
        let http = {
            let router = app.router.clone();
            tokio::spawn(async move { router.oneshot(req).await.unwrap() })
        };

        // The INVITE reaches the device's registrar, not the body's.
        let (invite, gw) = recv_from(&pbx).await;
        assert!(invite.starts_with("INVITE sip:2000@pbx.example.com SIP/2.0"));
        assert!(invite.contains("<sip:1001@pbx.example.com>"));
        let challenge = "WWW-Authenticate: Digest realm=\"pbx.example.com\", nonce=\"n1\"\r\n";
        pbx.send_to(
            pbx_reply(&invite, "401 Unauthorized", challenge, "").as_bytes(),
            gw,
        )
        .await
        .unwrap();
        let (ack, _) = recv_from(&pbx).await;
        assert!(ack.starts_with("ACK "));

        // The retry authenticates with the stored password and auth user.
        let (invite2, _) = recv_from(&pbx).await;
        let authz = crate::sip::message::extract_header(&invite2, "Authorization").unwrap();
        let expected = crate::sip::digest::DigestAuth::from_challenge(
            "Digest realm=\"pbx.example.com\", nonce=\"n1\"",
            "1001",
            "stored-pw",
            "sip:2000@pbx.example.com",
            "INVITE",
        )
        .unwrap();
        assert_eq!(authz, expected.to_header());

        pbx.send_to(
            pbx_reply(
                &invite2,
                "200 OK",
                "Content-Type: application/sdp\r\n",
                "v=0\r\n",
            )
            .as_bytes(),
            gw,
        )
        .await
        .unwrap();
        let resp = http.await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["sdp_answer"], "v=0\r\n");
        let token = json["call_token"].as_str().unwrap();
        assert_eq!(
            app.handoff.call_owner(token).await,
            Some(CallOwner::User("bob".into()))
        );
    }

    #[tokio::test]
    async fn outgoing_call_needs_an_active_device_of_the_caller() {
        let app = test_app(Some(ISSUER_KEY)).await;
        let pbx = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = pbx.local_addr().unwrap().port();
        add_sip_device(&app, "alice-dev", "alice", port, true).await;
        add_sip_device(&app, "carol-old", "carol", port, false).await;

        for user in ["bob", "carol"] {
            let (status, _) = app
                .send(post_as(
                    user,
                    "/v1/calls",
                    &make_call_body(serde_json::json!({})),
                ))
                .await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{user}");
        }
        // Alice's own account works only with its own username.
        let (status, _) = app
            .send(post_as(
                "alice",
                "/v1/calls",
                &make_call_body(serde_json::json!({"sip_username": "1002"})),
            ))
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let mut buf = [0u8; 2048];
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(200), pbx.recv(&mut buf))
                .await
                .is_err(),
            "no INVITE may be sent"
        );
    }

    // ── Cancelling a ringing outgoing call ──────────────────────────────────

    struct RingingCall {
        pbx: tokio::net::UdpSocket,
        gw: std::net::SocketAddr,
        invite: String,
        http: tokio::task::JoinHandle<axum::response::Response>,
    }

    /// Bob places a call with `client_ref`; the fake PBX answers 180.
    async fn ringing_call(app: &TestApp, client_ref: &str) -> RingingCall {
        let pbx = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        add_sip_device(
            app,
            "bob-dev",
            "bob",
            pbx.local_addr().unwrap().port(),
            true,
        )
        .await;
        let req = post_as(
            "bob",
            "/v1/calls",
            &make_call_body(serde_json::json!({ "client_ref": client_ref })),
        );
        let http = {
            let router = app.router.clone();
            tokio::spawn(async move { router.oneshot(req).await.unwrap() })
        };
        let (invite, gw) = recv_from(&pbx).await;
        assert!(invite.starts_with("INVITE "));
        pbx.send_to(pbx_reply(&invite, "180 Ringing", "", "").as_bytes(), gw)
            .await
            .unwrap();
        RingingCall {
            pbx,
            gw,
            invite,
            http,
        }
    }

    async fn cancel_as(app: &TestApp, user: &str, client_ref: &str) -> StatusCode {
        app.send(post_as(
            user,
            "/v1/calls/cancel",
            &serde_json::json!({ "client_ref": client_ref }),
        ))
        .await
        .0
    }

    async fn http_result(
        http: tokio::task::JoinHandle<axum::response::Response>,
    ) -> (StatusCode, String) {
        let resp = tokio::time::timeout(std::time::Duration::from_secs(5), http)
            .await
            .expect("POST /v1/calls should have returned")
            .unwrap();
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    fn h(msg: &str, name: &str) -> String {
        crate::sip::message::extract_header(msg, name).unwrap_or_default()
    }

    #[tokio::test]
    async fn ringing_call_can_be_cancelled() {
        let app = test_app(Some(ISSUER_KEY)).await;
        let pbx = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        add_sip_device(
            &app,
            "bob-dev",
            "bob",
            pbx.local_addr().unwrap().port(),
            true,
        )
        .await;
        let req = post_as(
            "bob",
            "/v1/calls",
            &make_call_body(serde_json::json!({ "client_ref": "ref-1" })),
        );
        let http = {
            let router = app.router.clone();
            tokio::spawn(async move { router.oneshot(req).await.unwrap() })
        };

        // Challenge the first INVITE so the CANCEL must match the second.
        let (invite1, gw) = recv_from(&pbx).await;
        let challenge = "WWW-Authenticate: Digest realm=\"pbx.example.com\", nonce=\"n1\"\r\n";
        pbx.send_to(
            pbx_reply(&invite1, "401 Unauthorized", challenge, "").as_bytes(),
            gw,
        )
        .await
        .unwrap();
        let (ack1, _) = recv_from(&pbx).await;
        assert!(ack1.starts_with("ACK "));
        assert_eq!(
            h(&ack1, "Via"),
            h(&invite1, "Via"),
            "non-2xx ACK reuses the branch"
        );
        let (invite, _) = recv_from(&pbx).await;
        assert_eq!(h(&invite, "CSeq"), "2 INVITE");
        pbx.send_to(pbx_reply(&invite, "180 Ringing", "", "").as_bytes(), gw)
            .await
            .unwrap();

        assert_eq!(cancel_as(&app, "bob", "ref-1").await, StatusCode::ACCEPTED);

        let (cancel, _) = recv_from(&pbx).await;
        assert_eq!(
            cancel.lines().next().unwrap(),
            "CANCEL sip:2000@pbx.example.com SIP/2.0"
        );
        assert_eq!(h(&cancel, "Via"), h(&invite, "Via"));
        assert_eq!(h(&cancel, "Call-ID"), h(&invite, "Call-ID"));
        assert_eq!(h(&cancel, "From"), h(&invite, "From"));
        assert_eq!(h(&cancel, "To"), h(&invite, "To"));
        assert_eq!(h(&cancel, "CSeq"), "2 CANCEL");

        pbx.send_to(pbx_reply(&cancel, "200 OK", "", "").as_bytes(), gw)
            .await
            .unwrap();
        pbx.send_to(
            pbx_reply(&invite, "487 Request Terminated", "", "").as_bytes(),
            gw,
        )
        .await
        .unwrap();
        let (ack, _) = recv_from(&pbx).await;
        assert!(ack.starts_with("ACK "));
        assert_eq!(h(&ack, "CSeq"), "2 ACK");
        assert_eq!(h(&ack, "Via"), h(&invite, "Via"));

        let (status, body) = http_result(http).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body, r#"{"error":"cancelled"}"#);

        // The pending entry is gone.
        assert_eq!(cancel_as(&app, "bob", "ref-1").await, StatusCode::NOT_FOUND);
        assert!(!app.handoff.is_call_active(&h(&invite, "Call-ID")).await);
    }

    #[tokio::test]
    async fn answer_crossing_the_cancel_is_hung_up() {
        let app = test_app(Some(ISSUER_KEY)).await;
        let RingingCall {
            pbx,
            gw,
            invite,
            http,
        } = ringing_call(&app, "ref-x").await;

        assert_eq!(cancel_as(&app, "bob", "ref-x").await, StatusCode::ACCEPTED);
        let (cancel, _) = recv_from(&pbx).await;
        assert!(cancel.starts_with("CANCEL "));

        // The PBX had already answered: 200 OK to the INVITE, and the
        // CANCEL finds no pending transaction.
        pbx.send_to(
            pbx_reply(
                &invite,
                "200 OK",
                "Content-Type: application/sdp\r\n",
                "v=0\r\n",
            )
            .as_bytes(),
            gw,
        )
        .await
        .unwrap();
        pbx.send_to(
            pbx_reply(&cancel, "481 Call/Transaction Does Not Exist", "", "").as_bytes(),
            gw,
        )
        .await
        .unwrap();

        // ACK then BYE in the dialog the 200 OK created.
        let mut ack = None;
        let bye = loop {
            let (msg, _) = recv_from(&pbx).await;
            if msg.starts_with("ACK ") {
                ack = Some(msg);
            } else if msg.starts_with("BYE ") {
                break msg;
            }
        };
        assert!(ack.is_some(), "the 200 OK must be ACKed before the BYE");
        assert_eq!(h(&bye, "Call-ID"), h(&invite, "Call-ID"));
        assert_eq!(h(&bye, "CSeq"), "2 BYE");
        assert!(h(&bye, "To").contains("tag=pbxtag"));
        pbx.send_to(pbx_reply(&bye, "200 OK", "", "").as_bytes(), gw)
            .await
            .unwrap();

        let (status, body) = http_result(http).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body, r#"{"error":"cancelled"}"#);
        assert!(!app.handoff.is_call_active(&h(&invite, "Call-ID")).await);
        assert_eq!(cancel_as(&app, "bob", "ref-x").await, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn another_users_ref_cannot_cancel_the_call() {
        let app = test_app(Some(ISSUER_KEY)).await;
        let RingingCall {
            pbx,
            gw,
            invite,
            http,
        } = ringing_call(&app, "shared-ref").await;

        assert_eq!(
            cancel_as(&app, "alice", "shared-ref").await,
            StatusCode::NOT_FOUND
        );
        // The same ref can't be reused for a second pending call.
        let (status, body) = app
            .send(post_as(
                "bob",
                "/v1/calls",
                &make_call_body(serde_json::json!({ "client_ref": "shared-ref" })),
            ))
            .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body, r#"{"error":"client_ref_in_use"}"#);

        // No CANCEL went out; the call connects normally.
        pbx.send_to(
            pbx_reply(
                &invite,
                "200 OK",
                "Content-Type: application/sdp\r\n",
                "v=0\r\n",
            )
            .as_bytes(),
            gw,
        )
        .await
        .unwrap();
        let (ack, _) = recv_from(&pbx).await;
        assert!(ack.starts_with("ACK "), "{ack}");
        let (status, body) = http_result(http).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(app.handoff.is_call_active(&h(&invite, "Call-ID")).await);

        // Once answered, the ref can no longer cancel anything.
        assert_eq!(
            cancel_as(&app, "bob", "shared-ref").await,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn unknown_or_invalid_refs() {
        let app = test_app(Some(ISSUER_KEY)).await;
        assert_eq!(
            cancel_as(&app, "bob", "never-used").await,
            StatusCode::NOT_FOUND
        );

        let too_long = "a".repeat(65);
        for bad in ["", "has space", "semi;colon", "ünï", too_long.as_str()] {
            assert_eq!(
                cancel_as(&app, "bob", bad).await,
                StatusCode::BAD_REQUEST,
                "{bad:?}"
            );
            let (status, _) = app
                .send(post_as(
                    "bob",
                    "/v1/calls",
                    &make_call_body(serde_json::json!({ "client_ref": bad })),
                ))
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{bad:?}");
        }
        let (status, _) = app
            .send(post_as("bob", "/v1/calls/cancel", &serde_json::json!({})))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(is_valid_client_ref(&"a".repeat(64)));
        assert!(is_valid_client_ref("Abc_09-x"));

        // Unauthenticated cancel is refused outright.
        let (status, _) = app
            .send(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/calls/cancel")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"client_ref":"x"}"#))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}
