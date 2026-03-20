//! HTTP API server for the push gateway.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::auth::{self, AuthUser, JwtSecret};
use crate::db::{Database, DeviceRecord};
use crate::handoff::{self, HandoffManager};
use crate::push::PushManager;
use crate::sip::SipProxyManager;

#[derive(Clone)]
struct AppState {
    db: Database,
    sip_proxy: Arc<SipProxyManager>,
    push_manager: Arc<PushManager>,
    handoff: Arc<HandoffManager>,
    jwt_secret: String,
    token_expiry_secs: u64,
}

pub fn build_router(
    db: Database,
    sip_proxy: Arc<SipProxyManager>,
    push_manager: Arc<PushManager>,
    handoff: Arc<HandoffManager>,
    jwt_secret: String,
    token_expiry_secs: u64,
) -> Router {
    let state = AppState {
        db,
        sip_proxy,
        push_manager,
        handoff,
        jwt_secret: jwt_secret.clone(),
        token_expiry_secs,
    };

    Router::new()
        // Auth
        .route("/v1/auth/token", post(create_token))
        // Device management
        .route("/v1/devices", post(register_device))
        .route("/v1/devices/{id}", get(get_device_status))
        .route("/v1/devices/{id}", delete(unregister_device))
        // Call signaling
        .route("/v1/calls", post(make_call))
        .route("/v1/calls/{token}", get(get_call_offer))
        .route("/v1/calls/{token}/accept", post(accept_call))
        .route("/v1/calls/{token}/reject", post(reject_call))
        .route("/v1/calls/{token}/hangup", post(hangup_call))
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
    /// User identifier — typically the SIP username@domain
    user_id: String,
    /// Shared secret for token creation (optional — if omitted or "auto", issued freely)
    #[serde(default)]
    api_key: Option<String>,
}

#[derive(Serialize)]
struct TokenResponse {
    token: String,
    expires_in: u64,
}

async fn create_token(
    State(state): State<AppState>,
    Json(req): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, StatusCode> {
    // If an API key is provided and it's not the placeholder "auto", verify it
    if let Some(ref key) = req.api_key {
        if key != "auto" && !key.is_empty() && key != &state.jwt_secret {
            return Err(StatusCode::UNAUTHORIZED);
        }
    }

    let expiry = state.token_expiry_secs;
    let token = auth::create_token(&req.user_id, &state.jwt_secret, expiry)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(TokenResponse {
        token,
        expires_in: expiry,
    }))
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

    // Deactivate previous devices for the same username OR same push token.
    // Same username: prevents stale registrations accumulating.
    // Same push token: prevents one physical device being registered as multiple extensions.
    if let Err(e) = state.db.deactivate_devices_for_user(&record.sip_username).await {
        tracing::warn!(user = %record.sip_username, %e, "failed to deactivate old devices by user");
    }
    if let Err(e) = state.db.deactivate_devices_for_token(&record.push_token).await {
        tracing::warn!(%e, "failed to deactivate old devices by token");
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
    _auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<DeviceStatusResponse>, StatusCode> {
    let device = state
        .db
        .get_device(&id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

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
    _auth: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, StatusCode> {
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

// ── Call Signaling ───────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct MakeCallRequest {
    destination_uri: String,
    sdp_offer: String,
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
async fn make_call(
    State(state): State<AppState>,
    _auth: AuthUser,
    Json(req): Json<MakeCallRequest>,
) -> Result<Json<MakeCallResponse>, StatusCode> {
    let (call_token, sdp_answer) = state
        .sip_proxy
        .originate_call(
            &req.destination_uri,
            &req.sdp_offer,
            &req.sip_username,
            &req.sip_password,
            &req.sip_domain,
            req.sip_registrar.as_deref(),
            &req.sip_transport,
            req.sip_port,
            req.sip_auth_username.as_deref(),
            &req.sip_display_name,
            state.handoff.clone(),
        )
        .await
        .map_err(|e| {
            tracing::error!("Outgoing call failed: {}", e);
            StatusCode::BAD_GATEWAY
        })?;

    Ok(Json(MakeCallResponse {
        call_token,
        sdp_answer,
    }))
}

async fn get_call_offer(
    State(state): State<AppState>,
    _auth: AuthUser,
    Path(token): Path<String>,
) -> Result<Json<handoff::CallOffer>, StatusCode> {
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
    _auth: AuthUser,
    Path(token): Path<String>,
    Json(req): Json<AcceptCallRequest>,
) -> Result<StatusCode, StatusCode> {
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
    _auth: AuthUser,
    Path(token): Path<String>,
) -> Result<StatusCode, StatusCode> {
    state
        .handoff
        .reject_call(&token)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    Ok(StatusCode::OK)
}

async fn hangup_call(
    State(state): State<AppState>,
    _auth: AuthUser,
    Path(token): Path<String>,
) -> Result<StatusCode, StatusCode> {
    state
        .handoff
        .hangup_call(&token)
        .await
        .map_err(|e| {
            tracing::error!("Hangup failed: {}", e);
            StatusCode::NOT_FOUND
        })?;

    Ok(StatusCode::OK)
}

async fn get_call_status(
    State(state): State<AppState>,
    _auth: AuthUser,
    Path(token): Path<String>,
) -> Json<handoff::CallStatus> {
    Json(state.handoff.get_call_status(&token).await)
}
