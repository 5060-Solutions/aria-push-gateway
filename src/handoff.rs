//! Call handoff protocol.
//!
//! When an INVITE arrives at the gateway, we hold it pending while sending
//! a push notification. The mobile app wakes up, connects to the gateway,
//! and provides an SDP answer. The gateway forwards the 200 OK to the PBX
//! with the app's SDP, and RTP flows directly between app and PBX.
//!
//! After acceptance, the call becomes "active" — the gateway tracks it so it
//! can forward BYE in both directions and handle ACK.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use crate::sip::message;

/// A pending call waiting for the mobile app to respond.
struct PendingCall {
    device_id: String,
    call_id: String,
    /// The raw INVITE request from the PBX.
    invite_raw: String,
    /// Where to send the response (PBX address).
    pbx_addr: SocketAddr,
    /// The proxy registration's socket for sending responses.
    proxy_reg: Arc<RwLock<super::sip::proxy::ProxyRegistration>>,
}

/// An active call (post-200 OK) tracked for mid-dialog request forwarding.
pub struct ActiveCall {
    pub device_id: String,
    pub call_id: String,
    pub pbx_addr: SocketAddr,
    pub proxy_reg: Arc<RwLock<super::sip::proxy::ProxyRegistration>>,
    /// The original INVITE (for header reference).
    pub invite_raw: String,
}

/// Manages pending call handoffs and active calls.
pub struct HandoffManager {
    pending: Arc<RwLock<HashMap<String, PendingCall>>>,
    /// Active calls keyed by SIP Call-ID (for mid-dialog routing).
    active: Arc<RwLock<HashMap<String, ActiveCall>>>,
    /// Reverse map: call_token -> call_id (so the app can end calls by token).
    token_to_call_id: Arc<RwLock<HashMap<String, String>>>,
}

impl HandoffManager {
    pub fn new() -> Self {
        Self {
            pending: Arc::new(RwLock::new(HashMap::new())),
            active: Arc::new(RwLock::new(HashMap::new())),
            token_to_call_id: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a pending call entry and return a unique call token.
    pub async fn create_pending_call(
        &self,
        device_id: String,
        call_id: String,
        invite_raw: String,
        pbx_addr: SocketAddr,
        proxy_reg: Arc<RwLock<super::sip::proxy::ProxyRegistration>>,
    ) -> String {
        let call_token = uuid::Uuid::new_v4().to_string();

        let pending = PendingCall {
            device_id,
            call_id,
            invite_raw,
            pbx_addr,
            proxy_reg,
        };

        let token = call_token.clone();
        {
            let mut calls = self.pending.write().await;
            calls.insert(call_token.clone(), pending);
        }

        // Spawn timeout — if app doesn't respond in 30s, send 480
        let pending_ref = Arc::clone(&self.pending);
        let token_clone = token.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(30)).await;
            let mut calls = pending_ref.write().await;
            if let Some(call) = calls.remove(&token_clone) {
                tracing::warn!(
                    token = %token_clone,
                    "Call handoff timed out — sending 480"
                );
                if let Some(resp) = message::build_480(&call.invite_raw) {
                    let reg = call.proxy_reg.read().await;
                    let _ = reg.socket.send_to(resp.as_bytes(), call.pbx_addr).await;
                }
            }
        });

        token
    }

    /// Mobile app accepts the call with an SDP answer.
    pub async fn accept_call(
        &self,
        call_token: &str,
        sdp_answer: String,
    ) -> anyhow::Result<()> {
        let call = {
            let mut calls = self.pending.write().await;
            calls
                .remove(call_token)
                .ok_or_else(|| anyhow::anyhow!("Call token not found or expired"))?
        };

        // Build 200 OK with the app's SDP and send to PBX
        let reg = call.proxy_reg.read().await;
        let contact_uri = format!(
            "sip:{}@{}:{}",
            "aria-gateway",
            reg.local_addr.ip(),
            reg.local_addr.port()
        );

        if let Some(ok) =
            message::build_200_ok_invite(&call.invite_raw, &sdp_answer, &contact_uri)
        {
            reg.socket.send_to(ok.as_bytes(), call.pbx_addr).await?;
            tracing::info!(token = %call_token, "Sent 200 OK to PBX");

            // Move to active calls
            let active_call = ActiveCall {
                device_id: call.device_id,
                call_id: call.call_id.clone(),
                pbx_addr: call.pbx_addr,
                proxy_reg: call.proxy_reg.clone(),
                invite_raw: call.invite_raw,
            };

            {
                let mut active = self.active.write().await;
                active.insert(call.call_id.clone(), active_call);
            }
            {
                let mut map = self.token_to_call_id.write().await;
                map.insert(call_token.to_string(), call.call_id);
            }
        }

        Ok(())
    }

    /// Mobile app rejects the call.
    pub async fn reject_call(&self, call_token: &str) -> anyhow::Result<()> {
        let call = {
            let mut calls = self.pending.write().await;
            calls
                .remove(call_token)
                .ok_or_else(|| anyhow::anyhow!("Call token not found or expired"))?
        };

        // Send 603 Decline
        let reg = call.proxy_reg.read().await;
        let via = message::extract_header(&call.invite_raw, "Via").unwrap_or_default();
        let from = message::extract_header(&call.invite_raw, "From").unwrap_or_default();
        let to = message::extract_header(&call.invite_raw, "To").unwrap_or_default();
        let cid = message::extract_header(&call.invite_raw, "Call-ID").unwrap_or_default();
        let cseq = message::extract_header(&call.invite_raw, "CSeq").unwrap_or_default();

        let resp = format!(
            "SIP/2.0 603 Decline\r\n\
             Via: {via}\r\n\
             From: {from}\r\n\
             To: {to}\r\n\
             Call-ID: {cid}\r\n\
             CSeq: {cseq}\r\n\
             Content-Length: 0\r\n\r\n"
        );

        reg.socket.send_to(resp.as_bytes(), call.pbx_addr).await?;
        tracing::info!(token = %call_token, "Call rejected, sent 603");
        Ok(())
    }

    /// Get the SDP offer from a pending call (so the app can generate an answer).
    pub async fn get_call_offer(&self, call_token: &str) -> anyhow::Result<CallOffer> {
        let calls = self.pending.read().await;
        let call = calls
            .get(call_token)
            .ok_or_else(|| anyhow::anyhow!("Call token not found or expired"))?;

        // Extract SDP from INVITE body
        let sdp = call
            .invite_raw
            .split("\r\n\r\n")
            .nth(1)
            .unwrap_or("")
            .to_string();

        let (caller_user, caller_domain) =
            message::extract_from_uri(&call.invite_raw).unwrap_or(("unknown".into(), "".into()));
        let caller_name = message::extract_display_name(&call.invite_raw);

        Ok(CallOffer {
            call_token: call_token.to_string(),
            caller_uri: format!("{}@{}", caller_user, caller_domain),
            caller_name,
            sdp_offer: sdp,
        })
    }

    /// Handle an incoming ACK for an active call (after 200 OK).
    pub async fn handle_ack(&self, call_id: &str) {
        let active = self.active.read().await;
        if active.contains_key(call_id) {
            tracing::debug!(call_id = %call_id, "ACK received for active call");
        }
    }

    /// Handle an incoming BYE from the PBX for an active call.
    /// Returns the device_id so the caller can send a push/notification.
    pub async fn handle_bye_from_pbx(
        &self,
        call_id: &str,
        bye_raw: &str,
        from: SocketAddr,
    ) -> anyhow::Result<Option<String>> {
        let call = {
            let mut active = self.active.write().await;
            active.remove(call_id)
        };

        let Some(call) = call else {
            return Ok(None);
        };

        // Send 200 OK for the BYE
        let reg = call.proxy_reg.read().await;
        let via = message::extract_header(bye_raw, "Via").unwrap_or_default();
        let bye_from = message::extract_header(bye_raw, "From").unwrap_or_default();
        let bye_to = message::extract_header(bye_raw, "To").unwrap_or_default();
        let cid = message::extract_header(bye_raw, "Call-ID").unwrap_or_default();
        let cseq = message::extract_header(bye_raw, "CSeq").unwrap_or_default();

        let resp = format!(
            "SIP/2.0 200 OK\r\n\
             Via: {via}\r\n\
             From: {bye_from}\r\n\
             To: {bye_to}\r\n\
             Call-ID: {cid}\r\n\
             CSeq: {cseq}\r\n\
             Content-Length: 0\r\n\r\n"
        );

        reg.socket.send_to(resp.as_bytes(), from).await?;
        tracing::info!(call_id = %call_id, "BYE from PBX — sent 200 OK, call ended");

        // Clean up token mapping
        {
            let mut map = self.token_to_call_id.write().await;
            map.retain(|_, v| v != call_id);
        }

        Ok(Some(call.device_id))
    }

    /// Mobile app hangs up — send BYE to PBX.
    pub async fn hangup_call(&self, call_token: &str) -> anyhow::Result<()> {
        let call_id = {
            let map = self.token_to_call_id.read().await;
            map.get(call_token).cloned()
        };

        let call_id = call_id
            .ok_or_else(|| anyhow::anyhow!("Call token not found or not active"))?;

        let call = {
            let mut active = self.active.write().await;
            active.remove(&call_id)
        };

        let call = call.ok_or_else(|| anyhow::anyhow!("Call not active"))?;

        let reg = call.proxy_reg.read().await;

        // Build BYE from the original INVITE's dialog info
        let from = message::extract_header(&call.invite_raw, "To").unwrap_or_default();
        let to = message::extract_header(&call.invite_raw, "From").unwrap_or_default();
        let cid = &call.call_id;
        let branch = aria_sip_core::generate_branch();

        let bye = format!(
            "BYE sip:unknown@{pbx_ip} SIP/2.0\r\n\
             Via: SIP/2.0/UDP {local_ip}:{local_port};branch={branch};rport\r\n\
             Max-Forwards: 70\r\n\
             From: {from}\r\n\
             To: {to}\r\n\
             Call-ID: {cid}\r\n\
             CSeq: 1 BYE\r\n\
             User-Agent: Aria-Gateway/0.1.0\r\n\
             Content-Length: 0\r\n\r\n",
            pbx_ip = call.pbx_addr.ip(),
            local_ip = reg.local_addr.ip(),
            local_port = reg.local_addr.port(),
        );

        reg.socket.send_to(bye.as_bytes(), call.pbx_addr).await?;
        tracing::info!(call_id = %call_id, "Sent BYE to PBX (app hangup)");

        // Clean up token mapping
        {
            let mut map = self.token_to_call_id.write().await;
            map.retain(|_, v| v != &call_id);
        }

        Ok(())
    }

    /// Register an active call directly (used for outgoing calls that skip the
    /// pending phase since we already have the SDP answer).
    pub async fn register_active_call(
        &self,
        call_token: String,
        call_id: String,
        device_id: String,
        invite_raw: String,
        pbx_addr: SocketAddr,
        proxy_reg: Arc<RwLock<super::sip::proxy::ProxyRegistration>>,
    ) {
        let active_call = ActiveCall {
            device_id,
            call_id: call_id.clone(),
            pbx_addr,
            proxy_reg,
            invite_raw,
        };

        {
            let mut active = self.active.write().await;
            active.insert(call_id.clone(), active_call);
        }
        {
            let mut map = self.token_to_call_id.write().await;
            map.insert(call_token, call_id);
        }
    }
}

/// Information about a pending incoming call, sent to the mobile app.
#[derive(serde::Serialize)]
pub struct CallOffer {
    pub call_token: String,
    pub caller_uri: String,
    pub caller_name: Option<String>,
    pub sdp_offer: String,
}
