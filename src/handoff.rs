//! Call handoff protocol.
//!
//! When an INVITE arrives at the gateway, we hold it pending while sending
//! a push notification. The mobile app wakes up, connects to the gateway,
//! and provides an SDP answer. The gateway rewrites SDP to insert its own
//! RTP relay addresses and forwards the 200 OK to the PBX.
//!
//! After acceptance, the call becomes "active" — the gateway tracks it so it
//! can forward BYE in both directions, handle ACK, and stop the RTP relay.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use crate::sip::message;
use crate::sip::rtp_relay::RtpRelay;

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
    /// Pre-allocated RTP relay for this call (allocated when INVITE arrives).
    rtp_relay: Option<Arc<RtpRelay>>,
    /// The gateway's local IP for SDP rewriting.
    local_ip: String,
    /// The phone-side RTP relay port.
    phone_rtp_port: u16,
    /// The PBX-side RTP relay port.
    pbx_rtp_port: u16,
}

/// An active call (post-200 OK) tracked for mid-dialog request forwarding.
pub struct ActiveCall {
    pub device_id: String,
    pub call_id: String,
    pub pbx_addr: SocketAddr,
    pub proxy_reg: Arc<RwLock<super::sip::proxy::ProxyRegistration>>,
    /// The original INVITE (for header reference).
    pub invite_raw: String,
    /// RTP relay for this call — stopped and dropped when the call ends.
    pub rtp_relay: Option<Arc<RtpRelay>>,
}

/// Manages pending call handoffs and active calls.
pub struct HandoffManager {
    pending: Arc<RwLock<HashMap<String, PendingCall>>>,
    /// Active calls keyed by SIP Call-ID (for mid-dialog routing).
    active: Arc<RwLock<HashMap<String, ActiveCall>>>,
    /// Reverse map: call_token -> call_id (so the app can end calls by token).
    token_to_call_id: Arc<RwLock<HashMap<String, String>>>,
    /// Calls that have been ended (by BYE or CANCEL). Keyed by call_token.
    /// Mobile app polls this to detect remote hangup.
    ended_calls: Arc<RwLock<HashMap<String, EndedCallInfo>>>,
}

/// Info about a call that has ended, available for mobile app polling.
#[derive(Clone, serde::Serialize)]
pub struct EndedCallInfo {
    pub reason: String,
    pub ended_at: chrono::DateTime<chrono::Utc>,
}

impl HandoffManager {
    pub fn new() -> Self {
        let ended = Arc::new(RwLock::new(HashMap::<String, EndedCallInfo>::new()));

        // Spawn a cleanup task to expire ended call records after 2 minutes
        let ended_ref = Arc::clone(&ended);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                let now = chrono::Utc::now();
                let mut map = ended_ref.write().await;
                map.retain(|_, info| {
                    (now - info.ended_at).num_seconds() < 120
                });
            }
        });

        Self {
            pending: Arc::new(RwLock::new(HashMap::new())),
            active: Arc::new(RwLock::new(HashMap::new())),
            token_to_call_id: Arc::new(RwLock::new(HashMap::new())),
            ended_calls: ended,
        }
    }

    /// Create a pending call entry and return a unique call token.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_pending_call(
        &self,
        device_id: String,
        call_id: String,
        invite_raw: String,
        pbx_addr: SocketAddr,
        proxy_reg: Arc<RwLock<super::sip::proxy::ProxyRegistration>>,
        rtp_relay: Option<Arc<RtpRelay>>,
        local_ip: String,
        phone_rtp_port: u16,
        pbx_rtp_port: u16,
    ) -> String {
        let call_token = uuid::Uuid::new_v4().to_string();

        let pending = PendingCall {
            device_id,
            call_id,
            invite_raw,
            pbx_addr,
            proxy_reg,
            rtp_relay,
            local_ip,
            phone_rtp_port,
            pbx_rtp_port,
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

        // Extract the phone's RTP address from its SDP answer
        let phone_media = message::extract_sdp_media_address(&sdp_answer);
        if let Some((ip, port)) = &phone_media {
            tracing::info!(ip = %ip, port, "Phone SDP answer media address");
        }

        // Rewrite the app's SDP answer: replace phone's media address with
        // the gateway's PBX-side relay port (this is what the PBX sees).
        let rewritten_sdp = if call.rtp_relay.is_some() {
            message::rewrite_sdp_media_address(
                &sdp_answer,
                &call.local_ip,
                call.pbx_rtp_port,
            )
        } else {
            sdp_answer.clone()
        };

        // Also extract PBX's RTP address from the original INVITE SDP offer
        let invite_sdp = call
            .invite_raw
            .split("\r\n\r\n")
            .nth(1)
            .unwrap_or("");
        let pbx_media = message::extract_sdp_media_address(invite_sdp);

        // Start the RTP relay if allocated
        if let Some(ref relay) = call.rtp_relay {
            if let Some((pbx_ip, pbx_port)) = &pbx_media {
                let pbx_addr: SocketAddr = format!("{}:{}", pbx_ip, pbx_port)
                    .parse()
                    .unwrap_or_else(|_| call.pbx_addr);
                relay.start(pbx_addr);
                tracing::info!(
                    pbx_rtp = %pbx_addr,
                    "Started RTP relay for inbound call"
                );
            } else {
                tracing::warn!("Could not extract PBX media address from INVITE SDP");
            }
        }

        // Build 200 OK with the rewritten SDP and send to PBX
        let reg = call.proxy_reg.read().await;
        let contact_uri = format!(
            "sip:{}@{}:{}",
            "aria-gateway",
            reg.local_addr.ip(),
            reg.local_addr.port()
        );

        if let Some(ok) =
            message::build_200_ok_invite(&call.invite_raw, &rewritten_sdp, &contact_uri)
        {
            reg.socket.send_to(ok.as_bytes(), call.pbx_addr).await?;
            tracing::info!(token = %call_token, "Sent 200 OK to PBX with rewritten SDP");

            // Move to active calls
            let active_call = ActiveCall {
                device_id: call.device_id,
                call_id: call.call_id.clone(),
                pbx_addr: call.pbx_addr,
                proxy_reg: call.proxy_reg.clone(),
                invite_raw: call.invite_raw,
                rtp_relay: call.rtp_relay,
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
    ///
    /// The SDP is rewritten so that the media address points to the gateway's
    /// phone-side RTP relay port — the phone will send its RTP there.
    pub async fn get_call_offer(&self, call_token: &str) -> anyhow::Result<CallOffer> {
        let calls = self.pending.read().await;
        let call = calls
            .get(call_token)
            .ok_or_else(|| anyhow::anyhow!("Call token not found or expired"))?;

        // Extract SDP from INVITE body
        let raw_sdp = call
            .invite_raw
            .split("\r\n\r\n")
            .nth(1)
            .unwrap_or("")
            .to_string();

        // Rewrite the SDP offer with the gateway's phone-side relay address
        let sdp = if call.rtp_relay.is_some() {
            message::rewrite_sdp_media_address(
                &raw_sdp,
                &call.local_ip,
                call.phone_rtp_port,
            )
        } else {
            raw_sdp
        };

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

    /// Handle a CANCEL from the PBX — remove the pending call so the mobile
    /// app's accept attempt will fail cleanly with "cancelled".
    pub async fn handle_cancel(&self, call_id: &str) {
        let mut pending = self.pending.write().await;
        // Find the token for this call_id
        let token = pending
            .iter()
            .find(|(_, c)| c.call_id == call_id)
            .map(|(t, _)| t.clone());

        if let Some(token) = token {
            pending.remove(&token);
            tracing::info!(call_id = %call_id, token = %token, "Pending call cancelled");

            // Record as ended so mobile app can detect cancellation
            let mut ended = self.ended_calls.write().await;
            ended.insert(token, EndedCallInfo {
                reason: "cancelled".to_string(),
                ended_at: chrono::Utc::now(),
            });
        }
    }

    /// Get the status of a call by token. Returns None if unknown,
    /// or an EndedCallInfo if the call was ended by the remote party.
    pub async fn get_call_status(&self, call_token: &str) -> CallStatus {
        // Check if still pending
        {
            let pending = self.pending.read().await;
            if pending.contains_key(call_token) {
                return CallStatus::Pending;
            }
        }

        // Check if active
        {
            let map = self.token_to_call_id.read().await;
            if let Some(call_id) = map.get(call_token) {
                let active = self.active.read().await;
                if active.contains_key(call_id) {
                    return CallStatus::Active;
                }
            }
        }

        // Check if ended
        {
            let ended = self.ended_calls.read().await;
            if let Some(info) = ended.get(call_token) {
                return CallStatus::Ended(info.clone());
            }
        }

        CallStatus::Unknown
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

        // Stop RTP relay
        if let Some(ref relay) = call.rtp_relay {
            relay.stop();
            tracing::info!(call_id = %call_id, "Stopped RTP relay for ended call");
        }

        tracing::info!(call_id = %call_id, "BYE from PBX — sent 200 OK, call ended");

        // Clean up token mapping and record ended state
        {
            let mut map = self.token_to_call_id.write().await;
            let tokens: Vec<String> = map
                .iter()
                .filter(|(_, v)| v.as_str() == call_id)
                .map(|(k, _)| k.clone())
                .collect();
            for token in &tokens {
                map.remove(token);
            }

            // Record as ended so mobile app can detect remote hangup
            let mut ended = self.ended_calls.write().await;
            for token in tokens {
                ended.insert(token, EndedCallInfo {
                    reason: "bye_from_remote".to_string(),
                    ended_at: chrono::Utc::now(),
                });
            }
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
        let branch = rsip::generators::generate_branch();

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

        // Stop RTP relay
        if let Some(ref relay) = call.rtp_relay {
            relay.stop();
            tracing::info!(call_id = %call_id, "Stopped RTP relay for hung-up call");
        }

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
        rtp_relay: Option<Arc<RtpRelay>>,
    ) {
        let active_call = ActiveCall {
            device_id,
            call_id: call_id.clone(),
            pbx_addr,
            proxy_reg,
            invite_raw,
            rtp_relay,
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

/// Status of a call from the gateway's perspective.
#[derive(serde::Serialize)]
#[serde(tag = "status")]
pub enum CallStatus {
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "active")]
    Active,
    #[serde(rename = "ended")]
    Ended(EndedCallInfo),
    #[serde(rename = "unknown")]
    Unknown,
}
