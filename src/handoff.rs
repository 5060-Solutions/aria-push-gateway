//! Call handoff protocol.
//!
//! When an INVITE arrives at the gateway, we hold it pending while sending
//! a push notification. The mobile app wakes up, connects to the gateway,
//! and provides an SDP answer. The gateway rewrites SDP to insert its own
//! RTP relay addresses and forwards the 200 OK to the PBX.
//!
//! After acceptance, the call becomes "active" — the gateway tracks it so it
//! can forward BYE in both directions, handle ACK, and stop the RTP relay.
//!
//! Active calls can also be blind-transferred: the gateway sends a REFER on
//! the PBX dialog and, once the PBX reports (via NOTIFY) that the transfer
//! target answered, ends its own leg with a BYE.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{oneshot, Mutex, RwLock};

use crate::sip::digest::DigestAuth;
use crate::sip::message;
use crate::sip::rtp_relay::RtpRelay;

/// Who a call belongs to, for authorizing app requests on its token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallOwner {
    /// An incoming call delivered to this registered device (owned by the
    /// device's user).
    Device(String),
    /// An outgoing call placed by this authenticated user.
    User(String),
}

impl std::fmt::Display for CallOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Device(id) => write!(f, "device {id}"),
            Self::User(id) => write!(f, "user {id}"),
        }
    }
}

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
    /// The device (incoming) or user (outgoing) the call belongs to.
    pub owner: CallOwner,
    pub pbx_addr: SocketAddr,
    pub proxy_reg: Arc<RwLock<super::sip::proxy::ProxyRegistration>>,
    /// Dialog identifiers and routing used for in-dialog requests (BYE, REFER).
    pub dialog: Dialog,
    /// Last CSeq number the gateway used for a request on this dialog.
    local_cseq: AtomicU32,
    /// Set while a REFER is outstanding or after the PBX accepted one, so a
    /// later NOTIFY/BYE is attributed to the transfer.
    transfer_pending: AtomicBool,
    /// RTP relay for this call — stopped and dropped when the call ends.
    pub rtp_relay: Option<Arc<RtpRelay>>,
}

impl ActiveCall {
    fn new(
        owner: CallOwner,
        pbx_addr: SocketAddr,
        proxy_reg: Arc<RwLock<super::sip::proxy::ProxyRegistration>>,
        dialog: Dialog,
        initial_cseq: u32,
        rtp_relay: Option<Arc<RtpRelay>>,
    ) -> Self {
        Self {
            owner,
            pbx_addr,
            proxy_reg,
            dialog,
            local_cseq: AtomicU32::new(initial_cseq),
            transfer_pending: AtomicBool::new(false),
            rtp_relay,
        }
    }

    /// Allocate the CSeq number for the next request the gateway sends.
    fn next_cseq(&self) -> u32 {
        self.local_cseq.fetch_add(1, Ordering::SeqCst) + 1
    }
}

/// The state of one SIP dialog between the gateway and the PBX, from the
/// gateway's point of view (RFC 3261 §12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dialog {
    pub call_id: String,
    /// Our end of the dialog — sent as `From` (carries the gateway's tag).
    pub local: String,
    /// The PBX's end of the dialog — sent as `To` (carries the PBX's tag).
    pub remote: String,
    /// Request-URI for in-dialog requests (the PBX's Contact).
    pub remote_target: String,
    /// `Route` header values, in the order they must be sent.
    pub route_set: Vec<String>,
}

impl Dialog {
    /// Dialog for a call the PBX sent to the gateway: we are the UAS.
    ///
    /// `ok_response` is the 200 OK the gateway sent, whose `To` carries the
    /// tag the gateway chose.
    pub fn from_uas(invite: &str, ok_response: &str, pbx_addr: SocketAddr) -> Self {
        let header = |msg: &str, name: &str| message::extract_header(msg, name).unwrap_or_default();
        Self {
            call_id: header(invite, "Call-ID"),
            local: message::extract_header(ok_response, "To")
                .unwrap_or_else(|| header(invite, "To")),
            remote: header(invite, "From"),
            remote_target: contact_uri(invite)
                .unwrap_or_else(|| format!("sip:unknown@{}", pbx_addr.ip())),
            route_set: split_header_values(&message::extract_all_headers(invite, "Record-Route")),
        }
    }

    /// Dialog for a call the gateway originated: we are the UAC, and
    /// `ok_response` is the PBX's 200 OK to our INVITE.
    pub fn from_uac(ok_response: &str, pbx_addr: SocketAddr) -> Self {
        let header = |name: &str| message::extract_header(ok_response, name).unwrap_or_default();
        let mut route_set =
            split_header_values(&message::extract_all_headers(ok_response, "Record-Route"));
        route_set.reverse();
        Self {
            call_id: header("Call-ID"),
            local: header("From"),
            remote: header("To"),
            remote_target: contact_uri(ok_response)
                .unwrap_or_else(|| format!("sip:unknown@{}", pbx_addr.ip())),
            route_set,
        }
    }

    /// The URI inside the local party's header (used for `Referred-By`).
    fn local_uri(&self) -> String {
        name_addr_uri(&self.local)
    }
}

/// Extract the URI from the `Contact` header of a message.
fn contact_uri(msg: &str) -> Option<String> {
    let value = message::extract_header(msg, "Contact")?;
    let uri = name_addr_uri(&value);
    (!uri.is_empty()).then_some(uri)
}

/// Extract the URI from a name-addr (`"Name" <sip:..>;tag=x`) or addr-spec
/// (`sip:..;tag=x`) header value.
fn name_addr_uri(value: &str) -> String {
    if let (Some(start), Some(end)) = (value.find('<'), value.find('>')) {
        if start < end {
            return value[start + 1..end].trim().to_string();
        }
    }
    value
        .split([';', ','])
        .next()
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// Split comma-separated header values (e.g. several routes on one
/// `Record-Route` line), ignoring commas inside `<...>` or quotes.
fn split_header_values(lines: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for line in lines {
        let mut depth = 0u32;
        let mut quoted = false;
        let mut current = String::new();
        for c in line.chars() {
            match c {
                '"' => quoted = !quoted,
                '<' if !quoted => depth += 1,
                '>' if !quoted => depth = depth.saturating_sub(1),
                ',' if !quoted && depth == 0 => {
                    let v = current.trim();
                    if !v.is_empty() {
                        out.push(v.to_string());
                    }
                    current.clear();
                    continue;
                }
                _ => {}
            }
            current.push(c);
        }
        let v = current.trim();
        if !v.is_empty() {
            out.push(v.to_string());
        }
    }
    out
}

/// Build an in-dialog request from the gateway to the PBX.
///
/// `extra_headers` must already be CRLF-terminated header lines.
pub fn build_in_dialog_request(
    method: &str,
    dialog: &Dialog,
    cseq: u32,
    local_addr: SocketAddr,
    branch: &str,
    extra_headers: &str,
) -> String {
    let mut msg = format!(
        "{method} {target} SIP/2.0\r\n\
         Via: SIP/2.0/UDP {local_ip}:{local_port};branch={branch};rport\r\n\
         Max-Forwards: 70\r\n",
        target = dialog.remote_target,
        local_ip = local_addr.ip(),
        local_port = local_addr.port(),
    );
    for route in &dialog.route_set {
        msg.push_str(&format!("Route: {route}\r\n"));
    }
    msg.push_str(&format!(
        "From: {from}\r\n\
         To: {to}\r\n\
         Call-ID: {cid}\r\n\
         CSeq: {cseq} {method}\r\n",
        from = dialog.local,
        to = dialog.remote,
        cid = dialog.call_id,
    ));
    msg.push_str(extra_headers);
    msg.push_str("User-Agent: Aria-Gateway/0.1.0\r\nContent-Length: 0\r\n\r\n");
    msg
}

/// Build a blind-transfer REFER (RFC 3515) on `dialog`.
///
/// `auth` is an optional `(header name, value)` pair answering a digest
/// challenge, e.g. `("Authorization", "Digest ...")`.
pub fn build_refer(
    dialog: &Dialog,
    cseq: u32,
    local_addr: SocketAddr,
    branch: &str,
    refer_to: &str,
    auth: Option<(&str, &str)>,
) -> String {
    let mut extra = format!(
        "Contact: <sip:aria-gateway@{ip}:{port}>\r\n\
         Refer-To: <{refer_to}>\r\n\
         Referred-By: <{referred_by}>\r\n\
         Allow: INVITE, ACK, CANCEL, BYE, OPTIONS, REFER, NOTIFY\r\n",
        ip = local_addr.ip(),
        port = local_addr.port(),
        referred_by = dialog.local_uri(),
    );
    if let Some((name, value)) = auth {
        extra.push_str(&format!("{name}: {value}\r\n"));
    }
    build_in_dialog_request("REFER", dialog, cseq, local_addr, branch, &extra)
}

/// Maximum accepted length of a transfer target, in bytes.
const MAX_TARGET_LEN: usize = 256;

/// A validated transfer destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferTarget {
    /// A bare number or extension (`1002`, `+15551234567`, `*97`).
    Number(String),
    /// A full `sip:`/`sips:` URI.
    Uri(String),
}

impl TransferTarget {
    /// Validate a client-supplied target.
    ///
    /// The result is placed verbatim into a `Refer-To` header, so anything
    /// that could break out of the `<...>` or the header line is rejected:
    /// control characters (including CR/LF), whitespace, `<`, `>`, `"`, `,`
    /// and `?` (URI-embedded headers). A `method=` URI parameter, which would
    /// make the PBX send something other than an INVITE, is also rejected.
    pub fn parse(raw: &str) -> Result<Self, &'static str> {
        let target = raw.trim();
        if target.is_empty() {
            return Err("target is empty");
        }
        if target.len() > MAX_TARGET_LEN {
            return Err("target is too long");
        }
        if !target.is_ascii() {
            return Err("target must be ASCII");
        }

        let lower = target.to_ascii_lowercase();
        if lower.starts_with("sip:") || lower.starts_with("sips:") {
            Self::parse_uri(target).map(Self::Uri)
        } else {
            let ok = target
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "+*#.-_".contains(c));
            if ok {
                Ok(Self::Number(target.to_string()))
            } else {
                Err("target contains characters not allowed in a number or extension")
            }
        }
    }

    fn parse_uri(target: &str) -> Result<String, &'static str> {
        const ALLOWED_PUNCT: &str = "@.-_+*:;=%!~'()&$/[]";
        if !target
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ALLOWED_PUNCT.contains(c))
        {
            return Err("target URI contains characters that are not allowed");
        }

        // Percent-escapes must be well-formed and must not smuggle in
        // control characters or header delimiters.
        let bytes = target.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' {
                let hex = target
                    .get(i + 1..i + 3)
                    .ok_or("target URI has a truncated percent-escape")?;
                let decoded = u8::from_str_radix(hex, 16)
                    .map_err(|_| "target URI has an invalid percent-escape")?;
                if !(0x21..0x7f).contains(&decoded) || b"<>\",?".contains(&decoded) {
                    return Err("target URI has a disallowed percent-escape");
                }
                i += 3;
            } else {
                i += 1;
            }
        }

        let (_, rest) = target.split_once(':').ok_or("target URI is malformed")?;
        let hostport = rest
            .split(';')
            .next()
            .unwrap_or_default()
            .rsplit('@')
            .next()
            .unwrap_or_default();
        if hostport.is_empty() || hostport.starts_with(':') {
            return Err("target URI has no host");
        }
        if rest.starts_with('@') {
            return Err("target URI has an empty user part");
        }
        if rest.matches('@').count() > 1 {
            return Err("target URI is malformed");
        }
        if rest
            .split(';')
            .skip(1)
            .any(|p| p.to_ascii_lowercase().starts_with("method="))
        {
            return Err("target URI must not carry a method parameter");
        }
        Ok(target.to_string())
    }

    /// The `Refer-To` URI for this target; bare numbers are placed in `domain`.
    pub fn refer_to_uri(&self, domain: &str) -> String {
        match self {
            Self::Number(n) => format!("sip:{}@{}", n.replace('#', "%23"), domain),
            Self::Uri(u) => u.clone(),
        }
    }
}

/// Why a transfer request failed.
#[derive(Debug, PartialEq, Eq)]
pub enum TransferError {
    /// The target failed validation.
    InvalidTarget(&'static str),
    /// No active call has this token.
    NotFound,
    /// The PBX answered the REFER with a non-2xx final response.
    Rejected(u16),
    /// The PBX did not answer the REFER in time.
    Timeout,
    /// The REFER could not be sent.
    Send(String),
}

impl std::fmt::Display for TransferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTarget(why) => write!(f, "invalid transfer target: {why}"),
            Self::NotFound => write!(f, "call token not found or not active"),
            Self::Rejected(status) => write!(f, "PBX rejected REFER with {status}"),
            Self::Timeout => write!(f, "no final response to REFER"),
            Self::Send(e) => write!(f, "failed to send REFER: {e}"),
        }
    }
}

/// How long to wait for the PBX's final response to a REFER.
const REFER_TIMEOUT: Duration = Duration::from_secs(8);
/// Initial UDP retransmission interval (RFC 3261 T1).
const SIP_T1: Duration = Duration::from_millis(500);
/// Maximum retransmission interval for non-INVITE requests (RFC 3261 T2).
const SIP_T2: Duration = Duration::from_secs(4);

/// Status code from the `message/sipfrag` body of a `refer` NOTIFY, or
/// `None` if the request is not a refer-subscription NOTIFY.
pub fn refer_notify_status(notify: &str) -> Option<u16> {
    let event = message::extract_header(notify, "Event")?;
    let package = event.split(';').next().unwrap_or_default().trim();
    if !package.eq_ignore_ascii_case("refer") {
        return None;
    }
    let body = notify.split_once("\r\n\r\n")?.1;
    message::parse_sipfrag_status(body.trim_start())
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
    /// Outstanding REFER transactions keyed by Via branch; the sender gets
    /// the final response.
    pending_refers: Arc<Mutex<HashMap<String, oneshot::Sender<String>>>>,
}

/// Info about a call that has ended, available for mobile app polling.
#[derive(Clone, serde::Serialize)]
pub struct EndedCallInfo {
    pub reason: String,
    pub ended_at: chrono::DateTime<chrono::Utc>,
    /// Who the call belonged to; kept so `/status` stays owner-only.
    #[serde(skip)]
    pub owner: CallOwner,
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
                map.retain(|_, info| (now - info.ended_at).num_seconds() < 120);
            }
        });

        Self {
            pending: Arc::new(RwLock::new(HashMap::new())),
            active: Arc::new(RwLock::new(HashMap::new())),
            token_to_call_id: Arc::new(RwLock::new(HashMap::new())),
            ended_calls: ended,
            pending_refers: Arc::new(Mutex::new(HashMap::new())),
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
    pub async fn accept_call(&self, call_token: &str, sdp_answer: String) -> anyhow::Result<()> {
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
            message::rewrite_sdp_media_address(&sdp_answer, &call.local_ip, call.pbx_rtp_port)
        } else {
            sdp_answer.clone()
        };

        // Also extract PBX's RTP address from the original INVITE SDP offer
        let invite_sdp = call.invite_raw.split("\r\n\r\n").nth(1).unwrap_or("");
        let pbx_media = message::extract_sdp_media_address(invite_sdp);

        // Start the RTP relay if allocated
        if let Some(ref relay) = call.rtp_relay {
            if let Some((pbx_ip, pbx_port)) = &pbx_media {
                let pbx_addr: SocketAddr = format!("{}:{}", pbx_ip, pbx_port)
                    .parse()
                    .unwrap_or(call.pbx_addr);
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

            // Move to active calls. The gateway has sent no requests on this
            // dialog yet, so its first one (BYE/REFER) uses CSeq 1.
            let dialog = Dialog::from_uas(&call.invite_raw, &ok, call.pbx_addr);
            let active_call = ActiveCall::new(
                CallOwner::Device(call.device_id),
                call.pbx_addr,
                call.proxy_reg.clone(),
                dialog,
                0,
                call.rtp_relay,
            );

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
            message::rewrite_sdp_media_address(&raw_sdp, &call.local_ip, call.phone_rtp_port)
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
            let call = pending.remove(&token);
            tracing::info!(call_id = %call_id, token = %token, "Pending call cancelled");
            let owner = CallOwner::Device(call.map(|c| c.device_id).unwrap_or_default());

            // Record as ended so mobile app can detect cancellation
            let mut ended = self.ended_calls.write().await;
            ended.insert(
                token,
                EndedCallInfo {
                    reason: "cancelled".to_string(),
                    ended_at: chrono::Utc::now(),
                    owner,
                },
            );
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

    /// Who owns the call behind `call_token`, whether it is pending, active
    /// or recently ended. `None` if the token is unknown.
    pub async fn call_owner(&self, call_token: &str) -> Option<CallOwner> {
        if let Some(call) = self.pending.read().await.get(call_token) {
            return Some(CallOwner::Device(call.device_id.clone()));
        }
        let call_id = self.token_to_call_id.read().await.get(call_token).cloned();
        if let Some(call_id) = call_id {
            if let Some(call) = self.active.read().await.get(&call_id) {
                return Some(call.owner.clone());
            }
        }
        self.ended_calls
            .read()
            .await
            .get(call_token)
            .map(|info| info.owner.clone())
    }

    /// Handle an incoming BYE from the PBX for an active call.
    /// Returns the call's owner, or `None` if no such call is active.
    pub async fn handle_bye_from_pbx(
        &self,
        call_id: &str,
        bye_raw: &str,
        from: SocketAddr,
    ) -> anyhow::Result<Option<CallOwner>> {
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
            let reason = if call.transfer_pending.load(Ordering::SeqCst) {
                "transferred"
            } else {
                "bye_from_remote"
            };
            let mut ended = self.ended_calls.write().await;
            for token in tokens {
                ended.insert(
                    token,
                    EndedCallInfo {
                        reason: reason.to_string(),
                        ended_at: chrono::Utc::now(),
                        owner: call.owner.clone(),
                    },
                );
            }
        }

        Ok(Some(call.owner))
    }

    /// Look up the SIP Call-ID of an active call by its token.
    async fn active_call_id(&self, call_token: &str) -> Option<String> {
        let call_id = self
            .token_to_call_id
            .read()
            .await
            .get(call_token)
            .cloned()?;
        self.active
            .read()
            .await
            .contains_key(&call_id)
            .then_some(call_id)
    }

    /// Whether a call with this SIP Call-ID is still active.
    pub async fn is_call_active(&self, call_id: &str) -> bool {
        self.active.read().await.contains_key(call_id)
    }

    /// Mobile app hangs up — send BYE to PBX.
    pub async fn hangup_call(&self, call_token: &str) -> anyhow::Result<()> {
        let call_id = {
            let map = self.token_to_call_id.read().await;
            map.get(call_token).cloned()
        };

        let call_id =
            call_id.ok_or_else(|| anyhow::anyhow!("Call token not found or not active"))?;

        self.end_call_with_bye(&call_id, None).await
    }

    /// Remove an active call, send BYE to the PBX on its dialog, stop the RTP
    /// relay and drop its token mapping. If `ended_reason` is set, the call
    /// is also recorded as ended so the mobile app sees it when polling.
    async fn end_call_with_bye(
        &self,
        call_id: &str,
        ended_reason: Option<&str>,
    ) -> anyhow::Result<()> {
        let call = {
            let mut active = self.active.write().await;
            active.remove(call_id)
        };

        let call = call.ok_or_else(|| anyhow::anyhow!("Call not active"))?;

        let reg = call.proxy_reg.read().await;

        let branch = message::generate_branch();
        let bye = build_in_dialog_request(
            "BYE",
            &call.dialog,
            call.next_cseq(),
            reg.local_addr,
            &branch,
            "",
        );

        let sent = reg.socket.send_to(bye.as_bytes(), call.pbx_addr).await;

        // Stop RTP relay
        if let Some(ref relay) = call.rtp_relay {
            relay.stop();
            tracing::info!(call_id = %call_id, "Stopped RTP relay for ended call");
        }

        tracing::info!(call_id = %call_id, "Sent BYE to PBX");

        // Clean up token mapping
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
            if let Some(reason) = ended_reason {
                let mut ended = self.ended_calls.write().await;
                for token in tokens {
                    ended.insert(
                        token,
                        EndedCallInfo {
                            reason: reason.to_string(),
                            ended_at: chrono::Utc::now(),
                            owner: call.owner.clone(),
                        },
                    );
                }
            }
        }

        sent?;
        Ok(())
    }

    /// Blind-transfer an active call: send a REFER on the PBX dialog and wait
    /// for the PBX to accept it.
    ///
    /// On success the call stays active; it is torn down when the PBX sends
    /// BYE, or when a NOTIFY reports that the transfer target answered (see
    /// [`Self::handle_notify`]).
    pub async fn transfer_call(&self, call_token: &str, target: &str) -> Result<(), TransferError> {
        let target = TransferTarget::parse(target).map_err(TransferError::InvalidTarget)?;

        let call_id = self
            .active_call_id(call_token)
            .await
            .ok_or(TransferError::NotFound)?;

        let (dialog, pbx_addr, proxy_reg) = {
            let active = self.active.read().await;
            let call = active.get(&call_id).ok_or(TransferError::NotFound)?;
            call.transfer_pending.store(true, Ordering::SeqCst);
            (call.dialog.clone(), call.pbx_addr, call.proxy_reg.clone())
        };

        let (socket, local_addr, domain, (auth_user, password)) = {
            let reg = proxy_reg.read().await;
            (
                reg.socket.clone(),
                reg.local_addr,
                reg.sip_domain().to_string(),
                reg.digest_credentials(),
            )
        };
        let domain = if domain.is_empty() {
            pbx_addr.ip().to_string()
        } else {
            domain
        };
        let refer_to = target.refer_to_uri(&domain);

        tracing::info!(call_id = %call_id, refer_to = %refer_to, "Sending REFER to PBX");

        // Send the REFER; if the PBX challenges it, resend once with digest
        // credentials from the registration that carried the call.
        let mut credentials: Option<(&'static str, String)> = None;
        let result = loop {
            let Some(cseq) = self.next_cseq(&call_id).await else {
                break Err(TransferError::NotFound);
            };
            let branch = message::generate_branch();
            let refer = build_refer(
                &dialog,
                cseq,
                local_addr,
                &branch,
                &refer_to,
                credentials.as_ref().map(|(n, v)| (*n, v.as_str())),
            );
            let response = match self
                .refer_transaction(&socket, pbx_addr, &refer, &branch)
                .await
            {
                Ok(r) => r,
                Err(e) => break Err(e),
            };
            let status = message::parse_status_code(&response).unwrap_or_default();
            match status {
                200..=299 => break Ok(()),
                401 | 407 if credentials.is_none() => {
                    let (challenge_header, auth_header) = if status == 401 {
                        ("WWW-Authenticate", "Authorization")
                    } else {
                        ("Proxy-Authenticate", "Proxy-Authorization")
                    };
                    let auth = message::extract_header(&response, challenge_header).and_then(
                        |challenge| {
                            DigestAuth::from_challenge(
                                &challenge,
                                &auth_user,
                                &password,
                                &dialog.remote_target,
                                "REFER",
                            )
                        },
                    );
                    let Some(auth) = auth else {
                        tracing::warn!(call_id = %call_id, status, "REFER challenge could not be parsed");
                        break Err(TransferError::Rejected(status));
                    };
                    tracing::debug!(call_id = %call_id, status, "REFER challenged — resending with credentials");
                    credentials = Some((auth_header, auth.to_header()));
                }
                _ => break Err(TransferError::Rejected(status)),
            }
        };

        match &result {
            Ok(()) => {
                tracing::info!(call_id = %call_id, "PBX accepted REFER");
            }
            Err(e) => {
                tracing::warn!(call_id = %call_id, "Transfer failed: {}", e);
                if let Some(call) = self.active.read().await.get(&call_id) {
                    call.transfer_pending.store(false, Ordering::SeqCst);
                }
            }
        }
        result
    }

    /// Allocate the next local CSeq on an active call's dialog.
    async fn next_cseq(&self, call_id: &str) -> Option<u32> {
        self.active.read().await.get(call_id).map(|c| c.next_cseq())
    }

    /// Run one REFER client transaction: send `refer`, retransmitting per
    /// RFC 3261 §17.1.2 (UDP), until a final response arrives or we give up.
    async fn refer_transaction(
        &self,
        socket: &tokio::net::UdpSocket,
        pbx_addr: SocketAddr,
        refer: &str,
        branch: &str,
    ) -> Result<String, TransferError> {
        let (tx, mut rx) = oneshot::channel();
        self.pending_refers
            .lock()
            .await
            .insert(branch.to_string(), tx);

        let deadline = tokio::time::Instant::now() + REFER_TIMEOUT;
        let mut interval = SIP_T1;
        let result = loop {
            if let Err(e) = socket.send_to(refer.as_bytes(), pbx_addr).await {
                break Err(TransferError::Send(e.to_string()));
            }
            let wait =
                interval.min(deadline.saturating_duration_since(tokio::time::Instant::now()));
            match tokio::time::timeout(wait, &mut rx).await {
                Ok(Ok(response)) => break Ok(response),
                Ok(Err(_)) => break Err(TransferError::Send("transaction dropped".into())),
                Err(_) if tokio::time::Instant::now() >= deadline => {
                    break Err(TransferError::Timeout)
                }
                Err(_) => interval = (interval * 2).min(SIP_T2),
            }
        };

        self.pending_refers.lock().await.remove(branch);
        result
    }

    /// Deliver a response to a REFER the gateway sent. Provisional responses
    /// are ignored; the first final response completes the transaction.
    pub async fn handle_refer_response(&self, response: &str) {
        let (Some(status), Some(branch)) = (
            message::parse_status_code(response),
            message::extract_via_branch(response),
        ) else {
            return;
        };
        if status < 200 {
            return;
        }
        if let Some(tx) = self.pending_refers.lock().await.remove(&branch) {
            let _ = tx.send(response.to_string());
        }
    }

    /// Handle a NOTIFY from the PBX (already answered with 200 OK by the
    /// caller). For a `refer` subscription whose sipfrag reports a 2xx, the
    /// transfer has completed: end our leg of the call with a BYE.
    pub async fn handle_notify(&self, call_id: &str, notify: &str) {
        let Some(status) = refer_notify_status(notify) else {
            tracing::debug!(call_id = %call_id, "NOTIFY is not a refer progress report");
            return;
        };

        let transferring = self
            .active
            .read()
            .await
            .get(call_id)
            .is_some_and(|c| c.transfer_pending.load(Ordering::SeqCst));
        if !transferring {
            tracing::debug!(call_id = %call_id, status, "refer NOTIFY for a call with no transfer in progress");
            return;
        }

        match status {
            100..=199 => {
                tracing::debug!(call_id = %call_id, status, "Transfer in progress");
            }
            200..=299 => {
                tracing::info!(call_id = %call_id, "Transfer completed — ending gateway leg");
                if let Err(e) = self.end_call_with_bye(call_id, Some("transferred")).await {
                    tracing::warn!(call_id = %call_id, "Failed to end transferred call: {}", e);
                }
            }
            _ => {
                tracing::warn!(call_id = %call_id, status, "Transfer target failed — call stays up");
                if let Some(call) = self.active.read().await.get(call_id) {
                    call.transfer_pending.store(false, Ordering::SeqCst);
                }
            }
        }
    }

    /// Register an active call directly (used for outgoing calls that skip the
    /// pending phase since we already have the SDP answer).
    ///
    /// `invite_raw` is the PBX's 200 OK to the gateway's INVITE.
    #[allow(clippy::too_many_arguments)]
    pub async fn register_active_call(
        &self,
        call_token: String,
        call_id: String,
        owner: CallOwner,
        invite_raw: String,
        pbx_addr: SocketAddr,
        proxy_reg: Arc<RwLock<super::sip::proxy::ProxyRegistration>>,
        rtp_relay: Option<Arc<RtpRelay>>,
    ) {
        let dialog = Dialog::from_uac(&invite_raw, pbx_addr);
        // Continue the CSeq space our INVITE started.
        let initial_cseq = message::extract_header(&invite_raw, "CSeq")
            .and_then(|v| v.split_whitespace().next()?.parse().ok())
            .unwrap_or(1);
        let active_call =
            ActiveCall::new(owner, pbx_addr, proxy_reg, dialog, initial_cseq, rtp_relay);

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

#[cfg(test)]
mod tests {
    use super::*;

    const PBX: &str = "10.0.0.1:5060";

    fn pbx_addr() -> SocketAddr {
        PBX.parse().unwrap()
    }

    fn local_addr() -> SocketAddr {
        "192.168.1.10:40000".parse().unwrap()
    }

    const INBOUND_INVITE: &str = "\
INVITE sip:1001@192.168.1.10:40000 SIP/2.0\r\n\
Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-inv\r\n\
Record-Route: <sip:10.0.0.1;lr>, <sip:edge.example.com;lr>\r\n\
Record-Route: <sip:core.example.com;lr>\r\n\
From: \"Bob\" <sip:2000@pbx.example.com>;tag=pbxtag\r\n\
To: <sip:1001@pbx.example.com>\r\n\
Call-ID: inbound-call-1\r\n\
CSeq: 102 INVITE\r\n\
Contact: <sip:2000@10.0.0.1:5060;transport=udp>\r\n\
Content-Length: 0\r\n\r\n";

    const INBOUND_200: &str = "\
SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-inv\r\n\
From: \"Bob\" <sip:2000@pbx.example.com>;tag=pbxtag\r\n\
To: <sip:1001@pbx.example.com>;tag=gwtag\r\n\
Call-ID: inbound-call-1\r\n\
CSeq: 102 INVITE\r\n\
Contact: <sip:aria-gateway@192.168.1.10:40000>\r\n\
Content-Length: 0\r\n\r\n";

    const OUTBOUND_200: &str = "\
SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP 192.168.1.10:40000;branch=z9hG4bK-out;rport\r\n\
Record-Route: <sip:a.example.com;lr>\r\n\
Record-Route: <sip:b.example.com;lr>\r\n\
From: \"Alice\" <sip:1001@pbx.example.com>;tag=gwtag\r\n\
To: <sip:2000@pbx.example.com>;tag=pbxtag\r\n\
Call-ID: outbound-call-1\r\n\
CSeq: 2 INVITE\r\n\
Contact: <sip:2000@10.0.0.1:5060>\r\n\
Content-Length: 0\r\n\r\n";

    // ── Target validation ───────────────────────────────────────────────────

    #[test]
    fn accepts_numbers_and_extensions() {
        for t in ["1002", "+15551234567", "*97", "1#", "ext.2_a-b"] {
            assert_eq!(
                TransferTarget::parse(t),
                Ok(TransferTarget::Number(t.to_string())),
                "{t}"
            );
        }
        assert_eq!(
            TransferTarget::parse("  1002 "),
            Ok(TransferTarget::Number("1002".into()))
        );
    }

    #[test]
    fn accepts_sip_uris() {
        for t in [
            "sip:1002@pbx.example.com",
            "SIP:bob@10.0.0.5",
            "sips:alice@example.com:5061;transport=tls",
            "sip:+15551234567@pbx.example.com;user=phone",
            "sip:pbx.example.com",
            "sip:1%23@pbx.example.com",
        ] {
            assert_eq!(
                TransferTarget::parse(t),
                Ok(TransferTarget::Uri(t.to_string())),
                "{t}"
            );
        }
    }

    #[test]
    fn rejects_empty_and_oversized_targets() {
        assert!(TransferTarget::parse("").is_err());
        assert!(TransferTarget::parse("   ").is_err());
        assert!(TransferTarget::parse(&"1".repeat(MAX_TARGET_LEN + 1)).is_err());
        assert!(TransferTarget::parse(&"1".repeat(MAX_TARGET_LEN)).is_ok());
    }

    #[test]
    fn rejects_header_injection() {
        for t in [
            "1002\r\nX-Evil: 1",
            "1002\nX-Evil: 1",
            "1002\rX",
            "sip:a@b\r\nX-Evil: 1",
            "sip:a@b>\r\nX-Evil: 1",
            "<sip:a@b>",
            "sip:a@b>",
            "sip:<a@b",
            "sip:\"x\"@b",
            "sip:a@b,sip:c@d",
            "sip:a@b?Replaces=abc",
            "sip:a@b;method=BYE",
            "sip:a@b;METHOD=INVITE",
            "sip:a%0d%0aX@b",
            "sip:a%0A@b",
            "sip:a%3e@b",
            "sip:a%00@b",
            "1002\0",
            "10 02",
            "10\t02",
            "1002>",
        ] {
            assert!(
                TransferTarget::parse(t).is_err(),
                "{t:?} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_malformed_targets() {
        for t in [
            "sip:",
            "sip:@host",
            "sip:a@",
            "sip:a@b@c",
            "sip:a@:5060",
            "sip:a%zz@b",
            "sip:a%2",
            "tel:+15551234567",
            "1002@host",
            "ünïcode",
        ] {
            assert!(
                TransferTarget::parse(t).is_err(),
                "{t:?} should be rejected"
            );
        }
    }

    #[test]
    fn refer_to_uri_places_numbers_in_pbx_domain() {
        let n = TransferTarget::parse("1002").unwrap();
        assert_eq!(
            n.refer_to_uri("pbx.example.com"),
            "sip:1002@pbx.example.com"
        );

        let hash = TransferTarget::parse("*72#").unwrap();
        assert_eq!(
            hash.refer_to_uri("pbx.example.com"),
            "sip:*72%23@pbx.example.com"
        );

        let uri = TransferTarget::parse("sip:2000@other.example.com").unwrap();
        assert_eq!(
            uri.refer_to_uri("pbx.example.com"),
            "sip:2000@other.example.com"
        );
    }

    // ── Dialog construction ─────────────────────────────────────────────────

    #[test]
    fn uas_dialog_swaps_from_and_to_and_keeps_our_tag() {
        let d = Dialog::from_uas(INBOUND_INVITE, INBOUND_200, pbx_addr());
        assert_eq!(d.call_id, "inbound-call-1");
        assert_eq!(d.local, "<sip:1001@pbx.example.com>;tag=gwtag");
        assert_eq!(d.remote, "\"Bob\" <sip:2000@pbx.example.com>;tag=pbxtag");
        assert_eq!(d.remote_target, "sip:2000@10.0.0.1:5060;transport=udp");
        assert_eq!(
            d.route_set,
            vec![
                "<sip:10.0.0.1;lr>",
                "<sip:edge.example.com;lr>",
                "<sip:core.example.com;lr>"
            ]
        );
    }

    #[test]
    fn uac_dialog_keeps_from_and_to_and_reverses_routes() {
        let d = Dialog::from_uac(OUTBOUND_200, pbx_addr());
        assert_eq!(d.call_id, "outbound-call-1");
        assert_eq!(d.local, "\"Alice\" <sip:1001@pbx.example.com>;tag=gwtag");
        assert_eq!(d.remote, "<sip:2000@pbx.example.com>;tag=pbxtag");
        assert_eq!(d.remote_target, "sip:2000@10.0.0.1:5060");
        assert_eq!(
            d.route_set,
            vec!["<sip:b.example.com;lr>", "<sip:a.example.com;lr>"]
        );
    }

    #[test]
    fn dialog_falls_back_to_pbx_address_without_contact() {
        let invite =
            INBOUND_INVITE.replace("Contact: <sip:2000@10.0.0.1:5060;transport=udp>\r\n", "");
        let d = Dialog::from_uas(&invite, INBOUND_200, pbx_addr());
        assert_eq!(d.remote_target, "sip:unknown@10.0.0.1");
    }

    #[test]
    fn split_header_values_ignores_commas_inside_brackets_and_quotes() {
        let lines = vec![
            "<sip:a;lr>, \"x, y\" <sip:b;lr>".to_string(),
            "<sip:c;foo=1,2>".to_string(),
        ];
        assert_eq!(
            split_header_values(&lines),
            vec!["<sip:a;lr>", "\"x, y\" <sip:b;lr>", "<sip:c;foo=1,2>"]
        );
    }

    // ── REFER construction ──────────────────────────────────────────────────

    fn header_lines(msg: &str) -> Vec<&str> {
        msg.split("\r\n\r\n")
            .next()
            .unwrap()
            .split("\r\n")
            .collect()
    }

    #[test]
    fn refer_is_built_on_the_dialog() {
        let d = Dialog::from_uas(INBOUND_INVITE, INBOUND_200, pbx_addr());
        let refer = build_refer(
            &d,
            1,
            local_addr(),
            "z9hG4bK-ref",
            "sip:1002@pbx.example.com",
            None,
        );
        let lines = header_lines(&refer);

        assert_eq!(
            lines[0],
            "REFER sip:2000@10.0.0.1:5060;transport=udp SIP/2.0"
        );
        assert_eq!(
            lines[1],
            "Via: SIP/2.0/UDP 192.168.1.10:40000;branch=z9hG4bK-ref;rport"
        );
        for expected in [
            "Max-Forwards: 70",
            "Route: <sip:10.0.0.1;lr>",
            "Route: <sip:edge.example.com;lr>",
            "Route: <sip:core.example.com;lr>",
            "From: <sip:1001@pbx.example.com>;tag=gwtag",
            "To: \"Bob\" <sip:2000@pbx.example.com>;tag=pbxtag",
            "Call-ID: inbound-call-1",
            "CSeq: 1 REFER",
            "Contact: <sip:aria-gateway@192.168.1.10:40000>",
            "Refer-To: <sip:1002@pbx.example.com>",
            "Referred-By: <sip:1001@pbx.example.com>",
            "Content-Length: 0",
        ] {
            assert!(
                lines.contains(&expected),
                "missing {expected:?} in\n{refer}"
            );
        }
        assert!(refer.ends_with("Content-Length: 0\r\n\r\n"));

        // Routes come in route-set order, before From.
        let pos = |h: &str| lines.iter().position(|l| *l == h).unwrap();
        assert!(pos("Route: <sip:10.0.0.1;lr>") < pos("Route: <sip:edge.example.com;lr>"));
        assert!(
            pos("Route: <sip:core.example.com;lr>")
                < pos("From: <sip:1001@pbx.example.com>;tag=gwtag")
        );

        // Every header line is well-formed and nothing is duplicated.
        for line in &lines[1..] {
            assert!(line.contains(": "), "malformed header line {line:?}");
        }
        assert_eq!(
            lines.iter().filter(|l| l.starts_with("Refer-To:")).count(),
            1
        );
    }

    #[test]
    fn refer_for_outgoing_call_does_not_swap_parties() {
        let d = Dialog::from_uac(OUTBOUND_200, pbx_addr());
        let refer = build_refer(
            &d,
            3,
            local_addr(),
            "z9hG4bK-x",
            "sip:1002@pbx.example.com",
            None,
        );
        let lines = header_lines(&refer);
        assert_eq!(lines[0], "REFER sip:2000@10.0.0.1:5060 SIP/2.0");
        assert!(lines.contains(&"From: \"Alice\" <sip:1001@pbx.example.com>;tag=gwtag"));
        assert!(lines.contains(&"To: <sip:2000@pbx.example.com>;tag=pbxtag"));
        assert!(lines.contains(&"CSeq: 3 REFER"));
        assert!(lines.contains(&"Route: <sip:b.example.com;lr>"));
    }

    #[test]
    fn refer_header_cannot_be_split_by_a_validated_target() {
        let d = Dialog::from_uas(INBOUND_INVITE, INBOUND_200, pbx_addr());
        let target = TransferTarget::parse("sip:1002@pbx.example.com;user=phone").unwrap();
        let refer = build_refer(&d, 1, local_addr(), "b", &target.refer_to_uri("pbx"), None);
        let lines = header_lines(&refer);
        assert!(lines.contains(&"Refer-To: <sip:1002@pbx.example.com;user=phone>"));
    }

    #[test]
    fn bye_uses_same_dialog_and_given_cseq() {
        let d = Dialog::from_uas(INBOUND_INVITE, INBOUND_200, pbx_addr());
        let bye = build_in_dialog_request("BYE", &d, 2, local_addr(), "z9hG4bK-bye", "");
        let lines = header_lines(&bye);
        assert_eq!(lines[0], "BYE sip:2000@10.0.0.1:5060;transport=udp SIP/2.0");
        assert!(lines.contains(&"CSeq: 2 BYE"));
        assert!(lines.contains(&"From: <sip:1001@pbx.example.com>;tag=gwtag"));
        assert!(!bye.contains("Refer-To"));
    }

    // ── NOTIFY / response handling ──────────────────────────────────────────

    fn notify(event: &str, frag: &str) -> String {
        format!(
            "NOTIFY sip:aria-gateway@192.168.1.10:40000 SIP/2.0\r\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-n\r\n\
             From: <sip:2000@pbx.example.com>;tag=pbxtag\r\n\
             To: <sip:1001@pbx.example.com>;tag=gwtag\r\n\
             Call-ID: inbound-call-1\r\n\
             CSeq: 103 NOTIFY\r\n\
             Event: {event}\r\n\
             Subscription-State: terminated;reason=noresource\r\n\
             Content-Type: message/sipfrag;version=2.0\r\n\
             Content-Length: {}\r\n\r\n{frag}",
            frag.len()
        )
    }

    #[test]
    fn refer_notify_status_reads_sipfrag() {
        assert_eq!(
            refer_notify_status(&notify("refer", "SIP/2.0 200 OK\r\n")),
            Some(200)
        );
        assert_eq!(
            refer_notify_status(&notify("refer;id=7", "SIP/2.0 100 Trying\r\n")),
            Some(100)
        );
        assert_eq!(
            refer_notify_status(&notify("REFER", "SIP/2.0 486 Busy Here\r\n")),
            Some(486)
        );
        assert_eq!(
            refer_notify_status(&notify("dialog", "SIP/2.0 200 OK\r\n")),
            None
        );
        assert_eq!(refer_notify_status(&notify("refer", "garbage")), None);
    }

    #[tokio::test]
    async fn refer_final_response_is_delivered_by_branch() {
        let mgr = HandoffManager::new();
        let (tx, rx) = oneshot::channel();
        mgr.pending_refers
            .lock()
            .await
            .insert("z9hG4bK-ref".into(), tx);

        let resp = |status: &str, branch: &str| {
            format!(
                "SIP/2.0 {status}\r\n\
                 Via: SIP/2.0/UDP 192.168.1.10:40000;branch={branch};rport\r\n\
                 Call-ID: inbound-call-1\r\n\
                 CSeq: 1 REFER\r\n\
                 Content-Length: 0\r\n\r\n"
            )
        };

        // Provisional and unrelated responses don't complete the transaction.
        mgr.handle_refer_response(&resp("100 Trying", "z9hG4bK-ref"))
            .await;
        mgr.handle_refer_response(&resp("202 Accepted", "z9hG4bK-other"))
            .await;
        assert!(mgr.pending_refers.lock().await.contains_key("z9hG4bK-ref"));

        mgr.handle_refer_response(&resp("202 Accepted", "z9hG4bK-ref"))
            .await;
        assert_eq!(rx.await, Ok(resp("202 Accepted", "z9hG4bK-ref")));
        assert!(mgr.pending_refers.lock().await.is_empty());
    }

    #[tokio::test]
    async fn transfer_rejects_bad_target_before_lookup_and_unknown_token() {
        let mgr = HandoffManager::new();
        assert_eq!(
            mgr.transfer_call("no-such-token", "1002\r\nX: y").await,
            Err(TransferError::InvalidTarget(
                "target contains characters not allowed in a number or extension"
            ))
        );
        assert_eq!(
            mgr.transfer_call("no-such-token", "1002").await,
            Err(TransferError::NotFound)
        );
    }

    // ── End-to-end over UDP with a fake PBX ─────────────────────────────────

    struct Harness {
        mgr: Arc<HandoffManager>,
        pbx: tokio::net::UdpSocket,
    }

    async fn outgoing_call_harness() -> Harness {
        use crate::sip::proxy::ProxyRegistration;
        use tokio::net::UdpSocket;

        let mgr = Arc::new(HandoffManager::new());
        let pbx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let gw = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let reg = Arc::new(RwLock::new(ProxyRegistration::for_test(
            gw,
            "pbx.example.com",
            mgr.clone(),
        )));
        mgr.register_active_call(
            "tok".into(),
            "outbound-call-1".into(),
            CallOwner::User("alice".into()),
            OUTBOUND_200.into(),
            pbx.local_addr().unwrap(),
            reg,
            None,
        )
        .await;
        Harness { mgr, pbx }
    }

    async fn recv_text(sock: &tokio::net::UdpSocket) -> String {
        let mut buf = vec![0u8; 65535];
        let len = tokio::time::timeout(Duration::from_secs(2), sock.recv(&mut buf))
            .await
            .expect("timed out waiting for SIP message")
            .unwrap();
        String::from_utf8(buf[..len].to_vec()).unwrap()
    }

    fn response_to(request: &str, status: &str) -> String {
        format!(
            "SIP/2.0 {status}\r\n\
             Via: {}\r\n\
             Call-ID: {}\r\n\
             CSeq: {}\r\n\
             Content-Length: 0\r\n\r\n",
            message::extract_header(request, "Via").unwrap(),
            message::extract_header(request, "Call-ID").unwrap(),
            message::extract_header(request, "CSeq").unwrap(),
        )
    }

    #[tokio::test]
    async fn accepted_transfer_then_notify_200_ends_the_call() {
        let Harness { mgr, pbx } = outgoing_call_harness().await;

        let task = {
            let mgr = mgr.clone();
            tokio::spawn(async move { mgr.transfer_call("tok", "1002").await })
        };

        let refer = recv_text(&pbx).await;
        assert!(refer.starts_with("REFER sip:2000@10.0.0.1:5060 SIP/2.0\r\n"));
        // Continues the CSeq space after our INVITE (CSeq 2).
        assert_eq!(message::extract_header(&refer, "CSeq").unwrap(), "3 REFER");
        assert_eq!(
            message::extract_header(&refer, "Refer-To").unwrap(),
            "<sip:1002@pbx.example.com>"
        );

        mgr.handle_refer_response(&response_to(&refer, "202 Accepted"))
            .await;
        assert_eq!(task.await.unwrap(), Ok(()));
        assert!(matches!(
            mgr.get_call_status("tok").await,
            CallStatus::Active
        ));

        // Progress NOTIFYs leave the call alone; a 200 sipfrag ends it.
        mgr.handle_notify(
            "outbound-call-1",
            &notify("refer", "SIP/2.0 180 Ringing\r\n"),
        )
        .await;
        assert!(mgr.is_call_active("outbound-call-1").await);
        mgr.handle_notify("outbound-call-1", &notify("refer", "SIP/2.0 200 OK\r\n"))
            .await;

        let bye = recv_text(&pbx).await;
        assert!(bye.starts_with("BYE sip:2000@10.0.0.1:5060 SIP/2.0\r\n"));
        assert_eq!(message::extract_header(&bye, "CSeq").unwrap(), "4 BYE");
        assert!(!mgr.is_call_active("outbound-call-1").await);
        match mgr.get_call_status("tok").await {
            CallStatus::Ended(info) => assert_eq!(info.reason, "transferred"),
            _ => panic!("call should be ended"),
        }
    }

    #[tokio::test]
    async fn rejected_refer_keeps_the_call_up() {
        let Harness { mgr, pbx } = outgoing_call_harness().await;

        let task = {
            let mgr = mgr.clone();
            tokio::spawn(async move { mgr.transfer_call("tok", "sip:9999@pbx.example.com").await })
        };
        let refer = recv_text(&pbx).await;
        mgr.handle_refer_response(&response_to(&refer, "603 Decline"))
            .await;
        assert_eq!(task.await.unwrap(), Err(TransferError::Rejected(603)));

        // A stray NOTIFY 200 must not end a call whose transfer failed.
        mgr.handle_notify("outbound-call-1", &notify("refer", "SIP/2.0 200 OK\r\n"))
            .await;
        assert!(mgr.is_call_active("outbound-call-1").await);
    }

    #[tokio::test]
    async fn unanswered_refer_is_retransmitted() {
        let Harness { mgr, pbx } = outgoing_call_harness().await;

        let task = {
            let mgr = mgr.clone();
            tokio::spawn(async move { mgr.transfer_call("tok", "1002").await })
        };
        let first = recv_text(&pbx).await;
        let second = recv_text(&pbx).await;
        assert_eq!(first, second, "retransmission must be byte-identical");
        mgr.handle_refer_response(&response_to(&second, "202 Accepted"))
            .await;
        assert_eq!(task.await.unwrap(), Ok(()));
    }

    fn challenge_to(request: &str, status: &str, header: &str) -> String {
        response_to(request, status).replace(
            "Content-Length: 0\r\n",
            &format!(
                "{header}: Digest realm=\"pbx.example.com\", nonce=\"n0nce\"\r\nContent-Length: 0\r\n"
            ),
        )
    }

    #[tokio::test]
    async fn challenged_refer_is_resent_with_digest_credentials() {
        for (status, challenge, authorization) in [
            ("401 Unauthorized", "WWW-Authenticate", "Authorization"),
            (
                "407 Proxy Authentication Required",
                "Proxy-Authenticate",
                "Proxy-Authorization",
            ),
        ] {
            let Harness { mgr, pbx } = outgoing_call_harness().await;
            let task = {
                let mgr = mgr.clone();
                tokio::spawn(async move { mgr.transfer_call("tok", "1002").await })
            };

            let first = recv_text(&pbx).await;
            assert_eq!(message::extract_header(&first, "CSeq").unwrap(), "3 REFER");
            assert!(message::extract_header(&first, authorization).is_none());
            mgr.handle_refer_response(&challenge_to(&first, status, challenge))
                .await;

            let second = recv_text(&pbx).await;
            assert_eq!(message::extract_header(&second, "CSeq").unwrap(), "4 REFER");
            assert_ne!(
                message::extract_via_branch(&first),
                message::extract_via_branch(&second),
                "a new transaction needs a new branch"
            );
            assert_eq!(
                message::extract_header(&second, "Refer-To"),
                message::extract_header(&first, "Refer-To")
            );
            let creds = message::extract_header(&second, authorization)
                .unwrap_or_else(|| panic!("missing {authorization} in\n{second}"));
            let expected = DigestAuth::from_challenge(
                "Digest realm=\"pbx.example.com\", nonce=\"n0nce\"",
                "1001",
                "secret",
                "sip:2000@10.0.0.1:5060",
                "REFER",
            )
            .unwrap();
            assert_eq!(creds, expected.to_header());
            assert!(creds.contains("uri=\"sip:2000@10.0.0.1:5060\""));

            mgr.handle_refer_response(&response_to(&second, "202 Accepted"))
                .await;
            assert_eq!(task.await.unwrap(), Ok(()), "{status}");
            assert!(mgr.is_call_active("outbound-call-1").await);
        }
    }

    #[tokio::test]
    async fn refer_is_retried_with_credentials_only_once() {
        let Harness { mgr, pbx } = outgoing_call_harness().await;
        let task = {
            let mgr = mgr.clone();
            tokio::spawn(async move { mgr.transfer_call("tok", "1002").await })
        };

        let first = recv_text(&pbx).await;
        mgr.handle_refer_response(&challenge_to(
            &first,
            "401 Unauthorized",
            "WWW-Authenticate",
        ))
        .await;
        let second = recv_text(&pbx).await;
        assert!(message::extract_header(&second, "Authorization").is_some());
        mgr.handle_refer_response(&challenge_to(
            &second,
            "407 Proxy Authentication Required",
            "Proxy-Authenticate",
        ))
        .await;

        assert_eq!(task.await.unwrap(), Err(TransferError::Rejected(407)));
        // No third attempt, and the call is left up.
        let mut buf = [0u8; 2048];
        assert!(
            tokio::time::timeout(Duration::from_millis(700), pbx.recv(&mut buf))
                .await
                .is_err(),
            "no further REFER may be sent"
        );
        assert!(mgr.is_call_active("outbound-call-1").await);
    }

    #[tokio::test]
    async fn challenge_without_a_parseable_header_fails_the_transfer() {
        let Harness { mgr, pbx } = outgoing_call_harness().await;
        let task = {
            let mgr = mgr.clone();
            tokio::spawn(async move { mgr.transfer_call("tok", "1002").await })
        };
        let first = recv_text(&pbx).await;
        mgr.handle_refer_response(&response_to(&first, "401 Unauthorized"))
            .await;
        assert_eq!(task.await.unwrap(), Err(TransferError::Rejected(401)));
    }
}
