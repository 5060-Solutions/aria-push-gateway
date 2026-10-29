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
use tokio::sync::{oneshot, RwLock};

use crate::sip::digest::DigestAuth;
use crate::sip::message;
use crate::sip::rtp_relay::RtpRelay;
use crate::sip::transaction::{self, ServerTransactions};

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
    /// The socket the INVITE arrived on (and its responses leave from).
    socket: Arc<tokio::net::UdpSocket>,
    /// Our To tag for every response to this INVITE.
    local_tag: String,
    /// Top Via branch of the INVITE (identifies its transaction).
    invite_branch: String,
    /// The gateway's local IP for SDP rewriting.
    local_ip: String,
    /// The phone-side RTP relay port.
    phone_rtp_port: u16,
    /// The PBX-side RTP relay port.
    pbx_rtp_port: u16,
}

/// What the app can learn about a blind transfer after the PBX accepted it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransferProgress {
    /// No transfer accepted yet on this call.
    #[default]
    None,
    /// The PBX accepted the REFER; the outcome is not known yet.
    Pending,
    /// The transfer failed with this SIP status (408 if it never reported).
    Failed(u16),
}

/// Transfer bookkeeping for one active call.
#[derive(Debug, Default)]
struct TransferTrack {
    /// Bumped per accepted REFER so a stale watchdog can't touch a newer one.
    generation: u64,
    progress: TransferProgress,
    /// Whether any refer NOTIFY arrived for the current generation.
    notified: bool,
}

/// An active call (post-200 OK) tracked for mid-dialog request forwarding.
pub struct ActiveCall {
    /// The device (incoming) or user (outgoing) the call belongs to.
    pub owner: CallOwner,
    pub pbx_addr: SocketAddr,
    pub proxy_reg: Arc<RwLock<super::sip::proxy::ProxyRegistration>>,
    /// The socket that owns this dialog; in-dialog requests are only
    /// accepted when they arrive on it.
    socket: Arc<tokio::net::UdpSocket>,
    /// Dialog identifiers and routing used for in-dialog requests (BYE, REFER).
    pub dialog: Dialog,
    /// Last CSeq number the gateway used for a request on this dialog.
    local_cseq: AtomicU32,
    /// Set while a REFER is outstanding or after the PBX accepted one, so a
    /// later NOTIFY/BYE is attributed to the transfer.
    transfer_pending: Arc<AtomicBool>,
    /// RTP relay for this call — stopped and dropped when the call ends.
    pub rtp_relay: Option<Arc<RtpRelay>>,
    /// Outcome of the latest accepted transfer, for `/status`.
    transfer: std::sync::Mutex<TransferTrack>,
    /// Our session description (sent again on a session-refresh re-INVITE).
    local_sdp: String,
    /// Our Contact URI on this dialog.
    contact: String,
    /// Branch of the INVITE that created the dialog, for an incoming call.
    invite_branch: Option<String>,
    /// While a 2xx to an INVITE is being retransmitted: its CSeq number and
    /// the signal that stops it when the ACK arrives.
    ack_wait: std::sync::Mutex<Option<(u32, oneshot::Sender<()>)>>,
    /// The latest 2xx we sent to an INVITE on this dialog and its CSeq.
    last_2xx: std::sync::Mutex<Option<(u32, String)>>,
    /// Dropped together with the call, which wakes the receiver returned by
    /// [`HandoffManager::register_active_call`] however the call ended.
    _ended: Option<oneshot::Sender<()>>,
}

impl ActiveCall {
    fn new(
        owner: CallOwner,
        pbx_addr: SocketAddr,
        proxy_reg: Arc<RwLock<super::sip::proxy::ProxyRegistration>>,
        socket: Arc<tokio::net::UdpSocket>,
        dialog: Dialog,
        initial_cseq: u32,
        rtp_relay: Option<Arc<RtpRelay>>,
    ) -> Self {
        Self {
            owner,
            pbx_addr,
            proxy_reg,
            socket,
            dialog,
            local_cseq: AtomicU32::new(initial_cseq),
            transfer_pending: Arc::new(AtomicBool::new(false)),
            rtp_relay,
            transfer: std::sync::Mutex::new(TransferTrack::default()),
            local_sdp: String::new(),
            contact: String::new(),
            invite_branch: None,
            ack_wait: std::sync::Mutex::new(None),
            last_2xx: std::sync::Mutex::new(None),
            _ended: None,
        }
    }

    /// Whether `request` from the PBX belongs to this call's dialog and
    /// arrived on the socket that owns it: same Call-ID, the PBX's tag in
    /// From and ours in To (RFC 3261 §12.2.2).
    fn owns_request(&self, request: &str, socket: &Arc<tokio::net::UdpSocket>) -> bool {
        Arc::ptr_eq(&self.socket, socket)
            && message::extract_header(request, "Call-ID").as_deref()
                == Some(self.dialog.call_id.as_str())
            && message::extract_header(request, "From")
                .and_then(|v| message::header_param(&v, "tag"))
                == message::header_param(&self.dialog.remote, "tag")
            && message::extract_to_tag(request) == message::header_param(&self.dialog.local, "tag")
    }

    fn ack_wait(&self) -> std::sync::MutexGuard<'_, Option<(u32, oneshot::Sender<()>)>> {
        self.ack_wait
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn last_2xx(&self) -> std::sync::MutexGuard<'_, Option<(u32, String)>> {
        self.last_2xx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn transfer_track(&self) -> std::sync::MutexGuard<'_, TransferTrack> {
        self.transfer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The transfer state the app sees.
    pub fn transfer_progress(&self) -> TransferProgress {
        self.transfer_track().progress
    }

    /// Mark the transfer failed with `code` and release the call for
    /// another transfer attempt.
    fn fail_transfer(&self, code: u16) {
        self.transfer_track().progress = TransferProgress::Failed(code);
        self.transfer_pending.store(false, Ordering::SeqCst);
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

/// The number in a message's CSeq header.
fn cseq_number(msg: &str) -> Option<u32> {
    message::extract_header(msg, "CSeq")?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// Whether two handles name the same socket.
fn c_matches(a: &Arc<tokio::net::UdpSocket>, b: &Arc<tokio::net::UdpSocket>) -> bool {
    Arc::ptr_eq(a, b)
}

/// Fire-and-forget UDP send from synchronous context (a lock is held).
fn try_send(
    socket: &Arc<tokio::net::UdpSocket>,
    msg: &str,
    dest: SocketAddr,
) -> std::io::Result<usize> {
    socket.try_send_to(msg.as_bytes(), dest)
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
    /// Another transfer of this call is already in progress.
    InProgress,
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
            Self::InProgress => write!(f, "a transfer of this call is already in progress"),
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
#[cfg(test)]
pub fn refer_notify_status(notify: &str) -> Option<u16> {
    parse_refer_notify(notify)?.status
}

/// Outstanding REFER transactions: Via branch -> where the final response
/// goes, and the socket the REFER was sent on (the only one whose responses
/// may complete it).
type PendingRefers = HashMap<String, (oneshot::Sender<String>, Arc<tokio::net::UdpSocket>)>;

fn lock_refers(
    refers: &std::sync::Mutex<PendingRefers>,
) -> std::sync::MutexGuard<'_, PendingRefers> {
    refers
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Releases a call's transfer claim when dropped, unless the transfer was
/// accepted. Covers every way `transfer_call` can stop, including its
/// future being dropped when the HTTP client disconnects mid-transfer.
struct TransferClaim {
    flag: Arc<AtomicBool>,
    accepted: bool,
}

impl Drop for TransferClaim {
    fn drop(&mut self) {
        if !self.accepted {
            self.flag.store(false, Ordering::SeqCst);
        }
    }
}

/// Removes a REFER transaction's response slot when dropped.
struct ReferSlot<'a> {
    refers: &'a std::sync::Mutex<PendingRefers>,
    branch: &'a str,
}

impl Drop for ReferSlot<'_> {
    fn drop(&mut self) {
        lock_refers(self.refers).remove(self.branch);
    }
}

/// A NOTIFY for a `refer` event subscription (RFC 3515).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReferNotify {
    /// Status code from the `message/sipfrag` body, if it parses.
    pub status: Option<u16>,
    /// `Subscription-State: terminated` — no further NOTIFYs will come.
    pub terminated: bool,
}

/// Parse a refer-subscription NOTIFY, or `None` for another event package.
pub fn parse_refer_notify(notify: &str) -> Option<ReferNotify> {
    let event = message::extract_header(notify, "Event")?;
    let package = event.split(';').next().unwrap_or_default().trim();
    if !package.eq_ignore_ascii_case("refer") {
        return None;
    }
    let terminated = message::extract_header(notify, "Subscription-State").is_some_and(|v| {
        v.split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .eq_ignore_ascii_case("terminated")
    });
    let status = notify
        .split_once("\r\n\r\n")
        .and_then(|(_, body)| message::parse_sipfrag_status(body.trim_start()));
    Some(ReferNotify { status, terminated })
}

/// How long after the PBX accepts a REFER the gateway waits for the first
/// NOTIFY before reporting the transfer as failed (408).
const REFER_NOTIFY_TIMEOUT: Duration = Duration::from_secs(30);

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
    pending_refers: Arc<std::sync::Mutex<PendingRefers>>,
    /// See [`REFER_NOTIFY_TIMEOUT`]; shortened in tests.
    refer_notify_timeout: Duration,
    /// Responses for retransmitted requests and ACKs of non-2xx finals.
    uas: Arc<ServerTransactions>,
}

/// Why accepting a call failed.
#[derive(Debug, PartialEq, Eq)]
pub enum AcceptError {
    /// No pending call has this token (expired, cancelled or answered).
    NotFound,
    /// A call with this Call-ID is already active; it is never replaced.
    Conflict,
    /// The 200 OK could not be built or sent to the PBX.
    Send(String),
}

impl std::fmt::Display for AcceptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "call token not found or expired"),
            Self::Conflict => write!(f, "a call with this Call-ID is already active"),
            Self::Send(e) => write!(f, "failed to send 200 OK: {e}"),
        }
    }
}

/// How an incoming INVITE without a To tag relates to calls we know.
pub enum InviteDisposition {
    /// A new call.
    New,
    /// A retransmission of an INVITE we're handling: send this again.
    Retransmission(String),
    /// Same Call-ID as a call we know but a different transaction (loop or
    /// merged request): answer 482.
    Merged,
}

/// What a CANCEL from the PBX matched.
pub enum CancelOutcome {
    /// A ringing call: it is ended; answer 200 to the CANCEL and 487 to the
    /// INVITE (`invite`, sent to `dest` with our `local_tag`).
    Cancelled {
        invite: String,
        local_tag: String,
        dest: SocketAddr,
    },
    /// The INVITE was already answered; the CANCEL has no effect (200).
    AlreadyAnswered,
    /// No such INVITE transaction (481).
    Unknown,
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
            pending_refers: Arc::new(std::sync::Mutex::new(HashMap::new())),
            refer_notify_timeout: REFER_NOTIFY_TIMEOUT,
            uas: Arc::new(ServerTransactions::default()),
        }
    }

    /// Server transaction memory shared with the SIP receive loops.
    pub fn server_transactions(&self) -> &Arc<ServerTransactions> {
        &self.uas
    }

    /// Shorten the wait for the first refer NOTIFY (tests only).
    #[cfg(test)]
    fn with_refer_notify_timeout(mut self, timeout: Duration) -> Self {
        self.refer_notify_timeout = timeout;
        self
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
        let socket = proxy_reg.read().await.socket.clone();
        let invite_branch = message::extract_via_branch(&invite_raw).unwrap_or_default();

        let pending = PendingCall {
            device_id,
            call_id,
            invite_raw,
            pbx_addr,
            proxy_reg,
            rtp_relay,
            socket,
            local_tag: message::generate_tag(),
            invite_branch,
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
        let uas = Arc::clone(&self.uas);
        let token_clone = token.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(30)).await;
            let mut calls = pending_ref.write().await;
            if let Some(call) = calls.remove(&token_clone) {
                tracing::warn!(
                    token = %token_clone,
                    "Call handoff timed out — sending 480"
                );
                if let Some(resp) = message::build_response(
                    &call.invite_raw,
                    480,
                    "Temporarily Unavailable",
                    Some(&call.local_tag),
                    false,
                    "",
                    None,
                ) {
                    uas.send_final(&call.socket, call.pbx_addr, &call.invite_raw, resp);
                }
            }
        });

        token
    }

    /// Mobile app accepts the call with an SDP answer.
    ///
    /// The pending-calls lock is held until the call is in the active map,
    /// so nothing (status polls, ownership checks, hangup, CANCEL, the
    /// handoff timeout) can observe the call as neither pending nor active.
    ///
    /// The 200 OK is retransmitted until the PBX ACKs it; without an ACK
    /// within 64·T1 the call is ended with a BYE (RFC 3261 §13.3.1.4).
    pub async fn accept_call(
        self: &Arc<Self>,
        call_token: &str,
        sdp_answer: String,
    ) -> Result<(), AcceptError> {
        let mut pending = self.pending.write().await;
        let call_id = pending
            .get(call_token)
            .ok_or(AcceptError::NotFound)?
            .call_id
            .clone();
        if self.active.read().await.contains_key(&call_id) {
            tracing::warn!(call_id = %call_id, "accept for a Call-ID that is already active — refused");
            return Err(AcceptError::Conflict);
        }
        let call = pending.remove(call_token).ok_or(AcceptError::NotFound)?;

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
        let local_addr = call.proxy_reg.read().await.local_addr;
        let contact_uri = format!("sip:aria-gateway@{}:{}", local_addr.ip(), local_addr.port());
        let ok = message::build_200_ok_invite(
            &call.invite_raw,
            &rewritten_sdp,
            &contact_uri,
            &call.local_tag,
        )
        .ok_or_else(|| AcceptError::Send("INVITE is malformed".into()))?;
        call.socket
            .send_to(ok.as_bytes(), call.pbx_addr)
            .await
            .map_err(|e| AcceptError::Send(e.to_string()))?;
        tracing::info!(token = %call_token, "Sent 200 OK to PBX with rewritten SDP");

        // Move to active calls. The gateway has sent no requests on this
        // dialog yet, so its first one (BYE/REFER) uses CSeq 1.
        let dialog = Dialog::from_uas(&call.invite_raw, &ok, call.pbx_addr);
        let invite_cseq = cseq_number(&call.invite_raw).unwrap_or(0);
        let mut active_call = ActiveCall::new(
            CallOwner::Device(call.device_id),
            call.pbx_addr,
            call.proxy_reg.clone(),
            call.socket.clone(),
            dialog,
            0,
            call.rtp_relay,
        );
        active_call.local_sdp = rewritten_sdp;
        active_call.contact = contact_uri;
        active_call.invite_branch = Some(call.invite_branch);
        let (ack_tx, ack_rx) = oneshot::channel();
        *active_call.ack_wait() = Some((invite_cseq, ack_tx));
        *active_call.last_2xx() = Some((invite_cseq, ok.clone()));

        {
            let mut active = self.active.write().await;
            active.insert(call.call_id.clone(), active_call);
        }
        {
            let mut map = self.token_to_call_id.write().await;
            map.insert(call_token.to_string(), call.call_id.clone());
        }
        self.retransmit_2xx(call.call_id, call.socket, call.pbx_addr, ok, ack_rx);

        drop(pending);
        Ok(())
    }

    /// Retransmit a 2xx to an INVITE until its ACK arrives (`ack` fires, or
    /// is dropped with the call). Without an ACK the call is ended.
    fn retransmit_2xx(
        self: &Arc<Self>,
        call_id: String,
        socket: Arc<tokio::net::UdpSocket>,
        dest: SocketAddr,
        ok: String,
        ack: oneshot::Receiver<()>,
    ) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            // Already sent once; resume at the first retransmission.
            tokio::time::sleep(transaction::T1).await;
            let mut ack = ack;
            if ack.try_recv() != Err(oneshot::error::TryRecvError::Empty) {
                return;
            }
            if transaction::retransmit_until(&socket, dest, &ok, transaction::T2, ack).await {
                return;
            }
            tracing::warn!(call_id = %call_id, "No ACK for our 200 OK — ending the call");
            let _ = this.end_call_with_bye(&call_id, Some("no_ack")).await;
        });
    }

    /// Wait for any `accept_call` in flight to finish moving its call from
    /// pending to active.
    async fn settle_accepts(&self) {
        drop(self.pending.read().await);
    }

    /// Mobile app rejects the call.
    pub async fn reject_call(&self, call_token: &str) -> anyhow::Result<()> {
        let call = {
            let mut calls = self.pending.write().await;
            calls
                .remove(call_token)
                .ok_or_else(|| anyhow::anyhow!("Call token not found or expired"))?
        };

        // Send 603 Decline (retransmitted until the PBX ACKs it)
        let resp = message::build_response(
            &call.invite_raw,
            603,
            "Decline",
            Some(&call.local_tag),
            false,
            "",
            None,
        )
        .ok_or_else(|| anyhow::anyhow!("INVITE is malformed"))?;
        self.uas
            .send_final(&call.socket, call.pbx_addr, &call.invite_raw, resp);
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

    /// Handle an ACK from the PBX: either for a non-2xx final we are
    /// retransmitting (same branch as the INVITE), or for a 2xx on one of
    /// this socket's dialogs (matching CSeq). Returns whether it matched.
    pub async fn handle_ack(&self, ack: &str, socket: &Arc<tokio::net::UdpSocket>) -> bool {
        if self.uas.ack(socket, ack) {
            return true;
        }
        let call_id = message::extract_header(ack, "Call-ID").unwrap_or_default();
        let active = self.active.read().await;
        let Some(call) = active.get(&call_id).filter(|c| c.owns_request(ack, socket)) else {
            tracing::debug!(call_id = %call_id, "ACK matches no transaction");
            return false;
        };
        let mut wait = call.ack_wait();
        if wait.as_ref().map(|(cseq, _)| *cseq) == cseq_number(ack) {
            if let Some((_, tx)) = wait.take() {
                let _ = tx.send(());
            }
            tracing::debug!(call_id = %call_id, "ACK received for our 200 OK");
        }
        true
    }

    /// Classify an INVITE without a To tag that arrived on `socket`.
    pub async fn classify_invite(
        &self,
        invite: &str,
        socket: &Arc<tokio::net::UdpSocket>,
    ) -> InviteDisposition {
        let call_id = message::extract_header(invite, "Call-ID").unwrap_or_default();
        let branch = message::extract_via_branch(invite).unwrap_or_default();

        if let Some(call) = self
            .pending
            .read()
            .await
            .values()
            .find(|c| c.call_id == call_id)
        {
            return if c_matches(&call.socket, socket) && call.invite_branch == branch {
                message::build_100_trying(invite)
                    .map_or(InviteDisposition::Merged, InviteDisposition::Retransmission)
            } else {
                InviteDisposition::Merged
            };
        }
        if let Some(call) = self.active.read().await.get(&call_id) {
            let same = c_matches(&call.socket, socket)
                && call.invite_branch.as_deref() == Some(branch.as_str());
            return match call.last_2xx().clone() {
                Some((_, ok)) if same => InviteDisposition::Retransmission(ok),
                _ => InviteDisposition::Merged,
            };
        }
        match self.uas.replay(socket, invite) {
            Some(resp) => InviteDisposition::Retransmission(resp),
            None => InviteDisposition::New,
        }
    }

    /// Answer an in-dialog re-INVITE (session refresh, hold, ...) on one of
    /// `socket`'s dialogs with 200 OK and our current session description.
    /// A re-INVITE while our previous 2xx is still unacknowledged gets 491.
    /// Returns `None` if the request matches no dialog (the caller sends
    /// 481), else the response sent.
    pub async fn handle_reinvite(
        self: &Arc<Self>,
        invite: &str,
        from: SocketAddr,
        socket: &Arc<tokio::net::UdpSocket>,
    ) -> Option<String> {
        let call_id = message::extract_header(invite, "Call-ID").unwrap_or_default();
        let cseq = cseq_number(invite).unwrap_or(0);
        let (ok, ack_rx) = {
            let active = self.active.read().await;
            let call = active
                .get(&call_id)
                .filter(|c| c.owns_request(invite, socket))?;

            if let Some((last_cseq, last)) = call.last_2xx().clone() {
                if last_cseq == cseq {
                    // Retransmitted re-INVITE.
                    let _ = try_send(socket, &last, from);
                    return Some(last);
                }
            }
            if call.ack_wait().is_some() {
                let resp = message::build_simple_response(invite, 491, "Request Pending")?;
                self.uas.remember(socket, invite, &resp, from);
                let _ = try_send(socket, &resp, from);
                return Some(resp);
            }

            let ok = message::build_response(
                invite,
                200,
                "OK",
                None,
                false,
                &format!(
                    "Contact: <{}>\r\nAllow: INVITE, ACK, CANCEL, BYE, OPTIONS, REFER, NOTIFY\r\n",
                    call.contact
                ),
                Some(("application/sdp", &call.local_sdp)),
            )?;
            let (tx, rx) = oneshot::channel();
            *call.ack_wait() = Some((cseq, tx));
            *call.last_2xx() = Some((cseq, ok.clone()));
            (ok, rx)
        };
        tracing::info!(call_id = %call_id, "Answered re-INVITE with our current session");
        let _ = socket.send_to(ok.as_bytes(), from).await;
        self.retransmit_2xx(call_id, socket.clone(), from, ok.clone(), ack_rx);
        Some(ok)
    }

    /// Handle a CANCEL from the PBX. Only a CANCEL for a still-ringing INVITE
    /// on this socket (same Call-ID and branch) ends the call; one for an
    /// answered INVITE has no effect, and anything else is unknown.
    pub async fn handle_cancel(
        &self,
        cancel: &str,
        socket: &Arc<tokio::net::UdpSocket>,
    ) -> CancelOutcome {
        let call_id = message::extract_header(cancel, "Call-ID").unwrap_or_default();
        let branch = message::extract_via_branch(cancel).unwrap_or_default();

        let mut pending = self.pending.write().await;
        let token = pending
            .iter()
            .find(|(_, c)| {
                c.call_id == call_id && c.invite_branch == branch && c_matches(&c.socket, socket)
            })
            .map(|(t, _)| t.clone());

        if let Some(token) = token {
            let call = pending.remove(&token).expect("found above");
            drop(pending);
            tracing::info!(call_id = %call_id, token = %token, "Pending call cancelled");

            // Record as ended so mobile app can detect cancellation
            self.ended_calls.write().await.insert(
                token,
                EndedCallInfo {
                    reason: "cancelled".to_string(),
                    ended_at: chrono::Utc::now(),
                    owner: CallOwner::Device(call.device_id),
                },
            );
            return CancelOutcome::Cancelled {
                invite: call.invite_raw,
                local_tag: call.local_tag,
                dest: call.pbx_addr,
            };
        }
        drop(pending);

        let answered = self.active.read().await.get(&call_id).is_some_and(|c| {
            c_matches(&c.socket, socket) && c.invite_branch.as_deref() == Some(branch.as_str())
        }) || self.uas.answered_invite(socket, &branch);
        if answered {
            CancelOutcome::AlreadyAnswered
        } else {
            CancelOutcome::Unknown
        }
    }

    /// Answer a CANCEL as [`Self::handle_cancel`] decides: 200 (and 487 to
    /// the INVITE) for a ringing call, 200 for an answered one, else 481.
    pub async fn answer_cancel(
        &self,
        cancel: &str,
        from: SocketAddr,
        socket: &Arc<tokio::net::UdpSocket>,
    ) -> anyhow::Result<()> {
        match self.handle_cancel(cancel, socket).await {
            CancelOutcome::Cancelled {
                invite,
                local_tag,
                dest,
            } => {
                if let Some(ok) =
                    message::build_response(cancel, 200, "OK", Some(&local_tag), false, "", None)
                {
                    socket.send_to(ok.as_bytes(), from).await?;
                    self.uas.remember(socket, cancel, &ok, from);
                }
                if let Some(terminated) = message::build_response(
                    &invite,
                    487,
                    "Request Terminated",
                    Some(&local_tag),
                    false,
                    "",
                    None,
                ) {
                    self.uas.send_final(socket, dest, &invite, terminated);
                }
            }
            CancelOutcome::AlreadyAnswered => {
                if let Some(ok) = message::build_simple_response(cancel, 200, "OK") {
                    socket.send_to(ok.as_bytes(), from).await?;
                    self.uas.remember(socket, cancel, &ok, from);
                }
            }
            CancelOutcome::Unknown => {
                if let Some(resp) = message::build_481(cancel) {
                    socket.send_to(resp.as_bytes(), from).await?;
                }
            }
        }
        Ok(())
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
                if let Some(call) = active.get(call_id) {
                    return CallStatus::active(call.transfer_progress());
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
    ///
    /// The BYE must match the call's dialog (Call-ID and both tags) and
    /// arrive on the socket that owns it; otherwise it is treated as unknown.
    pub async fn handle_bye_from_pbx(
        &self,
        call_id: &str,
        bye_raw: &str,
        from: SocketAddr,
        socket: &Arc<tokio::net::UdpSocket>,
    ) -> anyhow::Result<Option<CallOwner>> {
        let call = {
            let mut active = self.active.write().await;
            match active.get(call_id) {
                Some(c) if c.owns_request(bye_raw, socket) => active.remove(call_id),
                Some(_) => {
                    tracing::warn!(call_id = %call_id, "BYE does not match the call's dialog or socket");
                    None
                }
                None => None,
            }
        };

        let Some(call) = call else {
            return Ok(None);
        };

        // Send 200 OK for the BYE (and repeat it for retransmissions)
        if let Some(resp) = message::build_simple_response(bye_raw, 200, "OK") {
            self.uas.remember(socket, bye_raw, &resp, from);
            socket.send_to(resp.as_bytes(), from).await?;
        }

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

    /// Simulate the PBX cancelling the ringing call `call_id` (tests only).
    #[cfg(test)]
    pub async fn cancel_pending(&self, call_id: &str) -> CancelOutcome {
        let found = self
            .pending
            .read()
            .await
            .values()
            .find(|c| c.call_id == call_id)
            .map(|c| (message::build_cancel(&c.invite_raw), c.socket.clone()));
        match found {
            Some((Some(cancel), socket)) => self.handle_cancel(&cancel, &socket).await,
            _ => CancelOutcome::Unknown,
        }
    }

    /// Token of the ringing call with this Call-ID (tests only).
    #[cfg(test)]
    pub async fn pending_token(&self, call_id: &str) -> Option<String> {
        self.pending
            .read()
            .await
            .iter()
            .find(|(_, c)| c.call_id == call_id)
            .map(|(t, _)| t.clone())
    }

    /// Number of calls waiting for the app to answer (tests only).
    #[cfg(test)]
    pub async fn pending_count(&self) -> usize {
        self.pending.read().await.len()
    }

    /// Whether a call with this SIP Call-ID is still active.
    #[cfg(test)]
    pub async fn is_call_active(&self, call_id: &str) -> bool {
        self.active.read().await.contains_key(call_id)
    }

    /// Mobile app hangs up — send BYE to PBX.
    pub async fn hangup_call(&self, call_token: &str) -> anyhow::Result<()> {
        self.settle_accepts().await;
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
        self.settle_accepts().await;

        let call_id = self
            .active_call_id(call_token)
            .await
            .ok_or(TransferError::NotFound)?;

        let (mut claim, dialog, pbx_addr, proxy_reg) = {
            let active = self.active.read().await;
            let call = active.get(&call_id).ok_or(TransferError::NotFound)?;
            // Claim the call for this transfer; a second concurrent one is
            // refused rather than racing the first on the same dialog.
            if call
                .transfer_pending
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
            {
                return Err(TransferError::InProgress);
            }
            let claim = TransferClaim {
                flag: call.transfer_pending.clone(),
                accepted: false,
            };
            (
                claim,
                call.dialog.clone(),
                call.pbx_addr,
                call.proxy_reg.clone(),
            )
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
                // Stay claimed until the NOTIFY/BYE resolves the transfer.
                claim.accepted = true;
                tracing::info!(call_id = %call_id, "PBX accepted REFER");
                self.watch_transfer(&call_id).await;
            }
            Err(e) => {
                tracing::warn!(call_id = %call_id, "Transfer failed: {}", e);
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
        socket: &Arc<tokio::net::UdpSocket>,
        pbx_addr: SocketAddr,
        refer: &str,
        branch: &str,
    ) -> Result<String, TransferError> {
        let (tx, mut rx) = oneshot::channel();
        lock_refers(&self.pending_refers).insert(branch.to_string(), (tx, socket.clone()));
        let _slot = ReferSlot {
            refers: &self.pending_refers,
            branch,
        };

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
        result
    }

    /// Deliver a response to a REFER the gateway sent. Provisional responses
    /// are ignored; the first final response completes the transaction.
    ///
    /// Only a response arriving on the socket the REFER was sent from can
    /// complete it.
    pub async fn handle_refer_response_on(
        &self,
        response: &str,
        socket: &Arc<tokio::net::UdpSocket>,
    ) {
        let (Some(status), Some(branch)) = (
            message::parse_status_code(response),
            message::extract_via_branch(response),
        ) else {
            return;
        };
        if status < 200 {
            return;
        }
        let slot = {
            let mut refers = lock_refers(&self.pending_refers);
            match refers.get(&branch) {
                Some((_, owner)) if Arc::ptr_eq(owner, socket) => refers.remove(&branch),
                Some(_) => {
                    tracing::warn!(%branch, "REFER response arrived on the wrong socket — ignored");
                    None
                }
                None => None,
            }
        };
        if let Some((tx, _)) = slot {
            let _ = tx.send(response.to_string());
        }
    }

    /// [`Self::handle_refer_response_on`] on the REFER's own socket (tests).
    #[cfg(test)]
    pub async fn handle_refer_response(&self, response: &str) {
        let socket = message::extract_via_branch(response).and_then(|b| {
            lock_refers(&self.pending_refers)
                .get(&b)
                .map(|(_, socket)| socket.clone())
        });
        if let Some(socket) = socket {
            self.handle_refer_response_on(response, &socket).await;
        }
    }

    /// Mark the call's transfer pending and start a watchdog: if no refer
    /// NOTIFY arrives within the timeout, the transfer is reported failed
    /// with 408 and the call is released for another attempt.
    async fn watch_transfer(&self, call_id: &str) {
        let generation = {
            let active = self.active.read().await;
            let Some(call) = active.get(call_id) else {
                return;
            };
            let mut track = call.transfer_track();
            track.generation += 1;
            track.progress = TransferProgress::Pending;
            track.notified = false;
            track.generation
        };

        let active = Arc::clone(&self.active);
        let call_id = call_id.to_string();
        let timeout = self.refer_notify_timeout;
        tokio::spawn(async move {
            tokio::time::sleep(timeout).await;
            let active = active.read().await;
            let Some(call) = active.get(&call_id) else {
                return;
            };
            let silent = {
                let track = call.transfer_track();
                track.generation == generation
                    && track.progress == TransferProgress::Pending
                    && !track.notified
            };
            if silent {
                tracing::warn!(call_id = %call_id, "No NOTIFY after accepted REFER — transfer failed (408)");
                call.fail_transfer(408);
            }
        });
    }

    /// Handle a NOTIFY from the PBX (already answered with 200 OK by the
    /// caller) for a refer subscription:
    ///
    /// - a 2xx sipfrag means the transfer completed: end our leg with a BYE;
    /// - a 3xx–6xx sipfrag means it failed: report it and keep the call up;
    /// - a terminated subscription without a 2xx also means it failed (408
    ///   when no final status was reported).
    ///
    /// Returns whether the NOTIFY belongs to a dialog owned by `socket`
    /// (Call-ID and both tags); the caller answers 481 when it doesn't.
    pub async fn handle_notify_on(
        &self,
        call_id: &str,
        notify: &str,
        socket: &Arc<tokio::net::UdpSocket>,
    ) -> bool {
        let in_dialog = self
            .active
            .read()
            .await
            .get(call_id)
            .is_some_and(|c| c.owns_request(notify, socket));
        if !in_dialog {
            tracing::debug!(call_id = %call_id, "NOTIFY matches no dialog on this socket");
            return false;
        }

        let Some(report) = parse_refer_notify(notify) else {
            tracing::debug!(call_id = %call_id, "NOTIFY is not a refer progress report");
            return true;
        };

        let completed = {
            let active = self.active.read().await;
            let Some(call) = active
                .get(call_id)
                .filter(|c| c.transfer_pending.load(Ordering::SeqCst))
            else {
                tracing::debug!(call_id = %call_id, ?report, "refer NOTIFY for a call with no transfer in progress");
                return true;
            };
            call.transfer_track().notified = true;

            match report.status {
                Some(200..=299) => true,
                Some(status @ 300..) => {
                    tracing::warn!(call_id = %call_id, status, "Transfer target failed — call stays up");
                    call.fail_transfer(status);
                    false
                }
                status if report.terminated => {
                    tracing::warn!(call_id = %call_id, ?status, "Refer subscription ended without success — call stays up");
                    call.fail_transfer(408);
                    false
                }
                status => {
                    tracing::debug!(call_id = %call_id, ?status, "Transfer in progress");
                    false
                }
            }
        };

        if completed {
            tracing::info!(call_id = %call_id, "Transfer completed — ending gateway leg");
            if let Err(e) = self.end_call_with_bye(call_id, Some("transferred")).await {
                tracing::warn!(call_id = %call_id, "Failed to end transferred call: {}", e);
            }
        }
        true
    }

    /// [`Self::handle_notify_on`] on the call's own socket (tests only).
    #[cfg(test)]
    pub async fn handle_notify(&self, call_id: &str, notify: &str) {
        let socket = self
            .active
            .read()
            .await
            .get(call_id)
            .map(|c| c.socket.clone());
        if let Some(socket) = socket {
            self.handle_notify_on(call_id, notify, &socket).await;
        }
    }

    /// Register an active call directly (used for outgoing calls that skip the
    /// pending phase since we already have the SDP answer).
    ///
    /// `invite_raw` is the PBX's 200 OK to the gateway's INVITE.
    ///
    /// The returned receiver completes (with an error) once the call is no
    /// longer active — hung up by the app, ended by the PBX or transferred —
    /// so the caller can stop the call's receive loop.
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
        local_sdp: String,
        contact: String,
    ) -> oneshot::Receiver<()> {
        let dialog = Dialog::from_uac(&invite_raw, pbx_addr);
        // Continue the CSeq space our INVITE started.
        let initial_cseq = message::extract_header(&invite_raw, "CSeq")
            .and_then(|v| v.split_whitespace().next()?.parse().ok())
            .unwrap_or(1);
        let (ended_tx, ended_rx) = oneshot::channel();
        let socket = proxy_reg.read().await.socket.clone();
        let mut active_call = ActiveCall::new(
            owner,
            pbx_addr,
            proxy_reg,
            socket,
            dialog,
            initial_cseq,
            rtp_relay,
        );
        active_call._ended = Some(ended_tx);
        active_call.local_sdp = local_sdp;
        active_call.contact = contact;

        {
            let mut active = self.active.write().await;
            active.insert(call_id.clone(), active_call);
        }
        {
            let mut map = self.token_to_call_id.write().await;
            map.insert(call_token, call_id);
        }
        ended_rx
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

impl CallStatus {
    fn active(progress: TransferProgress) -> Self {
        let (transfer, transfer_code) = match progress {
            TransferProgress::None => (None, None),
            TransferProgress::Pending => (Some("pending"), None),
            TransferProgress::Failed(code) => (Some("failed"), Some(code)),
        };
        Self::Active {
            transfer,
            transfer_code,
        }
    }
}

/// Status of a call from the gateway's perspective.
#[derive(serde::Serialize)]
#[serde(tag = "status")]
pub enum CallStatus {
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "active")]
    Active {
        /// `"pending"` or `"failed"` once a transfer was accepted; omitted
        /// otherwise.
        #[serde(skip_serializing_if = "Option::is_none")]
        transfer: Option<&'static str>,
        /// SIP status of a failed transfer (408 if it never reported).
        #[serde(skip_serializing_if = "Option::is_none")]
        transfer_code: Option<u16>,
    },
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
        notify_with_state(event, frag, "active;expires=60")
    }

    fn notify_with_state(event: &str, frag: &str, state: &str) -> String {
        format!(
            "NOTIFY sip:aria-gateway@192.168.1.10:40000 SIP/2.0\r\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-n\r\n\
             From: <sip:2000@pbx.example.com>;tag=pbxtag\r\n\
             To: <sip:1001@pbx.example.com>;tag=gwtag\r\n\
             Call-ID: outbound-call-1\r\n\
             CSeq: 103 NOTIFY\r\n\
             Event: {event}\r\n\
             Subscription-State: {state}\r\n\
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
        let own = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let other = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        lock_refers(&mgr.pending_refers).insert("z9hG4bK-ref".into(), (tx, own.clone()));

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
        assert!(lock_refers(&mgr.pending_refers).contains_key("z9hG4bK-ref"));

        // A response on another socket can't complete it either.
        mgr.handle_refer_response_on(&resp("202 Accepted", "z9hG4bK-ref"), &other)
            .await;
        assert!(lock_refers(&mgr.pending_refers).contains_key("z9hG4bK-ref"));

        mgr.handle_refer_response_on(&resp("202 Accepted", "z9hG4bK-ref"), &own)
            .await;
        assert_eq!(rx.await, Ok(resp("202 Accepted", "z9hG4bK-ref")));
        assert!(lock_refers(&mgr.pending_refers).is_empty());
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
        outgoing_call_harness_with(HandoffManager::new()).await
    }

    async fn outgoing_call_harness_with(mgr: HandoffManager) -> Harness {
        use crate::sip::proxy::ProxyRegistration;
        use tokio::net::UdpSocket;

        let mgr = Arc::new(mgr);
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
            "v=0\r\n".into(),
            "sip:gw@127.0.0.1".into(),
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
            CallStatus::Active { .. }
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

    #[tokio::test]
    async fn second_concurrent_transfer_is_refused() {
        let Harness { mgr, pbx } = outgoing_call_harness().await;
        let first = {
            let mgr = mgr.clone();
            tokio::spawn(async move { mgr.transfer_call("tok", "1002").await })
        };
        let refer = recv_text(&pbx).await;

        // While the first REFER is outstanding...
        assert_eq!(
            mgr.transfer_call("tok", "1003").await,
            Err(TransferError::InProgress)
        );

        // ...and after the PBX accepted it, until the transfer resolves.
        mgr.handle_refer_response(&response_to(&refer, "202 Accepted"))
            .await;
        assert_eq!(first.await.unwrap(), Ok(()));
        assert_eq!(
            mgr.transfer_call("tok", "1003").await,
            Err(TransferError::InProgress)
        );

        // A failed transfer releases the call for another attempt.
        mgr.handle_notify(
            "outbound-call-1",
            &notify("refer", "SIP/2.0 486 Busy Here\r\n"),
        )
        .await;
        let retry = {
            let mgr = mgr.clone();
            tokio::spawn(async move { mgr.transfer_call("tok", "1003").await })
        };
        let refer = recv_text(&pbx).await;
        assert_eq!(
            message::extract_header(&refer, "Refer-To").unwrap(),
            "<sip:1003@pbx.example.com>"
        );
        mgr.handle_refer_response(&response_to(&refer, "202 Accepted"))
            .await;
        assert_eq!(retry.await.unwrap(), Ok(()));
    }

    #[tokio::test]
    async fn rejected_transfer_releases_the_call() {
        let Harness { mgr, pbx } = outgoing_call_harness().await;
        let task = {
            let mgr = mgr.clone();
            tokio::spawn(async move { mgr.transfer_call("tok", "1002").await })
        };
        let refer = recv_text(&pbx).await;
        mgr.handle_refer_response(&response_to(&refer, "603 Decline"))
            .await;
        assert_eq!(task.await.unwrap(), Err(TransferError::Rejected(603)));

        let task = {
            let mgr = mgr.clone();
            tokio::spawn(async move { mgr.transfer_call("tok", "1002").await })
        };
        let refer = recv_text(&pbx).await;
        mgr.handle_refer_response(&response_to(&refer, "202 Accepted"))
            .await;
        assert_eq!(task.await.unwrap(), Ok(()));
    }

    #[tokio::test]
    async fn abandoned_transfer_releases_the_call() {
        let Harness { mgr, pbx } = outgoing_call_harness().await;
        let task = {
            let mgr = mgr.clone();
            tokio::spawn(async move { mgr.transfer_call("tok", "1002").await })
        };
        recv_text(&pbx).await;
        // The HTTP request is dropped mid-transaction (client went away).
        task.abort();
        let _ = task.await;
        assert!(lock_refers(&mgr.pending_refers).is_empty());

        let retry = {
            let mgr = mgr.clone();
            tokio::spawn(async move { mgr.transfer_call("tok", "1003").await })
        };
        let refer = recv_text(&pbx).await;
        assert!(refer.contains("Refer-To: <sip:1003@pbx.example.com>"));
        mgr.handle_refer_response(&response_to(&refer, "202 Accepted"))
            .await;
        assert_eq!(retry.await.unwrap(), Ok(()));
    }

    #[tokio::test]
    async fn accept_is_never_observed_half_done() {
        use crate::sip::proxy::ProxyRegistration;
        use tokio::net::UdpSocket;

        for _ in 0..20 {
            let mgr = Arc::new(HandoffManager::new());
            let pbx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let gw = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let reg = Arc::new(RwLock::new(ProxyRegistration::for_test(
                gw,
                "pbx.example.com",
                mgr.clone(),
            )));
            let token = mgr
                .create_pending_call(
                    "dev".into(),
                    "inbound-call-1".into(),
                    INBOUND_INVITE.into(),
                    pbx.local_addr().unwrap(),
                    reg,
                    None,
                    String::new(),
                    0,
                    0,
                )
                .await;

            // Pollers race the accept and must only ever see pending or active.
            let pollers: Vec<_> = (0..4)
                .map(|_| {
                    let mgr = mgr.clone();
                    let token = token.clone();
                    tokio::spawn(async move {
                        loop {
                            assert_eq!(
                                mgr.call_owner(&token).await,
                                Some(CallOwner::Device("dev".into())),
                                "call owner vanished during accept"
                            );
                            match mgr.get_call_status(&token).await {
                                CallStatus::Pending => tokio::task::yield_now().await,
                                CallStatus::Active { .. } => break,
                                _ => panic!("call reported neither pending nor active"),
                            }
                        }
                    })
                })
                .collect();

            tokio::task::yield_now().await;
            mgr.accept_call(&token, "v=0\r\n".into()).await.unwrap();
            for p in pollers {
                p.await.unwrap();
            }
            assert!(recv_text(&pbx).await.starts_with("SIP/2.0 200 OK"));
        }
    }

    #[tokio::test]
    async fn hangup_racing_accept_finds_the_call() {
        use crate::sip::proxy::ProxyRegistration;
        use tokio::net::UdpSocket;

        for _ in 0..20 {
            let mgr = Arc::new(HandoffManager::new());
            let pbx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let gw = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let reg = Arc::new(RwLock::new(ProxyRegistration::for_test(
                gw,
                "pbx.example.com",
                mgr.clone(),
            )));
            let token = mgr
                .create_pending_call(
                    "dev".into(),
                    "inbound-call-1".into(),
                    INBOUND_INVITE.into(),
                    pbx.local_addr().unwrap(),
                    reg,
                    None,
                    String::new(),
                    0,
                    0,
                )
                .await;
            let hangup = {
                let mgr = mgr.clone();
                let token = token.clone();
                tokio::spawn(async move {
                    // Hang up as soon as the call stops looking pending; it
                    // must then be found active, never unknown.
                    while matches!(mgr.get_call_status(&token).await, CallStatus::Pending) {
                        tokio::task::yield_now().await;
                    }
                    mgr.hangup_call(&token).await
                })
            };
            tokio::task::yield_now().await;
            mgr.accept_call(&token, "v=0\r\n".into()).await.unwrap();
            hangup
                .await
                .unwrap()
                .expect("hangup must find the accepted call");
            assert!(recv_text(&pbx).await.starts_with("SIP/2.0 200 OK"));
            assert!(recv_text(&pbx).await.starts_with("BYE "));
        }
    }

    #[tokio::test]
    async fn cancel_after_accept_does_not_end_the_answered_call() {
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
        let token = mgr
            .create_pending_call(
                "dev".into(),
                "inbound-call-1".into(),
                INBOUND_INVITE.into(),
                pbx.local_addr().unwrap(),
                reg,
                None,
                String::new(),
                0,
                0,
            )
            .await;
        let accept = {
            let mgr = mgr.clone();
            let token = token.clone();
            tokio::spawn(async move { mgr.accept_call(&token, "v=0\r\n".into()).await })
        };
        let cancel = {
            let mgr = mgr.clone();
            tokio::spawn(async move { mgr.cancel_pending("inbound-call-1").await })
        };
        accept.await.unwrap().unwrap();
        cancel.await.unwrap();
        // Whichever ran first, the call is never left unknown: either the
        // CANCEL won (ended) or the answer did (active).
        match mgr.get_call_status(&token).await {
            CallStatus::Active { .. } | CallStatus::Ended(_) => {}
            _ => panic!("call left in an unknown state"),
        }
    }

    // ── Transfer outcome reporting ──────────────────────────────────────────

    fn status_json(status: &CallStatus) -> String {
        serde_json::to_string(status).unwrap()
    }

    /// Start a transfer and have the PBX accept the REFER.
    async fn accepted_transfer(
        mgr: &Arc<HandoffManager>,
        pbx: &tokio::net::UdpSocket,
        target: &str,
    ) {
        let task = {
            let mgr = mgr.clone();
            let target = target.to_string();
            tokio::spawn(async move { mgr.transfer_call("tok", &target).await })
        };
        let refer = recv_text(pbx).await;
        mgr.handle_refer_response(&response_to(&refer, "202 Accepted"))
            .await;
        assert_eq!(task.await.unwrap(), Ok(()));
    }

    #[tokio::test]
    async fn status_reports_no_transfer_until_one_is_accepted() {
        let Harness { mgr, .. } = outgoing_call_harness().await;
        assert_eq!(
            status_json(&mgr.get_call_status("tok").await),
            r#"{"status":"active"}"#
        );
    }

    #[tokio::test]
    async fn failed_transfer_is_reported_and_releases_the_call() {
        let Harness { mgr, pbx } = outgoing_call_harness().await;
        accepted_transfer(&mgr, &pbx, "1002").await;
        assert_eq!(
            status_json(&mgr.get_call_status("tok").await),
            r#"{"status":"active","transfer":"pending"}"#
        );

        // Progress keeps it pending; a 486 sipfrag fails it.
        mgr.handle_notify(
            "outbound-call-1",
            &notify("refer", "SIP/2.0 180 Ringing\r\n"),
        )
        .await;
        assert_eq!(
            status_json(&mgr.get_call_status("tok").await),
            r#"{"status":"active","transfer":"pending"}"#
        );
        mgr.handle_notify(
            "outbound-call-1",
            &notify_with_state(
                "refer",
                "SIP/2.0 486 Busy Here\r\n",
                "terminated;reason=noresource",
            ),
        )
        .await;
        assert_eq!(
            status_json(&mgr.get_call_status("tok").await),
            r#"{"status":"active","transfer":"failed","transfer_code":486}"#
        );
        assert!(mgr.is_call_active("outbound-call-1").await);

        // A new transfer is allowed and resets the state to pending.
        accepted_transfer(&mgr, &pbx, "1003").await;
        assert_eq!(
            status_json(&mgr.get_call_status("tok").await),
            r#"{"status":"active","transfer":"pending"}"#
        );
    }

    #[tokio::test]
    async fn terminated_subscription_without_success_fails_with_408() {
        let Harness { mgr, pbx } = outgoing_call_harness().await;
        accepted_transfer(&mgr, &pbx, "1002").await;
        mgr.handle_notify(
            "outbound-call-1",
            &notify_with_state(
                "refer",
                "SIP/2.0 180 Ringing\r\n",
                "terminated;reason=timeout",
            ),
        )
        .await;
        assert_eq!(
            status_json(&mgr.get_call_status("tok").await),
            r#"{"status":"active","transfer":"failed","transfer_code":408}"#
        );
        assert!(mgr.is_call_active("outbound-call-1").await);
    }

    #[tokio::test]
    async fn no_notify_after_accept_fails_with_408_and_clears_the_lock() {
        let Harness { mgr, pbx } = outgoing_call_harness_with(
            HandoffManager::new().with_refer_notify_timeout(Duration::from_millis(100)),
        )
        .await;
        accepted_transfer(&mgr, &pbx, "1002").await;
        assert_eq!(
            mgr.transfer_call("tok", "1003").await,
            Err(TransferError::InProgress)
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(
            status_json(&mgr.get_call_status("tok").await),
            r#"{"status":"active","transfer":"failed","transfer_code":408}"#
        );
        // No longer locked: another transfer goes out.
        accepted_transfer(&mgr, &pbx, "1003").await;
    }

    #[tokio::test]
    async fn a_notify_before_the_timeout_disarms_the_watchdog() {
        let Harness { mgr, pbx } = outgoing_call_harness_with(
            HandoffManager::new().with_refer_notify_timeout(Duration::from_millis(100)),
        )
        .await;
        accepted_transfer(&mgr, &pbx, "1002").await;
        mgr.handle_notify(
            "outbound-call-1",
            &notify("refer", "SIP/2.0 100 Trying\r\n"),
        )
        .await;
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(
            status_json(&mgr.get_call_status("tok").await),
            r#"{"status":"active","transfer":"pending"}"#
        );
    }

    #[test]
    fn refer_notify_reads_subscription_state() {
        let n = parse_refer_notify(&notify_with_state("refer", "garbage", "terminated")).unwrap();
        assert_eq!(
            n,
            ReferNotify {
                status: None,
                terminated: true
            }
        );
        let n = parse_refer_notify(&notify("refer", "SIP/2.0 200 OK\r\n")).unwrap();
        assert_eq!(
            n,
            ReferNotify {
                status: Some(200),
                terminated: false
            }
        );
        assert!(parse_refer_notify(&notify("dialog", "SIP/2.0 200 OK\r\n")).is_none());
    }
}
