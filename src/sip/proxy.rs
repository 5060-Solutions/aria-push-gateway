//! SIP Proxy Registration Manager.
//!
//! Maintains SIP registrations on behalf of mobile devices. When an INVITE
//! arrives for a registered device, triggers a push notification and manages
//! the call handoff. Also handles mid-dialog requests (ACK, BYE) for active calls.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

use super::digest::DigestAuth;
use super::message;
use super::resolver::SrvResolver;
use super::trust::{SourcePolicy, TrustedSources};
use crate::handoff::{CallOwner, HandoffManager, InviteDisposition};
use crate::push::PushManager;

/// SIP account configuration received from mobile devices.
#[derive(Debug, Clone)]
pub struct SipAccountConfig {
    pub username: String,
    pub password: String,
    pub domain: String,
    pub registrar: Option<String>,
    pub transport: String,
    pub port: u16,
    pub auth_username: Option<String>,
    pub display_name: String,
}

impl SipAccountConfig {
    pub fn effective_auth_username(&self) -> &str {
        self.auth_username
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(&self.username)
    }

    pub fn effective_registrar(&self) -> &str {
        self.registrar.as_deref().unwrap_or(&self.domain)
    }
}

/// State for a single device's proxy registration.
pub struct ProxyRegistration {
    pub(crate) device_id: String,
    config: SipAccountConfig,
    pub(crate) socket: Arc<UdpSocket>,
    server_addr: SocketAddr,
    /// Sources accepted on this registration: the IPs the registrar
    /// resolved to plus the operator allowlist (any port).
    peers: SourcePolicy,
    pub(crate) local_addr: SocketAddr,
    call_id: String,
    from_tag: String,
    cseq: u32,
    state: ProxyState,
    auth_attempts: u32,
    push_manager: Arc<PushManager>,
    handoff: Arc<HandoffManager>,
    /// Set to `true` to retire the registration: refreshes stop, and the
    /// receive loop exits once no call or transaction uses the socket.
    stop: tokio::sync::watch::Sender<bool>,
    /// An Expires: 0 REGISTER is in progress; no new calls are offered.
    unregistering: bool,
    /// Bumped on every successful REGISTER so only the latest refresh
    /// timer fires.
    refresh_generation: u64,
    /// When to refresh after a successful REGISTER.
    refresh_after: Duration,
}

/// Re-register at 80% of the 3600 s binding.
const REFRESH_AFTER: Duration = Duration::from_secs(2880);
/// How long a retiring registration waits for the 200 to its Expires: 0.
const UNREGISTER_GRACE: Duration = Duration::from_secs(5);

impl ProxyRegistration {
    /// Expires value for this registration's next REGISTER.
    fn expires(&self) -> u32 {
        if self.unregistering {
            0
        } else {
            3600
        }
    }

    /// Whether a packet from `from` may be processed on this registration.
    fn is_trusted_peer(&self, from: SocketAddr) -> bool {
        self.peers.admits(from)
    }

    /// Accept SIP traffic from `peer`'s IP too (tests only).
    #[cfg(test)]
    pub(crate) fn trust_peer(&mut self, peer: SocketAddr) {
        self.peers.add_ip(peer.ip());
    }

    /// Replace the accepted sources (tests only).
    #[cfg(test)]
    pub(crate) fn set_sources(&mut self, sources: SourcePolicy) {
        self.peers = sources;
    }

    /// The SIP domain of the account this registration belongs to.
    pub(crate) fn sip_domain(&self) -> &str {
        &self.config.domain
    }

    /// Digest credentials `(auth username, password)` for this account, used
    /// to answer challenges to in-dialog requests such as REFER.
    pub(crate) fn digest_credentials(&self) -> (String, String) {
        (
            self.config.effective_auth_username().to_string(),
            self.config.password.clone(),
        )
    }

    /// A registration bound to `socket`, for exercising call handling in tests.
    #[cfg(test)]
    pub(crate) fn for_test(
        socket: Arc<UdpSocket>,
        domain: &str,
        handoff: Arc<HandoffManager>,
    ) -> Self {
        let local_addr = socket.local_addr().expect("bound socket");
        Self {
            device_id: "test-device".into(),
            config: SipAccountConfig {
                username: "1001".into(),
                password: "secret".into(),
                domain: domain.into(),
                registrar: None,
                transport: "udp".into(),
                port: 5060,
                auth_username: None,
                display_name: String::new(),
            },
            socket,
            server_addr: local_addr,
            peers: SourcePolicy::default(),
            local_addr,
            call_id: String::new(),
            from_tag: String::new(),
            cseq: 0,
            state: ProxyState::Registered,
            auth_attempts: 0,
            push_manager: Arc::new(PushManager::new_noop()),
            handoff,
            stop: tokio::sync::watch::channel(false).0,
            unregistering: false,
            refresh_generation: 0,
            refresh_after: REFRESH_AFTER,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum ProxyState {
    Registering,
    Registered,
    Error(String),
}

/// Why an outgoing call ended without being connected, for outcomes the
/// API reports specifically (everything else is a plain failure).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginateRefusal {
    /// The app cancelled the call while it was ringing.
    Cancelled,
    /// Another outgoing call of this user is pending under the same
    /// `client_ref`.
    ClientRefInUse,
}

impl std::fmt::Display for OriginateRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => write!(f, "outgoing call cancelled"),
            Self::ClientRefInUse => write!(f, "client_ref already in use by a pending call"),
        }
    }
}

impl std::error::Error for OriginateRefusal {}

/// Pending outgoing INVITEs keyed by (owner user id, client_ref).
type PendingInvites = HashMap<(String, String), PendingInvite>;

struct PendingInvite {
    /// Distinguishes this INVITE from a later one reusing the same key.
    id: u64,
    /// Taken (and fired) by a cancel request; `None` once cancel was asked.
    cancel: Option<tokio::sync::oneshot::Sender<()>>,
}

/// An outgoing INVITE's entry in [`SipProxyManager::pending_invites`];
/// removes the entry when dropped, whatever the outcome.
pub(crate) struct InviteSlot {
    invites: Arc<std::sync::Mutex<PendingInvites>>,
    key: (String, String),
    id: u64,
}

fn lock_invites(m: &std::sync::Mutex<PendingInvites>) -> std::sync::MutexGuard<'_, PendingInvites> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl InviteSlot {
    /// The INVITE was answered: drop the entry so it can no longer be
    /// cancelled, and report whether a cancel had already been requested
    /// (a 200 OK crossing our CANCEL).
    pub(crate) fn claim_answer(&self) -> bool {
        let mut invites = lock_invites(&self.invites);
        match invites.get(&self.key) {
            Some(entry) if entry.id == self.id => {
                let cancel_requested = entry.cancel.is_none();
                invites.remove(&self.key);
                cancel_requested
            }
            _ => false,
        }
    }
}

impl Drop for InviteSlot {
    fn drop(&mut self) {
        let mut invites = lock_invites(&self.invites);
        if invites.get(&self.key).is_some_and(|e| e.id == self.id) {
            invites.remove(&self.key);
        }
    }
}

/// Whether `client_ref` is 1-64 characters of `[A-Za-z0-9_-]`.
pub fn is_valid_client_ref(client_ref: &str) -> bool {
    (1..=64).contains(&client_ref.len())
        && client_ref
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Manages all proxy registrations.
pub struct SipProxyManager {
    registrations: RwLock<HashMap<String, Arc<RwLock<ProxyRegistration>>>>,
    resolver: Arc<SrvResolver>,
    /// Outgoing INVITEs still waiting for a final response that the app
    /// can cancel by `client_ref`.
    pending_invites: Arc<std::sync::Mutex<PendingInvites>>,
    next_invite_id: std::sync::atomic::AtomicU64,
    /// How long an outgoing call may ring before the gateway cancels it.
    ring_timeout: Duration,
    /// When registrations refresh; shortened in tests.
    refresh_after: Duration,
    /// Operator allowlist of SIP sources (`TRUSTED_SIP_SOURCES`).
    trusted: Arc<TrustedSources>,
}

impl SipProxyManager {
    pub fn new() -> Self {
        let resolver = SrvResolver::new().expect("Failed to create DNS resolver");
        Self {
            registrations: RwLock::new(HashMap::new()),
            resolver: Arc::new(resolver),
            pending_invites: Arc::new(std::sync::Mutex::new(HashMap::new())),
            next_invite_id: std::sync::atomic::AtomicU64::new(0),
            ring_timeout: super::outgoing::RING_TIMEOUT,
            refresh_after: REFRESH_AFTER,
            trusted: Arc::default(),
        }
    }

    /// Also accept SIP from these IPs/CIDRs on every socket.
    pub fn with_trusted_sources(mut self, trusted: TrustedSources) -> Self {
        self.trusted = Arc::new(trusted);
        self
    }

    /// Shorten the registration refresh interval (tests only).
    #[cfg(test)]
    pub fn with_refresh_after(mut self, after: Duration) -> Self {
        self.refresh_after = after;
        self
    }

    /// Shorten the ring timeout (tests only).
    #[cfg(test)]
    pub fn with_ring_timeout(mut self, timeout: Duration) -> Self {
        self.ring_timeout = timeout;
        self
    }

    /// Ask the pending outgoing INVITE that `user_id` placed under
    /// `client_ref` to be cancelled. Returns `false` if there is no such
    /// INVITE (unknown ref, another user's ref, or already answered/ended).
    pub fn cancel_outgoing_call(&self, user_id: &str, client_ref: &str) -> bool {
        let mut invites = lock_invites(&self.pending_invites);
        let Some(entry) = invites.get_mut(&(user_id.to_string(), client_ref.to_string())) else {
            return false;
        };
        if let Some(tx) = entry.cancel.take() {
            let _ = tx.send(());
        }
        true
    }

    fn track_invite(
        &self,
        user_id: &str,
        client_ref: &str,
        cancel: tokio::sync::oneshot::Sender<()>,
    ) -> Result<InviteSlot, OriginateRefusal> {
        let key = (user_id.to_string(), client_ref.to_string());
        let id = self
            .next_invite_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut invites = lock_invites(&self.pending_invites);
        if invites.contains_key(&key) {
            return Err(OriginateRefusal::ClientRefInUse);
        }
        invites.insert(
            key.clone(),
            PendingInvite {
                id,
                cancel: Some(cancel),
            },
        );
        Ok(InviteSlot {
            invites: Arc::clone(&self.pending_invites),
            key,
            id,
        })
    }

    /// Start maintaining a SIP registration for a device.
    pub async fn register_device(
        &self,
        device_id: String,
        config: SipAccountConfig,
        push_manager: Arc<PushManager>,
        handoff: Arc<HandoffManager>,
    ) -> anyhow::Result<()> {
        if config.transport != "udp" {
            tracing::warn!(
                device = %device_id,
                transport = %config.transport,
                "Only UDP transport is currently supported — registering over UDP"
            );
        }

        tracing::info!(
            device = %device_id,
            user = %config.username,
            domain = %config.domain,
            display_name = %config.display_name,
            "Starting proxy registration"
        );

        // Resolve server address via SRV lookup (with A record fallback)
        let registrar = config.effective_registrar().to_string();
        let resolved = self
            .resolver
            .resolve(&registrar, config.port, &config.transport)
            .await?;
        let server_addr = resolved
            .first()
            .ok_or_else(|| anyhow::anyhow!("Failed to resolve {}", registrar))?
            .addr;

        // Bind UDP socket
        let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        let local_addr = socket.local_addr()?;

        // Discover actual local IP by connecting to server
        let probe = UdpSocket::bind("0.0.0.0:0").await?;
        probe.connect(server_addr).await?;
        let real_local_ip = probe.local_addr()?.ip();
        let local_addr = SocketAddr::new(real_local_ip, local_addr.port());

        let call_id = message::generate_call_id();
        let from_tag = format!("{:08x}", rand::random::<u32>());

        let reg = Arc::new(RwLock::new(ProxyRegistration {
            device_id: device_id.clone(),
            config,
            socket: socket.clone(),
            server_addr,
            peers: SourcePolicy::new(resolved.iter().map(|r| r.addr.ip()), self.trusted.clone()),
            local_addr,
            call_id,
            from_tag,
            cseq: 0,
            state: ProxyState::Registering,
            auth_attempts: 0,
            push_manager,
            handoff,
            stop: tokio::sync::watch::channel(false).0,
            unregistering: false,
            refresh_generation: 0,
            refresh_after: self.refresh_after,
        }));

        // Store registration, retiring any previous one for this device
        // (heartbeat/re-registration): its binding is removed and its
        // refreshes, loop and socket end instead of running alongside.
        let previous = {
            let mut regs = self.registrations.write().await;
            regs.insert(device_id.clone(), reg.clone())
        };
        if let Some(previous) = previous {
            tracing::info!(device = %device_id, "Replacing previous registration");
            Self::retire(&previous).await;
        }

        // Send initial REGISTER
        Self::send_register(&reg).await?;

        // Spawn receive loop for this device
        let reg_clone = reg.clone();
        let socket_clone = socket;
        let device_id_clone = device_id;
        let mut stop = reg.read().await.stop.subscribe();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            let mut consecutive_errors: u32 = 0;
            let mut stopping = false;
            loop {
                if stopping {
                    let handoff = reg_clone.read().await.handoff.clone();
                    if !handoff.socket_in_use(&socket_clone).await {
                        break;
                    }
                }
                // While retiring, wake up regularly to see if the socket is
                // still needed by a call.
                let wait = if stopping {
                    Duration::from_millis(250)
                } else {
                    Duration::from_secs(3600)
                };
                let received = tokio::select! {
                    changed = stop.changed(), if !stopping => {
                        if changed.is_err() || *stop.borrow() {
                            stopping = true;
                        }
                        continue;
                    }
                    r = tokio::time::timeout(wait, socket_clone.recv_from(&mut buf)) => match r {
                        Ok(r) => r,
                        Err(_) => continue,
                    },
                };
                match received {
                    Ok((len, from)) => {
                        consecutive_errors = 0;
                        let text = match std::str::from_utf8(&buf[..len]) {
                            Ok(s) => s.to_string(),
                            Err(_) => continue,
                        };

                        if let Err(e) = Self::handle_message(&reg_clone, &text, from).await {
                            tracing::error!(
                                device = %device_id_clone,
                                "Error handling SIP message: {}",
                                e
                            );
                        }
                    }
                    Err(e) => {
                        consecutive_errors += 1;
                        tracing::error!(
                            device = %device_id_clone,
                            errors = consecutive_errors,
                            "Socket recv error: {}",
                            e
                        );

                        if consecutive_errors >= 5 {
                            if stopping {
                                break;
                            }
                            tracing::error!(
                                device = %device_id_clone,
                                "Too many consecutive socket errors — attempting re-registration"
                            );
                            // Try to re-register after a delay
                            tokio::time::sleep(Duration::from_secs(5)).await;
                            if let Err(e) = Self::send_register(&reg_clone).await {
                                tracing::error!(
                                    device = %device_id_clone,
                                    "Re-registration after socket errors failed: {}",
                                    e
                                );
                                break;
                            }
                            consecutive_errors = 0;
                        }
                    }
                }
            }
            tracing::debug!(device = %device_id_clone, "Registration receive loop ended");
        });

        Ok(())
    }

    /// Retire a registration: send REGISTER with Expires: 0 (answering any
    /// challenge), and stop its refreshes and receive loop once the PBX
    /// confirms, or after a short grace period.
    async fn retire(reg: &Arc<RwLock<ProxyRegistration>>) {
        if let Err(e) = Self::send_unregister(reg).await {
            tracing::warn!("Failed to send unregister: {}", e);
        }
        let (stop, grace) = {
            let r = reg.read().await;
            (r.stop.clone(), UNREGISTER_GRACE.min(r.refresh_after))
        };
        tokio::spawn(async move {
            tokio::time::sleep(grace).await;
            stop.send_replace(true);
        });
    }

    /// Unregister a device (send REGISTER with Expires: 0).
    pub async fn unregister_device(&self, device_id: &str) -> anyhow::Result<()> {
        let reg = {
            let regs = self.registrations.read().await;
            regs.get(device_id).cloned()
        };

        if let Some(reg) = reg {
            self.registrations.write().await.remove(device_id);
            Self::retire(&reg).await;
        }

        Ok(())
    }

    /// Get registration status for a device.
    pub async fn get_status(&self, device_id: &str) -> Option<String> {
        let regs = self.registrations.read().await;
        if let Some(reg) = regs.get(device_id) {
            let r = reg.read().await;
            Some(match &r.state {
                ProxyState::Registering => "registering".to_string(),
                ProxyState::Registered => "registered".to_string(),
                ProxyState::Error(msg) => format!("error: {}", msg),
            })
        } else {
            None
        }
    }

    async fn send_register(reg: &Arc<RwLock<ProxyRegistration>>) -> anyhow::Result<()> {
        let (msg, server_addr, socket) = {
            let mut r = reg.write().await;
            r.cseq += 1;
            let registrar = r.config.effective_registrar().to_string();
            let msg = message::build_register(
                &r.config.username,
                &r.config.domain,
                &registrar,
                &r.local_addr.ip().to_string(),
                r.local_addr.port(),
                &r.config.transport,
                &r.call_id,
                r.cseq,
                &r.from_tag,
                None,
                r.expires(),
            );
            (msg, r.server_addr, r.socket.clone())
        };

        socket.send_to(msg.as_bytes(), server_addr).await?;
        tracing::debug!("Sent REGISTER to {}", server_addr);
        Ok(())
    }

    async fn send_unregister(reg: &Arc<RwLock<ProxyRegistration>>) -> anyhow::Result<()> {
        reg.write().await.unregistering = true;
        Self::send_register(reg).await
    }

    async fn handle_message(
        reg: &Arc<RwLock<ProxyRegistration>>,
        text: &str,
        from: SocketAddr,
    ) -> anyhow::Result<()> {
        // Only the PBX/registrar this registration resolved to may talk to
        // it: anyone else could otherwise ring the phone, end its calls or
        // probe the gateway with OPTIONS.
        let (trusted, device_id) = {
            let r = reg.read().await;
            (r.is_trusted_peer(from), r.device_id.clone())
        };
        if !trusted {
            tracing::warn!(
                device = %device_id,
                %from,
                first_line = %text.lines().next().unwrap_or_default(),
                "Dropping SIP message from an unexpected source"
            );
            return Ok(());
        }
        if message::is_request(text) {
            Self::handle_request(reg, text, from).await
        } else {
            Self::handle_response(reg, text).await
        }
    }

    async fn handle_request(
        reg: &Arc<RwLock<ProxyRegistration>>,
        text: &str,
        from: SocketAddr,
    ) -> anyhow::Result<()> {
        let (handoff, socket) = {
            let r = reg.read().await;
            (r.handoff.clone(), r.socket.clone())
        };
        Self::handle_request_on(&handoff, &socket, Some(reg), text, from).await
    }

    /// Handle a request from the trusted peer `from` on `socket`. `reg` is
    /// the registration that owns the socket; it is `None` for an outgoing
    /// call's own socket, which only carries that call's dialog.
    async fn handle_request_on(
        handoff: &Arc<HandoffManager>,
        socket: &Arc<UdpSocket>,
        reg: Option<&Arc<RwLock<ProxyRegistration>>>,
        text: &str,
        from: SocketAddr,
    ) -> anyhow::Result<()> {
        let method = message::extract_method(text).unwrap_or_default();
        let call_id = message::extract_header(text, "Call-ID").unwrap_or_default();
        let in_dialog = message::extract_to_tag(text).is_some();

        // A retransmitted non-INVITE request we already answered gets the
        // same response again rather than being processed twice.
        if method != "ACK" && method != "INVITE" {
            if let Some(resp) = handoff.server_transactions().replay(socket, text) {
                socket.send_to(resp.as_bytes(), from).await?;
                return Ok(());
            }
        }

        match method.as_str() {
            "ACK" => {
                handoff.handle_ack(text, socket).await;
            }
            "INVITE" if in_dialog => {
                if handoff.handle_reinvite(text, from, socket).await.is_none() {
                    tracing::debug!(call_id = %call_id, "re-INVITE for an unknown dialog — 481");
                    Self::reply(socket, message::build_481(text), from).await?;
                }
            }
            "INVITE" => {
                let Some(reg) = reg else {
                    Self::reply(socket, message::build_481(text), from).await?;
                    return Ok(());
                };
                match handoff.classify_invite(text, socket).await {
                    InviteDisposition::Retransmission(resp) => {
                        tracing::debug!(call_id = %call_id, "INVITE retransmission — repeating our response");
                        socket.send_to(resp.as_bytes(), from).await?;
                    }
                    InviteDisposition::Merged => {
                        tracing::warn!(call_id = %call_id, "INVITE for a Call-ID already in use — 482");
                        let resp = message::build_simple_response(text, 482, "Loop Detected");
                        if let Some(resp) = resp {
                            handoff
                                .server_transactions()
                                .send_final(socket, from, text, resp);
                        }
                    }
                    InviteDisposition::New => {
                        Self::offer_incoming_call(reg, handoff, socket, text, from).await?;
                    }
                }
            }
            "BYE" => match handoff
                .handle_bye_from_pbx(&call_id, text, from, socket)
                .await
            {
                Ok(Some(owner)) => {
                    tracing::info!(owner = %owner, call_id = %call_id, "Call ended by PBX");
                }
                Ok(None) => {
                    tracing::debug!(call_id = %call_id, "BYE for unknown call — sending 481");
                    Self::reply(socket, message::build_481(text), from).await?;
                }
                Err(e) => {
                    tracing::error!(call_id = %call_id, "Error handling BYE: {}", e);
                }
            },
            "CANCEL" => {
                tracing::info!(call_id = %call_id, "CANCEL received");
                handoff.answer_cancel(text, from, socket).await?;
            }
            "NOTIFY" => {
                // An in-dialog NOTIFY (refer progress) must match one of this
                // socket's dialogs, else 481. Out-of-dialog NOTIFYs from the
                // registrar (e.g. unsolicited MWI) are acknowledged and ignored.
                let matched = if in_dialog {
                    handoff.handle_notify_on(&call_id, text, socket).await
                } else {
                    reg.is_some()
                };
                let resp = if matched {
                    message::build_simple_response(text, 200, "OK")
                } else {
                    message::build_481(text)
                };
                if let Some(resp) = resp {
                    handoff
                        .server_transactions()
                        .remember(socket, text, &resp, from);
                    socket.send_to(resp.as_bytes(), from).await?;
                }
            }
            "OPTIONS" => {
                if let Some(resp) = message::build_simple_response(text, 200, "OK") {
                    handoff
                        .server_transactions()
                        .remember(socket, text, &resp, from);
                    socket.send_to(resp.as_bytes(), from).await?;
                }
            }
            _ => {
                tracing::debug!("Ignoring {} request", method);
            }
        }

        Ok(())
    }

    async fn reply(socket: &UdpSocket, resp: Option<String>, to: SocketAddr) -> anyhow::Result<()> {
        if let Some(resp) = resp {
            socket.send_to(resp.as_bytes(), to).await?;
        }
        Ok(())
    }

    /// A new incoming call: answer 100 Trying, hold the INVITE pending and
    /// push the device.
    async fn offer_incoming_call(
        reg: &Arc<RwLock<ProxyRegistration>>,
        handoff: &Arc<HandoffManager>,
        socket: &Arc<UdpSocket>,
        text: &str,
        from: SocketAddr,
    ) -> anyhow::Result<()> {
        if reg.read().await.unregistering {
            // The binding is being removed; this registration takes no
            // new calls.
            if let Some(resp) = message::build_simple_response(text, 480, "Temporarily Unavailable")
            {
                handoff
                    .server_transactions()
                    .send_final(socket, from, text, resp);
            }
            return Ok(());
        }
        tracing::info!("Incoming INVITE for proxy device");
        Self::reply(socket, message::build_100_trying(text), from).await?;

        let (caller_user, caller_domain) =
            message::extract_from_uri(text).unwrap_or(("unknown".into(), "unknown".into()));
        let caller_name = message::extract_display_name(text);
        let call_id = message::extract_header(text, "Call-ID").unwrap_or_default();
        let (device_id, push_mgr) = {
            let r = reg.read().await;
            (r.device_id.clone(), r.push_manager.clone())
        };

        // SDP passes through unchanged — phone talks directly to PBX relay
        let call_token = handoff
            .create_pending_call(
                device_id.clone(),
                call_id,
                text.to_string(),
                from,
                reg.clone(),
                None,
                String::new(),
                0,
                0,
            )
            .await;

        tracing::info!(
            device = %device_id,
            caller = %format!("{}@{}", caller_user, caller_domain),
            token = %call_token,
            "Sending push notification for incoming call"
        );
        push_mgr
            .send_incoming_call(
                &device_id,
                &call_token,
                &format!("{}@{}", caller_user, caller_domain),
                caller_name.as_deref(),
            )
            .await?;
        Ok(())
    }

    async fn handle_response(
        reg: &Arc<RwLock<ProxyRegistration>>,
        text: &str,
    ) -> anyhow::Result<()> {
        let status = match message::parse_status_code(text) {
            Some(s) => s,
            None => return Ok(()),
        };

        let method = message::extract_cseq_method(text).unwrap_or_default();

        match method.as_str() {
            "REGISTER" => Self::handle_register_response(reg, text, status).await,
            "BYE" | "REFER" => {
                let (handoff, socket) = {
                    let r = reg.read().await;
                    (r.handoff.clone(), r.socket.clone())
                };
                handoff.handle_refer_response_on(text, &socket).await;
                Ok(())
            }
            _ => Ok(()),
        }
    }

    async fn handle_register_response(
        reg: &Arc<RwLock<ProxyRegistration>>,
        text: &str,
        status: u16,
    ) -> anyhow::Result<()> {
        match status {
            200 => {
                let mut r = reg.write().await;
                r.auth_attempts = 0;
                if r.unregistering {
                    // Binding removed: nothing more to refresh.
                    tracing::info!(device = %r.device_id, "Proxy registration removed");
                    r.state = ProxyState::Error("unregistered".into());
                    r.stop.send_replace(true);
                    return Ok(());
                }
                r.state = ProxyState::Registered;
                tracing::info!(device = %r.device_id, "Proxy registration successful");

                // Schedule re-registration before expiry. Only the latest
                // timer fires, and none once the registration is retired.
                r.refresh_generation += 1;
                let generation = r.refresh_generation;
                let after = r.refresh_after;
                let mut stop = r.stop.subscribe();
                let reg_clone = reg.clone();
                tokio::spawn(async move {
                    tokio::select! {
                        _ = tokio::time::sleep(after) => {}
                        _ = stop.wait_for(|stopped| *stopped) => return,
                    }
                    let current = {
                        let r = reg_clone.read().await;
                        r.refresh_generation == generation && !r.unregistering && !*r.stop.borrow()
                    };
                    if current {
                        if let Err(e) = Self::send_register(&reg_clone).await {
                            tracing::error!("Re-registration failed: {}", e);
                        }
                    }
                });
            }
            401 | 407 => {
                let (auth_header, server_addr, socket) = {
                    let mut r = reg.write().await;
                    r.auth_attempts += 1;

                    if r.auth_attempts > 2 {
                        r.state =
                            ProxyState::Error("Authentication failed — check credentials".into());
                        tracing::error!(device = %r.device_id, "Too many auth attempts");
                        return Ok(());
                    }

                    let header_name = if status == 401 {
                        "WWW-Authenticate"
                    } else {
                        "Proxy-Authenticate"
                    };

                    let www_auth = match message::extract_header(text, header_name) {
                        Some(h) => h,
                        None => {
                            r.state = ProxyState::Error("No auth challenge header".into());
                            return Ok(());
                        }
                    };

                    let registrar = r.config.effective_registrar().to_string();
                    let uri = format!("sip:{}", registrar);

                    let auth = match DigestAuth::from_challenge(
                        &www_auth,
                        r.config.effective_auth_username(),
                        &r.config.password,
                        &uri,
                        "REGISTER",
                    ) {
                        Some(a) => a,
                        None => {
                            r.state = ProxyState::Error("Failed to parse auth challenge".into());
                            return Ok(());
                        }
                    };

                    r.cseq += 1;
                    let msg = message::build_register(
                        &r.config.username,
                        &r.config.domain,
                        &registrar,
                        &r.local_addr.ip().to_string(),
                        r.local_addr.port(),
                        &r.config.transport,
                        &r.call_id,
                        r.cseq,
                        &r.from_tag,
                        Some(&auth.to_header()),
                        r.expires(),
                    );

                    (msg, r.server_addr, r.socket.clone())
                };

                socket.send_to(auth_header.as_bytes(), server_addr).await?;
                tracing::debug!("Sent authenticated REGISTER");
            }
            _ if status >= 400 => {
                let mut r = reg.write().await;
                r.state = ProxyState::Error(format!("Registration failed: {}", status));
                tracing::error!(device = %r.device_id, status, "Registration failed");
            }
            _ => {}
        }

        Ok(())
    }

    /// Originate an outgoing call on behalf of a mobile client.
    ///
    /// The INVITE transaction runs in its own task (see
    /// [`super::outgoing`]), which owns the socket until the transaction is
    /// over. This future only waits for its outcome: dropping it (the HTTP
    /// client went away) cancels a ringing call instead of abandoning it.
    /// Returns (call_token, sdp_answer).
    ///
    /// With a `client_ref`, the pending INVITE can also be cancelled through
    /// [`Self::cancel_outgoing_call`]; the call then fails with
    /// [`OriginateRefusal::Cancelled`].
    pub async fn originate_call(
        &self,
        destination_uri: &str,
        sdp_offer: &str,
        account: &SipAccountConfig,
        owner_user_id: &str,
        client_ref: Option<&str>,
        handoff: Arc<HandoffManager>,
    ) -> anyhow::Result<(String, String)> {
        // Track the INVITE under its client_ref first, so a cancel works from
        // the moment the request is accepted. The slot is removed on every
        // outcome when it drops.
        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();
        let (slot, keep_cancel) = match client_ref {
            Some(r) => (Some(self.track_invite(owner_user_id, r, cancel_tx)?), None),
            None => (None, Some(cancel_tx)),
        };

        let registrar = account
            .registrar
            .as_deref()
            .filter(|r| !r.is_empty())
            .unwrap_or(&account.domain)
            .to_string();
        let resolved = self
            .resolver
            .resolve(&registrar, account.port, &account.transport)
            .await?;
        let server_addr = resolved
            .first()
            .ok_or_else(|| anyhow::anyhow!("Cannot resolve {}", registrar))?
            .addr;

        let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        let local_port = socket.local_addr()?.port();
        let probe = UdpSocket::bind("0.0.0.0:0").await?;
        probe.connect(server_addr).await?;
        let local_addr = SocketAddr::new(probe.local_addr()?.ip(), local_port);

        let target_uri = if destination_uri.starts_with("sip:") {
            destination_uri.to_string()
        } else {
            format!("sip:{}", destination_uri)
        };

        let invite = super::outgoing::OutgoingInvite {
            socket,
            server_addr,
            local_addr,
            account: account.clone(),
            target_uri,
            call_id: message::generate_call_id(),
            from_tag: message::generate_tag(),
            sdp_offer: sdp_offer.to_string(),
            owner_user_id: owner_user_id.to_string(),
            handoff,
            ring_timeout: self.ring_timeout,
            sources: SourcePolicy::new(resolved.iter().map(|r| r.addr.ip()), self.trusted.clone()),
        };
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let _keep_cancel = keep_cancel;
            invite.run(slot, cancel_rx, result_tx).await;
        });
        result_rx
            .await
            .map_err(|_| anyhow::anyhow!("outgoing call task ended without a result"))?
    }

    /// Store an answered outgoing call as active and start its receive loop
    /// (which re-sends `ack` for retransmitted 2xx responses).
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn connect_outgoing_call(
        handoff: &Arc<HandoffManager>,
        socket: &Arc<UdpSocket>,
        server_addr: SocketAddr,
        local_addr: SocketAddr,
        account: &SipAccountConfig,
        call_id: &str,
        from_tag: &str,
        ok: &str,
        ack: String,
        owner_user_id: &str,
        local_sdp: &str,
        sources: &SourcePolicy,
    ) -> String {
        let call_token = uuid::Uuid::new_v4().to_string();
        let proxy_reg = Arc::new(RwLock::new(ProxyRegistration {
            device_id: format!("outgoing-{}", &call_token[..8]),
            config: account.clone(),
            socket: socket.clone(),
            server_addr,
            peers: sources.clone(),
            local_addr,
            call_id: call_id.to_string(),
            from_tag: from_tag.to_string(),
            cseq: 0,
            state: ProxyState::Registered,
            auth_attempts: 0,
            push_manager: Arc::new(PushManager::new_noop()),
            handoff: handoff.clone(),
            stop: tokio::sync::watch::channel(false).0,
            unregistering: false,
            refresh_generation: 0,
            refresh_after: REFRESH_AFTER,
        }));
        let ended = handoff
            .register_active_call(
                call_token.clone(),
                call_id.to_string(),
                CallOwner::User(owner_user_id.to_string()),
                ok.to_string(),
                server_addr,
                proxy_reg,
                None,
                local_sdp.to_string(),
                format!(
                    "sip:{}@{}:{};transport=udp",
                    account.username,
                    local_addr.ip(),
                    local_addr.port()
                ),
            )
            .await;
        tracing::info!(call_id = %call_id, "Outgoing call connected");
        Self::spawn_outgoing_call_loop(
            socket.clone(),
            sources.clone(),
            handoff.clone(),
            call_id.to_string(),
            ended,
            Some(ack),
        );
        call_token
    }

    /// Receive loop for an outgoing call's dedicated socket: answers BYE and
    /// NOTIFY from the PBX and routes REFER responses.
    ///
    /// The loop exits once the call stops being active (`ended` completes)
    /// — whether the app hung up, the PBX sent BYE or a transfer completed —
    /// and any BYE we sent has been answered (or timed out), so the task and
    /// its socket don't outlive the call.
    fn spawn_outgoing_call_loop(
        socket: Arc<UdpSocket>,
        sources: SourcePolicy,
        handoff: Arc<HandoffManager>,
        call_id: String,
        mut ended: tokio::sync::oneshot::Receiver<()>,
        ack: Option<String>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            // Once the call has ended, keep reading only while our BYE (or
            // REFER) transaction is open, so its response is delivered and
            // its retransmissions stop; then close.
            let mut linger_until: Option<tokio::time::Instant> = None;
            loop {
                if let Some(until) = linger_until {
                    if !handoff.has_client_transactions(&socket)
                        || tokio::time::Instant::now() >= until
                    {
                        break;
                    }
                }
                // Poll while lingering so the loop notices the transaction end.
                let wait = if linger_until.is_some() {
                    Duration::from_millis(100)
                } else {
                    Duration::from_secs(3600)
                };
                let received = tokio::select! {
                    biased;
                    _ = &mut ended, if linger_until.is_none() => {
                        linger_until = Some(
                            tokio::time::Instant::now()
                                + super::transaction::TIMEOUT
                                + Duration::from_secs(1),
                        );
                        continue;
                    }
                    r = tokio::time::timeout(wait, socket.recv_from(&mut buf)) => match r {
                        Ok(r) => r,
                        Err(_) => continue,
                    },
                };
                let (len, from) = match received {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::debug!(call_id = %call_id, "Outgoing call socket error: {}", e);
                        break;
                    }
                };
                let Ok(text) = std::str::from_utf8(&buf[..len]) else {
                    continue;
                };
                if !sources.admits(from) {
                    tracing::warn!(call_id = %call_id, %from, "Dropping SIP message from an unexpected source");
                    continue;
                }

                if message::is_request(text) {
                    if let Err(e) =
                        Self::handle_request_on(&handoff, &socket, None, text, from).await
                    {
                        tracing::warn!(call_id = %call_id, "Error handling SIP request: {}", e);
                    }
                } else {
                    match message::extract_cseq_method(text).as_deref() {
                        Some("REFER" | "BYE") => {
                            handoff.handle_refer_response_on(text, &socket).await;
                        }
                        // The PBX didn't get our ACK and repeats its 2xx.
                        Some("INVITE")
                            if message::parse_status_code(text)
                                .is_some_and(|c| (200..300).contains(&c)) =>
                        {
                            if let Some(ack) = &ack {
                                let _ = socket.send_to(ack.as_bytes(), from).await;
                            }
                        }
                        _ => {}
                    }
                }
                // Other responses (200 OK to our BYE, etc.) are ignored.
            }
            tracing::debug!(call_id = %call_id, "Outgoing call receive loop ended");
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handoff::CallOwner;

    const OUTBOUND_200: &str = "\
SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP 127.0.0.1:40000;branch=z9hG4bK-out;rport\r\n\
From: <sip:1001@pbx.example.com>;tag=gwtag\r\n\
To: <sip:2000@pbx.example.com>;tag=pbxtag\r\n\
Call-ID: out-call-1\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:2000@127.0.0.1:5060>\r\n\
Content-Length: 0\r\n\r\n";

    struct OutgoingCall {
        handoff: Arc<HandoffManager>,
        pbx: UdpSocket,
        gw_addr: SocketAddr,
        recv_loop: tokio::task::JoinHandle<()>,
    }

    /// An active outgoing call whose receive loop is running, with a UDP
    /// socket standing in for the PBX.
    async fn outgoing_call() -> OutgoingCall {
        outgoing_call_trusting(None).await
    }

    /// An outgoing call whose loop trusts `trusted` (default: the fake
    /// PBX's own IP).
    async fn outgoing_call_trusting(trusted: Option<SourcePolicy>) -> OutgoingCall {
        let handoff = Arc::new(HandoffManager::new());
        let pbx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let gw = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let gw_addr = gw.local_addr().unwrap();
        let reg = Arc::new(RwLock::new(ProxyRegistration::for_test(
            gw.clone(),
            "pbx.example.com",
            handoff.clone(),
        )));
        let ended = handoff
            .register_active_call(
                "tok".into(),
                "out-call-1".into(),
                CallOwner::User("alice".into()),
                OUTBOUND_200.into(),
                pbx.local_addr().unwrap(),
                reg,
                None,
                "v=0\r\n".into(),
                "sip:gw@127.0.0.1".into(),
            )
            .await;
        let sources = trusted
            .unwrap_or_else(|| SourcePolicy::new([pbx.local_addr().unwrap().ip()], Arc::default()));
        let recv_loop = SipProxyManager::spawn_outgoing_call_loop(
            gw,
            sources,
            handoff.clone(),
            "out-call-1".into(),
            ended,
            None,
        );
        OutgoingCall {
            handoff,
            pbx,
            gw_addr,
            recv_loop,
        }
    }

    async fn recv_text(sock: &UdpSocket) -> String {
        let mut buf = vec![0u8; 65535];
        let len = tokio::time::timeout(Duration::from_secs(2), sock.recv(&mut buf))
            .await
            .expect("timed out waiting for SIP message")
            .unwrap();
        String::from_utf8(buf[..len].to_vec()).unwrap()
    }

    async fn loop_exits(recv_loop: tokio::task::JoinHandle<()>) {
        tokio::time::timeout(Duration::from_secs(2), recv_loop)
            .await
            .expect("receive loop should exit once the call has ended")
            .unwrap();
    }

    fn bye(call_id: &str) -> String {
        format!(
            "BYE sip:aria-gateway@127.0.0.1 SIP/2.0\r\n\
             Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-bye\r\n\
             From: <sip:2000@pbx.example.com>;tag=pbxtag\r\n\
             To: <sip:1001@pbx.example.com>;tag=gwtag\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: 5 BYE\r\n\
             Content-Length: 0\r\n\r\n"
        )
    }

    #[tokio::test]
    async fn outgoing_loop_exits_after_app_hangup() {
        let call = outgoing_call().await;
        call.handoff.hangup_call("tok").await.unwrap();
        let bye = recv_text(&call.pbx).await;
        assert!(bye.starts_with("BYE "));

        // Unanswered, the BYE is retransmitted and the socket stays open.
        assert_eq!(recv_text(&call.pbx).await, bye);
        assert!(!call.recv_loop.is_finished());

        let ok = message::build_simple_response(&bye, 200, "OK").unwrap();
        call.pbx.send_to(ok.as_bytes(), call.gw_addr).await.unwrap();
        loop_exits(call.recv_loop).await;
        nothing_arrives(&call.pbx).await;
    }

    #[tokio::test]
    async fn outgoing_loop_exits_after_bye_from_pbx() {
        let call = outgoing_call().await;
        call.pbx
            .send_to(bye("out-call-1").as_bytes(), call.gw_addr)
            .await
            .unwrap();
        assert!(recv_text(&call.pbx).await.starts_with("SIP/2.0 200 OK\r\n"));
        loop_exits(call.recv_loop).await;
        assert!(!call.handoff.is_call_active("out-call-1").await);
    }

    #[tokio::test]
    async fn outgoing_loop_keeps_running_while_the_call_is_up() {
        let call = outgoing_call().await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!call.recv_loop.is_finished());
        call.recv_loop.abort();
    }

    #[tokio::test]
    async fn outgoing_loop_answers_481_to_bye_for_another_call() {
        let call = outgoing_call().await;
        call.pbx
            .send_to(bye("some-other-call").as_bytes(), call.gw_addr)
            .await
            .unwrap();
        let resp = recv_text(&call.pbx).await;
        assert!(
            resp.starts_with("SIP/2.0 481 Call/Transaction Does Not Exist\r\n"),
            "{resp}"
        );
        assert_eq!(
            message::extract_header(&resp, "CSeq").as_deref(),
            Some("5 BYE")
        );
        // Our own call is untouched and the loop keeps serving it.
        assert!(call.handoff.is_call_active("out-call-1").await);
        assert!(!call.recv_loop.is_finished());
        call.recv_loop.abort();
    }

    #[tokio::test]
    async fn registration_answers_481_to_bye_for_unknown_or_ended_call() {
        let handoff = Arc::new(HandoffManager::new());
        let pbx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let pbx_addr = pbx.local_addr().unwrap();
        let gw = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let reg = Arc::new(RwLock::new(ProxyRegistration::for_test(
            gw,
            "pbx.example.com",
            handoff.clone(),
        )));
        let _ended = handoff
            .register_active_call(
                "tok".into(),
                "out-call-1".into(),
                CallOwner::User("alice".into()),
                OUTBOUND_200.into(),
                pbx_addr,
                reg.clone(),
                None,
                "v=0\r\n".into(),
                "sip:gw@127.0.0.1".into(),
            )
            .await;

        // Unknown dialog.
        SipProxyManager::handle_request(&reg, &bye("nope"), pbx_addr)
            .await
            .unwrap();
        assert!(recv_text(&pbx).await.starts_with("SIP/2.0 481 "));

        // First BYE ends the call with 200; its retransmission gets the
        // same 200 again, and a new BYE for the ended call gets 481.
        SipProxyManager::handle_request(&reg, &bye("out-call-1"), pbx_addr)
            .await
            .unwrap();
        let ok = recv_text(&pbx).await;
        assert!(ok.starts_with("SIP/2.0 200 OK\r\n"));
        SipProxyManager::handle_request(&reg, &bye("out-call-1"), pbx_addr)
            .await
            .unwrap();
        assert_eq!(recv_text(&pbx).await, ok);
        let new_bye = bye("out-call-1").replace("z9hG4bK-bye", "z9hG4bK-bye2");
        SipProxyManager::handle_request(&reg, &new_bye, pbx_addr)
            .await
            .unwrap();
        assert!(recv_text(&pbx).await.starts_with("SIP/2.0 481 "));
    }

    // ── Source and dialog checks ────────────────────────────────────────────

    struct Registered {
        handoff: Arc<HandoffManager>,
        reg: Arc<RwLock<ProxyRegistration>>,
        pbx: UdpSocket,
        pbx_addr: SocketAddr,
        foreign: UdpSocket,
        foreign_addr: SocketAddr,
    }

    /// A registration that trusts `pbx`, with an active call on it, plus a
    /// foreign socket on another port.
    async fn registered_with_call() -> Registered {
        let handoff = Arc::new(HandoffManager::new());
        let pbx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let pbx_addr = pbx.local_addr().unwrap();
        let foreign = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let foreign_addr = foreign.local_addr().unwrap();
        let gw = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let mut r = ProxyRegistration::for_test(gw, "pbx.example.com", handoff.clone());
        r.trust_peer(pbx_addr);
        let reg = Arc::new(RwLock::new(r));
        let _call_ended = handoff
            .register_active_call(
                "tok".into(),
                "out-call-1".into(),
                CallOwner::User("alice".into()),
                OUTBOUND_200.into(),
                pbx_addr,
                reg.clone(),
                None,
                "v=0\r\n".into(),
                "sip:gw@127.0.0.1".into(),
            )
            .await;
        Registered {
            handoff,
            reg,
            pbx,
            pbx_addr,
            foreign,
            foreign_addr,
        }
    }

    async fn nothing_arrives(sock: &UdpSocket) {
        let mut buf = [0u8; 4096];
        assert!(
            tokio::time::timeout(Duration::from_millis(150), sock.recv(&mut buf))
                .await
                .is_err(),
            "expected no reply"
        );
    }

    const INBOUND_INVITE: &str = "INVITE sip:1001@127.0.0.1 SIP/2.0\r\n\
        Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-spoof\r\n\
        From: <sip:666@evil.example.com>;tag=e1\r\n\
        To: <sip:1001@pbx.example.com>\r\n\
        Call-ID: spoofed-invite\r\n\
        CSeq: 1 INVITE\r\n\
        Content-Length: 0\r\n\r\n";

    fn options() -> &'static str {
        "OPTIONS sip:1001@127.0.0.1 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-opt\r\n\
         From: <sip:probe@x>;tag=p\r\nTo: <sip:1001@x>\r\nCall-ID: opt-1\r\n\
         CSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"
    }

    fn refer_notify(call_id: &str) -> String {
        let frag = "SIP/2.0 200 OK\r\n";
        format!(
            "NOTIFY sip:aria-gateway@127.0.0.1 SIP/2.0\r\n\
             Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-n\r\n\
             From: <sip:2000@pbx.example.com>;tag=pbxtag\r\n\
             To: <sip:1001@pbx.example.com>;tag=gwtag\r\n\
             Call-ID: {call_id}\r\nCSeq: 9 NOTIFY\r\nEvent: refer\r\n\
             Subscription-State: terminated\r\n\
             Content-Type: message/sipfrag\r\nContent-Length: {}\r\n\r\n{frag}",
            frag.len()
        )
    }

    #[tokio::test]
    async fn requests_from_foreign_sources_are_dropped() {
        let r = registered_with_call().await;
        // A foreign IP (TEST-NET-1); loopback aliases aren't available on
        // every host, and a dropped message is never answered anyway.
        let foreign: SocketAddr = "192.0.2.66:5060".parse().unwrap();

        for msg in [
            INBOUND_INVITE.to_string(),
            bye("out-call-1"),
            refer_notify("out-call-1"),
            options().to_string(),
        ] {
            SipProxyManager::handle_message(&r.reg, &msg, foreign)
                .await
                .unwrap();
        }
        nothing_arrives(&r.pbx).await;
        assert_eq!(r.handoff.pending_count().await, 0, "no call may be offered");
        assert!(r.handoff.is_call_active("out-call-1").await);

        // The PBX's IP is trusted on any source port.
        SipProxyManager::handle_message(&r.reg, options(), r.foreign_addr)
            .await
            .unwrap();
        assert!(recv_text(&r.foreign).await.starts_with("SIP/2.0 200 OK"));
    }

    #[tokio::test]
    async fn loopback_is_dropped_unless_resolved_or_allowlisted() {
        let r = registered_with_call().await;
        let policy = |allow: &str| {
            SourcePolicy::new(
                ["192.0.2.1".parse().unwrap()],
                Arc::new(TrustedSources::parse(allow).unwrap()),
            )
        };

        // Only 192.0.2.1 is trusted: the loopback PBX is dropped.
        r.reg.write().await.set_sources(policy(""));
        SipProxyManager::handle_message(&r.reg, options(), r.pbx_addr)
            .await
            .unwrap();
        nothing_arrives(&r.pbx).await;

        // An allowlisted CIDR admits it.
        r.reg
            .write()
            .await
            .set_sources(policy("10.0.0.0/8, 127.0.0.0/8"));
        SipProxyManager::handle_message(&r.reg, options(), r.pbx_addr)
            .await
            .unwrap();
        assert!(recv_text(&r.pbx).await.starts_with("SIP/2.0 200 OK"));
    }

    #[tokio::test]
    async fn bye_with_wrong_tags_gets_481_and_the_call_stays_up() {
        let r = registered_with_call().await;
        for bad in [
            bye("out-call-1").replace("tag=pbxtag", "tag=someone-else"),
            bye("out-call-1").replace("tag=gwtag", "tag=not-ours"),
            bye("out-call-1").replace(";tag=gwtag", ""),
        ] {
            SipProxyManager::handle_message(&r.reg, &bad, r.pbx_addr)
                .await
                .unwrap();
            assert!(recv_text(&r.pbx).await.starts_with("SIP/2.0 481 "));
        }
        assert!(r.handoff.is_call_active("out-call-1").await);

        // A wrong-tag NOTIFY is refused too.
        let notify = refer_notify("out-call-1").replace("tag=pbxtag", "tag=x");
        SipProxyManager::handle_message(&r.reg, &notify, r.pbx_addr)
            .await
            .unwrap();
        assert!(recv_text(&r.pbx).await.starts_with("SIP/2.0 481 "));
    }

    #[tokio::test]
    async fn bye_on_another_registrations_socket_does_not_end_the_call() {
        let r = registered_with_call().await;
        let other_gw = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let mut other = ProxyRegistration::for_test(other_gw, "pbx.example.com", r.handoff.clone());
        other.trust_peer(r.pbx_addr);
        let other = Arc::new(RwLock::new(other));

        SipProxyManager::handle_message(&other, &bye("out-call-1"), r.pbx_addr)
            .await
            .unwrap();
        assert!(recv_text(&r.pbx).await.starts_with("SIP/2.0 481 "));
        assert!(r.handoff.is_call_active("out-call-1").await);

        // On its own socket it ends the call.
        SipProxyManager::handle_message(&r.reg, &bye("out-call-1"), r.pbx_addr)
            .await
            .unwrap();
        assert!(recv_text(&r.pbx).await.starts_with("SIP/2.0 200 OK"));
        assert!(!r.handoff.is_call_active("out-call-1").await);
    }

    #[tokio::test]
    async fn outgoing_loop_drops_foreign_sources() {
        // The dialled server is 192.0.2.1: our loopback "PBX" is foreign.
        let call = outgoing_call_trusting(Some(SourcePolicy::new(
            ["192.0.2.1".parse().unwrap()],
            Arc::default(),
        )))
        .await;
        call.pbx
            .send_to(bye("out-call-1").as_bytes(), call.gw_addr)
            .await
            .unwrap();
        nothing_arrives(&call.pbx).await;
        assert!(call.handoff.is_call_active("out-call-1").await);
        call.recv_loop.abort();

        // From the server's IP, any port is accepted.
        let call = outgoing_call().await;
        let other_port = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        other_port
            .send_to(bye("out-call-1").as_bytes(), call.gw_addr)
            .await
            .unwrap();
        assert!(recv_text(&other_port).await.starts_with("SIP/2.0 200 OK"));
        call.recv_loop.abort();
    }

    // ── INVITE server transactions ──────────────────────────────────────────

    struct Ringing {
        handoff: Arc<HandoffManager>,
        reg: Arc<RwLock<ProxyRegistration>>,
        pbx: UdpSocket,
        pbx_addr: SocketAddr,
        invite: String,
        token: String,
    }

    fn incoming_invite(branch: &str) -> String {
        let sdp = "v=0\r\nc=IN IP4 127.0.0.1\r\nm=audio 4000 RTP/AVP 0\r\n";
        format!(
            "INVITE sip:1001@127.0.0.1 SIP/2.0\r\n\
             Via: SIP/2.0/UDP 127.0.0.1:5060;branch={branch}\r\n\
             Via: SIP/2.0/UDP 10.9.9.9:5060;branch=z9hG4bK-upstream\r\n\
             Record-Route: <sip:edge.example.com;lr>\r\n\
             From: \"Bob\" <sip:2000@pbx.example.com>;tag=pbxtag\r\n\
             To: <sip:1001@pbx.example.com>\r\n\
             Call-ID: in-1\r\nCSeq: 10 INVITE\r\n\
             Contact: <sip:2000@127.0.0.1:5060>\r\n\
             Content-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{sdp}",
            sdp.len()
        )
    }

    /// An incoming call ringing on a registration that trusts the fake PBX;
    /// the 100 Trying has been consumed.
    async fn ringing() -> Ringing {
        let handoff = Arc::new(HandoffManager::new());
        let pbx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let pbx_addr = pbx.local_addr().unwrap();
        let gw = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let mut r = ProxyRegistration::for_test(gw, "pbx.example.com", handoff.clone());
        r.trust_peer(pbx_addr);
        let reg = Arc::new(RwLock::new(r));
        let invite = incoming_invite("z9hG4bK-in1");
        // The no-op push manager fails to push; the call is still offered.
        let _ = SipProxyManager::handle_message(&reg, &invite, pbx_addr).await;
        assert!(recv_text(&pbx).await.starts_with("SIP/2.0 100 Trying"));
        let token = handoff.pending_token("in-1").await.unwrap();
        Ringing {
            handoff,
            reg,
            pbx,
            pbx_addr,
            invite,
            token,
        }
    }

    fn ack_for(response: &str, branch: &str) -> String {
        let h = |n: &str| message::extract_header(response, n).unwrap();
        format!(
            "ACK sip:aria-gateway@127.0.0.1 SIP/2.0\r\n\
             Via: SIP/2.0/UDP 127.0.0.1:5060;branch={branch}\r\n\
             From: {}\r\nTo: {}\r\nCall-ID: {}\r\nCSeq: {} ACK\r\n\
             Content-Length: 0\r\n\r\n",
            h("From"),
            h("To"),
            h("Call-ID"),
            h("CSeq").split_whitespace().next().unwrap()
        )
    }

    #[tokio::test]
    async fn invite_retransmission_is_not_a_new_call() {
        let r = ringing().await;
        let _ = SipProxyManager::handle_message(&r.reg, &r.invite, r.pbx_addr).await;
        assert!(recv_text(&r.pbx).await.starts_with("SIP/2.0 100 Trying"));
        assert_eq!(r.handoff.pending_count().await, 1);

        // Same Call-ID on a different transaction: merged request.
        let merged = incoming_invite("z9hG4bK-other");
        let _ = SipProxyManager::handle_message(&r.reg, &merged, r.pbx_addr).await;
        let resp = recv_text(&r.pbx).await;
        assert!(resp.starts_with("SIP/2.0 482 Loop Detected"), "{resp}");
        assert_eq!(r.handoff.pending_count().await, 1);
    }

    #[tokio::test]
    async fn answered_call_retransmits_200_until_ack_and_repeats_it_for_retransmissions() {
        let r = ringing().await;
        r.handoff
            .accept_call(
                &r.token,
                "v=0\r\nc=IN IP4 10.1.1.1\r\nm=audio 5000 RTP/AVP 0\r\n".into(),
            )
            .await
            .unwrap();
        let ok = recv_text(&r.pbx).await;
        assert!(ok.starts_with("SIP/2.0 200 OK\r\n"));
        // All Vias in order, Record-Route echoed, our tag on To.
        let vias: Vec<&str> = ok.lines().filter(|l| l.starts_with("Via:")).collect();
        assert_eq!(vias.len(), 2);
        assert!(vias[0].contains("z9hG4bK-in1") && vias[1].contains("z9hG4bK-upstream"));
        assert!(ok.contains("Record-Route: <sip:edge.example.com;lr>\r\n"));
        assert!(message::extract_to_tag(&ok).is_some());

        // Unacknowledged: retransmitted.
        assert_eq!(recv_text(&r.pbx).await, ok);
        // A retransmitted INVITE gets the same 200.
        let _ = SipProxyManager::handle_message(&r.reg, &r.invite, r.pbx_addr).await;
        assert_eq!(recv_text(&r.pbx).await, ok);
        // The ACK stops the retransmissions.
        SipProxyManager::handle_message(&r.reg, &ack_for(&ok, "z9hG4bK-ack"), r.pbx_addr)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut buf = [0u8; 4096];
        while r.pbx.try_recv(&mut buf).is_ok() {}
        nothing_arrives(&r.pbx).await;
    }

    #[tokio::test]
    async fn reinvite_is_answered_in_the_dialog_without_a_new_call() {
        let r = ringing().await;
        let answer = "v=0\r\nc=IN IP4 10.1.1.1\r\nm=audio 5000 RTP/AVP 0\r\n";
        r.handoff
            .accept_call(&r.token, answer.into())
            .await
            .unwrap();
        let ok = recv_text(&r.pbx).await;
        let our_tag = message::extract_to_tag(&ok).unwrap();

        // While the 200 is unacknowledged, a re-INVITE gets 491.
        let reinvite = |cseq: u32, branch: &str| {
            incoming_invite(branch)
                .replace(
                    "To: <sip:1001@pbx.example.com>",
                    &format!("To: <sip:1001@pbx.example.com>;tag={our_tag}"),
                )
                .replace("CSeq: 10 INVITE", &format!("CSeq: {cseq} INVITE"))
        };
        let _ =
            SipProxyManager::handle_message(&r.reg, &reinvite(11, "z9hG4bK-re1"), r.pbx_addr).await;
        let mut resp = recv_text(&r.pbx).await;
        while resp == ok {
            resp = recv_text(&r.pbx).await;
        }
        assert!(resp.starts_with("SIP/2.0 491 "), "{resp}");

        SipProxyManager::handle_message(&r.reg, &ack_for(&ok, "z9hG4bK-ack"), r.pbx_addr)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(600)).await;
        let mut buf = [0u8; 4096];
        while r.pbx.try_recv(&mut buf).is_ok() {}

        // Now a session-refresh re-INVITE gets 200 with our current SDP.
        let _ =
            SipProxyManager::handle_message(&r.reg, &reinvite(12, "z9hG4bK-re2"), r.pbx_addr).await;
        let ok2 = recv_text(&r.pbx).await;
        assert!(ok2.starts_with("SIP/2.0 200 OK\r\n"), "{ok2}");
        assert!(ok2.ends_with(answer));
        assert!(ok2.contains("CSeq: 12 INVITE"));
        assert_eq!(r.handoff.pending_count().await, 0);
        assert!(r.handoff.is_call_active("in-1").await);

        // A re-INVITE for an unknown dialog gets 481.
        let stray = reinvite(13, "z9hG4bK-re3").replace("Call-ID: in-1", "Call-ID: nope");
        let _ = SipProxyManager::handle_message(&r.reg, &stray, r.pbx_addr).await;
        let mut resp = recv_text(&r.pbx).await;
        while resp == ok2 {
            resp = recv_text(&r.pbx).await;
        }
        assert!(resp.starts_with("SIP/2.0 481 "), "{resp}");
    }

    #[tokio::test]
    async fn reject_sends_a_tagged_603_until_acked() {
        let r = ringing().await;
        r.handoff.reject_call(&r.token).await.unwrap();
        let decline = recv_text(&r.pbx).await;
        assert!(decline.starts_with("SIP/2.0 603 Decline"));
        assert!(message::extract_to_tag(&decline).is_some());
        assert_eq!(decline.lines().filter(|l| l.starts_with("Via:")).count(), 2);
        assert_eq!(recv_text(&r.pbx).await, decline, "retransmitted until ACK");

        // The non-2xx ACK reuses the INVITE branch and stops it.
        SipProxyManager::handle_message(&r.reg, &ack_for(&decline, "z9hG4bK-in1"), r.pbx_addr)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut buf = [0u8; 4096];
        while r.pbx.try_recv(&mut buf).is_ok() {}
        nothing_arrives(&r.pbx).await;
    }

    fn cancel_of(invite: &str) -> String {
        message::build_cancel(invite).unwrap()
    }

    #[tokio::test]
    async fn cancel_of_a_ringing_call_gets_200_and_a_tagged_487() {
        let r = ringing().await;
        SipProxyManager::handle_message(&r.reg, &cancel_of(&r.invite), r.pbx_addr)
            .await
            .unwrap();
        let ok = recv_text(&r.pbx).await;
        assert!(ok.starts_with("SIP/2.0 200 OK") && ok.contains("CSeq: 10 CANCEL"));
        let terminated = recv_text(&r.pbx).await;
        assert!(terminated.starts_with("SIP/2.0 487 Request Terminated"));
        assert!(terminated.contains("CSeq: 10 INVITE"));
        assert_eq!(
            message::extract_to_tag(&ok),
            message::extract_to_tag(&terminated)
        );
        assert_eq!(r.handoff.pending_count().await, 0);
    }

    #[tokio::test]
    async fn cancel_for_an_unknown_or_answered_invite() {
        let r = ringing().await;
        // Wrong branch: no such transaction.
        let wrong = cancel_of(&r.invite).replace("z9hG4bK-in1", "z9hG4bK-nope");
        SipProxyManager::handle_message(&r.reg, &wrong, r.pbx_addr)
            .await
            .unwrap();
        assert!(recv_text(&r.pbx).await.starts_with("SIP/2.0 481 "));
        assert_eq!(r.handoff.pending_count().await, 1);

        // After the answer, a CANCEL gets 200 but no 487 and the call stays.
        r.handoff
            .accept_call(&r.token, "v=0\r\n".into())
            .await
            .unwrap();
        let ok = recv_text(&r.pbx).await;
        SipProxyManager::handle_message(&r.reg, &ack_for(&ok, "z9hG4bK-ack"), r.pbx_addr)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(600)).await;
        let mut buf = [0u8; 4096];
        while r.pbx.try_recv(&mut buf).is_ok() {}
        SipProxyManager::handle_message(&r.reg, &cancel_of(&r.invite), r.pbx_addr)
            .await
            .unwrap();
        let resp = recv_text(&r.pbx).await;
        assert!(
            resp.starts_with("SIP/2.0 200 OK") && resp.contains("CANCEL"),
            "{resp}"
        );
        nothing_arrives(&r.pbx).await;
        assert!(r.handoff.is_call_active("in-1").await);
    }

    #[tokio::test]
    async fn accept_never_replaces_a_live_call() {
        let r = ringing().await;
        r.handoff
            .accept_call(&r.token, "v=0\r\n".into())
            .await
            .unwrap();
        // A second pending call that (bypassing classification) reuses the
        // Call-ID cannot be accepted over the live one.
        let token2 = r
            .handoff
            .create_pending_call(
                "test-device".into(),
                "in-1".into(),
                incoming_invite("z9hG4bK-dup"),
                r.pbx_addr,
                r.reg.clone(),
                None,
                String::new(),
                0,
                0,
            )
            .await;
        assert_eq!(
            r.handoff.accept_call(&token2, "v=0\r\n".into()).await,
            Err(crate::handoff::AcceptError::Conflict)
        );
        assert!(r.handoff.is_call_active("in-1").await);
    }

    // ── Registration lifecycle ──────────────────────────────────────────────

    async fn recv_from(sock: &UdpSocket) -> (String, SocketAddr) {
        let mut buf = vec![0u8; 65535];
        let (len, from) = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf))
            .await
            .expect("timed out waiting for SIP message")
            .unwrap();
        (String::from_utf8(buf[..len].to_vec()).unwrap(), from)
    }

    fn account(pbx: &UdpSocket) -> SipAccountConfig {
        SipAccountConfig {
            username: "1001".into(),
            password: "pw".into(),
            domain: "pbx.example.com".into(),
            registrar: Some("127.0.0.1".into()),
            transport: "udp".into(),
            port: pbx.local_addr().unwrap().port(),
            auth_username: None,
            display_name: String::new(),
        }
    }

    /// Answer every REGISTER with 200 and return what arrived, for `ms`.
    async fn registrar_traffic(pbx: &UdpSocket, ms: u64) -> Vec<(String, SocketAddr)> {
        let mut seen = Vec::new();
        let mut buf = vec![0u8; 65535];
        let until = tokio::time::Instant::now() + Duration::from_millis(ms);
        while let Ok(Ok((len, from))) =
            tokio::time::timeout_at(until, pbx.recv_from(&mut buf)).await
        {
            let msg = String::from_utf8(buf[..len].to_vec()).unwrap();
            if msg.starts_with("REGISTER ") {
                let ok = message::build_simple_response(&msg, 200, "OK").unwrap();
                pbx.send_to(ok.as_bytes(), from).await.unwrap();
            }
            seen.push((msg, from));
        }
        seen
    }

    fn expires(msg: &str) -> String {
        message::extract_header(msg, "Expires").unwrap_or_default()
    }

    #[tokio::test]
    async fn unregistering_stops_refreshes_and_the_loop() {
        let mgr = SipProxyManager::new().with_refresh_after(Duration::from_millis(150));
        let handoff = Arc::new(HandoffManager::new());
        let pbx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        mgr.register_device(
            "dev1".into(),
            account(&pbx),
            Arc::new(PushManager::new_noop()),
            handoff,
        )
        .await
        .unwrap();

        // Registered, then refreshed.
        let seen = registrar_traffic(&pbx, 400).await;
        assert!(seen.len() >= 2, "expected a refresh: {}", seen.len());
        assert!(seen.iter().all(|(m, _)| expires(m) == "3600"));
        let gw = seen[0].1;

        mgr.unregister_device("dev1").await.unwrap();
        let after = registrar_traffic(&pbx, 600).await;
        assert_eq!(after.len(), 1, "only the unregister may follow: {after:?}");
        assert_eq!(expires(&after[0].0), "0");
        assert_eq!(mgr.get_status("dev1").await, None);

        // The receive loop is gone: nothing answers on the old socket.
        let opts = "OPTIONS sip:1001@127.0.0.1 SIP/2.0\r\n\
            Via: SIP/2.0/UDP 127.0.0.1;branch=z9hG4bK-o\r\nFrom: <sip:x@y>;tag=1\r\n\
            To: <sip:1001@y>\r\nCall-ID: o1\r\nCSeq: 1 OPTIONS\r\n\r\n";
        pbx.send_to(opts.as_bytes(), gw).await.unwrap();
        nothing_arrives(&pbx).await;
    }

    #[tokio::test]
    async fn reregistering_replaces_the_previous_registration() {
        let mgr = SipProxyManager::new().with_refresh_after(Duration::from_millis(150));
        let handoff = Arc::new(HandoffManager::new());
        let pbx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let push = Arc::new(PushManager::new_noop());
        mgr.register_device("dev1".into(), account(&pbx), push.clone(), handoff.clone())
            .await
            .unwrap();
        let (first, old_gw) = recv_from(&pbx).await;
        let ok = message::build_simple_response(&first, 200, "OK").unwrap();
        pbx.send_to(ok.as_bytes(), old_gw).await.unwrap();

        // Heartbeat: register again.
        mgr.register_device("dev1".into(), account(&pbx), push, handoff)
            .await
            .unwrap();
        let seen = registrar_traffic(&pbx, 700).await;
        let from_old: Vec<_> = seen.iter().filter(|(_, f)| *f == old_gw).collect();
        assert_eq!(
            from_old.len(),
            1,
            "old registration only unregisters: {from_old:?}"
        );
        assert_eq!(expires(&from_old[0].0), "0");
        let new_refreshes = seen
            .iter()
            .filter(|(m, f)| *f != old_gw && expires(m) == "3600")
            .count();
        assert!(new_refreshes >= 2, "new registration keeps refreshing");
    }
}
