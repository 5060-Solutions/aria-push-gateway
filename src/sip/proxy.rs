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
    /// Addresses the PBX/registrar resolved to; SIP traffic from anywhere
    /// else is dropped.
    peers: Vec<SocketAddr>,
    pub(crate) local_addr: SocketAddr,
    call_id: String,
    from_tag: String,
    cseq: u32,
    state: ProxyState,
    auth_attempts: u32,
    push_manager: Arc<PushManager>,
    handoff: Arc<HandoffManager>,
}

impl ProxyRegistration {
    /// Whether a packet from `from` may be processed on this registration.
    fn is_trusted_peer(&self, from: SocketAddr) -> bool {
        self.peers.contains(&from)
    }

    /// Accept SIP traffic from `peer` too (tests only).
    #[cfg(test)]
    pub(crate) fn trust_peer(&mut self, peer: SocketAddr) {
        self.peers.push(peer);
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
            peers: Vec::new(),
            local_addr,
            call_id: String::new(),
            from_tag: String::new(),
            cseq: 0,
            state: ProxyState::Registered,
            auth_attempts: 0,
            push_manager: Arc::new(PushManager::new_noop()),
            handoff,
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
struct InviteSlot<'a> {
    invites: &'a std::sync::Mutex<PendingInvites>,
    key: (String, String),
    id: u64,
}

fn lock_invites(m: &std::sync::Mutex<PendingInvites>) -> std::sync::MutexGuard<'_, PendingInvites> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl InviteSlot<'_> {
    /// The INVITE was answered: drop the entry so it can no longer be
    /// cancelled, and report whether a cancel had already been requested
    /// (a 200 OK crossing our CANCEL).
    fn claim_answer(&self) -> bool {
        let mut invites = lock_invites(self.invites);
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

impl Drop for InviteSlot<'_> {
    fn drop(&mut self) {
        let mut invites = lock_invites(self.invites);
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
    pending_invites: std::sync::Mutex<PendingInvites>,
    next_invite_id: std::sync::atomic::AtomicU64,
}

impl SipProxyManager {
    pub fn new() -> Self {
        let resolver = SrvResolver::new().expect("Failed to create DNS resolver");
        Self {
            registrations: RwLock::new(HashMap::new()),
            resolver: Arc::new(resolver),
            pending_invites: std::sync::Mutex::new(HashMap::new()),
            next_invite_id: std::sync::atomic::AtomicU64::new(0),
        }
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
    ) -> Result<InviteSlot<'_>, OriginateRefusal> {
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
            invites: &self.pending_invites,
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
            peers: resolved.iter().map(|r| r.addr).collect(),
            local_addr,
            call_id,
            from_tag,
            cseq: 0,
            state: ProxyState::Registering,
            auth_attempts: 0,
            push_manager,
            handoff,
        }));

        // Store registration
        {
            let mut regs = self.registrations.write().await;
            regs.insert(device_id.clone(), reg.clone());
        }

        // Send initial REGISTER
        Self::send_register(&reg).await?;

        // Spawn receive loop for this device
        let reg_clone = reg.clone();
        let socket_clone = socket;
        let device_id_clone = device_id;
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            let mut consecutive_errors: u32 = 0;
            loop {
                match socket_clone.recv_from(&mut buf).await {
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
        });

        Ok(())
    }

    /// Unregister a device (send REGISTER with Expires: 0).
    pub async fn unregister_device(&self, device_id: &str) -> anyhow::Result<()> {
        let reg = {
            let regs = self.registrations.read().await;
            regs.get(device_id).cloned()
        };

        if let Some(reg) = reg {
            Self::send_unregister(&reg).await?;
            let mut regs = self.registrations.write().await;
            regs.remove(device_id);
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
                3600,
            );
            (msg, r.server_addr, r.socket.clone())
        };

        socket.send_to(msg.as_bytes(), server_addr).await?;
        tracing::debug!("Sent REGISTER to {}", server_addr);
        Ok(())
    }

    async fn send_unregister(reg: &Arc<RwLock<ProxyRegistration>>) -> anyhow::Result<()> {
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
                0, // Expires: 0 = unregister
            );
            (msg, r.server_addr, r.socket.clone())
        };

        socket.send_to(msg.as_bytes(), server_addr).await?;
        tracing::debug!("Sent unregister to {}", server_addr);
        Ok(())
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
            "BYE" => {
                // 200 OK to our BYE — call ended cleanly
                let call_id = message::extract_header(text, "Call-ID").unwrap_or_default();
                tracing::debug!(call_id = %call_id, status, "BYE response received");
                Ok(())
            }
            "REFER" => {
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
                r.state = ProxyState::Registered;
                r.auth_attempts = 0;
                tracing::info!(device = %r.device_id, "Proxy registration successful");

                // Schedule re-registration before expiry
                let reg_clone = reg.clone();
                tokio::spawn(async move {
                    // Re-register at 80% of the 3600s expiry
                    tokio::time::sleep(Duration::from_secs(2880)).await;
                    if let Err(e) = Self::send_register(&reg_clone).await {
                        tracing::error!("Re-registration failed: {}", e);
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
                        3600,
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
    /// Opens a temporary UDP socket, sends a SIP INVITE with the mobile
    /// client's SDP offer from `account` (the caller's registered device),
    /// handles auth challenges, and waits for a 200 OK.
    /// Returns (call_token, sdp_answer).
    ///
    /// With a `client_ref`, the pending INVITE can be cancelled through
    /// [`Self::cancel_outgoing_call`]: the gateway sends CANCEL, ACKs the
    /// final response, and BYEs a 200 OK that crosses the CANCEL. The call
    /// then fails with [`OriginateRefusal::Cancelled`].
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
        let (cancel_tx, mut cancel_rx) = tokio::sync::oneshot::channel::<()>();
        let (slot, _no_cancel) = match client_ref {
            Some(r) => (Some(self.track_invite(owner_user_id, r, cancel_tx)?), None),
            None => (None, Some(cancel_tx)),
        };

        let username = account.username.as_str();
        let password = account.password.as_str();
        let domain = account.domain.as_str();
        let registrar = account.registrar.as_deref().filter(|r| !r.is_empty());
        let transport = account.transport.as_str();
        let port = account.port;
        let auth_username = account.auth_username.as_deref().filter(|a| !a.is_empty());
        let display_name = account.display_name.as_str();
        let effective_registrar = registrar.unwrap_or(domain);
        let effective_auth_user = auth_username.unwrap_or(username);

        // Resolve target via SRV lookup (with A record fallback)
        let resolved = self
            .resolver
            .resolve(effective_registrar, port, transport)
            .await?;
        let server_addr = resolved
            .first()
            .ok_or_else(|| anyhow::anyhow!("Cannot resolve {}", effective_registrar))?
            .addr;

        // Bind temporary socket
        let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        let local_port = socket.local_addr()?.port();

        // Discover local IP
        let probe = UdpSocket::bind("0.0.0.0:0").await?;
        probe.connect(server_addr).await?;
        let local_ip = probe.local_addr()?.ip().to_string();

        let call_id = message::generate_call_id();
        let from_tag = format!("{:08x}", rand::random::<u32>());
        let branch = message::generate_branch();
        let _ = transport; // UDP only for now

        // Normalize URI
        let target_uri = if destination_uri.starts_with("sip:") {
            destination_uri.to_string()
        } else {
            format!("sip:{}", destination_uri)
        };

        // Extract phone's RTP address from its SDP offer
        let phone_media = message::extract_sdp_media_address(sdp_offer);
        if let Some((ref ip, port)) = phone_media {
            tracing::info!(ip = %ip, port, "Phone SDP offer media address");
        }

        // Pass phone's SDP offer through to PBX unchanged.
        // RTP flows directly between phone and PBX media relay — no gateway relay needed.
        if let Some((ip, port)) = message::extract_sdp_media_address(sdp_offer) {
            tracing::info!(ip, port, "Phone SDP offer media address (pass-through)");
        }

        let mut invite = Self::build_originate_invite(
            &target_uri,
            &local_ip,
            local_port,
            &call_id,
            1,
            &from_tag,
            &branch,
            username,
            domain,
            display_name,
            sdp_offer,
            None,
        );
        let mut invite_branch = branch;

        socket.send_to(invite.as_bytes(), server_addr).await?;
        tracing::info!(uri = %target_uri, "Sent outgoing INVITE (SDP pass-through)");

        // Wait for final response (up to 30s)
        let mut buf = vec![0u8; 65535];
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut cseq: u32 = 1;

        // Cancellation state: the CANCEL we sent (retransmitted until the
        // PBX answers it) and when to retransmit next.
        let mut cancel_armed = slot.is_some();
        let mut cancel: Option<String> = None;
        let mut cancel_answered = false;
        let mut cancel_interval = Duration::from_millis(500);
        let mut cancel_retx_at = deadline;

        enum Event {
            Cancel(bool),
            Recv(Result<std::io::Result<(usize, SocketAddr)>, tokio::time::error::Elapsed>),
        }

        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                if cancel.is_some() {
                    return Err(OriginateRefusal::Cancelled.into());
                }
                anyhow::bail!("Outgoing call timed out");
            }
            let wake = if cancel.is_some() && !cancel_answered {
                cancel_retx_at.min(deadline)
            } else {
                deadline
            };

            let event = tokio::select! {
                biased;
                r = &mut cancel_rx, if cancel_armed => Event::Cancel(r.is_ok()),
                r = tokio::time::timeout(wake.saturating_duration_since(now), socket.recv_from(&mut buf)) => Event::Recv(r),
            };

            let len = match event {
                Event::Cancel(requested) => {
                    cancel_armed = false;
                    if requested {
                        let msg = message::build_cancel(&invite)
                            .ok_or_else(|| anyhow::anyhow!("cannot build CANCEL"))?;
                        socket.send_to(msg.as_bytes(), server_addr).await?;
                        tracing::info!(call_id = %call_id, "Outgoing call cancelled by app — sent CANCEL");
                        cancel_retx_at = tokio::time::Instant::now() + cancel_interval;
                        cancel = Some(msg);
                    }
                    continue;
                }
                Event::Recv(Err(_)) => {
                    // Timer: retransmit the CANCEL, or loop round to the deadline.
                    if let (Some(msg), false) = (&cancel, cancel_answered) {
                        if tokio::time::Instant::now() >= cancel_retx_at {
                            socket.send_to(msg.as_bytes(), server_addr).await?;
                            cancel_interval = (cancel_interval * 2).min(Duration::from_secs(4));
                            cancel_retx_at = tokio::time::Instant::now() + cancel_interval;
                        }
                    }
                    continue;
                }
                Event::Recv(Ok(r)) => match r? {
                    (len, from) if from == server_addr => len,
                    (_, from) => {
                        tracing::warn!(call_id = %call_id, %from, "Dropping SIP message from an unexpected source");
                        continue;
                    }
                },
            };

            let text = std::str::from_utf8(&buf[..len])?;
            let status = match message::parse_status_code(text) {
                Some(s) => s,
                None => continue,
            };

            match message::extract_cseq_method(text).as_deref() {
                Some("INVITE") => {}
                Some("CANCEL") => {
                    tracing::debug!(status, "Response to our CANCEL");
                    cancel_answered = true;
                    continue;
                }
                _ => continue,
            }

            let cancelled = cancel.is_some();
            match status {
                100..=199 => {
                    tracing::debug!(status, "Provisional response for outgoing call");
                    continue;
                }
                200..=299 => {
                    let to_tag = message::extract_to_tag(text).unwrap_or_default();
                    let ack = Self::build_ack(
                        &target_uri,
                        &local_ip,
                        local_port,
                        &call_id,
                        cseq,
                        &from_tag,
                        &to_tag,
                        &message::generate_branch(),
                    );
                    socket.send_to(ack.as_bytes(), server_addr).await?;

                    // Answered: from here on the call can't be cancelled. If
                    // a cancel was asked for (even one still in flight), the
                    // answer crossed it — end the call right away.
                    let cancel_requested = slot.as_ref().is_some_and(|s| s.claim_answer());
                    if cancelled || cancel_requested {
                        tracing::info!(call_id = %call_id, "200 OK crossed our CANCEL — sending BYE");
                        let local_addr = SocketAddr::new(local_ip.parse()?, local_port);
                        let dialog = crate::handoff::Dialog::from_uac(text, server_addr);
                        let bye = crate::handoff::build_in_dialog_request(
                            "BYE",
                            &dialog,
                            cseq + 1,
                            local_addr,
                            &message::generate_branch(),
                            "",
                        );
                        Self::bye_cancelled_answer(&socket, server_addr, &bye, &ack).await;
                        return Err(OriginateRefusal::Cancelled.into());
                    }

                    // Extract SDP from 200 OK
                    let raw_sdp_answer = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();

                    // Pass PBX's SDP answer through to phone unchanged.
                    // Phone will send RTP directly to PBX media relay.
                    let sdp_answer = raw_sdp_answer;
                    if let Some((ip, port)) = message::extract_sdp_media_address(&sdp_answer) {
                        tracing::info!(ip, port, "PBX SDP answer media address (pass-through)");
                    }

                    // Create a call token for hangup tracking
                    let call_token = uuid::Uuid::new_v4().to_string();

                    // Store as an active call for BYE handling
                    let proxy_reg = Arc::new(RwLock::new(ProxyRegistration {
                        device_id: format!("outgoing-{}", &call_token[..8]),
                        config: SipAccountConfig {
                            username: username.to_string(),
                            password: password.to_string(),
                            domain: domain.to_string(),
                            registrar: registrar.map(|s| s.to_string()),
                            transport: "udp".to_string(),
                            port,
                            auth_username: auth_username.map(|s| s.to_string()),
                            display_name: display_name.to_string(),
                        },
                        socket: socket.clone(),
                        server_addr,
                        peers: vec![server_addr],
                        local_addr: SocketAddr::new(local_ip.parse().unwrap(), local_port),
                        call_id: call_id.clone(),
                        from_tag: from_tag.clone(),
                        cseq,
                        state: ProxyState::Registered,
                        auth_attempts: 0,
                        push_manager: Arc::new(PushManager::new_noop()),
                        handoff: handoff.clone(),
                    }));

                    // Register the active call with the RTP relay handle
                    let ended = handoff
                        .register_active_call(
                            call_token.clone(),
                            call_id.clone(),
                            CallOwner::User(owner_user_id.to_string()),
                            text.to_string(),
                            server_addr,
                            proxy_reg,
                            None,
                            sdp_offer.to_string(),
                            format!("sip:{username}@{local_ip}:{local_port};transport=udp"),
                        )
                        .await;

                    tracing::info!(call_id = %call_id, "Outgoing call connected");

                    Self::spawn_outgoing_call_loop(
                        socket.clone(),
                        server_addr,
                        handoff.clone(),
                        call_id.clone(),
                        ended,
                    );

                    return Ok((call_token, sdp_answer));
                }
                _ => {
                    // Every non-2xx final response is ACKed on the INVITE's
                    // own transaction (same branch).
                    let to_tag = message::extract_to_tag(text).unwrap_or_default();
                    let ack = Self::build_ack(
                        &target_uri,
                        &local_ip,
                        local_port,
                        &call_id,
                        cseq,
                        &from_tag,
                        &to_tag,
                        &invite_branch,
                    );
                    socket.send_to(ack.as_bytes(), server_addr).await?;

                    if cancelled {
                        tracing::info!(call_id = %call_id, status, "Outgoing call ended after CANCEL");
                        return Err(OriginateRefusal::Cancelled.into());
                    }
                    if status != 401 && status != 407 {
                        anyhow::bail!("Outgoing call rejected with status {}", status);
                    }

                    tracing::debug!(status, "Auth challenge for outgoing INVITE");
                    let (header_name, auth_header_name) = if status == 401 {
                        ("WWW-Authenticate", "Authorization")
                    } else {
                        ("Proxy-Authenticate", "Proxy-Authorization")
                    };
                    let www_auth = message::extract_header(text, header_name)
                        .ok_or_else(|| anyhow::anyhow!("No auth challenge header"))?;
                    let auth = DigestAuth::from_challenge(
                        &www_auth,
                        effective_auth_user,
                        password,
                        &target_uri,
                        "INVITE",
                    )
                    .ok_or_else(|| anyhow::anyhow!("Failed to parse auth challenge"))?;

                    // Re-send INVITE with auth on a new transaction; a later
                    // CANCEL must match this one.
                    cseq += 1;
                    invite_branch = message::generate_branch();
                    invite = Self::build_originate_invite(
                        &target_uri,
                        &local_ip,
                        local_port,
                        &call_id,
                        cseq,
                        &from_tag,
                        &invite_branch,
                        username,
                        domain,
                        display_name,
                        sdp_offer,
                        Some((auth_header_name, &auth.to_header())),
                    );
                    socket.send_to(invite.as_bytes(), server_addr).await?;
                    tracing::debug!("Re-sent INVITE with auth credentials");
                }
            }
        }
    }

    /// End a call whose 200 OK crossed our CANCEL: send `bye` and retransmit
    /// it (re-ACKing any retransmitted 200 OK) until the PBX answers it or
    /// about 4 seconds pass.
    async fn bye_cancelled_answer(
        socket: &UdpSocket,
        server_addr: SocketAddr,
        bye: &str,
        ack: &str,
    ) {
        let mut buf = vec![0u8; 65535];
        let give_up = tokio::time::Instant::now() + Duration::from_secs(4);
        let mut interval = Duration::from_millis(500);
        loop {
            if socket.send_to(bye.as_bytes(), server_addr).await.is_err() {
                return;
            }
            let retx_at = (tokio::time::Instant::now() + interval).min(give_up);
            loop {
                let wait = retx_at.saturating_duration_since(tokio::time::Instant::now());
                let Ok(Ok((len, from))) =
                    tokio::time::timeout(wait, socket.recv_from(&mut buf)).await
                else {
                    break;
                };
                if from != server_addr {
                    continue;
                }
                let Ok(text) = std::str::from_utf8(&buf[..len]) else {
                    continue;
                };
                match message::extract_cseq_method(text).as_deref() {
                    Some("BYE") if message::parse_status_code(text).is_some_and(|s| s >= 200) => {
                        return;
                    }
                    Some("INVITE")
                        if message::parse_status_code(text)
                            .is_some_and(|s| (200..300).contains(&s)) =>
                    {
                        let _ = socket.send_to(ack.as_bytes(), server_addr).await;
                    }
                    _ => {}
                }
            }
            if tokio::time::Instant::now() >= give_up {
                tracing::warn!("No response to BYE for a cancelled call");
                return;
            }
            interval = (interval * 2).min(Duration::from_secs(4));
        }
    }

    /// Receive loop for an outgoing call's dedicated socket: answers BYE and
    /// NOTIFY from the PBX and routes REFER responses.
    ///
    /// The loop exits as soon as the call stops being active (`ended`
    /// completes) — whether the app hung up, the PBX sent BYE or a transfer
    /// completed — so the task and its socket don't outlive the call.
    fn spawn_outgoing_call_loop(
        socket: Arc<UdpSocket>,
        peer: SocketAddr,
        handoff: Arc<HandoffManager>,
        call_id: String,
        mut ended: tokio::sync::oneshot::Receiver<()>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let received = tokio::select! {
                    biased;
                    _ = &mut ended => break,
                    r = socket.recv_from(&mut buf) => r,
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
                if from != peer {
                    tracing::warn!(call_id = %call_id, %from, "Dropping SIP message from an unexpected source");
                    continue;
                }

                if message::is_request(text) {
                    if let Err(e) =
                        Self::handle_request_on(&handoff, &socket, None, text, from).await
                    {
                        tracing::warn!(call_id = %call_id, "Error handling SIP request: {}", e);
                    }
                } else if message::extract_cseq_method(text).as_deref() == Some("REFER") {
                    handoff.handle_refer_response_on(text, &socket).await;
                }
                // Other responses (200 OK to our BYE, etc.) are ignored.
            }
            tracing::debug!(call_id = %call_id, "Outgoing call receive loop ended");
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn build_originate_invite(
        target_uri: &str,
        local_ip: &str,
        local_port: u16,
        call_id: &str,
        cseq: u32,
        from_tag: &str,
        branch: &str,
        username: &str,
        domain: &str,
        display_name: &str,
        sdp: &str,
        auth: Option<(&str, &str)>,
    ) -> String {
        let mut msg = format!(
            "INVITE {target_uri} SIP/2.0\r\n\
             Via: SIP/2.0/UDP {local_ip}:{local_port};branch={branch};rport\r\n\
             Max-Forwards: 70\r\n\
             From: \"{display_name}\" <sip:{username}@{domain}>;tag={from_tag}\r\n\
             To: <{target_uri}>\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: {cseq} INVITE\r\n\
             Contact: <sip:{username}@{local_ip}:{local_port};transport=udp>\r\n\
             Content-Type: application/sdp\r\n\
             Allow: INVITE, ACK, CANCEL, BYE, OPTIONS\r\n\
             User-Agent: Aria-Gateway/0.1.0\r\n"
        );

        if let Some((name, value)) = auth {
            msg.push_str(&format!("{}: {}\r\n", name, value));
        }

        msg.push_str(&format!("Content-Length: {}\r\n\r\n{}", sdp.len(), sdp));
        msg
    }

    #[allow(clippy::too_many_arguments)]
    fn build_ack(
        target_uri: &str,
        local_ip: &str,
        local_port: u16,
        call_id: &str,
        cseq: u32,
        from_tag: &str,
        to_tag: &str,
        branch: &str,
    ) -> String {
        format!(
            "ACK {target_uri} SIP/2.0\r\n\
             Via: SIP/2.0/UDP {local_ip}:{local_port};branch={branch};rport\r\n\
             Max-Forwards: 70\r\n\
             From: <sip:user@host>;tag={from_tag}\r\n\
             To: <{target_uri}>;tag={to_tag}\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: {cseq} ACK\r\n\
             Content-Length: 0\r\n\r\n"
        )
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
        let recv_loop = SipProxyManager::spawn_outgoing_call_loop(
            gw,
            pbx.local_addr().unwrap(),
            handoff.clone(),
            "out-call-1".into(),
            ended,
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
        assert!(recv_text(&call.pbx).await.starts_with("BYE "));
        loop_exits(call.recv_loop).await;
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

        for msg in [
            INBOUND_INVITE.to_string(),
            bye("out-call-1"),
            refer_notify("out-call-1"),
            options().to_string(),
        ] {
            SipProxyManager::handle_message(&r.reg, &msg, r.foreign_addr)
                .await
                .unwrap();
        }
        nothing_arrives(&r.foreign).await;
        nothing_arrives(&r.pbx).await;
        assert_eq!(r.handoff.pending_count().await, 0, "no call may be offered");
        assert!(r.handoff.is_call_active("out-call-1").await);

        // The same OPTIONS from the PBX is answered.
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
        let call = outgoing_call().await;
        let foreign = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        foreign
            .send_to(bye("out-call-1").as_bytes(), call.gw_addr)
            .await
            .unwrap();
        nothing_arrives(&foreign).await;
        assert!(call.handoff.is_call_active("out-call-1").await);
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
}
