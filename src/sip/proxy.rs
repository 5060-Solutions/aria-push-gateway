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
use crate::handoff::HandoffManager;
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
    pub(crate) local_addr: SocketAddr,
    call_id: String,
    from_tag: String,
    cseq: u32,
    state: ProxyState,
    auth_attempts: u32,
    push_manager: Arc<PushManager>,
    handoff: Arc<HandoffManager>,
}

#[derive(Debug, Clone, PartialEq)]
enum ProxyState {
    Registering,
    Registered,
    Error(String),
}

/// Manages all proxy registrations.
pub struct SipProxyManager {
    registrations: RwLock<HashMap<String, Arc<RwLock<ProxyRegistration>>>>,
    resolver: Arc<SrvResolver>,
}

impl SipProxyManager {
    pub fn new() -> Self {
        let resolver = SrvResolver::new().expect("Failed to create DNS resolver");
        Self {
            registrations: RwLock::new(HashMap::new()),
            resolver: Arc::new(resolver),
        }
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
        let resolved = self.resolver
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

                        if let Err(e) =
                            Self::handle_message(&reg_clone, &text, from).await
                        {
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

    async fn send_register(
        reg: &Arc<RwLock<ProxyRegistration>>,
    ) -> anyhow::Result<()> {
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

    async fn send_unregister(
        reg: &Arc<RwLock<ProxyRegistration>>,
    ) -> anyhow::Result<()> {
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
        let method = message::extract_method(text).unwrap_or_default();

        match method.as_str() {
            "INVITE" => {
                tracing::info!("Incoming INVITE for proxy device");

                // Send 100 Trying immediately
                if let Some(trying) = message::build_100_trying(text) {
                    let r = reg.read().await;
                    r.socket.send_to(trying.as_bytes(), from).await?;
                }

                // Extract caller info
                let (caller_user, caller_domain) =
                    message::extract_from_uri(text).unwrap_or(("unknown".into(), "unknown".into()));
                let caller_name = message::extract_display_name(text);
                let call_id = message::extract_header(text, "Call-ID").unwrap_or_default();

                let (device_id, push_mgr, handoff) = {
                    let r = reg.read().await;
                    (
                        r.device_id.clone(),
                        r.push_manager.clone(),
                        r.handoff.clone(),
                    )
                };

                // Create a handoff token for this INVITE
                let call_token = handoff
                    .create_pending_call(
                        device_id.clone(),
                        call_id,
                        text.to_string(),
                        from,
                        reg.clone(),
                    )
                    .await;

                tracing::info!(
                    device = %device_id,
                    caller = %format!("{}@{}", caller_user, caller_domain),
                    token = %call_token,
                    "Sending push notification for incoming call"
                );

                // Send push notification
                push_mgr
                    .send_incoming_call(
                        &device_id,
                        &call_token,
                        &format!("{}@{}", caller_user, caller_domain),
                        caller_name.as_deref(),
                    )
                    .await?;
            }
            "ACK" => {
                // ACK for an active call (after 200 OK)
                let call_id = message::extract_header(text, "Call-ID").unwrap_or_default();
                let handoff = {
                    let r = reg.read().await;
                    r.handoff.clone()
                };
                handoff.handle_ack(&call_id).await;
            }
            "BYE" => {
                // BYE from PBX — end the active call
                let call_id = message::extract_header(text, "Call-ID").unwrap_or_default();
                let handoff = {
                    let r = reg.read().await;
                    r.handoff.clone()
                };

                match handoff.handle_bye_from_pbx(&call_id, text, from).await {
                    Ok(Some(device_id)) => {
                        tracing::info!(
                            device = %device_id,
                            call_id = %call_id,
                            "Call ended by PBX"
                        );
                        // Could send a push notification here to notify the app
                    }
                    Ok(None) => {
                        tracing::debug!(call_id = %call_id, "BYE for unknown call — ignoring");
                    }
                    Err(e) => {
                        tracing::error!(call_id = %call_id, "Error handling BYE: {}", e);
                    }
                }
            }
            "CANCEL" => {
                // CANCEL from PBX — caller hung up before answer
                let call_id = message::extract_header(text, "Call-ID").unwrap_or_default();
                tracing::info!(call_id = %call_id, "CANCEL received — caller hung up");

                // Respond with 200 OK to the CANCEL
                let r = reg.read().await;
                let response = format!(
                    "SIP/2.0 200 OK\r\n\
                     {}\
                     Content-Length: 0\r\n\r\n",
                    Self::echo_headers(text),
                );
                r.socket.send_to(response.as_bytes(), from).await?;

                // Send 487 Request Terminated for the original INVITE
                let via = message::extract_header(text, "Via").unwrap_or_default();
                let cancel_from = message::extract_header(text, "From").unwrap_or_default();
                let cancel_to = message::extract_header(text, "To").unwrap_or_default();
                let cseq_val = message::extract_header(text, "CSeq")
                    .unwrap_or_default()
                    .replace("CANCEL", "INVITE");

                let terminated = format!(
                    "SIP/2.0 487 Request Terminated\r\n\
                     Via: {via}\r\n\
                     From: {cancel_from}\r\n\
                     To: {cancel_to}\r\n\
                     Call-ID: {call_id}\r\n\
                     CSeq: {cseq_val}\r\n\
                     Content-Length: 0\r\n\r\n"
                );
                r.socket.send_to(terminated.as_bytes(), from).await?;
            }
            "OPTIONS" => {
                // Respond to keepalive OPTIONS
                let r = reg.read().await;
                let response = format!(
                    "SIP/2.0 200 OK\r\n\
                     {}\
                     Content-Length: 0\r\n\r\n",
                    Self::echo_headers(text),
                );
                r.socket.send_to(response.as_bytes(), from).await?;
            }
            _ => {
                tracing::debug!("Ignoring {} request", method);
            }
        }

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

                socket
                    .send_to(auth_header.as_bytes(), server_addr)
                    .await?;
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
    /// client's SDP offer, handles auth challenges, and waits for a 200 OK.
    /// Returns (call_token, sdp_answer).
    #[allow(clippy::too_many_arguments)]
    pub async fn originate_call(
        &self,
        destination_uri: &str,
        sdp_offer: &str,
        username: &str,
        password: &str,
        domain: &str,
        registrar: Option<&str>,
        transport: &str,
        port: u16,
        auth_username: Option<&str>,
        display_name: &str,
        handoff: Arc<HandoffManager>,
    ) -> anyhow::Result<(String, String)> {
        let effective_registrar = registrar.unwrap_or(domain);
        let effective_auth_user = auth_username.unwrap_or(username);

        // Resolve target via SRV lookup (with A record fallback)
        let resolved = self.resolver
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

        // Build INVITE
        let invite = Self::build_originate_invite(
            &target_uri, &local_ip, local_port, &call_id, 1, &from_tag, &branch,
            username, domain, display_name, sdp_offer, None,
        );

        socket.send_to(invite.as_bytes(), server_addr).await?;
        tracing::info!(uri = %target_uri, "Sent outgoing INVITE");

        // Wait for final response (up to 30s)
        let mut buf = vec![0u8; 65535];
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut cseq: u32 = 1;

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                anyhow::bail!("Outgoing call timed out");
            }

            let len = tokio::time::timeout(remaining, socket.recv(&mut buf))
                .await
                .map_err(|_| anyhow::anyhow!("Outgoing call timed out"))??;

            let text = std::str::from_utf8(&buf[..len])?;
            let status = match message::parse_status_code(text) {
                Some(s) => s,
                None => continue,
            };

            match status {
                100 | 180 | 183 => {
                    tracing::debug!(status, "Provisional response for outgoing call");
                    continue;
                }
                200 => {
                    // Extract SDP from 200 OK
                    let sdp_answer = text
                        .split("\r\n\r\n")
                        .nth(1)
                        .unwrap_or("")
                        .to_string();

                    // Send ACK
                    let to_tag = message::extract_to_tag(text).unwrap_or_default();
                    let ack = Self::build_ack(
                        &target_uri, &local_ip, local_port, &call_id, cseq,
                        &from_tag, &to_tag, &branch,
                    );
                    socket.send_to(ack.as_bytes(), server_addr).await?;

                    // Create a call token for hangup tracking
                    // We reuse the handoff manager with a stub pending call structure
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
                        local_addr: SocketAddr::new(local_ip.parse().unwrap(), local_port),
                        call_id: call_id.clone(),
                        from_tag: from_tag.clone(),
                        cseq,
                        state: ProxyState::Registered,
                        auth_attempts: 0,
                        push_manager: Arc::new(PushManager::new_noop()),
                        handoff: handoff.clone(),
                    }));

                    // Register the active call in the handoff manager via accept flow
                    // We directly create the active call entry
                    handoff.register_active_call(
                        call_token.clone(),
                        call_id.clone(),
                        format!("outgoing-{}", &call_token[..8]),
                        text.to_string(),
                        server_addr,
                        proxy_reg,
                    ).await;

                    tracing::info!(call_id = %call_id, "Outgoing call connected");
                    return Ok((call_token, sdp_answer));
                }
                401 | 407 => {
                    tracing::debug!(status, "Auth challenge for outgoing INVITE");

                    let header_name = if status == 401 {
                        "WWW-Authenticate"
                    } else {
                        "Proxy-Authenticate"
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

                    // Send ACK for the 401/407
                    let to_tag = message::extract_to_tag(text).unwrap_or_default();
                    let ack = Self::build_ack(
                        &target_uri, &local_ip, local_port, &call_id, cseq,
                        &from_tag, &to_tag, &branch,
                    );
                    socket.send_to(ack.as_bytes(), server_addr).await?;

                    // Re-send INVITE with auth
                    cseq += 1;
                    let new_branch = message::generate_branch();
                    let auth_header_name = if status == 401 {
                        "Authorization"
                    } else {
                        "Proxy-Authorization"
                    };

                    let invite = Self::build_originate_invite(
                        &target_uri, &local_ip, local_port, &call_id, cseq,
                        &from_tag, &new_branch, username, domain, display_name,
                        sdp_offer,
                        Some((auth_header_name, &auth.to_header())),
                    );
                    socket.send_to(invite.as_bytes(), server_addr).await?;
                    tracing::debug!("Re-sent INVITE with auth credentials");
                }
                _ if status >= 400 => {
                    anyhow::bail!("Outgoing call rejected with status {}", status);
                }
                _ => continue,
            }
        }
    }

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

    /// Echo Via/From/To/Call-ID/CSeq headers for simple responses.
    fn echo_headers(msg: &str) -> String {
        let mut out = String::new();
        for name in ["Via", "From", "To", "Call-ID", "CSeq"] {
            if let Some(val) = message::extract_header(msg, name) {
                out.push_str(&format!("{}: {}\r\n", name, val));
            }
        }
        out
    }
}
