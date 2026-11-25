//! SIP transports toward the PBX: UDP, and TCP or TLS flows (RFC 5626).
//!
//! [`SipSocket`] is what the rest of the gateway sends and receives SIP on.
//! A UDP socket is used as it always was. A stream socket wraps a [`Flow`]:
//! one TCP or TLS connection at a time to the registrar the registration is
//! on. The flow can be reconnected (after a failure, or to another target
//! after a failover) without the socket changing, so dialogs and server
//! transactions keyed by the socket keep matching.
//!
//! On a flow:
//! - messages are framed by `Content-Length` (RFC 3261 §18.3);
//! - an RFC 5626 §4.4.1 double-CRLF ping is sent every keep-alive interval
//!   (80-100 % of the registrar's `Flow-Timer`, else [`DEFAULT_KEEPALIVE`]),
//!   and a missing single-CRLF pong within [`PONG_TIMEOUT`] fails the flow;
//! - an EOF, read or write error, or missed pong is a flow failure, reported
//!   through [`Flow::failures`] so the registration re-registers at once;
//! - TLS certificates are always verified against the web PKI (plus an
//!   optional extra CA), never skipped, and a TLS registration never
//!   falls back to an unencrypted transport.
//!
//! Requests the gateway writes are built with a UDP `Via`; on a stream the
//! top `Via` sent-protocol and a `transport=udp` Contact parameter are
//! rewritten to the flow's transport as the message is written, the way a
//! transport layer fills in its own Via.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch};

/// How long a TCP connect plus TLS handshake to one target may take before
/// the target counts as down.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(4);
/// Keep-alive interval when the registrar gives no `Flow-Timer` (the PBX
/// closes idle stream connections after 30 s).
pub const DEFAULT_KEEPALIVE: Duration = Duration::from_secs(25);
/// RFC 5626 §4.4.1: a pong not received within 10 s means the flow failed.
pub const PONG_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest SIP message assembled from a stream.
pub const MAX_SIP_MESSAGE: usize = 128 * 1024;

/// A SIP transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    Udp,
    Tcp,
    Tls,
}

impl Transport {
    /// From a configured transport name; unknown names are `None`.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "udp" => Some(Self::Udp),
            "tcp" => Some(Self::Tcp),
            "tls" => Some(Self::Tls),
            _ => None,
        }
    }

    /// The `transport=` URI parameter value.
    pub fn param(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Tls => "tls",
        }
    }

    /// The Via sent-protocol transport.
    pub fn via(self) -> &'static str {
        match self {
            Self::Udp => "UDP",
            Self::Tcp => "TCP",
            Self::Tls => "TLS",
        }
    }

    /// Reliable transports have no SIP retransmission timers (RFC 3261 §17).
    pub fn is_reliable(self) -> bool {
        !matches!(self, Self::Udp)
    }
}

/// How often to ping a flow (RFC 5626 §4.4.1): between 80 and 100 % of the
/// registrar's `Flow-Timer` (`jitter` in `[0, 1)` picks where), else
/// [`DEFAULT_KEEPALIVE`].
pub fn keepalive_interval(flow_timer_secs: Option<u64>, jitter: f64) -> Duration {
    match flow_timer_secs.filter(|t| *t > 0) {
        None => DEFAULT_KEEPALIVE,
        Some(t) => Duration::from_secs(t)
            .mul_f64(1.0 - 0.2 * jitter.clamp(0.0, 1.0))
            .max(Duration::from_secs(1)),
    }
}

/// TLS client settings: the web PKI roots plus, optionally, an operator CA
/// (`SIP_TLS_CA_FILE`, a PEM bundle) for a PBX with a private certificate.
#[derive(Clone)]
pub struct TlsClient {
    connector: tokio_rustls::TlsConnector,
}

impl std::fmt::Debug for TlsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TlsClient")
    }
}

impl TlsClient {
    /// Roots: webpki-roots, plus the certificates in `extra_ca_pem`.
    pub fn new(extra_ca_pem: Option<&[u8]>) -> anyhow::Result<Self> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(pem) = extra_ca_pem {
            Self::add_pem(&mut roots, pem)?;
        }
        Self::with_roots(roots)
    }

    /// Only the certificates in `ca_pem` are trusted (tests).
    #[cfg(test)]
    pub fn trusting_only(ca_pem: &[u8]) -> anyhow::Result<Self> {
        let mut roots = rustls::RootCertStore::empty();
        Self::add_pem(&mut roots, ca_pem)?;
        Self::with_roots(roots)
    }

    /// From the environment: `SIP_TLS_CA_FILE` adds a CA bundle.
    pub fn from_env() -> anyhow::Result<Self> {
        match std::env::var("SIP_TLS_CA_FILE")
            .ok()
            .filter(|p| !p.trim().is_empty())
        {
            Some(path) => {
                let pem = std::fs::read(&path)
                    .map_err(|e| anyhow::anyhow!("SIP_TLS_CA_FILE {path}: {e}"))?;
                Self::new(Some(&pem))
            }
            None => Self::new(None),
        }
    }

    fn add_pem(roots: &mut rustls::RootCertStore, pem: &[u8]) -> anyhow::Result<()> {
        use rustls_pki_types::pem::PemObject;
        let mut added = 0;
        for cert in rustls_pki_types::CertificateDer::pem_slice_iter(pem) {
            roots.add(cert?)?;
            added += 1;
        }
        anyhow::ensure!(added > 0, "no certificate in the CA bundle");
        Ok(())
    }

    fn with_roots(roots: rustls::RootCertStore) -> anyhow::Result<Self> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self {
            connector: tokio_rustls::TlsConnector::from(Arc::new(config)),
        })
    }
}

/// The name a TLS target's certificate is checked against.
///
/// The SRV target's own host name when it is the SIP domain or a name under
/// it (`node1.sip.ariaroute.com` for `sip.ariaroute.com`): each node then
/// proves it is that node. A target outside the domain is checked against
/// the domain itself (RFC 5922 §4.1), since an SRV answer is not
/// authenticated and must not be able to name a host with merely *some*
/// valid certificate.
pub fn tls_server_name(domain: &str, target_host: &str) -> String {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    let host = target_host.trim_end_matches('.').to_ascii_lowercase();
    if host == domain || host.ends_with(&format!(".{domain}")) {
        host
    } else {
        domain
    }
}

/// What a SIP socket carries.
pub struct SipSocket {
    kind: Kind,
}

enum Kind {
    Udp(UdpSocket),
    Stream(Arc<Flow>),
}

impl From<UdpSocket> for SipSocket {
    fn from(s: UdpSocket) -> Self {
        Self { kind: Kind::Udp(s) }
    }
}

impl SipSocket {
    /// A stream socket over `flow` (not yet connected).
    pub fn stream(flow: Arc<Flow>) -> Self {
        Self {
            kind: Kind::Stream(flow),
        }
    }

    pub fn transport(&self) -> Transport {
        match &self.kind {
            Kind::Udp(_) => Transport::Udp,
            Kind::Stream(f) => f.transport,
        }
    }

    /// No retransmission timers on a reliable transport.
    pub fn is_reliable(&self) -> bool {
        self.transport().is_reliable()
    }

    /// The flow behind a stream socket.
    pub fn flow(&self) -> Option<&Arc<Flow>> {
        match &self.kind {
            Kind::Udp(_) => None,
            Kind::Stream(f) => Some(f),
        }
    }

    /// The local address; for a stream, the current connection's.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match &self.kind {
            Kind::Udp(s) => s.local_addr(),
            Kind::Stream(f) => f
                .local_addr()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "flow not connected")),
        }
    }

    /// Send `buf` to `dest`. On a stream `dest` must be the connected peer.
    pub async fn send_to(&self, buf: &[u8], dest: SocketAddr) -> io::Result<usize> {
        match &self.kind {
            Kind::Udp(s) => s.send_to(buf, dest).await,
            Kind::Stream(f) => f.send(buf, dest),
        }
    }

    /// Non-blocking [`Self::send_to`].
    pub fn try_send_to(&self, buf: &[u8], dest: SocketAddr) -> io::Result<usize> {
        match &self.kind {
            Kind::Udp(s) => s.try_send_to(buf, dest),
            Kind::Stream(f) => f.send(buf, dest),
        }
    }

    /// The next datagram or framed message and who sent it. A stream socket
    /// waits across reconnections; it errors only when the flow is shut.
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match &self.kind {
            Kind::Udp(s) => s.recv_from(buf).await,
            Kind::Stream(f) => {
                let (msg, from) = f.recv().await?;
                let n = msg.len().min(buf.len());
                buf[..n].copy_from_slice(&msg[..n]);
                Ok((n, from))
            }
        }
    }
}

trait Io: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Io for T {}

/// One live connection of a flow.
struct Conn {
    generation: u64,
    peer: SocketAddr,
    local: SocketAddr,
    tx: mpsc::UnboundedSender<Bytes>,
    tasks: Vec<tokio::task::AbortHandle>,
}

impl Drop for Conn {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

/// A TCP/TLS flow to the registrar: one connection at a time, replaced on
/// reconnect, with a stable inbound queue.
pub struct Flow {
    transport: Transport,
    tls: Option<TlsClient>,
    conn: Mutex<Option<Conn>>,
    next_generation: AtomicU64,
    inbound_tx: mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>,
    inbound_rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>>,
    /// Bumped on every failure of the current connection.
    failures: watch::Sender<u64>,
    /// Keep-alive interval in ms (0: no keep-alive).
    keepalive_ms: AtomicU64,
    /// How long a ping may wait for its pong, in ms.
    pong_timeout_ms: AtomicU64,
    /// The interval was fixed by a test; `Flow-Timer` does not change it.
    #[cfg(test)]
    keepalive_pinned: std::sync::atomic::AtomicBool,
    /// Pongs seen, so a ping knows whether it was answered.
    pongs: watch::Sender<u64>,
    shut: watch::Sender<bool>,
}

impl Flow {
    /// A flow over `transport` (TCP or TLS; TLS needs `tls`).
    pub fn new(transport: Transport, tls: Option<TlsClient>) -> Arc<Self> {
        assert!(transport.is_reliable(), "a flow is TCP or TLS");
        assert!(
            transport != Transport::Tls || tls.is_some(),
            "a TLS flow needs a TLS client"
        );
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        Arc::new(Self {
            transport,
            tls,
            conn: Mutex::new(None),
            next_generation: AtomicU64::new(1),
            inbound_tx,
            inbound_rx: tokio::sync::Mutex::new(inbound_rx),
            failures: watch::channel(0).0,
            keepalive_ms: AtomicU64::new(DEFAULT_KEEPALIVE.as_millis() as u64),
            pong_timeout_ms: AtomicU64::new(PONG_TIMEOUT.as_millis() as u64),
            #[cfg(test)]
            keepalive_pinned: std::sync::atomic::AtomicBool::new(false),
            pongs: watch::channel(0).0,
            shut: watch::channel(false).0,
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Conn>> {
        self.conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The connected peer, if any.
    pub fn peer(&self) -> Option<SocketAddr> {
        self.lock().as_ref().map(|c| c.peer)
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.lock().as_ref().map(|c| c.local)
    }

    /// Changes whenever the current connection fails.
    pub fn failures(&self) -> watch::Receiver<u64> {
        self.failures.subscribe()
    }

    /// Set the keep-alive interval (`Duration::ZERO` turns it off). Takes
    /// effect from the next ping.
    pub fn set_keepalive(&self, every: Duration) {
        #[cfg(test)]
        if self.keepalive_pinned.load(Ordering::Relaxed) {
            return;
        }
        self.keepalive_ms
            .store(every.as_millis() as u64, Ordering::Relaxed);
    }

    /// Fix the keep-alive interval (tests).
    #[cfg(test)]
    pub fn pin_keepalive(&self, every: Duration) {
        self.set_keepalive(every);
        self.keepalive_pinned.store(true, Ordering::Relaxed);
    }

    /// Shorten the pong timeout (tests).
    #[cfg(test)]
    pub fn set_pong_timeout(&self, d: Duration) {
        self.pong_timeout_ms
            .store(d.as_millis() as u64, Ordering::Relaxed);
    }

    pub fn keepalive(&self) -> Duration {
        Duration::from_millis(self.keepalive_ms.load(Ordering::Relaxed))
    }

    /// Close the flow for good: the receive side ends.
    pub fn shutdown(&self) {
        self.lock().take();
        self.shut.send_replace(true);
    }

    /// Make sure the flow is connected to `peer` (the TLS certificate
    /// checked against `server_name`). A connection to another peer is
    /// closed first. Fails when the connect or handshake fails or times out.
    pub async fn ensure(self: &Arc<Self>, peer: SocketAddr, server_name: &str) -> io::Result<()> {
        if self.peer() == Some(peer) {
            return Ok(());
        }
        self.lock().take();
        let (io, local) = self.open(peer, server_name).await?;
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::unbounded_channel::<Bytes>();
        let (read, write) = tokio::io::split(io);
        let reader = tokio::spawn(Self::read_loop(
            Arc::downgrade(self),
            read,
            peer,
            generation,
        ));
        let writer = tokio::spawn(Self::write_loop(
            Arc::downgrade(self),
            write,
            rx,
            generation,
        ));
        let pinger = tokio::spawn(Self::keepalive_loop(Arc::downgrade(self), generation));
        *self.lock() = Some(Conn {
            generation,
            peer,
            local,
            tx,
            tasks: vec![
                reader.abort_handle(),
                writer.abort_handle(),
                pinger.abort_handle(),
            ],
        });
        tracing::info!(transport = ?self.transport, %peer, %local, "SIP flow connected");
        Ok(())
    }

    async fn open(
        &self,
        peer: SocketAddr,
        server_name: &str,
    ) -> io::Result<(Box<dyn Io>, SocketAddr)> {
        let attempt = async {
            let tcp = TcpStream::connect(peer).await?;
            let _ = tcp.set_nodelay(true);
            let local = tcp.local_addr()?;
            let io: Box<dyn Io> = match self.transport {
                Transport::Tls => {
                    let tls = self.tls.as_ref().expect("checked in new");
                    let name = rustls_pki_types::ServerName::try_from(server_name.to_string())
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
                    Box::new(tls.connector.connect(name, tcp).await?)
                }
                _ => Box::new(tcp),
            };
            Ok::<_, io::Error>((io, local))
        };
        match tokio::time::timeout(CONNECT_TIMEOUT, attempt).await {
            Ok(r) => r.inspect_err(|e| {
                tracing::warn!(transport = ?self.transport, %peer, %server_name, "SIP flow connect failed: {e}")
            }),
            Err(_) => {
                tracing::warn!(transport = ?self.transport, %peer, "SIP flow connect timed out");
                Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))
            }
        }
    }

    /// Report a failure of connection `generation` (once: a later failure
    /// report of a connection already replaced is ignored).
    fn fail(&self, generation: u64, why: &str) {
        let mut conn = self.lock();
        if conn.as_ref().is_some_and(|c| c.generation == generation) {
            let peer = conn.as_ref().map(|c| c.peer);
            // Taking it drops the Conn, which aborts its tasks; this may be
            // running in one of them, so release the lock first.
            let old = conn.take();
            drop(conn);
            tracing::warn!(transport = ?self.transport, ?peer, "SIP flow failed: {why}");
            self.failures.send_modify(|n| *n += 1);
            drop(old);
        }
    }

    fn send(&self, buf: &[u8], dest: SocketAddr) -> io::Result<usize> {
        let conn = self.lock();
        let Some(c) = conn.as_ref() else {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "flow not connected",
            ));
        };
        if c.peer != dest {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                format!("flow is connected to {}, not {dest}", c.peer),
            ));
        }
        let wire = rewrite_for_transport(buf, self.transport);
        let n = buf.len();
        c.tx.send(wire)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "flow writer gone"))?;
        Ok(n)
    }

    async fn recv(&self) -> io::Result<(Vec<u8>, SocketAddr)> {
        let mut shut = self.shut.subscribe();
        let mut rx = self.inbound_rx.lock().await;
        tokio::select! {
            m = rx.recv() => m.ok_or_else(|| io::Error::new(io::ErrorKind::ConnectionAborted, "flow closed")),
            _ = shut.wait_for(|s| *s) => Err(io::Error::new(io::ErrorKind::ConnectionAborted, "flow shut down")),
        }
    }

    async fn read_loop(
        flow: std::sync::Weak<Self>,
        mut read: tokio::io::ReadHalf<Box<dyn Io>>,
        peer: SocketAddr,
        generation: u64,
    ) {
        let mut pending: Vec<u8> = Vec::new();
        let mut chunk = vec![0u8; 16 * 1024];
        let why = loop {
            let n = match read.read(&mut chunk).await {
                Ok(0) => break "closed by peer".to_string(),
                Ok(n) => n,
                Err(e) => break format!("read error: {e}"),
            };
            pending.extend_from_slice(&chunk[..n]);
            let Some(f) = flow.upgrade() else { return };
            match frame(&mut pending) {
                Ok(frames) => {
                    for fr in frames {
                        match fr {
                            Frame::Pong => {
                                f.pongs.send_modify(|n| *n += 1);
                            }
                            Frame::Message(m) => {
                                let _ = f.inbound_tx.send((m, peer));
                            }
                        }
                    }
                }
                Err(e) => break e.to_string(),
            }
        };
        if let Some(f) = flow.upgrade() {
            f.fail(generation, &why);
        }
    }

    async fn write_loop(
        flow: std::sync::Weak<Self>,
        mut write: tokio::io::WriteHalf<Box<dyn Io>>,
        mut rx: mpsc::UnboundedReceiver<Bytes>,
        generation: u64,
    ) {
        while let Some(buf) = rx.recv().await {
            let r = async {
                write.write_all(&buf).await?;
                write.flush().await
            };
            if let Err(e) = r.await {
                if let Some(f) = flow.upgrade() {
                    f.fail(generation, &format!("write error: {e}"));
                }
                return;
            }
        }
    }

    /// RFC 5626 §4.4.1 CRLF keep-alive: ping, and fail the flow when no
    /// pong comes back within [`PONG_TIMEOUT`].
    async fn keepalive_loop(flow: std::sync::Weak<Self>, generation: u64) {
        loop {
            let every = match flow.upgrade() {
                Some(f) => f.keepalive(),
                None => return,
            };
            if every.is_zero() {
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
            tokio::time::sleep(every).await;
            let Some(f) = flow.upgrade() else { return };
            let mut pongs = f.pongs.subscribe();
            pongs.mark_unchanged();
            let sent = {
                let conn = f.lock();
                match conn.as_ref() {
                    Some(c) if c.generation == generation => {
                        c.tx.send(Bytes::from_static(b"\r\n\r\n")).is_ok()
                    }
                    _ => return,
                }
            };
            if !sent {
                return;
            }
            let pong_timeout = Duration::from_millis(f.pong_timeout_ms.load(Ordering::Relaxed));
            drop(f);
            let answered = tokio::time::timeout(pong_timeout, pongs.changed()).await;
            if !matches!(answered, Ok(Ok(()))) {
                if let Some(f) = flow.upgrade() {
                    f.fail(generation, "keep-alive pong not received");
                }
                return;
            }
        }
    }
}

/// Send a one-off OPTIONS probe to `peer` on a fresh connection and wait for
/// any final response. Used for failback probes of a target the flow is not
/// connected to.
pub async fn probe(
    transport: Transport,
    tls: Option<TlsClient>,
    peer: SocketAddr,
    server_name: &str,
    options: &str,
    timeout: Duration,
) -> bool {
    let flow = Flow::new(transport, tls);
    flow.set_keepalive(Duration::ZERO);
    let r = tokio::time::timeout(timeout, async {
        flow.ensure(peer, server_name).await.ok()?;
        flow.send(options.as_bytes(), peer).ok()?;
        loop {
            let (msg, _) = flow.recv().await.ok()?;
            let text = String::from_utf8_lossy(&msg);
            if super::message::parse_status_code(&text).is_some_and(|c| c >= 200) {
                return Some(());
            }
        }
    })
    .await;
    flow.shutdown();
    matches!(r, Ok(Some(())))
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Frame {
    Pong,
    Message(Vec<u8>),
}

/// Take complete messages (and keep-alive pongs) off the front of `buf`.
pub(crate) fn frame(buf: &mut Vec<u8>) -> Result<Vec<Frame>, &'static str> {
    let mut out = Vec::new();
    let mut at = 0;
    loop {
        // A lone CRLF between messages is a pong (or a ping's half); a
        // double CRLF is the server's own ping, which needs no answer from a
        // client. Either way it is not part of a message.
        while buf[at..].starts_with(b"\r\n") {
            if buf[at..].starts_with(b"\r\n\r\n") {
                at += 4;
            } else {
                at += 2;
                out.push(Frame::Pong);
            }
        }
        let rest = &buf[at..];
        if rest.is_empty() || rest == b"\r" {
            break;
        }
        let Some(sep) = rest.windows(4).position(|w| w == b"\r\n\r\n") else {
            if rest.len() > MAX_SIP_MESSAGE {
                return Err("SIP header block too large");
            }
            break;
        };
        let headers = std::str::from_utf8(&rest[..sep]).map_err(|_| "non-UTF-8 SIP headers")?;
        let len = content_length(headers)?;
        let total = (sep + 4)
            .checked_add(len)
            .filter(|t| *t <= MAX_SIP_MESSAGE)
            .ok_or("SIP message too large")?;
        if rest.len() < total {
            break;
        }
        out.push(Frame::Message(rest[..total].to_vec()));
        at += total;
    }
    buf.drain(..at);
    Ok(out)
}

/// `Content-Length` (or `l`); required on a stream, and duplicates must agree.
fn content_length(headers: &str) -> Result<usize, &'static str> {
    let mut found = None;
    for line in headers.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name.eq_ignore_ascii_case("content-length") || name.eq_ignore_ascii_case("l") {
            let n: usize = value.trim().parse().map_err(|_| "bad Content-Length")?;
            if found.is_some_and(|f| f != n) {
                return Err("conflicting Content-Length");
            }
            found = Some(n);
        }
    }
    found.ok_or("missing Content-Length on a stream")
}

/// A request's top Via and Contact name the transport it is sent on.
fn rewrite_for_transport(buf: &[u8], transport: Transport) -> Bytes {
    let Ok(text) = std::str::from_utf8(buf) else {
        return Bytes::copy_from_slice(buf);
    };
    if text.starts_with("SIP/2.0") {
        // A response keeps the Vias of the request it answers.
        return Bytes::copy_from_slice(buf);
    }
    let Some(head_end) = text.find("\r\n\r\n") else {
        return Bytes::copy_from_slice(buf);
    };
    let (head, body) = text.split_at(head_end);
    let mut out = String::with_capacity(text.len() + 8);
    let mut via_done = false;
    for (i, line) in head.split("\r\n").enumerate() {
        if i > 0 {
            out.push_str("\r\n");
        }
        let lower = line.to_ascii_lowercase();
        if !via_done && (lower.starts_with("via:") || lower.starts_with("v:")) {
            via_done = true;
            out.push_str(&line.replacen("SIP/2.0/UDP", &format!("SIP/2.0/{}", transport.via()), 1));
        } else if lower.starts_with("contact:") || lower.starts_with("m:") {
            out.push_str(&line.replace(
                ";transport=udp",
                &format!(";transport={}", transport.param()),
            ));
        } else {
            out.push_str(line);
        }
    }
    out.push_str(body);
    Bytes::from(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keepalives_run_at_80_to_100_percent_of_the_flow_timer() {
        assert_eq!(keepalive_interval(None, 0.5), DEFAULT_KEEPALIVE);
        assert_eq!(keepalive_interval(Some(0), 0.5), DEFAULT_KEEPALIVE);
        assert_eq!(keepalive_interval(Some(120), 0.0), Duration::from_secs(120));
        assert_eq!(keepalive_interval(Some(120), 1.0), Duration::from_secs(96));
        let mid = keepalive_interval(Some(120), 0.5);
        assert!(mid > Duration::from_secs(96) && mid < Duration::from_secs(120));
    }

    #[test]
    fn frames_messages_pongs_and_partial_input() {
        let msg = b"SIP/2.0 200 OK\r\nContent-Length: 4\r\n\r\nbody";
        let mut buf = Vec::new();
        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(msg);
        buf.extend_from_slice(b"\r\n\r\nOPTIONS sip:x SIP/2.0\r\nContent-Le");
        let out = frame(&mut buf).unwrap();
        assert_eq!(out, vec![Frame::Pong, Frame::Message(msg.to_vec())]);
        assert!(buf.starts_with(b"OPTIONS"), "partial message kept");
        buf.extend_from_slice(b"ngth: 0\r\n\r\n");
        let out = frame(&mut buf).unwrap();
        assert_eq!(out.len(), 1);
        assert!(buf.is_empty());
    }

    #[test]
    fn a_stream_message_needs_a_consistent_content_length() {
        let mut buf = b"BYE sip:x SIP/2.0\r\nCall-ID: a\r\n\r\n".to_vec();
        assert!(frame(&mut buf).is_err());
        let mut buf = b"BYE sip:x SIP/2.0\r\nContent-Length: 1\r\nl: 2\r\n\r\nab".to_vec();
        assert!(frame(&mut buf).is_err());
        let mut buf = b"BYE sip:x SIP/2.0\r\nContent-Length: 999999999\r\n\r\n".to_vec();
        assert!(frame(&mut buf).is_err());
    }

    #[test]
    fn requests_name_the_stream_transport_responses_are_untouched() {
        let req = "REGISTER sip:pbx SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1:5000;branch=z9hG4bK-1\r\nContact: <sip:1001@10.0.0.1:5000;transport=udp>;reg-id=1\r\nContent-Length: 0\r\n\r\n";
        let out = rewrite_for_transport(req.as_bytes(), Transport::Tls);
        let out = std::str::from_utf8(&out).unwrap();
        assert!(out.contains("Via: SIP/2.0/TLS 10.0.0.1:5000"));
        assert!(out.contains(";transport=tls>"));
        assert!(out.ends_with("\r\n\r\n"));
        let resp = "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP x\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(
            &rewrite_for_transport(resp.as_bytes(), Transport::Tcp)[..],
            resp.as_bytes()
        );
    }

    #[test]
    fn tls_names_follow_the_srv_target_only_inside_the_domain() {
        assert_eq!(
            tls_server_name("sip.ariaroute.com", "node1.sip.ariaroute.com."),
            "node1.sip.ariaroute.com"
        );
        assert_eq!(
            tls_server_name("sip.ariaroute.com", "sip.ariaroute.com"),
            "sip.ariaroute.com"
        );
        assert_eq!(
            tls_server_name("sip.ariaroute.com", "evil.example.com"),
            "sip.ariaroute.com"
        );
        assert_eq!(
            tls_server_name("sip.ariaroute.com", "xsip.ariaroute.com"),
            "sip.ariaroute.com"
        );
    }
}
