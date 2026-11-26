//! Registration failover against fake PBX nodes on loopback: TCP and TLS
//! (with a private test CA), nodes that die and come back, keep-alives that
//! go unanswered, and an incoming INVITE delivered by the second node.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;

use super::message;
use super::proxy::{SipAccountConfig, SipProxyManager, TestTiming};
use super::resolver::{SrvRecord, SrvResolver, StaticDns};
use super::transport::{frame, Frame, TlsClient};
use crate::handoff::HandoffManager;
use crate::push::mock::MockFcm;
use crate::push::PushManager;

/// A private CA and certificates it issues.
struct TestCa {
    issuer: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
}

impl TestCa {
    fn new(name: &str) -> Self {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        let key = rcgen::KeyPair::generate().unwrap();
        Self {
            issuer: rcgen::CertifiedIssuer::self_signed(params, key).unwrap(),
        }
    }

    fn pem(&self) -> String {
        self.issuer.pem()
    }

    /// A TLS acceptor presenting a certificate for `names`.
    fn acceptor(&self, names: &[&str]) -> tokio_rustls::TlsAcceptor {
        let params =
            rcgen::CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
                .unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &self.issuer).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone(), self.issuer.der().clone()],
                rustls_pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
            )
            .unwrap();
        tokio_rustls::TlsAcceptor::from(Arc::new(config))
    }
}

#[derive(Default)]
struct NodeState {
    connections: AtomicUsize,
    registers: AtomicUsize,
    pings: AtomicUsize,
    /// Connections numbered up to this stop reading and answering (new
    /// ones are fine); 0 for none.
    stalled_upto: AtomicUsize,
    /// Writers of open connections, newest last.
    writers: Mutex<Vec<mpsc::UnboundedSender<Vec<u8>>>>,
    /// Where the last binding came from.
    bound: Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>,
    tasks: Mutex<Vec<tokio::task::AbortHandle>>,
}

/// A PBX node: answers REGISTER and OPTIONS with 200, CRLF pings with a
/// pong, and hands everything else to the test.
struct Node {
    port: u16,
    tls: Option<tokio_rustls::TlsAcceptor>,
    state: Arc<NodeState>,
    seen_tx: mpsc::UnboundedSender<String>,
    seen: tokio::sync::Mutex<mpsc::UnboundedReceiver<String>>,
}

impl Node {
    async fn start(tls: Option<tokio_rustls::TlsAcceptor>) -> Arc<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (seen_tx, seen) = mpsc::unbounded_channel();
        let node = Arc::new(Self {
            port,
            tls,
            state: Arc::default(),
            seen_tx,
            seen: tokio::sync::Mutex::new(seen),
        });
        node.serve(listener);
        node
    }

    fn serve(self: &Arc<Self>, listener: TcpListener) {
        let node = self.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let node2 = node.clone();
                let conn = tokio::spawn(async move {
                    match &node2.tls {
                        Some(acceptor) => {
                            if let Ok(tls) = acceptor.accept(tcp).await {
                                node2.connection(tls).await;
                            }
                        }
                        None => node2.connection(tcp).await,
                    }
                });
                node.state.tasks.lock().unwrap().push(conn.abort_handle());
            }
        });
        self.state.tasks.lock().unwrap().push(task.abort_handle());
    }

    async fn connection<
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    >(
        self: &Arc<Self>,
        io: S,
    ) {
        self.state.connections.fetch_add(1, Ordering::SeqCst);
        let generation = self.state.connections.load(Ordering::SeqCst);
        let (mut read, mut write) = tokio::io::split(io);
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        self.state.writers.lock().unwrap().push(tx.clone());
        let writer = tokio::spawn(async move {
            while let Some(b) = rx.recv().await {
                if write.write_all(&b).await.is_err() {
                    return;
                }
            }
        });
        self.state.tasks.lock().unwrap().push(writer.abort_handle());
        let mut buf = Vec::new();
        let mut chunk = vec![0u8; 8192];
        loop {
            let Ok(n) = read.read(&mut chunk).await else {
                return;
            };
            if n == 0 {
                return;
            }
            // A stalled connection is one this node opened before the
            // stall: it neither reads nor answers any more.
            if generation <= self.state.stalled_upto.load(Ordering::SeqCst) {
                continue;
            }
            buf.extend_from_slice(&chunk[..n]);
            while buf.starts_with(b"\r\n\r\n") {
                buf.drain(..4);
                self.state.pings.fetch_add(1, Ordering::SeqCst);
                let _ = tx.send(b"\r\n".to_vec());
            }
            let Ok(frames) = frame(&mut buf) else { return };
            for f in frames {
                let Frame::Message(m) = f else { continue };
                let text = String::from_utf8_lossy(&m).to_string();
                self.on_message(&text, &tx);
            }
        }
    }

    fn on_message(&self, text: &str, tx: &mpsc::UnboundedSender<Vec<u8>>) {
        match message::extract_method(text).as_deref() {
            Some("REGISTER") if message::is_request(text) => {
                let contact = message::extract_header(text, "Contact").unwrap_or_default();
                let expires = message::extract_header(text, "Expires").unwrap_or_default();
                if expires.trim() != "0" {
                    self.state.registers.fetch_add(1, Ordering::SeqCst);
                    *self.state.bound.lock().unwrap() = Some(tx.clone());
                }
                let ok = message::build_response(
                    text,
                    200,
                    "OK",
                    Some("reg"),
                    false,
                    &format!("Contact: {contact}\r\nExpires: {expires}\r\n"),
                    None,
                )
                .unwrap();
                let _ = tx.send(ok.into_bytes());
                let _ = self.seen_tx.send(text.to_string());
            }
            Some("OPTIONS") if message::is_request(text) => {
                let ok = message::build_simple_response(text, 200, "OK").unwrap();
                let _ = tx.send(ok.into_bytes());
            }
            _ => {
                let _ = self.seen_tx.send(text.to_string());
            }
        }
    }

    /// Stop listening and drop every connection.
    fn kill(&self) {
        for t in self.state.tasks.lock().unwrap().drain(..) {
            t.abort();
        }
        self.state.writers.lock().unwrap().clear();
        self.state.bound.lock().unwrap().take();
    }

    /// Listen again on the same port.
    async fn revive(self: &Arc<Self>) {
        let listener = TcpListener::bind(("127.0.0.1", self.port)).await.unwrap();
        self.serve(listener);
    }

    /// Send `msg` on the connection the binding came in on.
    fn send_to_binding(&self, msg: &str) {
        let tx = self.state.bound.lock().unwrap().clone().expect("a binding");
        tx.send(msg.as_bytes().to_vec()).unwrap();
    }

    fn registers(&self) -> usize {
        self.state.registers.load(Ordering::SeqCst)
    }

    async fn next_seen(&self, what: &str) -> String {
        let mut seen = self.seen.lock().await;
        loop {
            let m = tokio::time::timeout(Duration::from_secs(5), seen.recv())
                .await
                .unwrap_or_else(|_| panic!("nothing like {what:?} arrived"))
                .unwrap();
            if m.starts_with(what) {
                return m;
            }
        }
    }
}

async fn wait_for(what: &str, limit: Duration, mut cond: impl FnMut() -> bool) -> Duration {
    let start = Instant::now();
    while !cond() {
        assert!(start.elapsed() < limit, "{what}: not within {limit:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    start.elapsed()
}

fn account(transport: &str) -> SipAccountConfig {
    SipAccountConfig {
        username: "1001".into(),
        password: "secret".into(),
        domain: "sip.test".into(),
        registrar: None,
        transport: transport.into(),
        port: 5061,
        auth_username: None,
        display_name: String::new(),
        platform: "ios".into(),
    }
}

/// `sip.test` publishing `nodes` under `srv` (priority 10, 20, ...).
fn dns(srv: &str, nodes: &[(&str, u16)]) -> StaticDns {
    let mut t = StaticDns::default();
    t.srv.insert(
        format!("{srv}.sip.test"),
        nodes
            .iter()
            .enumerate()
            .map(|(i, (host, port))| SrvRecord {
                priority: 10 * (i as u16 + 1),
                weight: 50,
                port: *port,
                target: host.to_string(),
            })
            .collect(),
    );
    for (host, _) in nodes {
        t.hosts
            .insert(host.to_string(), vec!["127.0.0.1".parse().unwrap()]);
    }
    t
}

fn timing() -> TestTiming {
    TestTiming {
        speedup: 20,
        keepalive: None,
        pong_timeout: None,
    }
}

/// Two TLS nodes signed by one CA, and a manager that trusts only that CA.
async fn tls_pair() -> (Arc<Node>, Arc<Node>, SipProxyManager) {
    let ca = TestCa::new("Aria test CA");
    let n1 = Node::start(Some(ca.acceptor(&["sip.test", "node1.sip.test"]))).await;
    let n2 = Node::start(Some(ca.acceptor(&["sip.test", "node2.sip.test"]))).await;
    let mgr = SipProxyManager::new()
        .with_resolver(SrvResolver::with_static(dns(
            "_sips._tcp",
            &[("node1.sip.test", n1.port), ("node2.sip.test", n2.port)],
        )))
        .with_tls(TlsClient::trusting_only(ca.pem().as_bytes()).unwrap())
        .with_refresh_after(Duration::from_secs(2))
        .with_test_timing(timing());
    (n1, n2, mgr)
}

#[tokio::test]
async fn tls_registration_fails_over_to_node2_and_back_to_node1() {
    let (n1, n2, mgr) = tls_pair().await;
    let push = Arc::new(PushManager::new_noop());
    let handoff = Arc::new(HandoffManager::new());
    // Three devices (three users) on the gateway.
    for (i, dev) in ["dev1", "dev2", "dev3"].iter().enumerate() {
        let mut acct = account("auto");
        acct.username = format!("100{}", i + 1);
        mgr.register_device(dev.to_string(), acct, push.clone(), handoff.clone())
            .await
            .unwrap();
    }
    wait_for("registered on node1", Duration::from_secs(3), || {
        n1.registers() >= 3
    })
    .await;
    let register = n1.next_seen("REGISTER").await;
    assert!(register.contains("Via: SIP/2.0/TLS "), "{register}");
    assert!(register.contains(";transport=tls>"), "{register}");
    assert!(register.contains("+sip.instance=") && register.contains("reg-id=1"));
    assert_eq!(n2.registers(), 0, "node2 is only the backup");
    assert_eq!(mgr.get_status("dev1").await.as_deref(), Some("registered"));

    // node1 goes away: the flow breaks, node1 refuses the reconnect, and
    // the registration moves to node2 at once.
    n1.kill();
    let took = wait_for("all re-registered on node2", Duration::from_secs(3), || {
        n2.registers() >= 3
    })
    .await;
    assert!(took < Duration::from_secs(2), "failover took {took:?}");
    for dev in ["dev1", "dev2", "dev3"] {
        assert_eq!(
            mgr.get_status(dev).await.as_deref(),
            Some("registered"),
            "{dev} kept"
        );
    }

    // node1 comes back: a failback probe finds it and the registration
    // moves home (cooldown + probe interval, sped up 20x: a few seconds).
    let before = n1.registers();
    n1.revive().await;
    wait_for("all failed back to node1", Duration::from_secs(10), || {
        n1.registers() >= before + 3
    })
    .await;
    for dev in ["dev1", "dev2", "dev3"] {
        assert_eq!(
            mgr.get_status(dev).await.as_deref(),
            Some("registered"),
            "{dev} kept"
        );
    }
}

#[tokio::test]
async fn a_tls_failure_never_falls_back_to_udp() {
    // node1's certificate is from a CA the gateway does not trust; the
    // domain also publishes UDP on the same port.
    let rogue = TestCa::new("Rogue CA");
    let trusted = TestCa::new("Aria test CA");
    let n1 = Node::start(Some(rogue.acceptor(&["sip.test", "node1.sip.test"]))).await;
    let udp = UdpSocket::bind(("127.0.0.1", n1.port)).await.unwrap();
    let mut table = dns("_sips._tcp", &[("node1.sip.test", n1.port)]);
    table.srv.insert(
        "_sip._udp.sip.test".into(),
        vec![SrvRecord {
            priority: 10,
            weight: 50,
            port: n1.port,
            target: "node1.sip.test".into(),
        }],
    );
    let mgr = SipProxyManager::new()
        .with_resolver(SrvResolver::with_static(table))
        .with_tls(TlsClient::trusting_only(trusted.pem().as_bytes()).unwrap())
        .with_refresh_after(Duration::from_secs(2))
        .with_test_timing(timing());
    mgr.register_device(
        "dev1".into(),
        account("auto"),
        Arc::new(PushManager::new_noop()),
        Arc::new(HandoffManager::new()),
    )
    .await
    .unwrap();
    let mut buf = [0u8; 2048];
    let got = tokio::time::timeout(Duration::from_millis(1500), udp.recv_from(&mut buf)).await;
    assert!(got.is_err(), "nothing may be sent over UDP");
    assert_eq!(
        n1.registers(),
        0,
        "no REGISTER over an unverified TLS session"
    );
    assert_ne!(mgr.get_status("dev1").await.as_deref(), Some("registered"));
}

#[tokio::test]
async fn a_missed_keepalive_pong_recovers_the_flow_with_a_new_register() {
    // Plain TCP this time, with fast keep-alives.
    let n1 = Node::start(None).await;
    let mgr = SipProxyManager::new()
        .with_resolver(SrvResolver::with_static(dns(
            "_sip._tcp",
            &[("node1.sip.test", n1.port)],
        )))
        .with_refresh_after(Duration::from_secs(60))
        .with_test_timing(TestTiming {
            speedup: 20,
            keepalive: Some(Duration::from_millis(150)),
            pong_timeout: Some(Duration::from_millis(200)),
        });
    mgr.register_device(
        "dev1".into(),
        account("tcp"),
        Arc::new(PushManager::new_noop()),
        Arc::new(HandoffManager::new()),
    )
    .await
    .unwrap();
    wait_for("registered", Duration::from_secs(3), || n1.registers() >= 1).await;
    let register = n1.next_seen("REGISTER").await;
    assert!(register.contains("Via: SIP/2.0/TCP "), "{register}");
    wait_for("pings answered", Duration::from_secs(2), || {
        n1.state.pings.load(Ordering::SeqCst) >= 2
    })
    .await;
    assert_eq!(
        n1.state.connections.load(Ordering::SeqCst),
        1,
        "pongs keep the flow"
    );

    // The connection goes silent (a NAT dropped it, say): no pong. The
    // gateway gives the flow up and re-registers on a new connection.
    let open = n1.state.connections.load(Ordering::SeqCst);
    n1.state.stalled_upto.store(open, Ordering::SeqCst);
    let took = wait_for(
        "re-registered on a new flow",
        Duration::from_secs(3),
        || n1.state.connections.load(Ordering::SeqCst) >= 2 && n1.registers() >= 2,
    )
    .await;
    assert!(took < Duration::from_secs(1), "flow recovery took {took:?}");
}

#[tokio::test]
async fn an_invite_arriving_via_node2_rings_the_device() {
    let (n1, n2, mgr) = tls_pair().await;
    let mut fcm = MockFcm::start().await;
    let handoff = Arc::new(HandoffManager::new());
    mgr.register_device(
        "dev1".into(),
        account("tls"),
        fcm.manager("dev1").await,
        handoff.clone(),
    )
    .await
    .unwrap();
    wait_for("registered on node1", Duration::from_secs(3), || {
        n1.registers() >= 1
    })
    .await;
    n1.kill();
    wait_for("re-registered on node2", Duration::from_secs(3), || {
        n2.registers() >= 1
    })
    .await;

    let sdp = "v=0\r\nc=IN IP4 127.0.0.1\r\nm=audio 4000 RTP/AVP 0\r\n";
    let invite = format!(
        "INVITE sip:1001@127.0.0.1 SIP/2.0\r\n\
         Via: SIP/2.0/TLS 127.0.0.1:{port};branch=z9hG4bK-n2inv\r\n\
         From: \"Bob\" <sip:2000@sip.test>;tag=pbxtag\r\n\
         To: <sip:1001@sip.test>\r\n\
         Call-ID: via-node2\r\nCSeq: 10 INVITE\r\n\
         Contact: <sip:pbx@node2.sip.test:{port};transport=tls>\r\n\
         Content-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{sdp}",
        sdp.len(),
        port = n2.port,
    );
    n2.send_to_binding(&invite);
    assert!(n2
        .next_seen("SIP/2.0 100 Trying")
        .await
        .contains("Call-ID: via-node2"));
    let ringing = n2.next_seen("SIP/2.0 180 Ringing").await;
    assert!(ringing.contains("Call-ID: via-node2"));
    let token = handoff.pending_token("via-node2").await.unwrap();
    let (pushed, _) = tokio::time::timeout(Duration::from_secs(2), fcm.delivered.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        pushed, token,
        "the device was woken for the call node2 delivered"
    );
}

#[tokio::test]
async fn requests_on_a_stream_are_not_retransmitted() {
    use super::transaction::{retransmit_until, T2};
    use super::transport::{Flow, SipSocket, Transport};
    let n1 = Node::start(None).await;
    let flow = Flow::new(Transport::Tcp, None);
    let peer: std::net::SocketAddr = ([127, 0, 0, 1], n1.port).into();
    flow.ensure(peer, "node1.sip.test").await.unwrap();
    let socket = SipSocket::stream(flow);
    let bye = "BYE sip:2000@pbx SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:1;branch=z9hG4bK-b\r\nCall-ID: c\r\nCSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n";
    let never = std::future::pending::<()>();
    // Over UDP this would be sent at 0, 0.5, 1.5 s...: here just once.
    let _ = tokio::time::timeout(
        Duration::from_millis(1700),
        retransmit_until(&socket, peer, bye, T2, never),
    )
    .await;
    let first = n1.next_seen("BYE").await;
    assert!(first.contains("Via: SIP/2.0/TCP "), "{first}");
    let again = tokio::time::timeout(Duration::from_millis(100), async {
        n1.seen.lock().await.recv().await
    })
    .await;
    assert!(
        again.is_err(),
        "retransmitted on a reliable transport: {again:?}"
    );
}
