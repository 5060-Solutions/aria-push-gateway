//! Minimal SIP transaction helpers for UDP (RFC 3261 §17).
//!
//! - [`retransmit_until`] implements the doubling retransmission timers
//!   (A/E/G): send at once, then after T1, 2·T1, … capped at T2, until the
//!   transaction is answered or 64·T1 has passed.
//! - [`ServerTransactions`] remembers the final responses the gateway sent
//!   so a retransmitted request is answered with the same response instead
//!   of being processed again, and tracks INVITE transactions waiting for
//!   the ACK of a non-2xx final response.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::oneshot;

use super::message;

/// RTT estimate (RFC 3261 T1).
pub const T1: Duration = Duration::from_millis(500);
/// Maximum retransmission interval for non-INVITE requests and responses.
pub const T2: Duration = Duration::from_secs(4);
/// Transaction timeout (64·T1).
pub const TIMEOUT: Duration = Duration::from_secs(32);

/// Identity of a socket, for "did this arrive where the dialog lives".
pub fn socket_id(socket: &Arc<UdpSocket>) -> usize {
    Arc::as_ptr(socket) as *const () as usize
}

/// Send `msg` to `dest`, then retransmit it with doubling intervals (T1 up
/// to `cap`) until `done` completes (returns `true`) or `TIMEOUT` passes
/// (returns `false`). A send error ends the attempt early (`false`).
pub async fn retransmit_until<F: Future>(
    socket: &UdpSocket,
    dest: SocketAddr,
    msg: &str,
    cap: Duration,
    done: F,
) -> bool {
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    let mut interval = T1;
    tokio::pin!(done);
    loop {
        if socket.send_to(msg.as_bytes(), dest).await.is_err() {
            return false;
        }
        let wake = (tokio::time::Instant::now() + interval).min(deadline);
        tokio::select! {
            _ = &mut done => return true,
            _ = tokio::time::sleep_until(wake) => {}
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        interval = (interval * 2).min(cap);
    }
}

type ResponseKey = (usize, String, String);

#[derive(Default)]
struct Inner {
    /// (socket, branch, method) -> (response, destination, when sent).
    responses: HashMap<ResponseKey, (String, SocketAddr, Instant)>,
    /// (socket, INVITE branch) -> wakes the non-2xx retransmission on ACK.
    acks: HashMap<(usize, String), oneshot::Sender<()>>,
}

/// Server-side transaction memory shared by every socket of the gateway.
#[derive(Default)]
pub struct ServerTransactions {
    inner: std::sync::Mutex<Inner>,
}

fn key(socket: &Arc<UdpSocket>, request: &str) -> Option<ResponseKey> {
    Some((
        socket_id(socket),
        message::extract_via_branch(request)?,
        message::extract_cseq_method(request)?,
    ))
}

impl ServerTransactions {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Remember the final `response` sent for `request` so retransmissions
    /// of the request get it again (for 64·T1).
    pub fn remember(
        &self,
        socket: &Arc<UdpSocket>,
        request: &str,
        response: &str,
        dest: SocketAddr,
    ) {
        let Some(k) = key(socket, request) else {
            return;
        };
        let mut inner = self.lock();
        let now = Instant::now();
        inner
            .responses
            .retain(|_, (_, _, at)| now.duration_since(*at) < TIMEOUT);
        inner.responses.insert(k, (response.to_string(), dest, now));
    }

    /// The response previously sent for this exact request (same socket,
    /// branch and method), if it is a retransmission.
    pub fn replay(&self, socket: &Arc<UdpSocket>, request: &str) -> Option<String> {
        let k = key(socket, request)?;
        let inner = self.lock();
        inner
            .responses
            .get(&k)
            .filter(|(_, _, at)| at.elapsed() < TIMEOUT)
            .map(|(r, _, _)| r.clone())
    }

    /// Whether a final response was sent for the INVITE with this branch.
    pub fn answered_invite(&self, socket: &Arc<UdpSocket>, branch: &str) -> bool {
        self.lock().responses.contains_key(&(
            socket_id(socket),
            branch.to_string(),
            "INVITE".to_string(),
        ))
    }

    /// Absorb an ACK for a non-2xx final response; returns whether it
    /// matched one (same socket and INVITE branch).
    pub fn ack(&self, socket: &Arc<UdpSocket>, ack: &str) -> bool {
        let Some(branch) = message::extract_via_branch(ack) else {
            return false;
        };
        match self.lock().acks.remove(&(socket_id(socket), branch)) {
            Some(tx) => {
                let _ = tx.send(());
                true
            }
            None => false,
        }
    }

    /// Send a non-2xx final `response` to `invite` reliably: remember it
    /// for retransmitted INVITEs and retransmit it (Timer G) until the ACK
    /// arrives or 64·T1 passes.
    pub fn send_final(
        self: &Arc<Self>,
        socket: &Arc<UdpSocket>,
        dest: SocketAddr,
        invite: &str,
        response: String,
    ) {
        self.remember(socket, invite, &response, dest);
        let (tx, rx) = oneshot::channel();
        if let Some(branch) = message::extract_via_branch(invite) {
            self.lock()
                .acks
                .insert((socket_id(socket), branch.clone()), tx);
            let this = Arc::clone(self);
            let socket = Arc::clone(socket);
            tokio::spawn(async move {
                retransmit_until(&socket, dest, &response, T2, rx).await;
                this.lock().acks.remove(&(socket_id(&socket), branch));
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn retransmits_until_done_then_stops() {
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (tx, rx) = oneshot::channel::<()>();
        let dest = b.local_addr().unwrap();
        let task = tokio::spawn(async move { retransmit_until(&a, dest, "X", T2, rx).await });
        let mut buf = [0u8; 8];
        for _ in 0..2 {
            tokio::time::timeout(Duration::from_secs(2), b.recv(&mut buf))
                .await
                .unwrap()
                .unwrap();
        }
        tx.send(()).unwrap();
        assert!(task.await.unwrap());
    }

    #[tokio::test]
    async fn remembers_responses_per_socket_branch_and_method() {
        let s1 = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let s2 = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let t = ServerTransactions::default();
        let bye = "BYE sip:x SIP/2.0\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK-1\r\nCSeq: 2 BYE\r\n\r\n";
        t.remember(
            &s1,
            bye,
            "SIP/2.0 200 OK\r\n\r\n",
            "127.0.0.1:9".parse().unwrap(),
        );
        assert_eq!(
            t.replay(&s1, bye).as_deref(),
            Some("SIP/2.0 200 OK\r\n\r\n")
        );
        assert_eq!(t.replay(&s2, bye), None);
        assert_eq!(t.replay(&s1, &bye.replace("z9hG4bK-1", "z9hG4bK-2")), None);
        assert_eq!(t.replay(&s1, &bye.replace("2 BYE", "2 CANCEL")), None);
    }
}
