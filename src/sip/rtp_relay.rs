//! RTP media relay for the B2BUA.
//!
//! For each active call, two UDP sockets are allocated:
//! - `phone_socket` — the phone sends RTP here
//! - `pbx_socket` — the PBX sends RTP here
//!
//! A forwarding task relays packets bidirectionally. The phone's actual
//! address is learned from the first received packet (symmetric RTP / comedia)
//! to handle NAT traversal.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

/// Manages a pair of RTP relay sockets for one call.
pub struct RtpRelay {
    /// Socket facing the phone (mobile client sends RTP here).
    pub phone_socket: Arc<UdpSocket>,
    /// Socket facing the PBX (PBX media relay sends RTP here).
    pub pbx_socket: Arc<UdpSocket>,
    /// Phone's actual RTP address — learned from first packet (symmetric RTP).
    phone_addr: Arc<Mutex<Option<SocketAddr>>>,
    /// PBX's RTP address — extracted from SDP.
    pbx_addr: Arc<Mutex<Option<SocketAddr>>>,
    /// Flag to stop forwarding tasks.
    running: Arc<AtomicBool>,
}

impl RtpRelay {
    /// Allocate a new RTP relay with two ephemeral UDP sockets.
    /// Returns the relay and (phone_port, pbx_port).
    pub async fn allocate() -> anyhow::Result<(Self, u16, u16)> {
        let phone_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        let pbx_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);

        let phone_port = phone_socket.local_addr()?.port();
        let pbx_port = pbx_socket.local_addr()?.port();

        tracing::info!(
            phone_port,
            pbx_port,
            "Allocated RTP relay ports"
        );

        let relay = Self {
            phone_socket,
            pbx_socket,
            phone_addr: Arc::new(Mutex::new(None)),
            pbx_addr: Arc::new(Mutex::new(None)),
            running: Arc::new(AtomicBool::new(false)),
        };

        Ok((relay, phone_port, pbx_port))
    }

    /// Start bidirectional RTP forwarding.
    ///
    /// `pbx_addr` is the PBX's media address from its SDP answer/offer.
    /// The phone address is learned from the first received packet.
    pub fn start(&self, pbx_addr: SocketAddr) {
        self.running.store(true, Ordering::SeqCst);
        {
            // Set PBX addr synchronously via blocking — this is fine since
            // we only call start() once before spawning tasks.
            let pbx_addr_ref = self.pbx_addr.clone();
            let addr = pbx_addr;
            tokio::spawn(async move {
                *pbx_addr_ref.lock().await = Some(addr);
            });
        }

        // Phone → PBX forwarding
        let phone_sock = self.phone_socket.clone();
        let pbx_sock = self.pbx_socket.clone();
        let phone_addr = self.phone_addr.clone();
        let running = self.running.clone();
        let pbx_target = pbx_addr;

        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            while running.load(Ordering::Relaxed) {
                let result = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    phone_sock.recv_from(&mut buf),
                )
                .await;

                match result {
                    Ok(Ok((len, from))) => {
                        // Learn the phone's address from the first packet (symmetric RTP)
                        {
                            let mut addr = phone_addr.lock().await;
                            if addr.is_none() {
                                tracing::info!(
                                    addr = %from,
                                    "Learned phone RTP address (symmetric RTP)"
                                );
                            }
                            *addr = Some(from);
                        }

                        // Forward to PBX
                        if let Err(e) = pbx_sock.send_to(&buf[..len], pbx_target).await {
                            tracing::debug!("Error forwarding RTP to PBX: {}", e);
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::debug!("Phone socket recv error: {}", e);
                    }
                    Err(_) => {
                        // Timeout — check if still running
                        continue;
                    }
                }
            }
            tracing::debug!("Phone→PBX RTP forwarding stopped");
        });

        // PBX → Phone forwarding
        let phone_sock = self.phone_socket.clone();
        let pbx_sock = self.pbx_socket.clone();
        let phone_addr = self.phone_addr.clone();
        let running = self.running.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            while running.load(Ordering::Relaxed) {
                let result = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    pbx_sock.recv_from(&mut buf),
                )
                .await;

                match result {
                    Ok(Ok((len, _from))) => {
                        // Forward to phone (if we know its address)
                        let addr = phone_addr.lock().await;
                        if let Some(phone) = *addr {
                            if let Err(e) = phone_sock.send_to(&buf[..len], phone).await {
                                tracing::debug!("Error forwarding RTP to phone: {}", e);
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::debug!("PBX socket recv error: {}", e);
                    }
                    Err(_) => {
                        // Timeout — check if still running
                        continue;
                    }
                }
            }
            tracing::debug!("PBX→Phone RTP forwarding stopped");
        });

        tracing::info!(
            pbx = %pbx_addr,
            "RTP relay forwarding started"
        );
    }

    /// Stop the relay and release sockets.
    pub fn stop(&self) {
        if self.running.swap(false, Ordering::SeqCst) {
            tracing::info!("RTP relay stopped");
        }
    }
}

impl Drop for RtpRelay {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
    }
}
