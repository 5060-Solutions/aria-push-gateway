//! RTP media relay for the B2BUA.
//!
//! For each active call, two UDP sockets are allocated:
//! - `phone_socket` — the phone sends RTP here
//! - `pbx_socket` — the PBX sends RTP here
//!
//! A forwarding task relays packets bidirectionally. The phone's actual
//! address is learned from the first received packet (symmetric RTP / comedia)
//! to handle NAT traversal.
//!
//! Payloads are opaque: datagrams are forwarded byte for byte, never parsed,
//! so SDES-SRTP (and SRTCP multiplexed on the same port, RFC 5761) passes
//! through with its encryption and authentication tag intact. There is no
//! RTP+1 RTCP socket pair: RTCP is relayed only when the endpoints use
//! `a=rtcp-mux`.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

/// Receive buffer size: any UDP datagram fits, so a packet is never
/// truncated (a cut SRTP/SRTCP packet would fail its authentication tag).
const MAX_DATAGRAM: usize = 65_536;

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
    #[allow(dead_code)] // retained for the SDP-rewriting relay mode
    pub async fn allocate() -> anyhow::Result<(Self, u16, u16)> {
        let phone_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        let pbx_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);

        let phone_port = phone_socket.local_addr()?.port();
        let pbx_port = pbx_socket.local_addr()?.port();

        tracing::info!(phone_port, pbx_port, "Allocated RTP relay ports");

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
            let mut buf = vec![0u8; MAX_DATAGRAM];
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
            let mut buf = vec![0u8; MAX_DATAGRAM];
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    async fn recv(sock: &UdpSocket) -> (Vec<u8>, SocketAddr) {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        let (len, from) = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf))
            .await
            .expect("timed out waiting for relayed packet")
            .unwrap();
        buf.truncate(len);
        (buf, from)
    }

    /// An SRTP-looking packet: RTP header, arbitrary "ciphertext" covering
    /// every byte value, and a 10-byte auth tag.
    fn srtp_packet(seq: u16, len: usize) -> Vec<u8> {
        let mut p = vec![0x80, 0x00];
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0x03, 0x20, 0xde, 0xad, 0xbe, 0xef]);
        p.extend((0..len).map(|i| (i * 7 + seq as usize) as u8));
        p.extend_from_slice(&[0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a]);
        p
    }

    /// An SRTCP sender report as sent with rtcp-mux: RTCP header, encrypted
    /// part, E-flag + index word and an 80-bit auth tag.
    fn srtcp_packet() -> Vec<u8> {
        let mut p = vec![0x80, 200, 0x00, 0x06, 0xde, 0xad, 0xbe, 0xef];
        p.extend((0u8..=255).rev().take(24));
        p.extend_from_slice(&[0x80, 0x00, 0x00, 0x01]);
        p.extend_from_slice(&[0xff; 10]);
        p
    }

    #[tokio::test]
    async fn srtp_and_srtcp_are_relayed_byte_for_byte_both_ways() {
        let (relay, phone_port, pbx_port) = RtpRelay::allocate().await.unwrap();
        let phone = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let pbx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        relay.start(pbx.local_addr().unwrap());
        let to_phone_side: SocketAddr = format!("127.0.0.1:{phone_port}").parse().unwrap();
        let to_pbx_side: SocketAddr = format!("127.0.0.1:{pbx_port}").parse().unwrap();

        // Phone -> PBX: the first packet also teaches the relay the phone's
        // address. Sizes go up to a full Ethernet MTU and beyond the old
        // 2 KiB receive buffer.
        for (seq, len) in [(1u16, 160usize), (2, 1400), (3, 4000)] {
            let pkt = srtp_packet(seq, len);
            phone.send_to(&pkt, to_phone_side).await.unwrap();
            let (got, from) = recv(&pbx).await;
            assert_eq!(got, pkt, "phone->pbx packet {seq} changed");
            assert_eq!(from.port(), pbx_port, "sent from the PBX-facing socket");
        }
        let rtcp = srtcp_packet();
        phone.send_to(&rtcp, to_phone_side).await.unwrap();
        assert_eq!(recv(&pbx).await.0, rtcp, "phone->pbx SRTCP changed");

        // PBX -> phone.
        for (seq, len) in [(100u16, 160usize), (101, 1400), (102, 4000)] {
            let pkt = srtp_packet(seq, len);
            pbx.send_to(&pkt, to_pbx_side).await.unwrap();
            let (got, from) = recv(&phone).await;
            assert_eq!(got, pkt, "pbx->phone packet {seq} changed");
            assert_eq!(from.port(), phone_port, "sent from the phone-facing socket");
        }
        pbx.send_to(&rtcp, to_pbx_side).await.unwrap();
        assert_eq!(recv(&phone).await.0, rtcp, "pbx->phone SRTCP changed");
        relay.stop();
    }
}
