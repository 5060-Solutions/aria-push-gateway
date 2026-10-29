//! The INVITE client transaction for calls the gateway places (UAC side).
//!
//! It runs in its own task, owning the call's socket, so it can finish
//! properly even if the HTTP request that started it goes away:
//!
//! - the INVITE is retransmitted (Timer A) until any response, and given up
//!   after 64·T1 without one (Timer B);
//! - a cancel (by `client_ref`, the HTTP request being dropped, or the ring
//!   timeout) sends CANCEL only once a provisional response has arrived
//!   (RFC 3261 §9.1), and retransmits it until answered;
//! - a 2xx is ACKed on the dialog it creates (the 200's Contact as
//!   Request-URI, the reversed Record-Route as Route set, both tags); if a
//!   cancel was asked for, the call is ended right away with a BYE;
//! - a non-2xx final is ACKed on the INVITE's transaction, and
//!   retransmissions of it are ACKed again for 64·T1 (Timer D).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio::time::Instant;

use super::digest::DigestAuth;
use super::message;
use super::proxy::{InviteSlot, OriginateRefusal, SipAccountConfig, SipProxyManager};
use super::transaction::{T1, T2, TIMEOUT};
use crate::handoff::{build_in_dialog_request, Dialog, HandoffManager};

/// How long an outgoing call may ring before the gateway cancels it.
pub const RING_TIMEOUT: Duration = Duration::from_secs(30);

/// Result handed back to the HTTP request.
pub type Outcome = anyhow::Result<(String, String)>;

/// Everything the INVITE transaction needs.
pub struct OutgoingInvite {
    pub socket: Arc<UdpSocket>,
    pub server_addr: SocketAddr,
    pub local_addr: SocketAddr,
    pub account: SipAccountConfig,
    pub target_uri: String,
    pub call_id: String,
    pub from_tag: String,
    pub sdp_offer: String,
    pub owner_user_id: String,
    pub handoff: Arc<HandoffManager>,
    pub ring_timeout: Duration,
}

enum Event {
    CancelRequested(bool),
    HttpGone,
    Recv(std::io::Result<(usize, SocketAddr)>),
    Timer,
}

/// Escape a display name for a quoted-string (RFC 3261 §25.1).
pub fn quote_display_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 2);
    out.push('"');
    for c in name.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

impl OutgoingInvite {
    fn build_invite(&self, cseq: u32, branch: &str, auth: Option<(&str, &str)>) -> String {
        let ip = self.local_addr.ip();
        let port = self.local_addr.port();
        let user = &self.account.username;
        let mut msg = format!(
            "INVITE {target} SIP/2.0\r\n\
             Via: SIP/2.0/UDP {ip}:{port};branch={branch};rport\r\n\
             Max-Forwards: 70\r\n\
             From: {name} <sip:{user}@{domain}>;tag={tag}\r\n\
             To: <{target}>\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: {cseq} INVITE\r\n\
             Contact: <sip:{user}@{ip}:{port};transport=udp>\r\n\
             Content-Type: application/sdp\r\n\
             Allow: INVITE, ACK, CANCEL, BYE, OPTIONS, REFER, NOTIFY\r\n\
             User-Agent: Aria-Gateway/0.1.0\r\n",
            target = self.target_uri,
            name = quote_display_name(&self.account.display_name),
            domain = self.account.domain,
            tag = self.from_tag,
            call_id = self.call_id,
        );
        if let Some((name, value)) = auth {
            msg.push_str(&format!("{name}: {value}\r\n"));
        }
        msg.push_str(&format!(
            "Content-Length: {}\r\n\r\n{}",
            self.sdp_offer.len(),
            self.sdp_offer
        ));
        msg
    }

    async fn send(&self, msg: &str) -> std::io::Result<()> {
        self.socket
            .send_to(msg.as_bytes(), self.server_addr)
            .await?;
        Ok(())
    }

    /// Run the transaction to completion. `result` is answered as soon as
    /// the outcome is known; the task may continue afterwards (cancelling,
    /// ACKing retransmissions) until the transaction is over.
    pub async fn run(
        self,
        slot: Option<InviteSlot>,
        mut cancel_rx: oneshot::Receiver<()>,
        result: oneshot::Sender<Outcome>,
    ) {
        let mut result = Some(result);
        let report = |result: &mut Option<oneshot::Sender<Outcome>>, outcome: Outcome| {
            if let Some(tx) = result.take() {
                let _ = tx.send(outcome);
            }
        };

        let mut cseq: u32 = 1;
        let mut invite = self.build_invite(cseq, &message::generate_branch(), None);
        let mut auth_attempts = 0;
        if let Err(e) = self.send(&invite).await {
            report(&mut result, Err(e.into()));
            return;
        }
        tracing::info!(uri = %self.target_uri, call_id = %self.call_id, "Sent outgoing INVITE");

        let ring_deadline = Instant::now() + self.ring_timeout;
        // Timer A/B for the current INVITE transaction.
        let mut timer_b = Instant::now() + TIMEOUT;
        let mut retx_interval = T1;
        let mut retx_at = Instant::now() + retx_interval;
        let mut provisional = false;

        let mut cancel_armed = slot.is_some();
        let mut cancel_wanted = false;
        let mut cancel_msg: Option<String> = None;
        let mut cancel_answered = false;
        let mut cancel_interval = T1;
        let mut cancel_retx_at = Instant::now();
        let mut give_up_at: Option<Instant> = None;

        let mut buf = vec![0u8; 65535];
        loop {
            // Send the CANCEL once it is wanted and allowed (after a 1xx).
            if cancel_wanted && provisional && cancel_msg.is_none() {
                if let Some(msg) = message::build_cancel(&invite) {
                    let _ = self.send(&msg).await;
                    tracing::info!(call_id = %self.call_id, "Cancelling outgoing call — sent CANCEL");
                    cancel_retx_at = Instant::now() + cancel_interval;
                    give_up_at = Some(Instant::now() + TIMEOUT);
                    cancel_msg = Some(msg);
                }
            }

            let mut wake = timer_b;
            if !provisional {
                wake = wake.min(retx_at);
            }
            if result.is_some() && !cancel_wanted {
                wake = wake.min(ring_deadline);
            }
            if cancel_msg.is_some() && !cancel_answered {
                wake = wake.min(cancel_retx_at);
            }
            if let Some(at) = give_up_at {
                wake = wake.min(at);
            }

            let event = {
                let http_gone = async {
                    match result.as_mut() {
                        Some(tx) if !cancel_wanted => tx.closed().await,
                        _ => std::future::pending().await,
                    }
                };
                tokio::select! {
                    biased;
                    r = &mut cancel_rx, if cancel_armed => Event::CancelRequested(r.is_ok()),
                    _ = http_gone => Event::HttpGone,
                    r = tokio::time::timeout_at(wake, self.socket.recv_from(&mut buf)) => match r {
                        Ok(r) => Event::Recv(r),
                        Err(_) => Event::Timer,
                    },
                }
            };

            let (len, from) = match event {
                Event::CancelRequested(requested) => {
                    cancel_armed = false;
                    if requested {
                        tracing::info!(call_id = %self.call_id, "App cancelled the outgoing call");
                        cancel_wanted = true;
                    }
                    continue;
                }
                Event::HttpGone => {
                    tracing::info!(call_id = %self.call_id, "Request for the outgoing call went away — cancelling");
                    result = None;
                    cancel_wanted = true;
                    continue;
                }
                Event::Timer => {
                    let now = Instant::now();
                    if give_up_at.is_some_and(|at| now >= at) {
                        tracing::warn!(call_id = %self.call_id, "No final response after CANCEL — giving up");
                        report(&mut result, Err(OriginateRefusal::Cancelled.into()));
                        return;
                    }
                    if !provisional && now >= timer_b {
                        // Timer B: nothing at all came back; no CANCEL is
                        // needed (or allowed) without a provisional.
                        let outcome = if cancel_wanted {
                            Err(OriginateRefusal::Cancelled.into())
                        } else {
                            Err(anyhow::anyhow!("Outgoing call timed out"))
                        };
                        report(&mut result, outcome);
                        return;
                    }
                    if !provisional && now >= retx_at {
                        let _ = self.send(&invite).await;
                        retx_interval *= 2;
                        retx_at = now + retx_interval;
                    }
                    if let (Some(msg), false) = (&cancel_msg, cancel_answered) {
                        if now >= cancel_retx_at {
                            let _ = self.send(msg).await;
                            cancel_interval = (cancel_interval * 2).min(T2);
                            cancel_retx_at = now + cancel_interval;
                        }
                    }
                    if result.is_some() && !cancel_wanted && now >= ring_deadline {
                        tracing::info!(call_id = %self.call_id, "Outgoing call rang too long — cancelling");
                        report(&mut result, Err(anyhow::anyhow!("Outgoing call timed out")));
                        cancel_wanted = true;
                    }
                    continue;
                }
                Event::Recv(Ok(r)) => r,
                Event::Recv(Err(e)) => {
                    report(&mut result, Err(e.into()));
                    return;
                }
            };

            if from != self.server_addr {
                tracing::warn!(call_id = %self.call_id, %from, "Dropping SIP message from an unexpected source");
                continue;
            }
            let Ok(text) = std::str::from_utf8(&buf[..len]) else {
                continue;
            };
            let Some(status) = message::parse_status_code(text) else {
                continue;
            };
            match message::extract_cseq_method(text).as_deref() {
                Some("INVITE") => {}
                Some("CANCEL") => {
                    cancel_answered = true;
                    continue;
                }
                _ => continue,
            }
            if message::extract_header(text, "CSeq")
                .and_then(|v| v.split_whitespace().next()?.parse::<u32>().ok())
                != Some(cseq)
            {
                continue; // a stale response to an earlier INVITE
            }

            match status {
                100..=199 => {
                    provisional = true;
                    timer_b = Instant::now() + TIMEOUT.max(self.ring_timeout) * 4;
                }
                200..=299 => {
                    let dialog = Dialog::from_uac(text, self.server_addr);
                    let ack = build_in_dialog_request(
                        "ACK",
                        &dialog,
                        cseq,
                        self.local_addr,
                        &message::generate_branch(),
                        "",
                    );
                    let _ = self.send(&ack).await;

                    // Answered: from here the call can't be cancelled by ref.
                    // A cancel already asked for means the 200 crossed it.
                    let cancel_requested = slot.as_ref().is_some_and(|s| s.claim_answer());
                    if cancel_wanted || cancel_requested {
                        tracing::info!(call_id = %self.call_id, "Answer crossed our cancel — ending the call");
                        let bye = build_in_dialog_request(
                            "BYE",
                            &dialog,
                            cseq + 1,
                            self.local_addr,
                            &message::generate_branch(),
                            "",
                        );
                        drop(slot);
                        report(&mut result, Err(OriginateRefusal::Cancelled.into()));
                        self.bye_unwanted_answer(&bye, &ack).await;
                        return;
                    }

                    let sdp_answer = text
                        .split_once("\r\n\r\n")
                        .map(|(_, b)| b.to_string())
                        .unwrap_or_default();
                    let token = SipProxyManager::connect_outgoing_call(
                        &self.handoff,
                        &self.socket,
                        self.server_addr,
                        self.local_addr,
                        &self.account,
                        &self.call_id,
                        &self.from_tag,
                        text,
                        ack,
                        &self.owner_user_id,
                        &self.sdp_offer,
                    )
                    .await;
                    if result.is_none() {
                        // Nobody is waiting for this call any more.
                        let _ = self.handoff.hangup_call(&token).await;
                    }
                    report(&mut result, Ok((token, sdp_answer)));
                    return;
                }
                _ => {
                    let ack = message::build_non2xx_ack(&invite, text);
                    if let Some(ack) = &ack {
                        let _ = self.send(ack).await;
                    }
                    let challenged = matches!(status, 401 | 407);
                    if challenged && !cancel_wanted && auth_attempts < 2 {
                        if let Some(next) = self.authenticated_invite(text, status, cseq + 1) {
                            auth_attempts += 1;
                            cseq += 1;
                            invite = next;
                            let _ = self.send(&invite).await;
                            tracing::debug!(call_id = %self.call_id, "Re-sent INVITE with credentials");
                            provisional = false;
                            timer_b = Instant::now() + TIMEOUT;
                            retx_interval = T1;
                            retx_at = Instant::now() + retx_interval;
                            continue;
                        }
                    }
                    let outcome = if cancel_wanted {
                        Err(OriginateRefusal::Cancelled.into())
                    } else {
                        Err(anyhow::anyhow!(
                            "Outgoing call rejected with status {status}"
                        ))
                    };
                    // The INVITE is over: its client_ref is free again.
                    drop(slot);
                    report(&mut result, outcome);
                    if let Some(ack) = ack {
                        self.absorb_final_retransmissions(cseq, &ack).await;
                    }
                    return;
                }
            }
        }
    }

    /// A new INVITE (new branch) answering a 401/407 challenge.
    fn authenticated_invite(&self, response: &str, status: u16, cseq: u32) -> Option<String> {
        let (challenge_header, auth_header) = if status == 401 {
            ("WWW-Authenticate", "Authorization")
        } else {
            ("Proxy-Authenticate", "Proxy-Authorization")
        };
        let challenge = message::extract_header(response, challenge_header)?;
        let auth = DigestAuth::from_challenge(
            &challenge,
            self.account.effective_auth_username(),
            &self.account.password,
            &self.target_uri,
            "INVITE",
        )?;
        Some(self.build_invite(
            cseq,
            &message::generate_branch(),
            Some((auth_header, &auth.to_header())),
        ))
    }

    /// Timer D: for 64·T1 after a non-2xx final, ACK its retransmissions.
    async fn absorb_final_retransmissions(&self, cseq: u32, ack: &str) {
        let until = Instant::now() + TIMEOUT;
        let mut buf = vec![0u8; 65535];
        while let Ok(Ok((len, from))) =
            tokio::time::timeout_at(until, self.socket.recv_from(&mut buf)).await
        {
            let Ok(text) = std::str::from_utf8(&buf[..len]) else {
                continue;
            };
            let is_final_again = from == self.server_addr
                && message::extract_cseq_method(text).as_deref() == Some("INVITE")
                && message::parse_status_code(text).is_some_and(|s| s >= 300)
                && message::extract_header(text, "CSeq")
                    .and_then(|v| v.split_whitespace().next()?.parse::<u32>().ok())
                    == Some(cseq);
            if is_final_again {
                let _ = self.send(ack).await;
            }
        }
    }

    /// End a call answered after we wanted it cancelled: send `bye` and
    /// retransmit it until answered (Timers E/F), re-ACKing any retransmitted
    /// 2xx meanwhile.
    async fn bye_unwanted_answer(&self, bye: &str, ack: &str) {
        let deadline = Instant::now() + TIMEOUT;
        let mut interval = T1;
        let mut buf = vec![0u8; 65535];
        loop {
            if self.send(bye).await.is_err() {
                return;
            }
            let retx_at = (Instant::now() + interval).min(deadline);
            while let Ok(Ok((len, from))) =
                tokio::time::timeout_at(retx_at, self.socket.recv_from(&mut buf)).await
            {
                if from != self.server_addr {
                    continue;
                }
                let Ok(text) = std::str::from_utf8(&buf[..len]) else {
                    continue;
                };
                let status = message::parse_status_code(text);
                match message::extract_cseq_method(text).as_deref() {
                    Some("BYE") if status.is_some_and(|s| s >= 200) => return,
                    Some("INVITE") if status.is_some_and(|s| (200..300).contains(&s)) => {
                        let _ = self.send(ack).await;
                    }
                    _ => {}
                }
            }
            if Instant::now() >= deadline {
                tracing::warn!(call_id = %self.call_id, "No response to BYE for a cancelled call");
                return;
            }
            interval = (interval * 2).min(T2);
        }
    }
}
