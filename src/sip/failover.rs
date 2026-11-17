//! Registrar failover: which SRV target a registration is on, when it
//! moves, and when it moves back.
//!
//! [`Machine`] is pure (no I/O, no clock of its own): it is fed events with
//! the time they happened and answers with [`Action`]s for the caller to
//! carry out, so the whole failover/failback behaviour is tested with a fake
//! network. The registration in `proxy.rs` drives one machine per device.
//!
//! A registration fails over to the next target when
//! - a REGISTER gets no response within [`REGISTER_TIMEOUT`],
//! - the registrar answers 503 (its `Retry-After` is honoured), any other 5xx
//!   or 408,
//! - sending fails (socket error), or
//! - [`OPTIONS_MISSES`] health-check OPTIONS in a row go unanswered.
//!
//! It then re-registers on the new target. While on a lower-priority target
//! it probes the better ones with OPTIONS and fails back to the first that
//! answers. A new resolution replaces the target list when the SRV TTL
//! expires, and every resolved address is trusted to send SIP to the gateway.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use super::resolver::ResolvedServer;

/// How long a REGISTER may go unanswered before the target counts as down.
pub const REGISTER_TIMEOUT: Duration = Duration::from_secs(8);
/// How long an OPTIONS ping may go unanswered.
pub const OPTIONS_TIMEOUT: Duration = Duration::from_secs(4);
/// Unanswered OPTIONS pings in a row that count as a failure.
pub const OPTIONS_MISSES: u32 = 2;
/// Time between health-check pings while registered.
pub const OPTIONS_INTERVAL: Duration = Duration::from_secs(30);
/// Time between probes of a higher-priority target while on a lower one.
pub const PROBE_INTERVAL: Duration = Duration::from_secs(30);
/// How long a failed target is avoided when it gave no `Retry-After`.
pub const DEFAULT_COOLDOWN: Duration = Duration::from_secs(30);
/// Upper bound on a `Retry-After` we honour.
pub const MAX_COOLDOWN: Duration = Duration::from_secs(300);
/// Pause before looking a name up again after a failed lookup.
pub const RESOLVE_RETRY: Duration = Duration::from_secs(30);

/// Whether a REGISTER final response means "this target is unusable, try
/// another" (503 and any other 5xx, and 408) as opposed to an answer about
/// this registration itself (bad credentials, forbidden, ...).
pub fn is_failover_status(status: u16) -> bool {
    status == 408 || (500..600).contains(&status)
}

/// Something that happened to the registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Time passed: check every timer.
    Tick,
    /// The registrar answered 200 to our REGISTER.
    RegisterOk,
    /// The registrar challenged our REGISTER; a new one is on its way, so
    /// the no-response timer restarts.
    RegisterChallenged,
    /// A final response to REGISTER. 408 and 5xx fail over (honouring
    /// `Retry-After`); anything else is about the account, not the target,
    /// and ends the registration cycle.
    RegisterResponse {
        status: u16,
        retry_after: Option<Duration>,
    },
    /// Sending to, or receiving from, the socket failed.
    SocketError,
    /// A response to an OPTIONS ping, from this address.
    OptionsResponse { from: SocketAddr },
    /// A fresh resolution.
    Resolved(Vec<ResolvedServer>, Duration),
    /// A lookup failed.
    ResolveFailed,
}

/// What the caller must do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Send a REGISTER to this target.
    Register(SocketAddr),
    /// Send an OPTIONS ping to this target.
    Options(SocketAddr),
    /// Look the registrar up again and feed back `Resolved`/`ResolveFailed`.
    Resolve,
    /// Accept SIP from exactly these IPs (plus the operator allowlist).
    Trust(Vec<IpAddr>),
    /// The registration moved (for logs and status).
    Moved { from: SocketAddr, to: SocketAddr },
}

/// The failover state of one registration.
#[derive(Debug)]
pub struct Machine {
    servers: Vec<ResolvedServer>,
    current: SocketAddr,
    /// Targets to avoid until the instant.
    cooldown: HashMap<SocketAddr, Instant>,
    resolved_at: Instant,
    ttl: Duration,
    resolving: bool,
    resolve_retry_at: Option<Instant>,
    refresh_after: Duration,
    /// A REGISTER is out since this instant.
    register_pending: Option<Instant>,
    /// Send the next REGISTER at this instant (after a failover that has to
    /// wait out a cooldown).
    register_at: Option<Instant>,
    /// The current target holds our binding (the last REGISTER was
    /// answered 200); refresh when due.
    registered: bool,
    refresh_at: Instant,
    /// A health-check ping to the current target is out since this instant.
    options_pending: Option<Instant>,
    options_missed: u32,
    options_next: Instant,
    /// A probe of a higher-priority target is out since this instant.
    probe: Option<(SocketAddr, Instant)>,
    probe_next: Instant,
    /// A final answer other than success or failover ended the cycle.
    halted: bool,
}

impl Machine {
    /// Start on the first target of `servers` and register there.
    ///
    /// # Panics
    /// If `servers` is empty.
    pub fn start(
        servers: Vec<ResolvedServer>,
        ttl: Duration,
        refresh_after: Duration,
        now: Instant,
    ) -> (Self, Vec<Action>) {
        let current = servers.first().expect("at least one target").addr;
        let m = Self {
            servers,
            current,
            cooldown: HashMap::new(),
            resolved_at: now,
            ttl,
            resolving: false,
            resolve_retry_at: None,
            refresh_after,
            register_pending: Some(now),
            register_at: None,
            registered: false,
            refresh_at: now,
            options_pending: None,
            options_missed: 0,
            options_next: now,
            probe: None,
            probe_next: now,
            halted: false,
        };
        let actions = vec![m.trust_all(), Action::Register(current)];
        (m, actions)
    }

    /// The target the registration is on.
    pub fn current(&self) -> SocketAddr {
        self.current
    }

    /// Whether the current target holds the binding.
    #[cfg(test)]
    pub fn is_registered(&self) -> bool {
        self.registered
    }

    /// The ordered target list.
    #[cfg(test)]
    pub fn servers(&self) -> &[ResolvedServer] {
        &self.servers
    }

    fn trust_all(&self) -> Action {
        let mut ips: Vec<IpAddr> = self.servers.iter().map(|s| s.addr.ip()).collect();
        ips.push(self.current.ip());
        ips.sort();
        ips.dedup();
        Action::Trust(ips)
    }

    fn priority_of(&self, addr: SocketAddr) -> u16 {
        self.servers
            .iter()
            .find(|s| s.addr == addr)
            .map_or(u16::MAX, |s| s.priority)
    }

    fn cooled_down(&self, addr: SocketAddr, now: Instant) -> bool {
        self.cooldown.get(&addr).is_none_or(|until| *until <= now)
    }

    /// The target to use after `current` failed: the first healthy one in
    /// order, else the one whose cooldown ends soonest.
    fn next_target(&self, now: Instant) -> SocketAddr {
        self.servers
            .iter()
            .map(|s| s.addr)
            .find(|a| *a != self.current && self.cooled_down(*a, now))
            .or_else(|| {
                self.servers
                    .iter()
                    .map(|s| s.addr)
                    .min_by_key(|a| self.cooldown.get(a).copied().unwrap_or(now))
            })
            .unwrap_or(self.current)
    }

    /// A healthy target of better priority than the current one.
    fn failback_candidate(&self, now: Instant) -> Option<SocketAddr> {
        let here = self.priority_of(self.current);
        self.servers
            .iter()
            .find(|s| s.priority < here && self.cooled_down(s.addr, now))
            .map(|s| s.addr)
    }

    /// Mark `current` down and move to the next target.
    fn fail(&mut self, now: Instant, retry_after: Option<Duration>, out: &mut Vec<Action>) {
        let cooldown = retry_after
            .unwrap_or(DEFAULT_COOLDOWN)
            .clamp(Duration::from_secs(1), MAX_COOLDOWN);
        let from = self.current;
        self.cooldown.insert(from, now + cooldown);
        let to = self.next_target(now);
        self.move_to(from, to, now, out);
    }

    /// Re-register on `to` (immediately, or once its cooldown is over).
    fn move_to(&mut self, from: SocketAddr, to: SocketAddr, now: Instant, out: &mut Vec<Action>) {
        self.current = to;
        self.registered = false;
        self.register_pending = None;
        self.options_pending = None;
        self.options_missed = 0;
        self.probe = None;
        self.halted = false;
        let wait_until = self.cooldown.get(&to).copied().filter(|u| *u > now);
        match wait_until {
            None => {
                self.register_pending = Some(now);
                out.push(Action::Register(to));
            }
            Some(until) => self.register_at = Some(until),
        }
        if from != to {
            out.push(Action::Moved { from, to });
        }
        out.push(self.trust_all());
    }

    /// Apply an event at `now`.
    pub fn handle(&mut self, event: Event, now: Instant) -> Vec<Action> {
        let mut out = Vec::new();
        match event {
            Event::Tick => self.tick(now, &mut out),
            Event::RegisterOk => {
                self.cooldown.remove(&self.current);
                self.register_pending = None;
                self.register_at = None;
                self.halted = false;
                self.registered = true;
                self.refresh_at = now + self.refresh_after;
                self.options_pending = None;
                self.options_missed = 0;
                self.options_next = now + OPTIONS_INTERVAL;
                self.probe_next = now + PROBE_INTERVAL;
            }
            Event::RegisterChallenged => {
                if self.register_pending.is_some() {
                    self.register_pending = Some(now);
                }
            }
            Event::RegisterResponse {
                status,
                retry_after,
            } => {
                if is_failover_status(status) {
                    self.fail(now, retry_after, &mut out);
                } else {
                    self.register_pending = None;
                    self.registered = false;
                    self.halted = true;
                }
            }
            Event::SocketError => self.fail(now, None, &mut out),
            Event::OptionsResponse { from } => self.on_options_response(from, now, &mut out),
            Event::Resolved(servers, ttl) => self.on_resolved(servers, ttl, now, &mut out),
            Event::ResolveFailed => {
                self.resolving = false;
                self.resolve_retry_at = Some(now + RESOLVE_RETRY);
            }
        }
        out
    }

    fn on_options_response(&mut self, from: SocketAddr, now: Instant, out: &mut Vec<Action>) {
        if let Some((candidate, _)) = self.probe {
            if candidate.ip() == from.ip() {
                // The better target is back: fail back to it.
                self.cooldown.remove(&candidate);
                let old = self.current;
                self.move_to(old, candidate, now, out);
                return;
            }
        }
        if from.ip() == self.current.ip() && self.options_pending.is_some() {
            self.options_pending = None;
            self.options_missed = 0;
        }
    }

    fn on_resolved(
        &mut self,
        servers: Vec<ResolvedServer>,
        ttl: Duration,
        now: Instant,
        out: &mut Vec<Action>,
    ) {
        self.resolving = false;
        self.resolve_retry_at = None;
        if servers.is_empty() {
            self.resolve_retry_at = Some(now + RESOLVE_RETRY);
            return;
        }
        self.resolved_at = now;
        self.ttl = ttl;
        self.servers = servers;
        let live: Vec<SocketAddr> = self.servers.iter().map(|s| s.addr).collect();
        self.cooldown.retain(|a, _| live.contains(a));
        if live.contains(&self.current) {
            out.push(self.trust_all());
        } else {
            // The target we were on left the SRV set.
            let from = self.current;
            let to = self
                .servers
                .iter()
                .map(|s| s.addr)
                .find(|a| self.cooled_down(*a, now))
                .unwrap_or(self.servers[0].addr);
            self.current = to;
            self.move_to(from, to, now, out);
        }
    }

    fn tick(&mut self, now: Instant, out: &mut Vec<Action>) {
        if self.halted {
            self.tick_resolution(now, out);
            return;
        }

        // A REGISTER that was never answered.
        if self
            .register_pending
            .is_some_and(|sent| now.duration_since(sent) >= REGISTER_TIMEOUT)
        {
            self.fail(now, None, out);
            return;
        }
        // A failover waiting out a cooldown.
        if self.register_at.is_some_and(|at| at <= now) {
            self.register_at = None;
            self.register_pending = Some(now);
            out.push(Action::Register(self.current));
        }
        // Refresh.
        if self.registered && self.register_pending.is_none() && now >= self.refresh_at {
            self.register_pending = Some(now);
            out.push(Action::Register(self.current));
        }

        if self.registered && self.register_pending.is_none() {
            self.tick_health(now, out);
        }
        if self.registered {
            self.tick_failback(now, out);
        }
        self.tick_resolution(now, out);
    }

    fn tick_health(&mut self, now: Instant, out: &mut Vec<Action>) {
        if let Some(sent) = self.options_pending {
            if now.duration_since(sent) >= OPTIONS_TIMEOUT {
                self.options_pending = None;
                self.options_missed += 1;
                if self.options_missed >= OPTIONS_MISSES {
                    self.fail(now, None, out);
                    return;
                }
                // Ask again at once.
                self.options_next = now;
            }
        }
        if self.options_pending.is_none() && now >= self.options_next {
            self.options_pending = Some(now);
            self.options_next = now + OPTIONS_INTERVAL;
            out.push(Action::Options(self.current));
        }
    }

    fn tick_failback(&mut self, now: Instant, out: &mut Vec<Action>) {
        if let Some((candidate, sent)) = self.probe {
            if now.duration_since(sent) >= OPTIONS_TIMEOUT {
                self.probe = None;
                self.cooldown.insert(candidate, now + DEFAULT_COOLDOWN);
            }
            return;
        }
        if now < self.probe_next {
            return;
        }
        if let Some(candidate) = self.failback_candidate(now) {
            self.probe = Some((candidate, now));
            self.probe_next = now + PROBE_INTERVAL;
            out.push(Action::Options(candidate));
        }
    }

    fn tick_resolution(&mut self, now: Instant, out: &mut Vec<Action>) {
        if self.resolving {
            return;
        }
        let due = match self.resolve_retry_at {
            Some(at) => now >= at,
            None => now.duration_since(self.resolved_at) >= self.ttl,
        };
        if due {
            self.resolving = true;
            out.push(Action::Resolve);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn srv(addr: &str, priority: u16) -> ResolvedServer {
        ResolvedServer {
            addr: addr.parse().unwrap(),
            priority,
            weight: 10,
        }
    }

    fn a(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    const REFRESH: Duration = Duration::from_secs(2880);
    const TTL: Duration = Duration::from_secs(300);
    const A: &str = "10.0.0.1:5060";
    const B: &str = "10.0.0.2:5060";
    const C: &str = "10.0.0.3:5060";

    /// A fake network: each target is up or down. `run` applies the
    /// machine's actions to it the way the real transport would, answering
    /// from the targets that are up, until nothing more is sent.
    struct Net {
        up: HashMap<SocketAddr, bool>,
        sent: Vec<Action>,
        trust: Vec<IpAddr>,
        resolution: Option<(Vec<ResolvedServer>, Duration)>,
        /// What an `up` target answers to a REGISTER.
        register_status: HashMap<SocketAddr, (u16, Option<Duration>)>,
    }

    impl Net {
        fn new(targets: &[&str]) -> Self {
            Self {
                up: targets.iter().map(|t| (a(t), true)).collect(),
                sent: Vec::new(),
                trust: Vec::new(),
                resolution: None,
                register_status: HashMap::new(),
            }
        }

        fn set_up(&mut self, t: &str, up: bool) {
            self.up.insert(a(t), up);
        }

        fn deliver(&mut self, m: &mut Machine, actions: Vec<Action>, now: Instant) {
            let mut queue = actions;
            while !queue.is_empty() {
                let mut next = Vec::new();
                for action in queue {
                    self.sent.push(action.clone());
                    match action {
                        Action::Register(t) => {
                            if self.up.get(&t) == Some(&true) {
                                let (status, retry) =
                                    self.register_status.get(&t).copied().unwrap_or((200, None));
                                let ev = if status == 200 {
                                    Event::RegisterOk
                                } else {
                                    Event::RegisterResponse {
                                        status,
                                        retry_after: retry,
                                    }
                                };
                                next.extend(m.handle(ev, now));
                            }
                        }
                        Action::Options(t) => {
                            if self.up.get(&t) == Some(&true) {
                                next.extend(m.handle(Event::OptionsResponse { from: t }, now));
                            }
                        }
                        Action::Resolve => {
                            let ev = match self.resolution.clone() {
                                Some((s, ttl)) => Event::Resolved(s, ttl),
                                None => Event::ResolveFailed,
                            };
                            next.extend(m.handle(ev, now));
                        }
                        Action::Trust(ips) => self.trust = ips,
                        Action::Moved { .. } => {}
                    }
                }
                queue = next;
            }
        }

        fn registers(&self) -> Vec<SocketAddr> {
            self.sent
                .iter()
                .filter_map(|x| match x {
                    Action::Register(t) => Some(*t),
                    _ => None,
                })
                .collect()
        }
    }

    fn setup(targets: &[(&str, u16)]) -> (Machine, Net, Instant) {
        let now = Instant::now();
        let mut net = Net::new(&targets.iter().map(|t| t.0).collect::<Vec<_>>());
        let (mut m, actions) = Machine::start(
            targets.iter().map(|(t, p)| srv(t, *p)).collect(),
            TTL,
            REFRESH,
            now,
        );
        net.deliver(&mut m, actions, now);
        (m, net, now)
    }

    fn tick(m: &mut Machine, net: &mut Net, now: Instant) {
        let actions = m.handle(Event::Tick, now);
        net.deliver(m, actions, now);
    }

    #[test]
    fn starts_on_the_first_target() {
        let (m, net, _) = setup(&[(A, 10), (B, 10)]);
        assert_eq!(m.current(), a(A));
        assert!(m.is_registered());
        assert_eq!(net.registers(), vec![a(A)]);
    }

    #[test]
    fn no_response_to_register_fails_over_after_eight_seconds() {
        let (mut m, mut net, now) = setup(&[(A, 10), (B, 10)]);
        // Refresh time: A has gone silent.
        net.set_up(A, false);
        let t = now + REFRESH;
        tick(&mut m, &mut net, t);
        assert_eq!(m.current(), a(A), "still waiting for the answer");
        tick(&mut m, &mut net, t + Duration::from_secs(7));
        assert_eq!(m.current(), a(A));
        tick(&mut m, &mut net, t + REGISTER_TIMEOUT);
        assert_eq!(m.current(), a(B));
        assert!(m.is_registered(), "re-registered on B");
        assert_eq!(net.registers(), vec![a(A), a(A), a(B)]);
    }

    #[test]
    fn an_unanswered_first_register_fails_over_too() {
        let now = Instant::now();
        let mut net = Net::new(&[A, B]);
        net.set_up(A, false);
        let (mut m, actions) = Machine::start(vec![srv(A, 10), srv(B, 10)], TTL, REFRESH, now);
        net.deliver(&mut m, actions, now);
        assert!(!m.is_registered());
        tick(&mut m, &mut net, now + REGISTER_TIMEOUT);
        assert_eq!(m.current(), a(B));
        assert!(m.is_registered());
    }

    #[test]
    fn a_challenge_restarts_the_no_response_timer() {
        let (mut m, mut net, now) = setup(&[(A, 10), (B, 10)]);
        net.set_up(A, false);
        let t = now + REFRESH;
        tick(&mut m, &mut net, t);
        m.handle(Event::RegisterChallenged, t + Duration::from_secs(5));
        tick(&mut m, &mut net, t + REGISTER_TIMEOUT);
        assert_eq!(m.current(), a(A), "the authenticated REGISTER is still out");
        tick(
            &mut m,
            &mut net,
            t + Duration::from_secs(5) + REGISTER_TIMEOUT,
        );
        assert_eq!(m.current(), a(B));
    }

    #[test]
    fn five_xx_and_408_fail_over_other_errors_do_not() {
        for status in [500, 502, 503, 504, 599, 408] {
            let (mut m, mut net, now) = setup(&[(A, 10), (B, 10)]);
            let actions = m.handle(
                Event::RegisterResponse {
                    status,
                    retry_after: None,
                },
                now,
            );
            net.deliver(&mut m, actions, now);
            assert_eq!(m.current(), a(B), "{status}");
        }
        for status in [403, 404, 480, 486] {
            let (mut m, mut net, now) = setup(&[(A, 10), (B, 10)]);
            let actions = m.handle(
                Event::RegisterResponse {
                    status,
                    retry_after: None,
                },
                now,
            );
            net.deliver(&mut m, actions, now);
            assert_eq!(m.current(), a(A), "{status}");
            assert!(!m.is_registered());
        }
    }

    #[test]
    fn a_refresh_answered_503_fails_over_not_just_logs() {
        let (mut m, mut net, now) = setup(&[(A, 10), (B, 10)]);
        net.register_status.insert(a(A), (503, None));
        tick(&mut m, &mut net, now + REFRESH);
        assert_eq!(m.current(), a(B));
        assert!(m.is_registered());
    }

    #[test]
    fn socket_errors_fail_over() {
        let (mut m, mut net, now) = setup(&[(A, 10), (B, 10)]);
        let actions = m.handle(Event::SocketError, now);
        net.deliver(&mut m, actions, now);
        assert_eq!(m.current(), a(B));
    }

    #[test]
    fn retry_after_keeps_the_target_out_of_rotation() {
        let (mut m, mut net, now) = setup(&[(A, 10), (B, 10)]);
        let actions = m.handle(
            Event::RegisterResponse {
                status: 503,
                retry_after: Some(Duration::from_secs(120)),
            },
            now,
        );
        net.deliver(&mut m, actions, now);
        assert_eq!(m.current(), a(B));
        // B fails too: A asked us to wait 120 s, B only 30 s, so B is the
        // one retried, and not before its cooldown is over.
        let t = now + Duration::from_secs(10);
        let actions = m.handle(
            Event::RegisterResponse {
                status: 500,
                retry_after: None,
            },
            t,
        );
        net.deliver(&mut m, actions, t);
        assert_eq!(m.current(), a(B));
        assert!(!m.is_registered());
        let regs_before = net.registers().len();
        tick(&mut m, &mut net, t + Duration::from_secs(20));
        assert_eq!(
            net.registers().len(),
            regs_before,
            "B is still cooling down"
        );
        tick(&mut m, &mut net, now + Duration::from_secs(40));
        assert_eq!(net.registers().len(), regs_before + 1);
        assert!(m.is_registered());
    }

    #[test]
    fn a_single_target_is_retried_after_its_cooldown() {
        let (mut m, mut net, now) = setup(&[(A, 10)]);
        let actions = m.handle(Event::SocketError, now);
        net.deliver(&mut m, actions, now);
        assert_eq!(m.current(), a(A));
        assert!(!m.is_registered());
        tick(&mut m, &mut net, now + DEFAULT_COOLDOWN);
        assert!(m.is_registered());
        assert_eq!(net.registers(), vec![a(A), a(A)]);
    }

    #[test]
    fn two_missed_options_fail_over_one_does_not() {
        let (mut m, mut net, now) = setup(&[(A, 10), (B, 10)]);
        let t0 = now + OPTIONS_INTERVAL;
        // Healthy ping: no change.
        tick(&mut m, &mut net, t0);
        assert_eq!(m.current(), a(A));

        net.set_up(A, false);
        let t1 = t0 + OPTIONS_INTERVAL;
        tick(&mut m, &mut net, t1); // ping 1 sent, unanswered
        tick(&mut m, &mut net, t1 + OPTIONS_TIMEOUT); // miss 1, ping 2 sent
        assert_eq!(m.current(), a(A), "one miss is not a failure");
        tick(&mut m, &mut net, t1 + OPTIONS_TIMEOUT * 2); // miss 2
        assert_eq!(m.current(), a(B));
        assert!(m.is_registered());
    }

    #[test]
    fn an_answered_ping_resets_the_miss_count() {
        let (mut m, mut net, now) = setup(&[(A, 10), (B, 10)]);
        let t1 = now + OPTIONS_INTERVAL;
        net.set_up(A, false);
        tick(&mut m, &mut net, t1);
        tick(&mut m, &mut net, t1 + OPTIONS_TIMEOUT); // miss 1, re-ping
        net.set_up(A, true);
        let t = t1 + OPTIONS_TIMEOUT;
        let actions = m.handle(Event::OptionsResponse { from: a(A) }, t);
        net.deliver(&mut m, actions, t);
        // Next cycle starts from zero misses.
        net.set_up(A, false);
        let t2 = t + OPTIONS_INTERVAL;
        tick(&mut m, &mut net, t2);
        tick(&mut m, &mut net, t2 + OPTIONS_TIMEOUT);
        assert_eq!(m.current(), a(A));
    }

    #[test]
    fn fails_back_to_the_higher_priority_target_when_it_answers() {
        let (mut m, mut net, now) = setup(&[(A, 10), (B, 20)]);
        net.set_up(A, false);
        let actions = m.handle(Event::SocketError, now);
        net.deliver(&mut m, actions, now);
        assert_eq!(m.current(), a(B));

        // A is still down at the probe: stay on B.
        let t = now + PROBE_INTERVAL + DEFAULT_COOLDOWN;
        tick(&mut m, &mut net, t);
        tick(&mut m, &mut net, t + OPTIONS_TIMEOUT);
        assert_eq!(m.current(), a(B));

        // A recovers: the next probe moves the registration back.
        net.set_up(A, true);
        let t = t + OPTIONS_TIMEOUT + DEFAULT_COOLDOWN + PROBE_INTERVAL;
        tick(&mut m, &mut net, t);
        assert_eq!(m.current(), a(A));
        assert!(m.is_registered());
        assert_eq!(*net.registers().last().unwrap(), a(A));
    }

    #[test]
    fn does_not_probe_equal_or_lower_priority_targets() {
        let (mut m, mut net, now) = setup(&[(A, 10), (B, 10), (C, 20)]);
        let actions = m.handle(Event::SocketError, now);
        net.deliver(&mut m, actions, now);
        assert_eq!(m.current(), a(B));
        net.sent.clear();
        // A has the same priority and C a worse one: neither is probed.
        for i in 1..10 {
            tick(&mut m, &mut net, now + PROBE_INTERVAL * i);
        }
        assert!(net
            .sent
            .iter()
            .all(|x| !matches!(x, Action::Options(t) if *t != a(B))));
        assert_eq!(m.current(), a(B));
    }

    #[test]
    fn failover_prefers_the_next_in_order_over_cooled_down_ones() {
        let (mut m, mut net, now) = setup(&[(A, 10), (B, 10), (C, 20)]);
        let actions = m.handle(Event::SocketError, now);
        net.deliver(&mut m, actions, now);
        assert_eq!(m.current(), a(B));
        net.set_up(B, false);
        let actions = m.handle(Event::SocketError, now);
        net.deliver(&mut m, actions, now);
        assert_eq!(m.current(), a(C), "A and B are cooling down");
    }

    #[test]
    fn trust_covers_every_resolved_ip_not_just_the_current_one() {
        let (mut m, mut net, now) = setup(&[(A, 10), (B, 10)]);
        let ips: Vec<IpAddr> = vec!["10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap()];
        assert_eq!(net.trust, ips);

        // The set changes: C appears, B leaves. The list follows.
        net.resolution = Some((vec![srv(A, 10), srv(C, 10)], TTL));
        tick(&mut m, &mut net, now + TTL);
        let ips: Vec<IpAddr> = vec!["10.0.0.1".parse().unwrap(), "10.0.0.3".parse().unwrap()];
        assert_eq!(net.trust, ips);
        assert_eq!(m.current(), a(A), "still on A: no re-registration needed");
    }

    #[test]
    fn re_resolves_when_the_ttl_expires_and_not_before() {
        let (mut m, mut net, now) = setup(&[(A, 10)]);
        net.resolution = Some((vec![srv(A, 10), srv(B, 10)], TTL));
        tick(&mut m, &mut net, now + TTL - Duration::from_secs(1));
        assert!(!net.sent.contains(&Action::Resolve));
        tick(&mut m, &mut net, now + TTL);
        assert!(net.sent.contains(&Action::Resolve));
        assert_eq!(m.servers().len(), 2);
        // Not asked again until the new TTL runs out.
        net.sent.clear();
        tick(&mut m, &mut net, now + TTL + Duration::from_secs(10));
        assert!(!net.sent.contains(&Action::Resolve));
    }

    #[test]
    fn a_failed_lookup_keeps_the_old_targets_and_retries_later() {
        let (mut m, mut net, now) = setup(&[(A, 10), (B, 10)]);
        tick(&mut m, &mut net, now + TTL); // no resolution available
        assert_eq!(m.servers().len(), 2);
        net.sent.clear();
        tick(&mut m, &mut net, now + TTL + Duration::from_secs(5));
        assert!(!net.sent.contains(&Action::Resolve));
        tick(&mut m, &mut net, now + TTL + RESOLVE_RETRY);
        assert!(net.sent.contains(&Action::Resolve));
    }

    #[test]
    fn a_current_target_that_leaves_the_srv_set_is_replaced() {
        let (mut m, mut net, now) = setup(&[(A, 10), (B, 10)]);
        net.resolution = Some((vec![srv(B, 10), srv(C, 20)], TTL));
        tick(&mut m, &mut net, now + TTL);
        assert_eq!(m.current(), a(B));
        assert!(m.is_registered());
        assert_eq!(*net.registers().last().unwrap(), a(B));
    }
}
