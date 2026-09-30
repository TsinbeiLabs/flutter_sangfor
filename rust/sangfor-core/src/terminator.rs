//! The userspace TCP terminator: completes handshakes for flows the gateway
//! refuses to forward as raw IP and relays their bytes through a tunnel dial.
//!
//! RFC 793 server role, deliberately minimal — no window scaling, no SACK, no
//! timestamps, and out-of-order segments get a duplicate ACK so the peer
//! retransmits. That covers HTTP-shaped traffic and keeps the state machine
//! small enough to audit, which matters because this code runs inside an
//! extension with a memory budget.
//!
//! The core performs no I/O: every entry point returns the [`Effect`]s the host
//! must carry out, so the same state machine drives a tokio runtime, an
//! `NWConnection`, or a test harness.

use std::collections::VecDeque;

use crate::flow::Millis;
use crate::packet::{
    build_tcp, flag, ip_payload_tcp, sequence_add, sequence_difference, TcpHeader, TcpPacketParams,
};

/// What the host must do on the terminator's behalf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// Emit a raw IP packet towards the local stack (the TUN / packet flow).
    EmitPacket(Vec<u8>),
    /// Open a TCP-tunnel connection, then report back with
    /// [`Terminator::on_dial_connected`] or [`Terminator::on_dial_failed`].
    Dial {
        /// Correlation id chosen by the terminator.
        dial: u64,
        /// Host name to dial, already resolved through the plan's aliases.
        host: String,
        /// Destination port.
        port: u16,
        /// The address the flow was actually addressed to, host order.
        ///
        /// Not what gets dialled when the resource was published as a domain —
        /// [Self::Dial::host] is the alias. The gateway signs both, so the
        /// auth request needs the original: `destAddr` carries the name and
        /// `destIP` carries this.
        destination: u32,
    },
    /// Write relayed bytes upstream.
    RelaySend {
        /// The dial this stream belongs to.
        dial: u64,
        /// Payload.
        bytes: Vec<u8>,
    },
    /// Half-close a relay stream.
    RelayCloseWrite {
        /// The dial to half-close.
        dial: u64,
    },
    /// Close a relay stream.
    RelayClose {
        /// The dial to close.
        dial: u64,
    },
    /// Stop or resume delivering upstream bytes (backpressure).
    RelayPause {
        /// The dial to throttle.
        dial: u64,
        /// True to stop delivering.
        paused: bool,
    },
    /// Something the host should log.
    Error(String),
}

/// Tuning knobs, defaulted to the values the Dart reference uses.
#[derive(Debug, Clone, Copy)]
pub struct TerminatorConfig {
    /// Largest payload the terminator sends; a smaller peer MSS clamps it.
    pub maximum_segment_size: u16,
    /// Receive window advertised to the local stack. Without window scaling
    /// this also caps one connection's throughput.
    pub advertised_window: u16,
    /// Idle time before a flow is reset.
    pub idle_timeout_ms: Millis,
    /// First retransmit delay.
    pub initial_rto_ms: Millis,
    /// Retransmit delay ceiling.
    pub maximum_rto_ms: Millis,
    /// Retransmits before giving up on a flow.
    pub maximum_retransmits: u32,
    /// Upstream queue depth at which reading is paused.
    pub pause_upstream_at: usize,
    /// Depth reading resumes at.
    pub resume_upstream_at: usize,
}

impl Default for TerminatorConfig {
    fn default() -> Self {
        Self {
            maximum_segment_size: 1400,
            advertised_window: 65535,
            idle_timeout_ms: 300_000,
            initial_rto_ms: 300,
            maximum_rto_ms: 8_000,
            maximum_retransmits: 8,
            pause_upstream_at: 512 * 1024,
            resume_upstream_at: 128 * 1024,
        }
    }
}

/// Decides which flows the terminator claims.
pub trait TerminationPolicy {
    /// True when a TCP flow to `destination:port` must be terminated locally
    /// because the L3 plane refuses it and the TCP tunnel can serve it.
    fn should_terminate(&self, destination: u32, port: u16) -> bool;

    /// The host name to dial for a destination address, or `None` to dial the
    /// address itself. Domain-published resources need this to keep their
    /// identity (and therefore the right `appId`).
    fn dial_host(&self, destination: u32) -> Option<String> {
        let _ = destination;
        None
    }
}

/// A deterministic PRNG: reproducible initial sequence numbers under test and
/// no `rand` dependency in an extension binary.
#[derive(Debug, Clone, Copy)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// A generator seeded with [seed].
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// The next value.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    SynReceived,
    Established,
    InboundClosed,
    Closed,
}

/// One built-but-unacknowledged segment, kept for retransmission.
#[derive(Debug, Clone)]
struct Unacknowledged {
    packet: Vec<u8>,
    sequence: u32,
    /// Sequence space consumed: one for a bare SYN or FIN, the payload length
    /// otherwise.
    length: u32,
}

/// The four-tuple a terminated flow is keyed by, in the client's direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionKey {
    /// Client address.
    pub client: u32,
    /// Client port.
    pub client_port: u16,
    /// Service address.
    pub server: u32,
    /// Service port.
    pub server_port: u16,
}

impl ConnectionKey {
    /// The reversed direction, used to recognize echoes of our own packets.
    #[must_use]
    pub fn reversed(&self) -> Self {
        Self {
            client: self.server,
            client_port: self.server_port,
            server: self.client,
            server_port: self.client_port,
        }
    }

    /// A stable description for log lines.
    #[must_use]
    pub fn describe(&self) -> String {
        format!(
            "{}:{}->{}:{}",
            crate::packet::ipv4_text(self.client),
            self.client_port,
            crate::packet::ipv4_text(self.server),
            self.server_port
        )
    }
}

#[derive(Debug)]
struct Connection {
    key: ConnectionKey,
    dial: u64,
    state: State,

    our_initial_sequence: u32,
    receive_next: u32,
    send_next: u32,
    send_unacknowledged: u32,
    peer_window: u32,
    maximum_segment_size: u16,

    handshake_complete: bool,
    upstream_connected: bool,
    upstream_done: bool,
    inbound_closed: bool,
    upstream_paused: bool,
    fin_sent: bool,

    unacknowledged: VecDeque<Unacknowledged>,
    send_queue: VecDeque<u8>,
    pending_for_upstream: Vec<u8>,

    retransmit_at: Option<Millis>,
    retransmit_timeout: Millis,
    retransmits: u32,
    idle_deadline: Millis,
}

/// Terminates TCP flows arriving as raw IP packets.
#[derive(Debug)]
pub struct Terminator<P: TerminationPolicy> {
    policy: P,
    config: TerminatorConfig,
    connections: Vec<Connection>,
    next_dial: u64,
    random: SplitMix64,
    identification: u16,
    closed: bool,
}

impl<P: TerminationPolicy> Terminator<P> {
    /// A terminator driven by [policy].
    #[must_use]
    pub fn new(policy: P, config: TerminatorConfig, seed: u64) -> Self {
        let mut random = SplitMix64::new(seed);
        let identification = (random.next_u64() % 0xffff) as u16;
        Self {
            policy,
            config,
            connections: Vec::new(),
            next_dial: 0,
            random,
            identification,
            closed: false,
        }
    }

    /// Live terminated flows.
    #[must_use]
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// True after [`Terminator::close`].
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// The next moment [`Terminator::tick`] has work to do, if any.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Millis> {
        self.connections
            .iter()
            .flat_map(|connection| [Some(connection.idle_deadline), connection.retransmit_at])
            .flatten()
            .min()
    }

    /// Consumes one raw IP packet. Returns `(claimed, effects)`: when `claimed`
    /// is false the packet belongs to the caller, which forwards it to the
    /// tunnel as usual.
    pub fn accept(&mut self, packet: &[u8], now: Millis) -> (bool, Vec<Effect>) {
        if self.closed {
            return (false, Vec::new());
        }
        let Some(tcp) = ip_payload_tcp(packet) else {
            return (false, Vec::new());
        };
        let Some(key) = connection_key(packet, &tcp) else {
            return (false, Vec::new());
        };
        if let Some(index) = self.connections.iter().position(|c| c.key == key) {
            return (true, self.handle(index, &tcp, now));
        }
        if self
            .connections
            .iter()
            .any(|connection| connection.key == key.reversed())
        {
            // An echo of a packet we synthesized; never hand it to the tunnel.
            return (true, Vec::new());
        }
        let is_syn = tcp.flags() & flag::SYN != 0;
        let is_ack = tcp.flags() & flag::ACK != 0;
        if !is_syn || is_ack {
            return (false, Vec::new());
        }
        if !self.policy.should_terminate(key.server, key.server_port) {
            return (false, Vec::new());
        }
        let mut effects = Vec::new();
        self.open(key, &tcp, now, &mut effects);
        (true, effects)
    }

    /// Drives retransmit and idle timers. Call it once
    /// [`Terminator::next_deadline`] has passed.
    pub fn tick(&mut self, now: Millis) -> Vec<Effect> {
        let mut effects = Vec::new();
        for index in 0..self.connections.len() {
            self.run_timers(index, now, &mut effects);
        }
        self.retain_live();
        effects
    }

    /// The host finished a dial: the relay stream is ready.
    pub fn on_dial_connected(&mut self, dial: u64, now: Millis) -> Vec<Effect> {
        let mut effects = Vec::new();
        let Some(index) = self.connections.iter().position(|c| c.dial == dial) else {
            return effects;
        };
        {
            let connection = &mut self.connections[index];
            connection.upstream_connected = true;
            connection.idle_deadline = now + self.config.idle_timeout_ms;
        }
        self.flush_pending_upstream(index, &mut effects);
        self.flush(index, now, &mut effects);
        self.maybe_finish(index, &mut effects);
        effects
    }

    /// The host could not dial.
    pub fn on_dial_failed(&mut self, dial: u64, message: &str) -> Vec<Effect> {
        let mut effects = Vec::new();
        let Some(index) = self.connections.iter().position(|c| c.dial == dial) else {
            return effects;
        };
        effects.push(Effect::Error(format!(
            "dial failed for {}: {message}",
            self.connections[index].key.describe()
        )));
        self.dispose(index, true, &mut effects);
        self.retain_live();
        effects
    }

    /// Bytes arrived from the tunnel for [dial].
    pub fn on_relay_data(&mut self, dial: u64, data: &[u8], now: Millis) -> Vec<Effect> {
        let mut effects = Vec::new();
        let Some(index) = self.connections.iter().position(|c| c.dial == dial) else {
            return effects;
        };
        {
            let connection = &mut self.connections[index];
            connection.send_queue.extend(data.iter().copied());
            connection.idle_deadline = now + self.config.idle_timeout_ms;
        }
        self.flush(index, now, &mut effects);
        let (queued, paused, dial) = {
            let connection = &self.connections[index];
            (
                connection.send_queue.len(),
                connection.upstream_paused,
                connection.dial,
            )
        };
        if queued >= self.config.pause_upstream_at && !paused {
            self.connections[index].upstream_paused = true;
            effects.push(Effect::RelayPause { dial, paused: true });
        }
        effects
    }

    /// The tunnel closed the stream, or sent its EOF frame.
    pub fn on_relay_closed(&mut self, dial: u64, now: Millis) -> Vec<Effect> {
        let mut effects = Vec::new();
        let Some(index) = self.connections.iter().position(|c| c.dial == dial) else {
            return effects;
        };
        self.connections[index].upstream_done = true;
        self.flush(index, now, &mut effects);
        self.maybe_finish(index, &mut effects);
        self.retain_live();
        effects
    }

    /// Tears everything down.
    pub fn close(&mut self) -> Vec<Effect> {
        if self.closed {
            return Vec::new();
        }
        self.closed = true;
        let mut effects = Vec::new();
        for index in 0..self.connections.len() {
            self.dispose(index, false, &mut effects);
        }
        self.connections.clear();
        effects
    }

    // Internals.

    fn open(
        &mut self,
        key: ConnectionKey,
        syn: &TcpHeader<'_>,
        now: Millis,
        effects: &mut Vec<Effect>,
    ) {
        self.next_dial += 1;
        let dial = self.next_dial;
        let offered = syn.mss().unwrap_or(0);
        let maximum_segment_size = if offered == 0 {
            self.config.maximum_segment_size
        } else {
            offered.min(self.config.maximum_segment_size)
        };
        let our_initial_sequence = (self.random.next_u64() % 0x7fff_ffff) as u32;
        let connection = Connection {
            key,
            dial,
            state: State::SynReceived,
            our_initial_sequence,
            receive_next: sequence_add(syn.sequence_number(), 1),
            send_next: sequence_add(our_initial_sequence, 1),
            send_unacknowledged: our_initial_sequence,
            peer_window: u32::from(syn.window()),
            maximum_segment_size,
            handshake_complete: false,
            upstream_connected: false,
            upstream_done: false,
            inbound_closed: false,
            upstream_paused: false,
            fin_sent: false,
            unacknowledged: VecDeque::new(),
            send_queue: VecDeque::new(),
            pending_for_upstream: Vec::new(),
            retransmit_at: None,
            retransmit_timeout: self.config.initial_rto_ms,
            retransmits: 0,
            idle_deadline: now + self.config.idle_timeout_ms,
        };
        // The connection goes into the table before the SYN-ACK is built,
        // so every emitter can work by index.
        self.connections.push(connection);
        let index = self.connections.len() - 1;
        // Answer the SYN before dialing, so the local stack's handshake does
        // not wait on the tunnel round trip.
        self.emit(
            index,
            flag::SYN | flag::ACK,
            &[],
            Some(maximum_segment_size),
            Some(our_initial_sequence),
            1,
            effects,
        );
        {
            let connection = &mut self.connections[index];
            if connection.unacknowledged.is_empty() {
                connection.retransmit_at = None;
            } else if connection.retransmit_at.is_none() {
                let timeout = connection.retransmit_timeout;
                connection.retransmit_at = Some(now + timeout);
            }
        }
        let host = self
            .policy
            .dial_host(key.server)
            .unwrap_or_else(|| crate::packet::ipv4_text(key.server));
        effects.push(Effect::Dial {
            dial,
            host,
            port: key.server_port,
            destination: key.server,
        });
    }

    fn handle(&mut self, index: usize, tcp: &TcpHeader<'_>, now: Millis) -> Vec<Effect> {
        let mut effects = Vec::new();
        let flags = tcp.flags();
        let sequence = tcp.sequence_number();
        let acknowledgment = tcp.acknowledgment_number();
        let window = u32::from(tcp.window());
        let payload = tcp.payload().to_vec();
        {
            let connection = &mut self.connections[index];
            connection.idle_deadline = now + self.config.idle_timeout_ms;
            connection.peer_window = window;
        }
        if flags & flag::RST != 0 {
            self.dispose(index, false, &mut effects);
            self.retain_live();
            return effects;
        }
        if flags & flag::ACK != 0 {
            self.acknowledge(index, acknowledgment, now, &mut effects);
            if index >= self.connections.len() {
                return effects;
            }
        }
        if self.connections[index].state == State::SynReceived {
            if !self.connections[index].handshake_complete {
                // The SYN-ACK is still in flight; nothing else is meaningful.
                return effects;
            }
            self.connections[index].state = State::Established;
        }
        if flags & flag::SYN != 0 {
            // A retransmitted SYN: answer with the current state, keep the flow.
            self.emit_ack(index, &mut effects);
            return effects;
        }
        if !payload.is_empty() {
            self.accept_payload(index, sequence, &payload, &mut effects);
        }
        if flags & flag::FIN != 0 {
            let (dial, connected, already) = {
                let connection = &mut self.connections[index];
                connection.receive_next = sequence_add(connection.receive_next, 1);
                (
                    connection.dial,
                    connection.upstream_connected,
                    connection.inbound_closed,
                )
            };
            self.emit_ack(index, &mut effects);
            if !already {
                self.connections[index].inbound_closed = true;
                if connected {
                    effects.push(Effect::RelayCloseWrite { dial });
                }
            }
            if self.connections[index].state == State::Established {
                self.connections[index].state = State::InboundClosed;
            }
        }
        self.flush(index, now, &mut effects);
        self.maybe_finish(index, &mut effects);
        effects
    }

    fn accept_payload(
        &mut self,
        index: usize,
        sequence: u32,
        payload: &[u8],
        effects: &mut Vec<Effect>,
    ) {
        let (receive_next, gap) = {
            let connection = &self.connections[index];
            (
                connection.receive_next,
                sequence_difference(sequence, connection.receive_next),
            )
        };
        if gap > 0 {
            // A hole: drop it and repeat the ACK so the peer retransmits.
            self.emit_ack(index, effects);
            return;
        }
        let overlap = usize::try_from(-gap).unwrap_or(0);
        if overlap >= payload.len() {
            // Data we already relayed.
            self.emit_ack(index, effects);
            return;
        }
        let fresh = &payload[overlap..];
        self.connections[index].receive_next =
            sequence_add(receive_next, u32::try_from(fresh.len()).unwrap_or(u32::MAX));
        self.emit_ack(index, effects);
        let (connected, dial) = {
            let connection = &self.connections[index];
            (connection.upstream_connected, connection.dial)
        };
        if connected {
            effects.push(Effect::RelaySend {
                dial,
                bytes: fresh.to_vec(),
            });
        } else {
            // The dial is still in flight. Only a connection's first flight can
            // land here, so this buffer stays small.
            self.connections[index]
                .pending_for_upstream
                .extend_from_slice(fresh);
        }
    }

    fn flush_pending_upstream(&mut self, index: usize, effects: &mut Vec<Effect>) {
        let dial = self.connections[index].dial;
        let pending = std::mem::take(&mut self.connections[index].pending_for_upstream);
        if pending.is_empty() {
            return;
        }
        effects.push(Effect::RelaySend {
            dial,
            bytes: pending,
        });
    }

    fn maybe_finish(&mut self, index: usize, effects: &mut Vec<Effect>) {
        let (fin_sent, upstream_done, drained, state) = {
            let connection = &self.connections[index];
            (
                connection.fin_sent,
                connection.upstream_done,
                connection.send_queue.is_empty() && connection.unacknowledged.is_empty(),
                connection.state,
            )
        };
        if fin_sent || !upstream_done || !drained || state == State::Closed {
            return;
        }
        self.emit(index, flag::FIN | flag::ACK, &[], None, None, 1, effects);
        self.connections[index].fin_sent = true;
    }

    fn flush(&mut self, index: usize, now: Millis, effects: &mut Vec<Effect>) {
        if !self.connections[index].handshake_complete {
            return;
        }
        loop {
            let (in_flight, peer_window, mss) = {
                let connection = &self.connections[index];
                (
                    sequence_difference(connection.send_unacknowledged, connection.send_next),
                    connection.peer_window,
                    usize::from(connection.maximum_segment_size),
                )
            };
            let available = i64::from(peer_window) - i64::from(in_flight);
            if available <= 0 || self.connections[index].send_queue.is_empty() {
                break;
            }
            let limit = usize::try_from(available).unwrap_or(0).min(mss);
            let payload: Vec<u8> = {
                let connection = &mut self.connections[index];
                let take = limit.min(connection.send_queue.len());
                connection.send_queue.drain(..take).collect()
            };
            self.emit(
                index,
                flag::ACK | flag::PSH,
                &payload,
                None,
                None,
                u32::try_from(payload.len()).unwrap_or(u32::MAX),
                effects,
            );
        }
        if self.connections[index].send_queue.len() < self.config.resume_upstream_at
            && self.connections[index].upstream_paused
        {
            self.connections[index].upstream_paused = false;
            effects.push(Effect::RelayPause {
                dial: self.connections[index].dial,
                paused: false,
            });
        }
        {
            let connection = &mut self.connections[index];
            if connection.unacknowledged.is_empty() {
                connection.retransmit_at = None;
            } else if connection.retransmit_at.is_none() {
                let timeout = connection.retransmit_timeout;
                connection.retransmit_at = Some(now + timeout);
            }
        }
        if self.connections[index].upstream_done {
            self.maybe_finish(index, effects);
        }
    }

    fn emit_ack(&mut self, index: usize, effects: &mut Vec<Effect>) {
        if !self.connections[index].handshake_complete {
            return;
        }
        let packet = self.build(index, flag::ACK, &[], None);
        effects.push(Effect::EmitPacket(packet));
    }

    #[allow(clippy::too_many_arguments)]
    fn emit(
        &mut self,
        index: usize,
        flags: u8,
        payload: &[u8],
        mss: Option<u16>,
        sequence_override: Option<u32>,
        sequence_length: u32,
        effects: &mut Vec<Effect>,
    ) {
        self.identification = self.identification.wrapping_add(1);
        let identification = self.identification;
        let config = self.config;
        // Scoped so the immutable borrow of the connection ends before the
        // mutable one below; the two cannot overlap on `self.connections`.
        let (packet, sequence) = {
            let connection = &self.connections[index];
            let packet = build_segment(
                connection,
                &config,
                flags,
                payload,
                mss,
                sequence_override,
                identification,
            );
            let sequence = sequence_override.unwrap_or(connection.send_next);
            (packet, sequence)
        };
        {
            let connection = &mut self.connections[index];
            if sequence_override.is_none() {
                connection.send_next = sequence_add(connection.send_next, sequence_length);
            }
            connection.unacknowledged.push_back(Unacknowledged {
                packet: packet.clone(),
                sequence,
                length: sequence_length,
            });
        }
        effects.push(Effect::EmitPacket(packet));
    }

    fn build(&self, index: usize, flags: u8, payload: &[u8], mss: Option<u16>) -> Vec<u8> {
        build_segment(
            &self.connections[index],
            &self.config,
            flags,
            payload,
            mss,
            None,
            self.identification,
        )
    }

    fn acknowledge(
        &mut self,
        index: usize,
        acknowledgment: u32,
        now: Millis,
        effects: &mut Vec<Effect>,
    ) {
        let (send_unacknowledged, send_next, our_initial_sequence) = {
            let connection = &self.connections[index];
            (
                connection.send_unacknowledged,
                connection.send_next,
                connection.our_initial_sequence,
            )
        };
        if sequence_difference(send_unacknowledged, acknowledgment) < 0 {
            // Already acknowledged, or a duplicate ACK.
            self.maybe_finish(index, effects);
            return;
        }
        if sequence_difference(send_next, acknowledgment) > 0 {
            // Beyond anything we sent: ignore instead of trusting a bogus ACK.
            return;
        }
        let mut advanced = false;
        {
            let connection = &mut self.connections[index];
            while let Some(oldest) = connection.unacknowledged.front() {
                let end = sequence_add(oldest.sequence, oldest.length);
                // Stop at the first segment this ACK does not fully cover. A
                // cumulative ACK spans several segments, so this compares end
                // against ack and not the other way round — inverting it stalls
                // the flow after its first window of data.
                if sequence_difference(acknowledgment, end) > 0 {
                    break;
                }
                connection.unacknowledged.pop_front();
                connection.send_unacknowledged = end;
                advanced = true;
            }
            if advanced {
                connection.retransmits = 0;
                connection.retransmit_timeout = self.config.initial_rto_ms;
            }
            if !connection.handshake_complete
                && sequence_difference(
                    connection.send_unacknowledged,
                    sequence_add(our_initial_sequence, 1),
                ) >= 0
            {
                connection.handshake_complete = true;
            }
        }
        if self.connections[index].fin_sent && self.connections[index].unacknowledged.is_empty() {
            self.dispose(index, false, effects);
            self.retain_live();
            return;
        }
        self.flush(index, now, effects);
    }

    fn run_timers(&mut self, index: usize, now: Millis, effects: &mut Vec<Effect>) {
        let (idle_deadline, retransmit_at) = {
            let connection = &self.connections[index];
            (connection.idle_deadline, connection.retransmit_at)
        };
        if now >= idle_deadline {
            effects.push(Effect::Error(format!(
                "terminated flow {} went idle",
                self.connections[index].key.describe()
            )));
            self.dispose(index, true, effects);
            return;
        }
        let Some(due) = retransmit_at else { return };
        if now < due {
            return;
        }
        let (retransmits, maximum) = (
            self.connections[index].retransmits,
            self.config.maximum_retransmits,
        );
        if retransmits >= maximum {
            effects.push(Effect::Error(format!(
                "terminated flow {} gave up after {maximum} retransmits",
                self.connections[index].key.describe()
            )));
            self.dispose(index, true, effects);
            return;
        }
        let packet = self.connections[index]
            .unacknowledged
            .front()
            .map(|segment| segment.packet.clone());
        self.connections[index].retransmits = retransmits + 1;
        let timeout =
            (self.connections[index].retransmit_timeout * 2).min(self.config.maximum_rto_ms);
        self.connections[index].retransmit_timeout = timeout;
        self.connections[index].retransmit_at = Some(now + timeout);
        if let Some(packet) = packet {
            effects.push(Effect::EmitPacket(packet));
        }
    }

    fn dispose(&mut self, index: usize, reset: bool, effects: &mut Vec<Effect>) {
        if self.connections[index].state == State::Closed {
            return;
        }
        if reset {
            let packet = self.build(index, flag::RST, &[], None);
            effects.push(Effect::EmitPacket(packet));
        }
        let dial = self.connections[index].dial;
        let connection = &mut self.connections[index];
        connection.state = State::Closed;
        connection.retransmit_at = None;
        connection.unacknowledged.clear();
        connection.send_queue.clear();
        connection.pending_for_upstream.clear();
        effects.push(Effect::RelayClose { dial });
    }

    fn retain_live(&mut self) {
        self.connections
            .retain(|connection| connection.state != State::Closed);
    }
}

fn build_segment(
    connection: &Connection,
    config: &TerminatorConfig,
    flags: u8,
    payload: &[u8],
    mss: Option<u16>,
    sequence_override: Option<u32>,
    identification: u16,
) -> Vec<u8> {
    let params = TcpPacketParams {
        source: connection.key.server,
        destination: connection.key.client,
        source_port: connection.key.server_port,
        destination_port: connection.key.client_port,
        sequence: sequence_override.unwrap_or(connection.send_next),
        acknowledgment: connection.receive_next,
        flags,
        window: config.advertised_window,
        identification,
        ttl: 64,
        mss,
    };
    build_tcp(&params, payload)
}

fn connection_key(packet: &[u8], tcp: &TcpHeader<'_>) -> Option<ConnectionKey> {
    let ip = crate::packet::Ipv4Packet::parse(packet)?;
    Some(ConnectionKey {
        client: ip.source_address(),
        client_port: tcp.source_port(),
        server: ip.destination_address(),
        server_port: tcp.destination_port(),
    })
}
