//! Per-flow conntrack for the L3 plane.
//!
//! A flow has to be authenticated before the gateway will carry its packets,
//! and the auth round trip takes a network exchange. Until it completes, the
//! packets that triggered it are cached here and flushed with the token the
//! gateway returns — dropping them instead would make every new connection
//! lose its SYN.

use crate::error::Error;
use crate::packet::{build_packet_meta, PacketMeta, ICMP, TCP, UDP};

/// Monotonic milliseconds, supplied by the host. The core never reads a clock
/// so that everything stays deterministic under test.
pub type Millis = u64;

/// The five-tuple identity of a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    /// IP protocol number.
    pub protocol: u8,
    /// Source address, host order.
    pub source: u32,
    /// Source port.
    pub source_port: u16,
    /// Destination address, host order.
    pub destination: u32,
    /// Destination port.
    pub destination_port: u16,
}

impl FlowKey {
    /// Builds a key from parsed packet metadata.
    #[must_use]
    pub fn from_meta(meta: &PacketMeta) -> Self {
        Self {
            protocol: meta.protocol,
            source: meta.source_address,
            source_port: meta.source_port,
            destination: meta.destination_address,
            destination_port: meta.destination_port,
        }
    }

    /// The same flow seen from the other side.
    #[must_use]
    pub fn reversed(&self) -> Self {
        Self {
            protocol: self.protocol,
            source: self.destination,
            source_port: self.destination_port,
            destination: self.source,
            destination_port: self.source_port,
        }
    }

    /// `protocol:source:port-destination:port`, used in log lines and in the
    /// auth request's `url` field.
    #[must_use]
    pub fn url(&self, source_text: &str, destination_text: &str) -> String {
        format!(
            "{}:{}:{}-{}",
            crate::packet::protocol_name(self.protocol),
            destination_text,
            self.destination_port,
            source_text
        )
    }

    /// A stable description for diagnostics.
    #[must_use]
    pub fn describe(&self) -> String {
        format!(
            "{}:{}:{}->{}:{}",
            crate::packet::protocol_name(self.protocol),
            crate::packet::ipv4_text(self.source),
            self.source_port,
            crate::packet::ipv4_text(self.destination),
            self.destination_port
        )
    }
}

/// Where a flow is in its authentication lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowState {
    /// Waiting for the gateway's answer.
    Pending,
    /// Token received; packets flow.
    Authenticated,
    /// The gateway refused, or authentication timed out.
    Failed,
    /// Idle long enough to be forgotten.
    Expired,
}

/// One tracked flow.
#[derive(Debug)]
pub struct Flow {
    /// The id sent as `conntrackHash` and echoed back by the gateway.
    pub id: u64,
    /// The five-tuple.
    pub key: FlowKey,
    /// The resource that serves it.
    pub app_id: String,
    /// The node group that serves it.
    pub node_group_id: String,
    /// Packets waiting for the token.
    pub pending: Vec<Vec<u8>>,
    /// Lifecycle state.
    pub state: FlowState,
    /// The token, once authenticated.
    pub token: Option<String>,
    /// Why authentication failed, if it did.
    pub error: Option<Error>,
    /// True while an auth request is in flight.
    pub auth_requested: bool,
    /// When the in-flight auth gives up.
    pub auth_deadline: Option<Millis>,
    /// When a retry is allowed.
    pub auth_retry_at: Option<Millis>,
    /// How many auth attempts have timed out.
    pub auth_timeouts: u32,
    /// Last time the flow carried a packet.
    pub last_seen: Millis,
    /// When the flow is forgotten.
    pub expires_at: Millis,
}

/// TTLs, mirroring the reference client's conntrack.
pub mod ttl {
    use super::Millis;

    /// An established TCP flow.
    pub const TCP_ESTABLISHED: Millis = 6 * 60 * 60 * 1000;
    /// A UDP flow.
    pub const UDP: Millis = 120 * 1000;
    /// An ICMP flow.
    pub const ICMP: Millis = 30 * 1000;
    /// Anything else.
    pub const DEFAULT: Millis = 60 * 1000;
}

/// The flow table.
#[derive(Debug)]
pub struct FlowTracker {
    flows: Vec<Flow>,
    next_id: u64,
    /// Hard cap; the least recently seen flow is evicted when it is hit.
    pub max_flows: usize,
    /// Packets cached per flow while it authenticates.
    pub max_pending_packets: usize,
}

impl Default for FlowTracker {
    fn default() -> Self {
        Self {
            flows: Vec::new(),
            next_id: 0,
            // Smaller than the Dart/Swift tables on purpose: an extension has
            // a ~50 MB budget and 4k flows of cached packets would eat it.
            max_flows: 2048,
            max_pending_packets: 256,
        }
    }
}

impl FlowTracker {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The live flows.
    #[must_use]
    pub fn flows(&self) -> &[Flow] {
        &self.flows
    }

    /// The number of live flows.
    #[must_use]
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    /// True when the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    /// Finds a flow by its key.
    #[must_use]
    pub fn get(&self, key: &FlowKey) -> Option<&Flow> {
        self.flows.iter().find(|flow| flow.key == *key)
    }

    /// Finds a flow by its key, mutably.
    pub fn get_mut(&mut self, key: &FlowKey) -> Option<&mut Flow> {
        self.flows.iter_mut().find(|flow| flow.key == *key)
    }

    /// Finds a flow by the id the gateway echoed back.
    pub fn by_id(&self, id: u64) -> Option<&Flow> {
        self.flows.iter().find(|flow| flow.id == id)
    }

    /// Finds a flow by id, mutably.
    pub fn by_id_mut(&mut self, id: u64) -> Option<&mut Flow> {
        self.flows.iter_mut().find(|flow| flow.id == id)
    }

    /// Returns the id of the flow for [key], creating it when absent. Evicts
    /// expired flows first so a busy tunnel does not grow without bound.
    ///
    /// An id rather than a reference: the caller usually needs the tracker
    /// again immediately (to cache a packet, to mark an auth in flight), and
    /// holding a `&mut Flow` across that would alias the whole table.
    pub fn get_or_create(
        &mut self,
        key: FlowKey,
        app_id: &str,
        node_group_id: &str,
        now: Millis,
    ) -> u64 {
        self.remove_expired(now);
        if let Some(existing) = self.get_mut(&key) {
            existing.last_seen = now;
            return existing.id;
        }
        if self.flows.len() >= self.max_flows {
            if let Some(oldest) = self
                .flows
                .iter()
                .enumerate()
                .min_by_key(|(_, flow)| flow.last_seen)
                .map(|(index, _)| index)
            {
                self.flows.remove(oldest);
            }
        }
        self.next_id += 1;
        let id = self.next_id;
        self.flows.push(Flow {
            id,
            key,
            app_id: app_id.to_string(),
            node_group_id: node_group_id.to_string(),
            pending: Vec::new(),
            state: FlowState::Pending,
            token: None,
            error: None,
            auth_requested: false,
            auth_deadline: None,
            auth_retry_at: None,
            auth_timeouts: 0,
            last_seen: now,
            expires_at: now + ttl::DEFAULT,
        });
        id
    }

    /// Refreshes a flow's expiry from a packet that just travelled.
    pub fn observe(&mut self, key: &FlowKey, packet: &[u8], now: Millis) {
        let Some(flow) = self.get_mut(key) else {
            return;
        };
        flow.last_seen = now;
        flow.expires_at = now + ttl_for(packet);
    }

    /// Queues a packet while its flow is still unauthenticated. Returns false
    /// when the queue is full, which is the caller's cue to drop.
    pub fn cache_packet(&mut self, id: u64, packet: &[u8], now: Millis) -> bool {
        let limit = self.max_pending_packets;
        let Some(flow) = self.by_id_mut(id) else {
            return false;
        };
        if flow.state != FlowState::Pending || flow.pending.len() >= limit {
            return false;
        }
        flow.pending.push(packet.to_vec());
        flow.last_seen = now;
        true
    }

    /// Completes a flow. Returns the packets that were waiting so the caller
    /// can flush them with the new token.
    pub fn complete(
        &mut self,
        id: u64,
        token: Option<String>,
        error: Option<Error>,
    ) -> Vec<Vec<u8>> {
        let Some(index) = self.flows.iter().position(|flow| flow.id == id) else {
            return Vec::new();
        };
        if self.flows[index].state != FlowState::Pending {
            return Vec::new();
        }
        let packets = std::mem::take(&mut self.flows[index].pending);
        {
            let flow = &mut self.flows[index];
            flow.token = token;
            flow.error = error;
            flow.state = if flow.error.is_none() {
                FlowState::Authenticated
            } else {
                FlowState::Failed
            };
            flow.auth_deadline = None;
        }
        if self.flows[index].error.is_some() {
            self.flows.remove(index);
        }
        packets
    }

    /// Drops flows whose expiry has passed. Returns how many went.
    pub fn remove_expired(&mut self, now: Millis) -> usize {
        let before = self.flows.len();
        self.flows.retain(|flow| now <= flow.expires_at);
        before - self.flows.len()
    }

    /// Drops every flow.
    pub fn clear(&mut self) {
        self.flows.clear();
    }
}

fn ttl_for(packet: &[u8]) -> Millis {
    match build_packet_meta(packet).map(|meta| meta.protocol) {
        Some(TCP) => ttl::TCP_ESTABLISHED,
        Some(UDP) => ttl::UDP,
        Some(ICMP) => ttl::ICMP,
        _ => ttl::DEFAULT,
    }
}
