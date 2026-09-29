//! The data plane: node connections, route decisions, local TCP termination,
//! and the inbound packet stream.
//!
//! Like the rest of the crate this performs no I/O. The host (the iOS
//! extension, an Android service, a desktop daemon) drives it with four kinds
//! of call — transport bytes in, egress packets in, timer ticks, dial results —
//! and executes the [`PlaneEffect`]s that come back. That keeps one state
//! machine testable on a laptop and reusable across five platforms.

use std::collections::BTreeMap;

use crate::error::Error;
use crate::flow::{FlowKey, FlowState, FlowTracker, Millis};
use crate::l3::{self, AuthRequest, Command, Frame, FrameDecoder, HandshakeParser, IpInfo};
use crate::packet::{build_packet_meta, split_incoming_packets, TCP};
use crate::plan::SessionPlan;
use crate::route::{Route, RouteTable};
use crate::terminator::{Effect, TerminationPolicy, Terminator, TerminatorConfig};

/// What the host must do on the plane's behalf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlaneEffect {
    /// Ask the host to open a TLS channel to a node, then report back with
    /// [`DataPlane::on_node_connected`] or [`DataPlane::on_node_failed`].
    ConnectNode {
        /// Correlation id chosen by the plane.
        connection: u64,
        /// Node host.
        host: String,
        /// Node port.
        port: u16,
    },
    /// Send bytes on an established node channel.
    Send {
        /// The connection the bytes belong to.
        connection: u64,
        /// Protocol bytes.
        bytes: Vec<u8>,
    },
    /// Close a node channel.
    CloseNode {
        /// The connection to close.
        connection: u64,
    },
    /// Emit a raw IP packet towards the local stack.
    EmitPacket(Vec<u8>),
    /// Open a TCP-tunnel connection for a terminated flow.
    Dial {
        /// Correlation id.
        dial: u64,
        /// Host name to dial.
        host: String,
        /// Destination port.
        port: u16,
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
    /// Throttle a relay stream.
    RelayPause {
        /// The dial to throttle.
        dial: u64,
        /// True to stop delivering.
        paused: bool,
    },
    /// The gateway assigned (or changed) the client virtual IP.
    VirtualIp(Vec<String>),
    /// Something the host should log.
    Error(String),
    /// The session is dead; the control plane has to log in again.
    Fatal(Error),
}

/// Counters for the host's log line.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Statistics {
    /// Packets handed to the plane by the TUN.
    pub egress: u64,
    /// Packets forwarded as raw IP.
    pub routed: u64,
    /// Packets claimed by the terminator.
    pub terminated: u64,
    /// Packets no resource covers.
    pub unrouted: u64,
    /// Packets delivered to the local stack.
    pub ingress: u64,
    /// Egress bytes.
    pub egress_bytes: u64,
    /// Ingress bytes.
    pub ingress_bytes: u64,
    /// Node reconnects attempted.
    pub reconnects: u64,
    /// Live terminated flows.
    pub terminated_flows: usize,
    /// Tracked flows.
    pub flows: usize,
}

impl Statistics {
    /// A one-line rendering for logs.
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "egress={} routed={} terminated={} unrouted={} ingress={} reconnects={} flows={}",
            self.egress,
            self.routed,
            self.terminated,
            self.unrouted,
            self.ingress,
            self.reconnects,
            self.flows
        )
    }
}

/// Tuning for one node connection.
#[derive(Debug, Clone, Copy)]
pub struct ConnectionConfig {
    /// Heartbeat interval.
    pub heartbeat_interval_ms: Millis,
    /// Missed heartbeats before the connection is considered dead.
    pub heartbeat_miss_limit: u32,
    /// How long a flow auth may take.
    pub auth_timeout_ms: Millis,
    /// How often pending auths are scanned.
    pub auth_scan_interval_ms: Millis,
    /// How long to wait before retrying a refused auth.
    pub auth_retry_wait_ms: Millis,
    /// Auth attempts before a flow is failed.
    pub auth_max_attempts: u32,
    /// Flows authenticated per scan.
    pub auth_batch_size: usize,
    /// How long the initial handshake may take.
    pub connect_timeout_ms: Millis,
    /// Delay before a dropped connection is retried.
    pub reconnect_delay_ms: Millis,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval_ms: 5_000,
            heartbeat_miss_limit: 3,
            auth_timeout_ms: 5_000,
            auth_scan_interval_ms: 250,
            auth_retry_wait_ms: 10_000,
            auth_max_attempts: 3,
            auth_batch_size: 64,
            connect_timeout_ms: 10_000,
            reconnect_delay_ms: 5_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeState {
    /// The host has been asked to open the channel.
    Dialing,
    /// The channel is open; the authTunnel handshake is in flight.
    Handshaking,
    /// The tunnel is carrying traffic.
    Active,
    /// Waiting to retry.
    WaitingRetry,
    Closed,
}

#[derive(Debug)]
struct NodeConnection {
    id: u64,
    group: String,
    state: NodeState,
    decoder: FrameDecoder,
    handshake: HandshakeParser,
    data_stream: Vec<u8>,
    heartbeat_misses: u32,
    wrote_since_heartbeat: bool,
    next_heartbeat: Millis,
    next_auth_scan: Millis,
    retry_at: Option<Millis>,
    handshake_deadline: Millis,
    virtual_ip: Vec<String>,
}

/// The termination policy derived from a session plan: terminate exactly the
/// TCP flows the L3 plane refuses and the TCP tunnel can serve.
#[derive(Debug, Clone)]
pub struct PlanPolicy {
    table: RouteTable,
    dial_hosts: BTreeMap<u32, String>,
}

impl PlanPolicy {
    /// Builds the policy from [plan].
    #[must_use]
    pub fn new(plan: &SessionPlan) -> Self {
        let mut dial_hosts = BTreeMap::new();
        for (address, host) in &plan.dial_hosts {
            if let Some(parsed) = crate::packet::parse_ipv4(address) {
                dial_hosts.entry(parsed).or_insert_with(|| host.clone());
            }
        }
        Self {
            table: plan.route_table(),
            dial_hosts,
        }
    }

    /// The route table this policy matches against.
    #[must_use]
    pub fn table(&self) -> &RouteTable {
        &self.table
    }
}

impl TerminationPolicy for PlanPolicy {
    fn should_terminate(&self, destination: u32, port: u16) -> bool {
        if self.table.match_l3(destination, "tcp", port).is_some() {
            return false;
        }
        let host = self.dial_host(destination);
        self.table
            .match_tcp(host.as_deref().unwrap_or(""), port, true)
            .is_some()
            // An address with no alias can still match an IP-published resource.
            || self
                .table
                .match_tcp(&crate::packet::ipv4_text(destination), port, true)
                .is_some()
    }

    fn dial_host(&self, destination: u32) -> Option<String> {
        self.dial_hosts.get(&destination).cloned()
    }
}

/// The whole data plane for one session.
pub struct DataPlane {
    plan: SessionPlan,
    policy: PlanPolicy,
    config: ConnectionConfig,
    terminator: Terminator<PlanPolicy>,
    flows: FlowTracker,
    nodes: Vec<NodeConnection>,
    next_connection: u64,
    statistics: Statistics,
    virtual_ip: Vec<String>,
    closed: bool,
    unrouted_logs: u32,
}

impl DataPlane {
    /// Builds a plane for [plan]. [seed] makes the terminator's sequence
    /// numbers reproducible under test.
    #[must_use]
    pub fn new(
        plan: SessionPlan,
        config: ConnectionConfig,
        terminator_config: TerminatorConfig,
        seed: u64,
    ) -> Self {
        let policy = PlanPolicy::new(&plan);
        let terminator = Terminator::new(policy.clone(), terminator_config, seed);
        Self {
            plan,
            policy,
            config,
            terminator,
            flows: FlowTracker::new(),
            nodes: Vec::new(),
            next_connection: 0,
            statistics: Statistics::default(),
            virtual_ip: Vec::new(),
            closed: false,
            unrouted_logs: 0,
        }
    }

    /// The counters.
    #[must_use]
    pub fn statistics(&self) -> Statistics {
        Statistics {
            terminated_flows: self.terminator.connection_count(),
            flows: self.flows.len(),
            ..self.statistics
        }
    }

    /// The virtual IP the gateway assigned, once known.
    #[must_use]
    pub fn virtual_ip(&self) -> &[String] {
        &self.virtual_ip
    }

    /// True when the major group's tunnel is carrying traffic.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.nodes
            .iter()
            .any(|node| node.group == self.plan.major_node_group && node.state == NodeState::Active)
    }

    /// Opens the tunnel for the major node group.
    pub fn start(&mut self, now: Millis) -> Vec<PlaneEffect> {
        self.open_node(&self.plan.major_node_group.clone(), now)
    }

    /// Routes one packet the local stack handed to the tunnel.
    pub fn handle_egress(&mut self, packet: &[u8], now: Millis) -> Vec<PlaneEffect> {
        if self.closed {
            return Vec::new();
        }
        self.statistics.egress += 1;
        self.statistics.egress_bytes += packet.len() as u64;

        // TCP flows the gateway refuses to forward as raw IP are terminated
        // locally and relayed through the TCP tunnel instead of being dropped.
        let (claimed, terminator_effects) = self.terminator.accept(packet, now);
        if claimed {
            self.statistics.terminated += 1;
            let mut mapped = Vec::with_capacity(terminator_effects.len());
            for effect in terminator_effects {
                self.push_terminator_effect(effect, &mut mapped);
            }
            return mapped;
        }

        let Some(meta) = build_packet_meta(packet) else {
            self.statistics.unrouted += 1;
            return Vec::new();
        };
        let destination = meta.destination_address;
        let Some(route) = self
            .policy
            .table
            .match_l3(destination, meta.protocol_name(), meta.destination_port)
            .cloned()
        else {
            self.statistics.unrouted += 1;
            if self.unrouted_logs < 10 {
                self.unrouted_logs += 1;
                return vec![PlaneEffect::Error(format!(
                    "packet not routed: {}:{} ({})",
                    meta.destination_text(),
                    meta.destination_port,
                    meta.protocol_name()
                ))];
            }
            return Vec::new();
        };
        self.statistics.routed += 1;
        let group = route.node_group_id.clone();
        let Some(node) = self
            .nodes
            .iter()
            .find(|node| node.group == group && node.state == NodeState::Active)
            .or_else(|| {
                self.nodes.iter().find(|node| {
                    node.group == self.plan.major_node_group && node.state == NodeState::Active
                })
            })
            .map(|node| node.id)
        else {
            // The connection is still coming up; TCP retransmits cover the gap.
            return self.open_node(&group, now);
        };
        self.send_packet(node, packet, &route, meta, now)
    }

    /// Drives heartbeats, auth retries, reconnects, and terminator timers.
    pub fn tick(&mut self, now: Millis) -> Vec<PlaneEffect> {
        if self.closed {
            return Vec::new();
        }
        let mut effects = Vec::new();
        self.flows.remove_expired(now);
        for index in 0..self.nodes.len() {
            self.run_node_timers(index, now, &mut effects);
        }
        for effect in self.terminator.tick(now) {
            self.push_terminator_effect(effect, &mut effects);
        }
        effects
    }

    /// The next moment [`DataPlane::tick`] has work to do.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Millis> {
        let node_deadlines = self.nodes.iter().filter_map(|node| match node.state {
            NodeState::Active => Some(node.next_heartbeat.min(node.next_auth_scan)),
            NodeState::Handshaking => Some(node.handshake_deadline),
            NodeState::WaitingRetry => node.retry_at,
            _ => None,
        });
        node_deadlines.chain(self.terminator.next_deadline()).min()
    }

    /// The host opened a node channel.
    pub fn on_node_connected(&mut self, connection: u64, now: Millis) -> Vec<PlaneEffect> {
        let Some(index) = self.nodes.iter().position(|node| node.id == connection) else {
            return Vec::new();
        };
        if self.nodes[index].state != NodeState::Dialing {
            return Vec::new();
        }
        self.nodes[index].state = NodeState::Handshaking;
        self.nodes[index].handshake_deadline = now + self.config.connect_timeout_ms;
        let sid = self.plan.sid.clone();
        match l3::auth_tunnel_request(&sid) {
            Ok(frame) => {
                self.nodes[index].wrote_since_heartbeat = true;
                vec![PlaneEffect::Send {
                    connection,
                    bytes: frame,
                }]
            }
            Err(error) => vec![PlaneEffect::Error(error.to_string())],
        }
    }

    /// The host could not reach a node.
    pub fn on_node_failed(
        &mut self,
        connection: u64,
        message: &str,
        now: Millis,
    ) -> Vec<PlaneEffect> {
        let Some(index) = self.nodes.iter().position(|node| node.id == connection) else {
            return Vec::new();
        };
        let group = self.nodes[index].group.clone();
        self.nodes[index].state = NodeState::WaitingRetry;
        self.nodes[index].retry_at = Some(now + self.config.reconnect_delay_ms);
        vec![PlaneEffect::Error(format!(
            "node dial failed for group {group}: {message}"
        ))]
    }

    /// Bytes arrived on a node channel.
    pub fn on_node_data(&mut self, connection: u64, chunk: &[u8], now: Millis) -> Vec<PlaneEffect> {
        let Some(index) = self.nodes.iter().position(|node| node.id == connection) else {
            return Vec::new();
        };
        if self.nodes[index].state == NodeState::Handshaking {
            return self.consume_handshake(index, chunk, now);
        }
        if self.nodes[index].state != NodeState::Active {
            return Vec::new();
        }
        self.consume_frames(index, chunk, now)
    }

    /// A node channel closed.
    pub fn on_node_closed(
        &mut self,
        connection: u64,
        message: &str,
        now: Millis,
    ) -> Vec<PlaneEffect> {
        let Some(index) = self.nodes.iter().position(|node| node.id == connection) else {
            return Vec::new();
        };
        let group = self.nodes[index].group.clone();
        self.nodes[index].state = NodeState::WaitingRetry;
        self.nodes[index].retry_at = Some(now + self.config.reconnect_delay_ms);
        vec![PlaneEffect::Error(format!(
            "node channel closed for group {group}: {message}"
        ))]
    }

    /// The host finished a TCP-tunnel dial for a terminated flow.
    pub fn on_dial_connected(&mut self, dial: u64, now: Millis) -> Vec<PlaneEffect> {
        let mut effects = Vec::new();
        for effect in self.terminator.on_dial_connected(dial, now) {
            self.push_terminator_effect(effect, &mut effects);
        }
        effects
    }

    /// The host could not dial a terminated flow.
    pub fn on_dial_failed(&mut self, dial: u64, message: &str) -> Vec<PlaneEffect> {
        let mut effects = Vec::new();
        for effect in self.terminator.on_dial_failed(dial, message) {
            self.push_terminator_effect(effect, &mut effects);
        }
        effects
    }

    /// Bytes arrived from a TCP-tunnel dial.
    pub fn on_relay_data(&mut self, dial: u64, data: &[u8], now: Millis) -> Vec<PlaneEffect> {
        let mut effects = Vec::new();
        for effect in self.terminator.on_relay_data(dial, data, now) {
            self.push_terminator_effect(effect, &mut effects);
        }
        effects
    }

    /// A TCP-tunnel dial ended.
    pub fn on_relay_closed(&mut self, dial: u64, now: Millis) -> Vec<PlaneEffect> {
        let mut effects = Vec::new();
        for effect in self.terminator.on_relay_closed(dial, now) {
            self.push_terminator_effect(effect, &mut effects);
        }
        effects
    }

    /// Tears the plane down.
    pub fn close(&mut self) -> Vec<PlaneEffect> {
        if self.closed {
            return Vec::new();
        }
        self.closed = true;
        let mut effects = Vec::new();
        for effect in self.terminator.close() {
            self.push_terminator_effect(effect, &mut effects);
        }
        for node in &self.nodes {
            if node.state != NodeState::Closed {
                effects.push(PlaneEffect::CloseNode {
                    connection: node.id,
                });
            }
        }
        self.nodes.clear();
        self.flows.clear();
        effects
    }

    // Internals.

    fn open_node(&mut self, group: &str, now: Millis) -> Vec<PlaneEffect> {
        if let Some(node) = self
            .nodes
            .iter()
            .find(|node| node.group == group && node.state != NodeState::Closed)
        {
            if node.state != NodeState::WaitingRetry {
                return Vec::new();
            }
        }
        let Some((host, port)) = self.plan.node_endpoint(group) else {
            return vec![PlaneEffect::Error(format!(
                "no node endpoint for group {group}"
            ))];
        };
        if self.plan.sign_key().is_none_or(|key| key.is_empty()) {
            return vec![PlaneEffect::Error("no signing key".to_string())];
        }
        self.next_connection += 1;
        let id = self.next_connection;
        self.statistics.reconnects += 1;
        self.nodes.push(NodeConnection {
            id,
            group: group.to_string(),
            state: NodeState::Dialing,
            decoder: FrameDecoder::new(),
            handshake: HandshakeParser::new(),
            data_stream: Vec::new(),
            heartbeat_misses: 0,
            wrote_since_heartbeat: false,
            next_heartbeat: now + self.config.heartbeat_interval_ms,
            next_auth_scan: now + self.config.auth_scan_interval_ms,
            retry_at: None,
            handshake_deadline: now + self.config.connect_timeout_ms,
            virtual_ip: Vec::new(),
        });
        vec![PlaneEffect::ConnectNode {
            connection: id,
            host,
            port,
        }]
    }

    fn consume_handshake(&mut self, index: usize, chunk: &[u8], now: Millis) -> Vec<PlaneEffect> {
        let mut effects = Vec::new();
        let parsed = match self.nodes[index].handshake.push(chunk) {
            Ok(parsed) => parsed,
            Err(error) => {
                let fatal = error.is_fatal_for_session();
                let connection = self.nodes[index].id;
                self.nodes[index].state = NodeState::Closed;
                effects.push(PlaneEffect::CloseNode { connection });
                if fatal {
                    effects.push(PlaneEffect::Fatal(error));
                } else {
                    effects.push(PlaneEffect::Error(error.to_string()));
                }
                return effects;
            }
        };
        let Some((result, leftover)) = parsed else {
            return effects;
        };
        let connection = self.nodes[index].id;
        self.nodes[index].state = NodeState::Active;
        self.nodes[index].next_heartbeat = now + self.config.heartbeat_interval_ms;
        self.nodes[index].next_auth_scan = now + self.config.auth_scan_interval_ms;
        self.nodes[index].virtual_ip = result.virtual_ip.clone();
        if !result.virtual_ip.is_empty() {
            self.virtual_ip = result.virtual_ip.clone();
            effects.push(PlaneEffect::VirtualIp(result.virtual_ip));
        }
        if !leftover.is_empty() {
            effects.extend(self.consume_frames(index, &leftover, now));
        }
        let _ = connection;
        effects
    }

    fn consume_frames(&mut self, index: usize, chunk: &[u8], now: Millis) -> Vec<PlaneEffect> {
        let mut effects = Vec::new();
        let frames = match self.nodes[index].decoder.push(chunk) {
            Ok(frames) => frames,
            Err(error) => {
                effects.push(PlaneEffect::Error(error.to_string()));
                return effects;
            }
        };
        for frame in frames {
            self.handle_frame(index, frame, now, &mut effects);
        }
        effects
    }

    fn handle_frame(
        &mut self,
        index: usize,
        frame: Frame,
        now: Millis,
        effects: &mut Vec<PlaneEffect>,
    ) {
        match frame.command {
            Command::DataResponse => {
                self.nodes[index]
                    .data_stream
                    .extend_from_slice(&frame.payload);
                let stream = std::mem::take(&mut self.nodes[index].data_stream);
                match split_incoming_packets(&stream) {
                    Ok((packets, remaining)) => {
                        let packets: Vec<Vec<u8>> =
                            packets.iter().map(|packet| packet.to_vec()).collect();
                        self.nodes[index].data_stream = remaining.to_vec();
                        for packet in packets {
                            if let Some(meta) = build_packet_meta(&packet) {
                                self.flows.observe(
                                    &FlowKey::from_meta(&meta.reversed()),
                                    &packet,
                                    now,
                                );
                            }
                            self.statistics.ingress += 1;
                            self.statistics.ingress_bytes += packet.len() as u64;
                            effects.push(PlaneEffect::EmitPacket(packet));
                        }
                    }
                    Err(error) => {
                        // A malformed stream would desynchronize forever; drop
                        // it and let the next frame resynchronize.
                        effects.push(PlaneEffect::Error(error.to_string()));
                    }
                }
            }
            Command::AuthResponse => self.handle_auth_response(index, &frame, now, effects),
            Command::SecondVipResponse => {
                if frame.status == 0 {
                    let addresses = l3::extract_vips(&frame.payload);
                    if !addresses.is_empty() {
                        self.virtual_ip = addresses.clone();
                        effects.push(PlaneEffect::VirtualIp(addresses));
                    }
                }
            }
            Command::HeartbeatResponse => {
                self.nodes[index].heartbeat_misses = 0;
            }
            _ => {}
        }
    }

    fn handle_auth_response(
        &mut self,
        index: usize,
        frame: &Frame,
        now: Millis,
        effects: &mut Vec<PlaneEffect>,
    ) {
        let parsed: serde_json::Value = match serde_json::from_slice(&frame.payload) {
            Ok(parsed) => parsed,
            Err(_) => return,
        };
        let data = parsed.get("data");
        let conntrack_hash = data
            .and_then(|value| value.get("conntrackHash"))
            .and_then(serde_json::Value::as_u64);
        let flow_id = match conntrack_hash {
            Some(id) if self.flows.by_id(id).is_some() => id,
            _ => match self.find_flow_by_ip(data) {
                Some(id) => id,
                None => return,
            },
        };
        match frame.status {
            0x84 => {
                self.retry_auth(flow_id, now, 0);
                return;
            }
            0x85..=0x87 => {
                self.retry_auth(flow_id, now, self.config.auth_retry_wait_ms);
                return;
            }
            0 => {}
            status => {
                self.flows.complete(
                    flow_id,
                    None,
                    Some(Error::FlowAuthFailed(format!("status {status}"))),
                );
                return;
            }
        }
        let code = data
            .and_then(|value| value.get("code"))
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0);
        if code != 0 {
            let message = data
                .and_then(|value| value.get("message"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            self.flows.complete(
                flow_id,
                None,
                Some(Error::FlowAuthFailed(format!("code {code}: {message}"))),
            );
            return;
        }
        let token = data
            .and_then(|value| value.get("connectToken"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string();
        let packets = self.flows.complete(flow_id, Some(token.clone()), None);
        let connection = self.nodes[index].id;
        for packet in packets {
            match l3::data_request(&token, &packet) {
                Ok(frame) => {
                    self.mark_write(index);
                    effects.push(PlaneEffect::Send {
                        connection,
                        bytes: frame,
                    });
                }
                Err(error) => effects.push(PlaneEffect::Error(error.to_string())),
            }
        }
    }

    fn retry_auth(&mut self, flow_id: u64, now: Millis, delay: Millis) {
        if let Some(flow) = self.flows.by_id_mut(flow_id) {
            if flow.state != FlowState::Pending {
                return;
            }
            flow.auth_requested = false;
            flow.auth_deadline = None;
            flow.auth_retry_at = Some(now + delay);
        }
    }

    fn find_flow_by_ip(&self, data: Option<&serde_json::Value>) -> Option<u64> {
        let ip = data?.get("ip")?;
        let source = ip.get("srcAddr")?.as_str()?;
        let destination = ip.get("destAddr")?.as_str()?;
        let source_port = ip.get("srcPort").and_then(serde_json::Value::as_u64);
        let destination_port = ip.get("destPort").and_then(serde_json::Value::as_u64);
        let protocol = ip.get("protocol").and_then(serde_json::Value::as_u64);
        if let Some(atype) = ip.get("atype").and_then(serde_json::Value::as_u64) {
            if atype != 0x0800 {
                return None;
            }
        }
        self.flows.flows().iter().find_map(|flow| {
            let key = &flow.key;
            if crate::packet::ipv4_text(key.source) != source {
                return None;
            }
            if crate::packet::ipv4_text(key.destination) != destination {
                return None;
            }
            if let Some(port) = source_port {
                if u64::from(key.source_port) != port {
                    return None;
                }
            }
            if let Some(port) = destination_port {
                if u64::from(key.destination_port) != port {
                    return None;
                }
            }
            if let Some(protocol) = protocol {
                if u64::from(key.protocol) != protocol {
                    return None;
                }
            }
            Some(flow.id)
        })
    }

    fn send_packet(
        &mut self,
        connection: u64,
        packet: &[u8],
        route: &Route,
        meta: crate::packet::PacketMeta,
        now: Millis,
    ) -> Vec<PlaneEffect> {
        let key = FlowKey::from_meta(&meta);
        let flow_id = self
            .flows
            .get_or_create(key, &route.app_id, &route.node_group_id, now);
        self.flows.observe(&key, packet, now);
        let (state, token) = match self.flows.by_id(flow_id) {
            Some(flow) => (flow.state, flow.token.clone()),
            None => return Vec::new(),
        };
        if state == FlowState::Authenticated {
            if let Some(token) = token {
                return match l3::data_request(&token, packet) {
                    Ok(frame) => {
                        if let Some(index) = self.node_index(connection) {
                            self.mark_write(index);
                        }
                        vec![PlaneEffect::Send {
                            connection,
                            bytes: frame,
                        }]
                    }
                    Err(error) => vec![PlaneEffect::Error(error.to_string())],
                };
            }
            return Vec::new();
        }
        if state != FlowState::Pending {
            return Vec::new();
        }
        if !self.flows.cache_packet(flow_id, packet, now) {
            return Vec::new();
        }
        self.dispatch_auths(connection, now)
    }

    fn dispatch_auths(&mut self, connection: u64, now: Millis) -> Vec<PlaneEffect> {
        let mut effects = Vec::new();
        let Some(index) = self.node_index(connection) else {
            return effects;
        };
        let Some(sign_key) = self.plan.sign_key() else {
            effects.push(PlaneEffect::Error("no signing key".to_string()));
            return effects;
        };
        let process = self.plan.process();
        let mut dispatched = 0;
        let candidates: Vec<u64> = self
            .flows
            .flows()
            .iter()
            .filter(|flow| {
                flow.state == FlowState::Pending
                    && !flow.pending.is_empty()
                    && !flow.auth_requested
                    && flow.auth_retry_at.is_none_or(|at| now >= at)
            })
            .take(self.config.auth_batch_size)
            .map(|flow| flow.id)
            .collect();
        for id in candidates {
            let Some(request) = self.auth_request(id, &process) else {
                continue;
            };
            let frame = match request.frame(&sign_key) {
                Ok(frame) => frame,
                Err(error) => {
                    effects.push(PlaneEffect::Error(error.to_string()));
                    continue;
                }
            };
            if let Some(flow) = self.flows.by_id_mut(id) {
                flow.auth_requested = true;
                flow.auth_deadline = Some(now + self.config.auth_timeout_ms);
            }
            self.mark_write(index);
            effects.push(PlaneEffect::Send {
                connection,
                bytes: frame,
            });
            dispatched += 1;
        }
        let _ = dispatched;
        effects
    }

    fn auth_request(&self, flow_id: u64, process: &l3::ProcessInfo) -> Option<AuthRequest> {
        let flow = self.flows.by_id(flow_id)?;
        let key = flow.key;
        Some(AuthRequest {
            sid: self.plan.sid.clone(),
            app_id: flow.app_id.clone(),
            url: format!(
                "{}:{}:{}",
                crate::packet::protocol_name(key.protocol),
                crate::packet::ipv4_text(key.destination),
                key.destination_port
            ),
            device_id: self.plan.device_id.clone(),
            connection_id: self.plan.connection_id.clone(),
            lang: self.plan.lang.clone(),
            conntrack_hash: i64::try_from(flow.id).unwrap_or(i64::MAX),
            ip: IpInfo {
                atype: 0x0800,
                protocol: key.protocol,
                destination_address: crate::packet::ipv4_text(key.destination),
                destination_port: key.destination_port,
                source_address: crate::packet::ipv4_text(key.source),
                source_port: key.source_port,
            },
            proc_hash: None,
            app_token: None,
            rc_applied_info: 0,
            process: Some(process.clone()),
            domain: None,
        })
    }

    fn run_node_timers(&mut self, index: usize, now: Millis, effects: &mut Vec<PlaneEffect>) {
        match self.nodes[index].state {
            NodeState::WaitingRetry => {
                let due = self.nodes[index].retry_at.is_some_and(|at| now >= at);
                if due {
                    let group = self.nodes[index].group.clone();
                    self.nodes[index].state = NodeState::Closed;
                    effects.extend(self.open_node(&group, now));
                }
            }
            NodeState::Handshaking => {
                if now >= self.nodes[index].handshake_deadline {
                    let connection = self.nodes[index].id;
                    let group = self.nodes[index].group.clone();
                    self.nodes[index].state = NodeState::WaitingRetry;
                    self.nodes[index].retry_at = Some(now + self.config.reconnect_delay_ms);
                    effects.push(PlaneEffect::CloseNode { connection });
                    effects.push(PlaneEffect::Error(format!(
                        "handshake timed out for group {group}"
                    )));
                }
            }
            NodeState::Active => {
                if now >= self.nodes[index].next_auth_scan {
                    self.nodes[index].next_auth_scan = now + self.config.auth_scan_interval_ms;
                    self.expire_auths(now, effects);
                    let connection = self.nodes[index].id;
                    effects.extend(self.dispatch_auths(connection, now));
                }
                if now >= self.nodes[index].next_heartbeat {
                    self.nodes[index].next_heartbeat = now + self.config.heartbeat_interval_ms;
                    self.heartbeat(index, now, effects);
                }
            }
            _ => {}
        }
    }

    fn expire_auths(&mut self, now: Millis, effects: &mut Vec<PlaneEffect>) {
        let mut failed = Vec::new();
        for flow in self.flows.flows() {
            let Some(deadline) = flow.auth_deadline else {
                continue;
            };
            if now < deadline {
                continue;
            }
            if flow.auth_timeouts + 1 < self.config.auth_max_attempts {
                failed.push((flow.id, None));
            } else {
                failed.push((flow.id, Some(Error::FlowAuthTimeout(flow.key.describe()))));
            }
        }
        for (id, error) in failed {
            if let Some(error) = error {
                self.flows.complete(id, None, Some(error));
            } else if let Some(flow) = self.flows.by_id_mut(id) {
                flow.auth_timeouts += 1;
                flow.auth_requested = false;
                flow.auth_deadline = None;
                flow.auth_retry_at = Some(now);
            }
        }
        let _ = effects;
    }

    fn heartbeat(&mut self, index: usize, now: Millis, effects: &mut Vec<PlaneEffect>) {
        let _ = now;
        if self.nodes[index].wrote_since_heartbeat {
            self.nodes[index].wrote_since_heartbeat = false;
            self.nodes[index].heartbeat_misses = 0;
            return;
        }
        if self.nodes[index].heartbeat_misses >= self.config.heartbeat_miss_limit {
            let misses = self.nodes[index].heartbeat_misses;
            let connection = self.nodes[index].id;
            let group = self.nodes[index].group.clone();
            self.nodes[index].state = NodeState::WaitingRetry;
            self.nodes[index].retry_at = Some(now + self.config.reconnect_delay_ms);
            effects.push(PlaneEffect::CloseNode { connection });
            effects.push(PlaneEffect::Error(format!(
                "heartbeat timed out for group {group} after {misses} misses"
            )));
            return;
        }
        self.nodes[index].heartbeat_misses += 1;
        let connection = self.nodes[index].id;
        effects.push(PlaneEffect::Send {
            connection,
            bytes: l3::heartbeat_request(),
        });
    }

    fn mark_write(&mut self, index: usize) {
        self.nodes[index].wrote_since_heartbeat = true;
    }

    fn node_index(&self, connection: u64) -> Option<usize> {
        self.nodes.iter().position(|node| node.id == connection)
    }

    fn push_terminator_effect(&mut self, effect: Effect, effects: &mut Vec<PlaneEffect>) {
        match effect {
            Effect::EmitPacket(packet) => {
                self.statistics.ingress += 1;
                self.statistics.ingress_bytes += packet.len() as u64;
                effects.push(PlaneEffect::EmitPacket(packet));
            }
            Effect::Dial { dial, host, port } => {
                effects.push(PlaneEffect::Dial { dial, host, port })
            }
            Effect::RelaySend { dial, bytes } => {
                effects.push(PlaneEffect::RelaySend { dial, bytes })
            }
            Effect::RelayCloseWrite { dial } => effects.push(PlaneEffect::RelayCloseWrite { dial }),
            Effect::RelayClose { dial } => effects.push(PlaneEffect::RelayClose { dial }),
            Effect::RelayPause { dial, paused } => {
                effects.push(PlaneEffect::RelayPause { dial, paused });
            }
            Effect::Error(message) => effects.push(PlaneEffect::Error(message)),
        }
    }
}

/// The TCP protocol number, re-exported for hosts that route packets
/// themselves.
pub const TCP_PROTOCOL: u8 = TCP;
