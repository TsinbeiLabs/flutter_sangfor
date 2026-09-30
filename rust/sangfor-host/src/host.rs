//! The host event loop.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mio::{Events, Interest, Poll, Token, Waker};
use sangfor_core::flow::Millis;
use sangfor_core::plane::{DataPlane, PlaneEffect};
use sangfor_tun::PacketDevice;

use crate::channel::{ByteChannel, Connector, OpenedChannel};

/// The waker's token. Channel tokens start above it.
const WAKER_TOKEN: Token = Token(0);

/// Which plane identity a channel serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// An L3 node channel, carrying framed IP packets.
    Node(u64),
    /// A TCP-tunnel relay, carrying one terminated flow.
    Relay(u64),
}

impl Role {
    /// The plane's numeric id, regardless of kind.
    #[must_use]
    pub fn id(&self) -> u64 {
        match self {
            Self::Node(id) | Self::Relay(id) => *id,
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Node(id) => write!(f, "node {id}"),
            Self::Relay(id) => write!(f, "relay {id}"),
        }
    }
}

/// What the host noticed, for logging and for platform configuration.
#[derive(Debug, Clone)]
pub enum HostEvent {
    /// The gateway assigned a virtual IP. A desktop host configures the device
    /// address, routes, and DNS from this; a packet tunnel extension hands it to
    /// `setTunnelNetworkSettings`.
    VirtualIp(Vec<String>),
    /// A channel finished its handshake and was registered with the poller.
    ChannelOpened {
        /// Which plane identity it serves.
        role: Role,
        /// How the channel describes its peer.
        peer: String,
        /// The anti-MITM digest of its certificate, when it had one.
        digest: Option<String>,
    },
    /// A channel ended.
    ChannelClosed {
        /// Which plane identity it served.
        role: Role,
        /// Why, as far as the host can tell.
        reason: String,
    },
    /// A connect attempt failed before a channel existed.
    ConnectFailed {
        /// Which plane identity it was for.
        role: Role,
        /// The host that was dialled.
        host: String,
        /// The port that was dialled.
        port: u16,
        /// The error text.
        error: String,
    },
    /// A diagnostic worth logging.
    Log(String),
    /// The session cannot continue; the control plane must log in again.
    Fatal(String),
    /// The loop exited.
    Stopped,
}

/// Receives [`HostEvent`]s. Called from the host loop's thread, so an
/// implementation that touches UI or platform objects must hop threads itself.
pub trait HostObserver: Send + Sync + 'static {
    /// Handles one event.
    fn on_event(&self, event: HostEvent);
}

/// Counters the host adds to the plane's own.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Statistics {
    /// Packets read from the device and queued for the plane.
    pub device_packets: u64,
    /// Packets written to the device.
    pub emitted_packets: u64,
    /// Packets shed because the device queue was full.
    pub device_dropped: u64,
    /// Packets the device refused.
    pub emit_failures: u64,
    /// Bytes read from channels.
    pub channel_bytes_in: u64,
    /// Bytes written to channels.
    pub channel_bytes_out: u64,
    /// Channels currently open.
    pub channels_open: usize,
    /// Connects in flight on worker threads.
    pub connects_pending: usize,
    /// Connects that failed.
    pub connect_failures: u64,
    /// Connects refused because [`HostConfig::max_pending_connects`] was hit.
    pub connects_refused: u64,
    /// Writes deferred because a socket was full.
    pub writes_deferred: u64,
}

/// How the host behaves.
#[derive(Debug, Clone)]
pub struct HostConfig {
    /// How many device packets may be queued before the reader starts shedding.
    pub device_queue: usize,
    /// How many packets to hand the plane per loop iteration, so a busy device
    /// cannot starve socket readiness.
    pub max_packets_per_iteration: usize,
    /// How many reads to take from one channel per readiness event, for the same
    /// reason.
    pub max_reads_per_event: usize,
    /// Read buffer size. Must be at least the device MTU.
    pub read_buffer: usize,
    /// How many connects may be in flight. A burst of new flows spawns one
    /// worker thread each, and an unbounded burst is how a tunnel process runs
    /// out of threads.
    pub max_pending_connects: usize,
    /// The longest the loop waits in `poll` before ticking timers anyway.
    pub max_poll_wait: Duration,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            device_queue: 1024,
            max_packets_per_iteration: 256,
            max_reads_per_event: 64,
            read_buffer: 65_536,
            max_pending_connects: 64,
            max_poll_wait: Duration::from_millis(250),
        }
    }
}

struct ChannelSlot {
    channel: Box<dyn ByteChannel>,
    role: Role,
    /// Bytes the plane produced that the socket has not accepted yet.
    pending: VecDeque<Vec<u8>>,
    paused: bool,
}

enum Command {
    Connected {
        role: Role,
        opened: OpenedChannel,
    },
    ConnectFailed {
        role: Role,
        host: String,
        port: u16,
        error: String,
    },
}

/// The result of one non-blocking write, as a value so the borrow of the
/// channel table can end before it is acted on.
enum WriteOutcome {
    /// [usize] bytes were accepted.
    Progress(usize),
    /// The socket is full; the rest must wait for writability.
    Blocked,
    /// The channel is unusable, for the given reason.
    Failed(String),
}

/// Stops a [`Host`] from another thread.
///
/// [`Host::stop`] needs `&mut self`, which the thread running [`Host::run`]
/// owns. A Windows service control handler, an iOS `stopTunnel`, or a test all
/// need to end the loop from outside, so they take a handle instead.
#[derive(Clone)]
pub struct HostHandle {
    running: Arc<AtomicBool>,
    waker: Arc<Waker>,
    device: Arc<dyn PacketDevice>,
}

impl HostHandle {
    /// Ends the loop. Idempotent, and safe to call more than once or after the
    /// host has already finished.
    ///
    /// Closing the device is what actually unblocks the reader thread; the flag
    /// alone would leave it parked for a whole poll interval.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        let _ = self.device.close();
        let _ = self.waker.wake();
    }

    /// True while the loop should keep running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

/// The data plane, a device, and the sockets between them.
///
/// See the crate docs for the threading model. The short version: [`Self::run`]
/// blocks, owns the plane, and is the only thing that touches it.
pub struct Host {
    plane: DataPlane,
    device: Arc<dyn PacketDevice>,
    connector: Arc<dyn Connector>,
    config: HostConfig,
    observer: Option<Arc<dyn HostObserver>>,

    poll: Poll,
    waker: Arc<Waker>,
    events: Events,

    channels: HashMap<Token, ChannelSlot>,
    tokens: HashMap<Role, Token>,
    next_token: usize,

    packet_tx: SyncSender<Vec<u8>>,
    packet_rx: Receiver<Vec<u8>>,
    command_tx: Sender<Command>,
    command_rx: Receiver<Command>,
    device_drops: Arc<AtomicU64>,

    running: Arc<AtomicBool>,
    reader: Option<JoinHandle<()>>,
    /// Effects produced while applying effects. A queue rather than recursion so
    /// a reconnect storm cannot grow the stack.
    deferred: VecDeque<PlaneEffect>,
    stats: Statistics,
    stopped: bool,
}

impl Host {
    /// Wraps an already built [plane] around [device], dialling through
    /// [connector].
    ///
    /// The plane is not started until [`Self::run`], so a host can inspect it
    /// first.
    ///
    /// # Errors
    ///
    /// Fails when the platform cannot provide a poller or a waker.
    pub fn new(
        plane: DataPlane,
        device: Arc<dyn PacketDevice>,
        connector: Arc<dyn Connector>,
        config: HostConfig,
    ) -> io::Result<Self> {
        let poll = Poll::new()?;
        let waker = Waker::new(poll.registry(), WAKER_TOKEN)?;
        let (packet_tx, packet_rx) = mpsc::sync_channel(config.device_queue.max(1));
        let (command_tx, command_rx) = mpsc::channel();
        Ok(Self {
            plane,
            device,
            connector,
            config,
            observer: None,
            events: Events::with_capacity(128),
            poll,
            waker: Arc::new(waker),
            channels: HashMap::new(),
            tokens: HashMap::new(),
            next_token: 1,
            packet_tx,
            packet_rx,
            command_tx,
            command_rx,
            device_drops: Arc::new(AtomicU64::new(0)),
            running: Arc::new(AtomicBool::new(true)),
            reader: None,
            deferred: VecDeque::new(),
            stats: Statistics::default(),
            stopped: false,
        })
    }

    /// Receives events. Call before [`Self::run`].
    pub fn set_observer(&mut self, observer: Arc<dyn HostObserver>) {
        self.observer = Some(observer);
    }

    /// The plane's own counters.
    #[must_use]
    pub fn plane_statistics(&self) -> sangfor_core::plane::Statistics {
        self.plane.statistics()
    }

    /// The host's counters.
    #[must_use]
    pub fn statistics(&self) -> Statistics {
        Statistics {
            device_dropped: self.device_drops.load(Ordering::Relaxed),
            channels_open: self.channels.len(),
            ..self.stats
        }
    }

    /// The virtual IP the gateway assigned, if the handshake completed.
    #[must_use]
    pub fn virtual_ip(&self) -> &[String] {
        self.plane.virtual_ip()
    }

    /// True once the handshake completed and the tunnel is carrying traffic.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.plane.is_active()
    }

    /// A handle that stops this host from another thread.
    #[must_use]
    pub fn handle(&self) -> HostHandle {
        HostHandle {
            running: Arc::clone(&self.running),
            waker: Arc::clone(&self.waker),
            device: Arc::clone(&self.device),
        }
    }

    /// Runs until the session ends, [`Self::stop`] is called, or the plane
    /// reports a fatal error.
    ///
    /// # Errors
    ///
    /// Returns the poller's error. A channel failing is *not* an error: it is
    /// reported to the plane, which decides whether to reconnect the node or
    /// fail the flow.
    pub fn run(&mut self) -> io::Result<()> {
        if self.reader.is_none() {
            self.spawn_reader();
        }
        let effects = self.plane.start(now_ms());
        self.apply(effects);
        while !self.stopped && self.running.load(Ordering::SeqCst) {
            self.drain_commands();
            self.drain_packets();
            let timeout = self.poll_timeout();
            self.poll.poll(&mut self.events, Some(timeout))?;
            let ready: Vec<Token> = self
                .events
                .iter()
                .filter(|event| event.is_readable() || event.is_writable())
                .map(|event| event.token())
                .collect();
            for token in ready {
                if token != WAKER_TOKEN {
                    self.pump(token);
                }
            }
            self.drain_commands();
            self.drain_packets();
            self.tick();
        }
        self.finish()
    }

    /// Stops the loop. The reader thread is joined and every channel closed.
    /// Idempotent, and safe to call from an observer.
    pub fn stop(&mut self) {
        self.stopped = true;
        self.running.store(false, Ordering::SeqCst);
        // Closing the device makes its read return, which is what actually ends
        // the reader thread; the flag alone would wait out a poll interval.
        let _ = self.device.close();
        let _ = self.waker.wake();
    }

    fn finish(&mut self) -> io::Result<()> {
        self.running.store(false, Ordering::SeqCst);
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        let effects = self.plane.close();
        self.apply(effects);
        let tokens: Vec<Token> = self.channels.keys().copied().collect();
        for token in tokens {
            self.drop_channel(token, "the session ended");
        }
        self.emit_event(HostEvent::Stopped);
        Ok(())
    }

    fn spawn_reader(&mut self) {
        let device = Arc::clone(&self.device);
        let sender = self.packet_tx.clone();
        let waker = Arc::clone(&self.waker);
        let running = Arc::clone(&self.running);
        let drops = Arc::clone(&self.device_drops);
        let capacity = self.config.read_buffer;
        self.reader = thread::Builder::new()
            .name("sangfor-device".to_string())
            .spawn(move || {
                let mut buffer = Vec::with_capacity(capacity);
                while running.load(Ordering::SeqCst) {
                    match device.read_packet(&mut buffer) {
                        Ok(Some(_)) => {
                            // One copy per packet: the queue owns its bytes and
                            // the reader reuses its buffer. A pool would remove
                            // the allocation at the cost of a second lock on the
                            // hot path.
                            let packet =
                                std::mem::replace(&mut buffer, Vec::with_capacity(capacity));
                            match sender.try_send(packet) {
                                Ok(()) => {
                                    let _ = waker.wake();
                                }
                                Err(TrySendError::Full(packet)) => {
                                    drops.fetch_add(1, Ordering::Relaxed);
                                    buffer = packet;
                                }
                                Err(TrySendError::Disconnected(_)) => break,
                            }
                        }
                        Ok(None) => continue,
                        // EOF or an error: the device is gone, so there is
                        // nothing left to pump.
                        Err(_) => break,
                    }
                }
            })
            .ok();
    }

    fn drain_packets(&mut self) {
        for _ in 0..self.config.max_packets_per_iteration {
            let Ok(packet) = self.packet_rx.try_recv() else {
                return;
            };
            self.stats.device_packets += 1;
            let effects = self.plane.handle_egress(&packet, now_ms());
            self.apply(effects);
            if self.stopped {
                return;
            }
        }
        // More are queued than one iteration takes; come back promptly instead
        // of waiting out a poll timeout.
        let _ = self.waker.wake();
    }

    fn drain_commands(&mut self) {
        while let Ok(command) = self.command_rx.try_recv() {
            match command {
                Command::Connected { role, opened } => {
                    self.stats.connects_pending = self.stats.connects_pending.saturating_sub(1);
                    self.adopt(role, opened);
                }
                Command::ConnectFailed {
                    role,
                    host,
                    port,
                    error,
                } => {
                    self.stats.connects_pending = self.stats.connects_pending.saturating_sub(1);
                    self.stats.connect_failures += 1;
                    self.emit_event(HostEvent::ConnectFailed {
                        role,
                        host,
                        port,
                        error: error.clone(),
                    });
                    self.report_connect_failure(role, &error);
                }
            }
            if self.stopped {
                return;
            }
        }
    }

    fn report_connect_failure(&mut self, role: Role, error: &str) {
        let effects = match role {
            Role::Node(id) => self.plane.on_node_failed(id, error, now_ms()),
            Role::Relay(id) => self.plane.on_dial_failed(id, error),
        };
        self.apply(effects);
    }

    fn begin_connect(&mut self, role: Role, host: String, port: u16) {
        if self.stats.connects_pending >= self.config.max_pending_connects {
            self.stats.connects_refused += 1;
            let error = format!(
                "too many connects in flight ({})",
                self.config.max_pending_connects
            );
            self.emit_event(HostEvent::ConnectFailed {
                role,
                host,
                port,
                error: error.clone(),
            });
            self.report_connect_failure(role, &error);
            return;
        }
        self.stats.connects_pending += 1;
        let connector = Arc::clone(&self.connector);
        let sender = self.command_tx.clone();
        let waker = Arc::clone(&self.waker);
        // A short-lived worker per connect: the handshake is the slow part, and
        // running it inline would stall every other channel. The thread ends as
        // soon as the socket is handed back.
        let spawned = thread::Builder::new()
            .name(format!("sangfor-connect-{role}"))
            .spawn(move || {
                let command = match connector.connect(&host, port) {
                    Ok(opened) => Command::Connected { role, opened },
                    Err(error) => Command::ConnectFailed {
                        role,
                        host,
                        port,
                        error: error.to_string(),
                    },
                };
                let _ = sender.send(command);
                let _ = waker.wake();
            });
        if spawned.is_err() {
            self.stats.connects_pending = self.stats.connects_pending.saturating_sub(1);
            self.report_connect_failure(role, "the operating system refused a new thread");
        }
    }

    fn adopt(&mut self, role: Role, opened: OpenedChannel) {
        let token = Token(self.next_token);
        self.next_token += 1;
        let peer = opened.channel.describe();
        let digest = opened.channel.peer_digest().map(str::to_string);
        self.channels.insert(
            token,
            ChannelSlot {
                channel: opened.channel,
                role,
                pending: VecDeque::new(),
                paused: false,
            },
        );
        self.tokens.insert(role, token);
        if let Err(error) = self.register(token) {
            self.emit_event(HostEvent::Log(format!(
                "registering {role} with the poller failed: {error}"
            )));
            self.drop_channel(token, "the poller refused it");
            self.report_connect_failure(role, &error.to_string());
            return;
        }
        self.emit_event(HostEvent::ChannelOpened { role, peer, digest });
        let effects = match role {
            Role::Node(id) => self.plane.on_node_connected(id, now_ms()),
            Role::Relay(id) => self.plane.on_dial_connected(id, now_ms()),
        };
        self.apply(effects);
    }

    fn interest(slot: &ChannelSlot) -> Interest {
        if slot.paused {
            // A paused relay must not be read from, or the host would keep
            // handing bytes to a terminator that asked us to stop. Writability
            // is still wanted so a queued backlog can drain.
            return Interest::WRITABLE;
        }
        let mut interest = Interest::READABLE;
        if !slot.pending.is_empty() {
            interest |= Interest::WRITABLE;
        }
        interest
    }

    fn register(&mut self, token: Token) -> io::Result<()> {
        let Some(slot) = self.channels.get_mut(&token) else {
            return Ok(());
        };
        let interest = Self::interest(slot);
        slot.channel.register(self.poll.registry(), token, interest)
    }

    fn reregister(&mut self, token: Token) {
        let Some(slot) = self.channels.get(&token) else {
            return;
        };
        let interest = Self::interest(slot);
        if let Some(slot) = self.channels.get_mut(&token) {
            let _ = slot
                .channel
                .reregister(self.poll.registry(), token, interest);
        }
    }

    fn pump(&mut self, token: Token) {
        let mut buffer = vec![0_u8; self.config.read_buffer];
        for _ in 0..self.config.max_reads_per_event {
            let Some(slot) = self.channels.get(&token) else {
                return;
            };
            if slot.paused {
                break;
            }
            let role = slot.role;
            // The borrow ends before the plane is touched: applying effects can
            // close this very channel, so nothing may be held across it.
            let read = {
                let slot = self
                    .channels
                    .get_mut(&token)
                    .expect("checked above with nothing in between");
                slot.channel.read(&mut buffer)
            };
            match read {
                Ok(0) => {
                    self.channel_ended(token, role, "the peer closed the connection");
                    return;
                }
                Ok(count) => {
                    self.stats.channel_bytes_in += count as u64;
                    let effects = match role {
                        Role::Node(id) => self.plane.on_node_data(id, &buffer[..count], now_ms()),
                        Role::Relay(id) => self.plane.on_relay_data(id, &buffer[..count], now_ms()),
                    };
                    self.apply(effects);
                    if self.stopped {
                        return;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => {
                    self.channel_ended(token, role, &error.to_string());
                    return;
                }
            }
        }
        self.flush(token);
    }

    /// Drains a channel's write queue.
    ///
    /// Buffers are popped out of the queue rather than written through a borrow
    /// of it, because applying an effect can close the very channel being
    /// written and nothing may stay borrowed from `self.channels` across that.
    fn flush(&mut self, token: Token) {
        'buffers: while let Some(mut buffer) = self.take_front(token) {
            let mut offset = 0_usize;
            loop {
                match self.write_some(token, &buffer[offset..]) {
                    WriteOutcome::Progress(count) => {
                        offset += count;
                        self.stats.channel_bytes_out += count as u64;
                        if offset >= buffer.len() {
                            continue 'buffers;
                        }
                    }
                    WriteOutcome::Blocked => {
                        buffer.drain(..offset);
                        self.put_front(token, buffer);
                        self.stats.writes_deferred += 1;
                        self.reregister(token);
                        return;
                    }
                    WriteOutcome::Failed(reason) => {
                        self.end_channel(token, &reason);
                        return;
                    }
                }
            }
        }
        self.finish_flush(token);
    }

    fn take_front(&mut self, token: Token) -> Option<Vec<u8>> {
        self.channels
            .get_mut(&token)
            .and_then(|slot| slot.pending.pop_front())
    }

    fn put_front(&mut self, token: Token, buffer: Vec<u8>) {
        if buffer.is_empty() {
            return;
        }
        if let Some(slot) = self.channels.get_mut(&token) {
            slot.pending.push_front(buffer);
        }
    }

    /// One write attempt, with every borrow released before it returns.
    fn write_some(&mut self, token: Token, bytes: &[u8]) -> WriteOutcome {
        let Some(slot) = self.channels.get_mut(&token) else {
            return WriteOutcome::Failed("the channel was already closed".to_string());
        };
        match slot.channel.write(bytes) {
            // A zero-length write on a byte stream means the peer takes no more.
            Ok(0) => WriteOutcome::Failed("the peer stopped accepting writes".to_string()),
            Ok(count) => WriteOutcome::Progress(count),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => WriteOutcome::Blocked,
            Err(error) => WriteOutcome::Failed(error.to_string()),
        }
    }

    fn finish_flush(&mut self, token: Token) {
        let Some(slot) = self.channels.get_mut(&token) else {
            return;
        };
        // Computed before the branch so the borrow of the channel table ends
        // here; `end_channel` needs `&mut self`.
        let result = slot.channel.flush();
        if let Err(error) = result {
            if error.kind() != io::ErrorKind::WouldBlock {
                self.end_channel(token, &error.to_string());
                return;
            }
        }
        self.reregister(token);
    }

    /// Ends the channel registered under [token].
    fn end_channel(&mut self, token: Token, reason: &str) {
        let Some(role) = self.channels.get(&token).map(|slot| slot.role) else {
            return;
        };
        self.channel_ended(token, role, reason);
    }

    fn queue(&mut self, role: Role, bytes: Vec<u8>) {
        if bytes.is_empty() {
            return;
        }
        let Some(token) = self.tokens.get(&role).copied() else {
            // The plane can emit for a channel whose connect already failed, and
            // it has already been told; dropping is correct.
            return;
        };
        if let Some(slot) = self.channels.get_mut(&token) {
            slot.pending.push_back(bytes);
        }
        self.flush(token);
    }

    fn close_write(&mut self, role: Role) {
        let Some(token) = self.tokens.get(&role).copied() else {
            return;
        };
        if let Some(slot) = self.channels.get_mut(&token) {
            let _ = slot.channel.close_write();
        }
    }

    fn set_paused(&mut self, role: Role, paused: bool) {
        let Some(token) = self.tokens.get(&role).copied() else {
            return;
        };
        if let Some(slot) = self.channels.get_mut(&token) {
            slot.paused = paused;
        }
        self.reregister(token);
    }

    fn close_channel(&mut self, role: Role) {
        let Some(token) = self.tokens.get(&role).copied() else {
            return;
        };
        self.drop_channel(token, "the plane closed it");
    }

    fn channel_ended(&mut self, token: Token, role: Role, reason: &str) {
        // Tell the plane first: it may reconnect the node, and the effects that
        // produces must not be applied to a channel that is still registered.
        let effects = match role {
            Role::Node(id) => self.plane.on_node_closed(id, reason, now_ms()),
            Role::Relay(id) => self.plane.on_relay_closed(id, now_ms()),
        };
        self.drop_channel(token, reason);
        self.apply(effects);
    }

    fn drop_channel(&mut self, token: Token, reason: &str) {
        let Some(mut slot) = self.channels.remove(&token) else {
            return;
        };
        let _ = slot.channel.deregister(self.poll.registry());
        let _ = slot.channel.close();
        self.tokens.remove(&slot.role);
        self.emit_event(HostEvent::ChannelClosed {
            role: slot.role,
            reason: reason.to_string(),
        });
    }

    fn emit(&mut self, packet: &[u8]) {
        match self.device.write_packet(packet) {
            Ok(()) => self.stats.emitted_packets += 1,
            Err(error) => {
                self.stats.emit_failures += 1;
                self.emit_event(HostEvent::Log(format!(
                    "writing to {} failed: {error}",
                    self.device.name()
                )));
            }
        }
    }

    /// Applies effects, including any the application itself produces.
    ///
    /// A work queue rather than recursion: a reconnect or a burst of dials makes
    /// effects produce effects, and a deep enough chain would overflow the stack
    /// inside a packet tunnel extension.
    fn apply(&mut self, effects: Vec<PlaneEffect>) {
        self.deferred.extend(effects);
        while let Some(effect) = self.deferred.pop_front() {
            match effect {
                PlaneEffect::ConnectNode {
                    connection,
                    host,
                    port,
                } => self.begin_connect(Role::Node(connection), host, port),
                PlaneEffect::Dial { dial, host, port } => {
                    self.begin_connect(Role::Relay(dial), host, port);
                }
                PlaneEffect::Send { connection, bytes } => {
                    self.queue(Role::Node(connection), bytes)
                }
                PlaneEffect::RelaySend { dial, bytes } => self.queue(Role::Relay(dial), bytes),
                PlaneEffect::CloseNode { connection } => self.close_channel(Role::Node(connection)),
                PlaneEffect::RelayClose { dial } => self.close_channel(Role::Relay(dial)),
                PlaneEffect::RelayCloseWrite { dial } => self.close_write(Role::Relay(dial)),
                PlaneEffect::RelayPause { dial, paused } => {
                    self.set_paused(Role::Relay(dial), paused);
                }
                PlaneEffect::EmitPacket(packet) => self.emit(&packet),
                PlaneEffect::VirtualIp(addresses) => {
                    self.emit_event(HostEvent::VirtualIp(addresses));
                }
                PlaneEffect::Error(message) => self.emit_event(HostEvent::Log(message)),
                PlaneEffect::Fatal(error) => {
                    self.emit_event(HostEvent::Fatal(error.to_string()));
                    self.stop();
                }
            }
        }
    }

    fn tick(&mut self) {
        let effects = self.plane.tick(now_ms());
        self.apply(effects);
    }

    fn poll_timeout(&self) -> Duration {
        self.plane
            .next_deadline()
            .map(|deadline| deadline.saturating_sub(now_ms()))
            .map_or(self.config.max_poll_wait, Duration::from_millis)
            .min(self.config.max_poll_wait)
    }

    fn emit_event(&mut self, event: HostEvent) {
        if let Some(observer) = &self.observer {
            observer.on_event(event);
        }
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        self.stop();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

/// Wall-clock milliseconds, matching what `sangfor-ffi` feeds the plane so the
/// two hosts age flows identically.
fn now_ms() -> Millis {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as Millis)
}

/// An observer that collects events, for tests and for a host that wants to
/// replay them.
#[derive(Debug, Default)]
pub struct RecordingObserver {
    events: std::sync::Mutex<Vec<HostEvent>>,
}

impl RecordingObserver {
    /// An empty recorder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Every event so far.
    #[must_use]
    pub fn events(&self) -> Vec<HostEvent> {
        self.events
            .lock()
            .map(|events| events.clone())
            .unwrap_or_default()
    }

    /// True when any recorded event matches [predicate].
    pub fn any(&self, predicate: impl Fn(&HostEvent) -> bool) -> bool {
        self.events().iter().any(predicate)
    }
}

impl HostObserver for RecordingObserver {
    fn on_event(&self, event: HostEvent) {
        if let Ok(mut events) = self.events.lock() {
            events.push(event);
        }
    }
}

/// Polls [check] until [predicate] holds or [timeout] elapses.
///
/// Tunnel state changes on threads the test does not control, so tests need to
/// wait for a condition rather than assert immediately.
///
/// # Errors
///
/// Returns the last observed value when the deadline passes.
pub fn wait_until<T>(
    timeout: Duration,
    mut check: impl FnMut() -> T,
    predicate: impl Fn(&T) -> bool,
) -> Result<T, T> {
    let deadline = Instant::now() + timeout;
    loop {
        let value = check();
        if predicate(&value) {
            return Ok(value);
        }
        if Instant::now() >= deadline {
            return Err(value);
        }
        thread::sleep(Duration::from_millis(5));
    }
}

/// True while [flag] says the session should continue. Exposed for hosts that
/// drive the plane themselves instead of calling [`Host::run`].
#[must_use]
pub fn is_running(flag: &AtomicBool) -> bool {
    flag.load(Ordering::SeqCst)
}
