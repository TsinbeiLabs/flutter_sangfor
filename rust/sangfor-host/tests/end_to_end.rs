//! End to end: a packet device, the plane, real sockets, and a fake gateway.
//!
//! Everything the production path uses is here except the driver and the
//! certificate — [`LoopbackDevice`] stands in for wintun, and [`FakeConnector`]
//! stands in for TLS. The plane, the effect loop, the bounded queues, the
//! channel registry, and the framing are the real ones.
//!
//! The gateway replays the handshake recorded in the golden fixture, so the
//! bytes on the wire are the bytes the Dart reference produces. No privileges,
//! no driver, and no network beyond the loopback interface.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use sangfor_core::l3::Command;
use sangfor_core::packet::{build_tcp, flag, parse_ipv4, TcpPacketParams};
use sangfor_core::plan::SessionPlan;
use sangfor_core::plane::{ConnectionConfig, DataPlane};
use sangfor_core::terminator::TerminatorConfig;
use sangfor_core::{crypto, json};
use sangfor_host::{
    wait_until, Connector, Host, HostConfig, HostEvent, HostObserver, OpenedChannel,
    PlainByteChannel, RecordingObserver,
};
use sangfor_tun::LoopbackDevice;

const WAIT: Duration = Duration::from_secs(20);

fn fixture() -> serde_json::Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../packages/flutter_sangfor/test/fixtures/native_atrust.json");
    let raw = std::fs::read(path).expect("the golden fixture exists");
    serde_json::from_slice(&raw).expect("valid JSON")
}

fn text(value: &serde_json::Value, path: &[&str]) -> String {
    let mut node = value;
    for key in path {
        node = node.get(key).expect("fixture key");
    }
    node.as_str().expect("fixture string").to_string()
}

fn bytes(value: &serde_json::Value, path: &[&str]) -> Vec<u8> {
    crypto::unhex(&text(value, path)).expect("fixture hex")
}

fn plane() -> DataPlane {
    let fixture = fixture();
    let plan =
        SessionPlan::decode(text(&fixture, &["sessionPlan"]).as_bytes()).expect("the plan decodes");
    DataPlane::new(
        plan,
        ConnectionConfig::default(),
        TerminatorConfig::default(),
        0x5eed,
    )
}

/// An egress packet, shaped like the one the plane's own tests use.
fn client_packet(destination: &str, sequence: u32, flags: u8) -> Vec<u8> {
    build_tcp(
        &TcpPacketParams {
            source: parse_ipv4("10.0.0.42").expect("the fixture's virtual IP"),
            destination: parse_ipv4(destination).expect("a resource address"),
            source_port: 51000,
            destination_port: 443,
            sequence,
            acknowledgment: 0,
            flags,
            window: 65535,
            identification: 0,
            ttl: 64,
            mss: Some(1460),
        },
        &[],
    )
}

// ---------------------------------------------------------------------------
// The fake gateway
// ---------------------------------------------------------------------------

/// What the gateway saw, so a test asserts on the wire rather than guessing.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct GatewayLog {
    connections: usize,
    auth_requests: usize,
    data_requests: usize,
    heartbeats: usize,
    tcp_tunnel_handshakes: usize,
    /// The signed opening message a relay sent, before its hello.
    relay_opening: Option<Vec<u8>>,
    /// Reads on a relay that carried payload.
    relay_reads: usize,
    relay_first_payload: Option<Vec<u8>>,
}

/// Which kind of channel a connection turned out to be, decided by the opening
/// message rather than by what the test expected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// An L3 node channel, opened by `authTunnel` (`05 01 D0 53`).
    Node,
    /// A TCP-tunnel dial, opened by the signed handshake (`05 01 81 53`).
    Relay,
}

struct FakeGateway {
    port: u16,
    log: Arc<Mutex<GatewayLog>>,
    /// Never joined: the accept loop blocks until the process exits, which is
    /// fine for a test and avoids needing a shutdown path for the listener.
    _worker: JoinHandle<()>,
}

impl FakeGateway {
    /// Starts a gateway that answers the recorded handshake, authenticates
    /// every flow, and echoes [reply] back as an inbound data frame.
    fn start(handshake_response: Vec<u8>, reply: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
        let port = listener.local_addr().expect("a local address").port();
        let log = Arc::new(Mutex::new(GatewayLog::default()));
        let worker_log = Arc::clone(&log);
        let worker = thread::spawn(move || {
            // A node channel and a TCP-tunnel dial are independent connections
            // that both stay open, so each gets its own thread; serving them in
            // sequence would deadlock a test that expects both to be live.
            while let Ok((socket, _)) = listener.accept() {
                if let Ok(mut entry) = worker_log.lock() {
                    entry.connections += 1;
                }
                let handshake = handshake_response.clone();
                let reply = reply.clone();
                let log = Arc::clone(&worker_log);
                thread::spawn(move || {
                    let _ = serve(socket, &handshake, &reply, &log);
                });
            }
        });
        Self {
            port,
            log,
            _worker: worker,
        }
    }

    fn snapshot(&self) -> GatewayLog {
        self.log
            .lock()
            .map_or_else(|_| GatewayLog::default(), |log| log.clone())
    }
}

fn serve(
    mut socket: TcpStream,
    handshake_response: &[u8],
    reply: &[u8],
    log: &Arc<Mutex<GatewayLog>>,
) -> io::Result<()> {
    socket.set_read_timeout(Some(WAIT))?;
    socket.set_write_timeout(Some(WAIT))?;

    let mut buffer = Vec::new();
    let mut scratch = [0_u8; 8192];

    let Some(kind) = classify(&mut socket, &mut buffer, &mut scratch)? else {
        return Ok(());
    };
    // Consume the whole opening message. Leaving any of it buffered would wedge
    // the frame splitter behind a header shape it does not know — which is the
    // failure this test caught first.
    // Consume the whole opening message. Leaving any of it buffered would wedge
    // the frame splitter behind a header shape it does not know — which is the
    // failure this test caught first.
    let Some(opening) = take_opening(&mut socket, &mut buffer, &mut scratch, kind)? else {
        return Ok(());
    };

    match kind {
        Kind::Node => {
            socket.write_all(handshake_response)?;
            socket.flush()?;
            serve_node(&mut socket, &mut buffer, &mut scratch, reply, log)
        }
        Kind::Relay => {
            if let Ok(mut entry) = log.lock() {
                entry.tcp_tunnel_handshakes += 1;
                entry.relay_opening = Some(opening);
            }
            let fixture = fixture();
            socket.write_all(&bytes(&fixture, &["tcpTunnel", "serverResponseHex"]))?;
            socket.flush()?;
            serve_relay(&mut socket, &mut buffer, &mut scratch, log)
        }
    }
}

/// Reads until the opening message's first five bytes identify the channel.
fn classify(
    socket: &mut TcpStream,
    buffer: &mut Vec<u8>,
    scratch: &mut [u8],
) -> io::Result<Option<Kind>> {
    loop {
        if buffer.starts_with(&[0x05, 0x01, 0xd0, 0x53]) {
            return Ok(Some(Kind::Node));
        }
        if buffer.starts_with(&[0x05, 0x01, 0x81, 0x53]) {
            return Ok(Some(Kind::Relay));
        }
        if buffer.len() >= 5 {
            return Ok(None);
        }
        if !read_more(socket, buffer, scratch)? {
            return Ok(None);
        }
    }
}

/// Reads until the opening message is complete, consumes it from [buffer], and
/// returns it. `Ok(None)` means the peer hung up first.
fn take_opening(
    socket: &mut TcpStream,
    buffer: &mut Vec<u8>,
    scratch: &mut [u8],
    kind: Kind,
) -> io::Result<Option<Vec<u8>>> {
    loop {
        if let Some(length) = opening_length(buffer, kind) {
            if buffer.len() >= length {
                return Ok(Some(buffer.drain(..length).collect()));
            }
        }
        if !read_more(socket, buffer, scratch)? {
            return Ok(None);
        }
    }
}

/// The length of an opening message, or `None` until enough bytes have arrived
/// to know it.
fn opening_length(bytes: &[u8], kind: Kind) -> Option<usize> {
    if bytes.len() < 7 {
        return None;
    }
    let body = usize::from(u16::from_be_bytes([bytes[5], bytes[6]]));
    match kind {
        // 5 header + 2 length + body + a 10 byte trailer.
        Kind::Node => Some(5 + 2 + body + 10),
        // 5 header + 2 length + body + the destination record: 3 bytes of
        // header, a type-dependent address, and a 2 byte port.
        Kind::Relay => {
            let at = 5 + 2 + body;
            if bytes.len() < at + 5 {
                return None;
            }
            let address = match bytes[at + 3] {
                0x01 => 1 + 4,
                0x04 => 1 + 16,
                0x03 => 2 + usize::from(bytes[at + 4]),
                _ => return None,
            };
            Some(at + 3 + address + 2)
        }
    }
}

/// The L3 half: authenticate every flow, echo [reply] as an inbound packet.
fn serve_node(
    socket: &mut TcpStream,
    buffer: &mut Vec<u8>,
    scratch: &mut [u8],
    reply: &[u8],
    log: &Arc<Mutex<GatewayLog>>,
) -> io::Result<()> {
    loop {
        let frames = drain_frames(socket, buffer, scratch)?;
        if frames.is_empty() {
            return Ok(());
        }
        for frame in frames {
            match frame.command {
                Command::AuthRequest => {
                    if let Ok(mut entry) = log.lock() {
                        entry.auth_requests += 1;
                    }
                    socket.write_all(&auth_response(conntrack_hash(&frame.payload), "tok-e2e"))?;
                }
                Command::DataRequest => {
                    if let Ok(mut entry) = log.lock() {
                        entry.data_requests += 1;
                    }
                    socket.write_all(&data_response(reply))?;
                }
                Command::HeartbeatRequest => {
                    if let Ok(mut entry) = log.lock() {
                        entry.heartbeats += 1;
                    }
                    socket.write_all(&[0x05, 0x95, 0x00, 0x00])?;
                }
                _ => {}
            }
            socket.flush()?;
        }
    }
}

/// The TCP-tunnel half.
///
/// The fixture's hello offers no reuse, so the relay runs in raw mode and the
/// payload arrives as plain bytes rather than length-prefixed records. Each
/// chunk is recorded and echoed, which is enough for the terminator to keep
/// advancing the client's connection.
fn serve_relay(
    socket: &mut TcpStream,
    buffer: &mut Vec<u8>,
    scratch: &mut [u8],
    log: &Arc<Mutex<GatewayLog>>,
) -> io::Result<()> {
    loop {
        if !buffer.is_empty() {
            let payload = std::mem::take(buffer);
            if let Ok(mut entry) = log.lock() {
                entry.relay_reads += 1;
                if entry.relay_first_payload.is_none() {
                    entry.relay_first_payload = Some(payload.clone());
                }
            }
            socket.write_all(&payload)?;
            socket.flush()?;
        }
        if !read_more(socket, buffer, scratch)? {
            return Ok(());
        }
    }
}

/// Reads another chunk. `Ok(false)` means the peer is done.
fn read_more(socket: &mut TcpStream, buffer: &mut Vec<u8>, scratch: &mut [u8]) -> io::Result<bool> {
    match socket.read(scratch) {
        Ok(0) => Ok(false),
        Ok(count) => {
            buffer.extend_from_slice(&scratch[..count]);
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::TimedOut => Ok(false),
        Err(error) => Err(error),
    }
}

/// Splits whatever is buffered into whole frames, reading more if needed.
/// Returns an empty list when the peer hung up, which is how the loop ends.
fn drain_frames(
    socket: &mut TcpStream,
    buffer: &mut Vec<u8>,
    scratch: &mut [u8],
) -> io::Result<Vec<Received>> {
    loop {
        let frames = split_frames(buffer);
        if !frames.is_empty() {
            return Ok(frames);
        }
        if !read_more(socket, buffer, scratch)? {
            return Ok(Vec::new());
        }
    }
}

struct Received {
    command: Command,
    payload: Vec<u8>,
}

/// The server-side frame splitter.
///
/// The client's own decoder cannot be reused here: `DataRequest` puts the flow
/// token's length in the third byte rather than a payload length, a shape only
/// the sender produces. Everything else follows the ordinary layout.
fn split_frames(buffer: &mut Vec<u8>) -> Vec<Received> {
    let mut frames = Vec::new();
    while let Some(length) = frame_length(buffer) {
        if buffer.len() < length {
            break;
        }
        let raw: Vec<u8> = buffer.drain(..length).collect();
        let Some(command) = Command::from_u8(raw[1]) else {
            break;
        };
        // The JSON body of an auth request starts after version, command, and
        // length; other commands are not inspected closely enough to matter.
        let payload = if command == Command::AuthRequest {
            raw[4..].to_vec()
        } else {
            raw.clone()
        };
        frames.push(Received { command, payload });
    }
    frames
}

fn frame_length(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 4 || bytes[0] != 0x05 {
        return None;
    }
    let command = Command::from_u8(bytes[1])?;
    match command {
        Command::HeartbeatRequest | Command::HeartbeatResponse => Some(4),
        Command::DataRequest => {
            let token_length = usize::from(bytes[2]);
            let at = 3 + token_length + 3;
            if bytes.len() < at + 2 {
                return None;
            }
            let packet_length = usize::from(u16::from_be_bytes([bytes[at], bytes[at + 1]]));
            Some(at + 2 + packet_length)
        }
        Command::AuthResponse | Command::SecondVipResponse => {
            if bytes.len() < 5 {
                return None;
            }
            Some(5 + usize::from(u16::from_be_bytes([bytes[3], bytes[4]])))
        }
        _ => Some(4 + usize::from(u16::from_be_bytes([bytes[2], bytes[3]]))),
    }
}

fn conntrack_hash(payload: &[u8]) -> u64 {
    serde_json::from_slice::<serde_json::Value>(payload)
        .ok()
        .and_then(|body| {
            body.get("conntrackHash")
                .and_then(serde_json::Value::as_u64)
        })
        .unwrap_or(1)
}

/// The flow-auth answer, in the shape the plane's own tests use.
fn auth_response(conntrack_hash: u64, token: &str) -> Vec<u8> {
    let payload = json::encode(&json::Json::object(vec![
        ("code".into(), json::Json::Int(0)),
        ("message".into(), json::Json::string("ok")),
        (
            "data".into(),
            json::Json::object(vec![
                (
                    "conntrackHash".into(),
                    json::Json::Int(i64::try_from(conntrack_hash).unwrap_or(1)),
                ),
                ("connectToken".into(), json::Json::string(token)),
            ]),
        ),
    ]));
    let mut frame = vec![0x05, Command::AuthResponse as u8, 0x00];
    frame.extend_from_slice(&u16::try_from(payload.len()).unwrap_or(0).to_be_bytes());
    frame.extend_from_slice(&payload);
    frame
}

/// An inbound data frame carrying one raw IP packet.
fn data_response(packet: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x05, Command::DataResponse as u8];
    frame.extend_from_slice(&u16::try_from(packet.len()).unwrap_or(0).to_be_bytes());
    frame.extend_from_slice(packet);
    frame
}

// ---------------------------------------------------------------------------
// The connector that ignores the plan's addresses
// ---------------------------------------------------------------------------

/// Dials the fake gateway whatever the plan asked for: the plan names a
/// documentation-range address, and the test has to redirect it.
struct FakeConnector {
    port: u16,
}

impl Connector for FakeConnector {
    fn connect(&self, _host: &str, _port: u16) -> io::Result<OpenedChannel> {
        let socket = TcpStream::connect(("127.0.0.1", self.port))?;
        Ok(OpenedChannel {
            channel: Box::new(PlainByteChannel::new(socket)?),
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Builds a host over a loopback device, pointed at a fake gateway.
fn start_host(
    gateway: &FakeGateway,
) -> (
    Arc<LoopbackDevice>,
    Arc<RecordingObserver>,
    sangfor_host::HostHandle,
    JoinHandle<io::Result<()>>,
) {
    let device = Arc::new(LoopbackDevice::new("sangfor-e2e"));
    let connector = Arc::new(FakeConnector { port: gateway.port });
    let mut host = Host::new(
        plane(),
        Arc::clone(&device) as Arc<dyn sangfor_tun::PacketDevice>,
        connector,
        HostConfig::default(),
    )
    .expect("a host");
    let observer = Arc::new(RecordingObserver::new());
    host.set_observer(Arc::clone(&observer) as Arc<dyn HostObserver>);
    let handle = host.handle();
    let runner = thread::spawn(move || host.run());
    (device, observer, handle, runner)
}

fn wait_for_virtual_ip(observer: &RecordingObserver) {
    wait_until(
        WAIT,
        || observer.any(|event| matches!(event, HostEvent::VirtualIp(_))),
        |assigned| *assigned,
    )
    .unwrap_or_else(|_| panic!("no virtual IP; events: {:?}", observer.events()));
}

#[test]
fn a_packet_travels_from_the_device_to_the_gateway_and_back() {
    let fixture = fixture();
    let sample = bytes(&fixture, &["packet", "sampleHex"]);
    let gateway = FakeGateway::start(
        bytes(&fixture, &["l3", "handshakeResponseHex"]),
        sample.clone(),
    );
    let (device, observer, handle, runner) = start_host(&gateway);

    // The recorded handshake assigns 10.0.0.42; until that lands the plane
    // drops egress, so the test waits rather than racing.
    wait_for_virtual_ip(&observer);

    device.inject(client_packet("10.1.2.3", 5000, flag::SYN));

    let delivered = wait_until(
        WAIT,
        || device.take_written(),
        |packets| !packets.is_empty(),
    )
    .unwrap_or_else(|_| {
        panic!(
            "the gateway's reply never reached the device; gateway={:?} events={:?}",
            gateway.snapshot(),
            observer.events()
        )
    });
    assert!(
        delivered.iter().any(|packet| packet == &sample),
        "the inbound frame should reach the stack verbatim"
    );

    let log = wait_until(WAIT, || gateway.snapshot(), |log| log.data_requests >= 1)
        .unwrap_or_else(|last| panic!("the packet was never forwarded: {last:?}"));
    assert!(
        log.auth_requests >= 1,
        "the flow was authenticated: {log:?}"
    );

    handle.stop();
    runner
        .join()
        .expect("the host loop exited")
        .expect("cleanly");
}

#[test]
fn a_tcp_tunnel_only_destination_is_dialed_and_its_payload_relayed() {
    let fixture = fixture();
    let gateway = FakeGateway::start(
        bytes(&fixture, &["l3", "handshakeResponseHex"]),
        bytes(&fixture, &["packet", "sampleHex"]),
    );
    let (device, observer, handle, runner) = start_host(&gateway);
    wait_for_virtual_ip(&observer);

    // 10.9.0.0/16 is published for the TCP tunnel only, so the L3 matcher
    // refuses it and the terminator dials instead. This is the path that was
    // silently dropping packets before the terminator existed.
    let target = "10.9.1.2";
    device.inject(segment(target, 4000, 0, flag::SYN, &[]));

    // The dial is its own connection, and it opens with the signed handshake.
    let log = wait_until(
        WAIT,
        || gateway.snapshot(),
        |log| log.tcp_tunnel_handshakes >= 1,
    )
    .unwrap_or_else(|last| {
        panic!(
            "the terminator never dialed; gateway={last:?} events={:?}",
            observer.events()
        )
    });
    assert!(
        log.connections >= 2,
        "the dial is its own connection: {log:?}"
    );
    let opening = log.relay_opening.clone().expect("the opening message");
    let request = String::from_utf8_lossy(&opening);
    assert!(
        request.contains(&format!("tcp://{target}:443")),
        "the signed request names the destination: {request}"
    );
    assert!(
        request.contains("xRequestSig"),
        "the request is signed: {request}"
    );

    // A bare SYN carries no payload, so nothing is relayed yet. Complete the
    // handshake the terminator started, then send a body.
    let syn_ack = wait_until(
        WAIT,
        || device.take_written(),
        |packets| !packets.is_empty(),
    )
    .unwrap_or_else(|_| panic!("the terminator never answered the SYN; {log:?}"));
    let our_iss = syn_ack
        .iter()
        .find_map(|packet| sangfor_core::packet::ip_payload_tcp(packet))
        .expect("the reply is a TCP segment")
        .sequence_number();

    device.inject(segment(target, 4001, our_iss + 1, flag::ACK, &[]));
    let body = b"GET / HTTP/1.1\r\n\r\n";
    device.inject(segment(
        target,
        4001,
        our_iss + 1,
        flag::ACK | flag::PSH,
        body,
    ));

    let log = wait_until(WAIT, || gateway.snapshot(), |log| log.relay_reads >= 1).unwrap_or_else(
        |last| {
            panic!(
                "the payload never reached the gateway; gateway={last:?} events={:?}",
                observer.events()
            )
        },
    );
    assert_eq!(
        log.relay_first_payload.as_deref(),
        Some(&body[..]),
        "the relay carries the client's bytes verbatim"
    );

    handle.stop();
    runner
        .join()
        .expect("the host loop exited")
        .expect("cleanly");
}

/// A client TCP segment addressed to [target], from the plane's virtual IP.
fn segment(target: &str, sequence: u32, acknowledgment: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    build_tcp(
        &TcpPacketParams {
            source: parse_ipv4("10.0.0.42").expect("the fixture's virtual IP"),
            destination: parse_ipv4(target).expect("a resource address"),
            source_port: 51000,
            destination_port: 443,
            sequence,
            acknowledgment,
            flags,
            window: 65535,
            identification: 0,
            ttl: 64,
            mss: if flags & flag::SYN != 0 {
                Some(1460)
            } else {
                None
            },
        },
        payload,
    )
}

#[test]
fn stopping_the_host_closes_its_channels() {
    let fixture = fixture();
    let gateway = FakeGateway::start(
        bytes(&fixture, &["l3", "handshakeResponseHex"]),
        bytes(&fixture, &["packet", "sampleHex"]),
    );
    let (device, observer, handle, runner) = start_host(&gateway);
    wait_for_virtual_ip(&observer);
    assert!(
        observer.any(|event| matches!(event, HostEvent::ChannelOpened { .. })),
        "a node channel should have opened: {:?}",
        observer.events()
    );

    handle.stop();
    runner
        .join()
        .expect("the host loop exited")
        .expect("cleanly");

    assert!(
        observer.any(|event| matches!(event, HostEvent::ChannelClosed { .. })),
        "stopping should close the channel: {:?}",
        observer.events()
    );
    assert!(
        observer.any(|event| matches!(event, HostEvent::Stopped)),
        "the loop should announce its exit: {:?}",
        observer.events()
    );
    assert!(
        sangfor_tun::PacketDevice::is_closed(&*device),
        "the device is released"
    );
}

#[test]
fn the_frame_splitter_reads_the_layout_the_core_writes() {
    // Guards `split_frames` and `opening_length` against drifting from what the
    // core actually puts on the wire, using frames the Dart reference recorded.
    let fixture = fixture();

    let recorded = bytes(&fixture, &["l3", "dataRequestFrameHex"]);
    let mut buffer = recorded.clone();
    let frames = split_frames(&mut buffer);
    assert_eq!(frames.len(), 1, "one frame in, one frame out");
    assert_eq!(frames[0].command, Command::DataRequest);
    assert!(buffer.is_empty(), "the frame was consumed completely");

    // Two frames coalesced into one read are split apart.
    let mut both = recorded.clone();
    both.extend_from_slice(&recorded);
    assert_eq!(split_frames(&mut both).len(), 2);
    assert!(both.is_empty());

    // A partial frame is held back rather than guessed at.
    let mut partial = recorded[..recorded.len() - 1].to_vec();
    assert!(split_frames(&mut partial).is_empty());
    assert_eq!(partial.len(), recorded.len() - 1);

    // The opening message length must account for every byte, or the splitter
    // wedges — which is the bug this suite was written to catch.
    let auth_tunnel = bytes(&fixture, &["l3", "authTunnelRequestHex"]);
    assert_eq!(
        opening_length(&auth_tunnel, Kind::Node),
        Some(auth_tunnel.len()),
        "the authTunnel length rule must match the recorded frame"
    );
    let dial = bytes(&fixture, &["tcpTunnel", "handshakeHex"]);
    assert_eq!(
        opening_length(&dial, Kind::Relay),
        Some(dial.len()),
        "the TCP tunnel handshake length rule must match the recorded frame"
    );
}
