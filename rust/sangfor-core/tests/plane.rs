//! End-to-end data plane tests, driven entirely by the golden fixture: the
//! same session plan, handshake response, and packets the Dart reference
//! produces.
//!
//! This is the test that proves the pieces compose — node dial, authTunnel
//! handshake, route decisions, per-flow authentication, inbound frames, and
//! local TCP termination for the flows the gateway refuses to forward as raw
//! IP.

use sangfor_core::flow::Millis;
use sangfor_core::l3::Command;
use sangfor_core::packet::{build_tcp, flag, parse_ipv4, TcpPacketParams};
use sangfor_core::plan::SessionPlan;
use sangfor_core::plane::{ConnectionConfig, DataPlane, PlaneEffect, Statistics};
use sangfor_core::terminator::TerminatorConfig;
use sangfor_core::{crypto, json, l3, tcp_tunnel};

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

fn plan() -> SessionPlan {
    let fixture = fixture();
    SessionPlan::decode(text(&fixture, &["sessionPlan"]).as_bytes()).expect("the plan decodes")
}

fn plane() -> DataPlane {
    DataPlane::new(
        plan(),
        ConnectionConfig::default(),
        TerminatorConfig::default(),
        0x5eed,
    )
}

fn sends(effects: &[PlaneEffect]) -> Vec<Vec<u8>> {
    effects
        .iter()
        .filter_map(|effect| match effect {
            PlaneEffect::Send { bytes, .. } => Some(bytes.clone()),
            _ => None,
        })
        .collect()
}

fn emitted(effects: &[PlaneEffect]) -> Vec<Vec<u8>> {
    effects
        .iter()
        .filter_map(|effect| match effect {
            PlaneEffect::EmitPacket(packet) => Some(packet.clone()),
            _ => None,
        })
        .collect()
}

fn dials(effects: &[PlaneEffect]) -> Vec<(u64, String, u16)> {
    effects
        .iter()
        .filter_map(|effect| match effect {
            PlaneEffect::Dial { dial, host, port } => Some((*dial, host.clone(), *port)),
            _ => None,
        })
        .collect()
}

fn connections(effects: &[PlaneEffect]) -> Vec<(u64, String, u16)> {
    effects
        .iter()
        .filter_map(|effect| match effect {
            PlaneEffect::ConnectNode {
                connection,
                host,
                port,
            } => Some((*connection, host.clone(), *port)),
            _ => None,
        })
        .collect()
}

fn virtual_ips(effects: &[PlaneEffect]) -> Vec<Vec<String>> {
    effects
        .iter()
        .filter_map(|effect| match effect {
            PlaneEffect::VirtualIp(addresses) => Some(addresses.clone()),
            _ => None,
        })
        .collect()
}

fn client_packet(destination: &str, sequence: u32, flags: u8) -> Vec<u8> {
    build_tcp(
        &TcpPacketParams {
            source: parse_ipv4("10.0.0.42").expect("client"),
            destination: parse_ipv4(destination).expect("server"),
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

/// Brings the plane up: dial the major group, hand it the fixture's handshake
/// response, and return the connection id.
fn bring_up(plane: &mut DataPlane) -> u64 {
    let fixture = fixture();
    let now: Millis = 0;
    let effects = plane.start(now);
    let (connection, host, port) = connections(&effects).remove(0);
    assert_eq!(host, "203.0.113.9");
    assert_eq!(port, 441);

    let effects = plane.on_node_connected(connection, now);
    assert_eq!(
        crypto::hex_lower(&sends(&effects)[0]),
        text(&fixture, &["l3", "authTunnelRequestHex"]),
        "the plane opens with the authTunnel request"
    );

    let handshake = crypto::unhex(&text(&fixture, &["l3", "handshakeResponseHex"])).expect("hex");
    let effects = plane.on_node_data(connection, &handshake, now);
    assert_eq!(
        virtual_ips(&effects),
        vec![vec!["10.0.0.42".to_string()]],
        "the handshake yields the virtual IP"
    );
    assert!(plane.is_active());
    connection
}

#[test]
fn the_plane_opens_a_node_and_completes_the_handshake() {
    let mut plane = plane();
    assert!(!plane.is_active());
    bring_up(&mut plane);
    assert_eq!(plane.virtual_ip(), &["10.0.0.42".to_string()]);
}

#[test]
fn a_tcp_tunnel_only_flow_is_terminated_instead_of_dropped() {
    let mut plane = plane();
    let connection = bring_up(&mut plane);
    let _ = connection;

    // 10.9.0.0/16 is published for the TCP tunnel only, so the L3 matcher
    // refuses it; before the terminator existed this packet was dropped and the
    // connection hung with no reply.
    let effects = plane.handle_egress(&client_packet("10.9.1.2", 4000, flag::SYN), 0);
    assert_eq!(plane.statistics().terminated, 1);
    assert_eq!(plane.statistics().routed, 0);
    assert_eq!(
        dials(&effects),
        vec![(1, "10.9.1.2".to_string(), 443)],
        "the terminator dials the destination through the TCP tunnel"
    );
    let packets = emitted(&effects);
    assert_eq!(packets.len(), 1, "the client gets a SYN-ACK");
    let tcp = sangfor_core::packet::ip_payload_tcp(&packets[0]).expect("tcp");
    assert_eq!(tcp.flags(), flag::SYN | flag::ACK);
    assert_eq!(tcp.source_port(), 443);
}

#[test]
fn a_domain_published_resource_is_dialed_by_name_through_its_alias() {
    let mut plane = plane();
    bring_up(&mut plane);
    // 203.0.113.7 is what vpn.example.test resolved to; the plan's alias map
    // is what lets the terminator dial the domain and keep the resource's
    // identity (and therefore the right appId).
    let effects = plane.handle_egress(&client_packet("203.0.113.7", 4100, flag::SYN), 0);
    assert_eq!(plane.statistics().terminated, 1);
    assert_eq!(
        dials(&effects),
        vec![(1, "vpn.example.test".to_string(), 443)]
    );
}

#[test]
fn an_l3_preferred_flow_is_forwarded_as_raw_ip_and_authenticated() {
    let mut plane = plane();
    let connection = bring_up(&mut plane);

    let effects = plane.handle_egress(&client_packet("10.1.2.3", 5000, flag::SYN), 0);
    assert_eq!(plane.statistics().routed, 1);
    assert_eq!(plane.statistics().terminated, 0);
    let sent = sends(&effects);
    assert_eq!(
        sent.len(),
        1,
        "a new flow triggers exactly one auth request"
    );
    let frame = l3::decode_frame(&sent[0]).expect("a frame");
    assert_eq!(frame.command, Command::AuthRequest);
    let body: serde_json::Value = serde_json::from_slice(&frame.payload).expect("json");
    assert_eq!(body["appId"], "app-l3");
    assert_eq!(body["url"], "tcp:10.1.2.3:443");
    assert_eq!(body["conntrackHash"], 1);
    assert_eq!(body["ip"]["destAddr"], "10.1.2.3");
    assert_eq!(body["ip"]["srcPort"], 51000);
    assert_eq!(body["xRequestSig"].as_str().expect("sig").len(), 64);

    // Answering with a token flushes the queued packet as a data frame.
    let response = auth_response(1, "tok-77");
    let effects = plane.on_node_data(connection, &response, 0);
    let sent = sends(&effects);
    assert_eq!(sent.len(), 1, "the queued SYN is flushed once");
    assert_eq!(sent[0][0], 0x05);
    assert_eq!(sent[0][1], 0x14, "it is a data request");
    let token_len = usize::from(sent[0][2]);
    assert_eq!(&sent[0][3..3 + token_len], b"tok-77");

    // A second packet on the authenticated flow goes straight out.
    let effects = plane.handle_egress(&client_packet("10.1.2.3", 5001, flag::ACK), 0);
    assert_eq!(sends(&effects).len(), 1);
}

#[test]
fn inbound_data_frames_reach_the_local_stack() {
    let mut plane = plane();
    let connection = bring_up(&mut plane);
    let fixture = fixture();
    let sample = crypto::unhex(&text(&fixture, &["packet", "sampleHex"])).expect("hex");

    let mut frame = vec![0x05, 0x94];
    frame.extend_from_slice(&(sample.len() as u16).to_be_bytes());
    frame.extend_from_slice(&sample);
    let effects = plane.on_node_data(connection, &frame, 0);
    assert_eq!(emitted(&effects), vec![sample.clone()]);
    assert_eq!(plane.statistics().ingress, 1);

    // Two packets coalesced into one frame are split apart.
    let mut both = sample.clone();
    both.extend_from_slice(&sample);
    let mut frame = vec![0x05, 0x94];
    frame.extend_from_slice(&(both.len() as u16).to_be_bytes());
    frame.extend_from_slice(&both);
    let effects = plane.on_node_data(connection, &frame, 0);
    assert_eq!(emitted(&effects), vec![sample.clone(), sample]);
    assert_eq!(plane.statistics().ingress, 3);
}

#[test]
fn a_destination_no_resource_covers_is_counted_not_forwarded() {
    let mut plane = plane();
    let connection = bring_up(&mut plane);
    let effects = plane.handle_egress(&client_packet("192.0.2.7", 6000, flag::SYN), 0);
    assert_eq!(plane.statistics().unrouted, 1);
    assert!(sends(&effects).is_empty());
    assert!(emitted(&effects).is_empty());
    assert!(
        effects.iter().any(
            |effect| matches!(effect, PlaneEffect::Error(message) if message.contains("not routed"))
        ),
        "the first drops are logged"
    );
    let _ = connection;
}

#[test]
fn an_idle_tunnel_heartbeats_and_dies_after_three_misses() {
    let mut plane = plane();
    let connection = bring_up(&mut plane);

    // The first idle interval only consumes the "we wrote something" flag,
    // exactly like the reference client.
    let effects = plane.tick(5_000);
    assert!(sends(&effects).is_empty());

    let effects = plane.tick(10_000);
    assert_eq!(
        crypto::hex_lower(&sends(&effects)[0]),
        crypto::hex_lower(&l3::heartbeat_request())
    );

    let response = vec![0x05, 0x95, 0x00, 0x00];
    plane.on_node_data(connection, &response, 10_100);
    let effects = plane.tick(15_000);
    assert_eq!(sends(&effects).len(), 1, "another heartbeat goes out");
    assert!(
        !plane.is_active()
            || effects
                .iter()
                .all(|e| !matches!(e, PlaneEffect::CloseNode { .. }))
    );

    // Three unanswered heartbeats, then the fourth tick gives up — the same
    // "miss limit then fail" shape as the reference client.
    plane.tick(20_000);
    plane.tick(25_000);
    let effects = plane.tick(30_000);
    assert!(
        effects
            .iter()
            .any(|effect| matches!(effect, PlaneEffect::CloseNode { .. })),
        "a silent gateway tears the connection down"
    );
    assert!(!plane.is_active());

    // The retry reopens the same group.
    let effects = plane.tick(36_000);
    assert_eq!(connections(&effects).len(), 1);
    assert!(plane.statistics().reconnects >= 2);
}

#[test]
fn a_rejected_handshake_is_fatal_for_the_session() {
    let mut plane = plane();
    let effects = plane.start(0);
    let (connection, _, _) = connections(&effects).remove(0);
    plane.on_node_connected(connection, 0);
    // 0x05 0xD0 then an auth header with a non-zero status.
    let rejected = vec![0x05, 0xD0, 0x53, 0x01, 0x00, 0x00];
    let effects = plane.on_node_data(connection, &rejected, 0);
    assert!(
        effects.iter().any(|effect| matches!(
            effect,
            PlaneEffect::Fatal(error) if error.is_fatal_for_session()
        )),
        "the control plane has to log in again"
    );
}

#[test]
fn closing_releases_nodes_and_terminated_flows() {
    let mut plane = plane();
    let connection = bring_up(&mut plane);
    plane.handle_egress(&client_packet("10.9.1.2", 4000, flag::SYN), 0);
    assert_eq!(plane.statistics().terminated_flows, 1);

    let effects = plane.close();
    assert!(effects.iter().any(
        |effect| matches!(effect, PlaneEffect::CloseNode { connection: id } if *id == connection)
    ));
    assert!(
        effects
            .iter()
            .any(|effect| matches!(effect, PlaneEffect::RelayClose { .. })),
        "terminated flows close their relay streams"
    );
    assert_eq!(plane.statistics().terminated_flows, 0);
    assert!(plane
        .handle_egress(&client_packet("10.9.1.2", 4001, flag::SYN), 0)
        .is_empty());
}

#[test]
fn statistics_render_for_a_log_line() {
    let rendered = Statistics {
        egress: 3,
        routed: 1,
        terminated: 1,
        unrouted: 1,
        ingress: 2,
        egress_bytes: 180,
        ingress_bytes: 120,
        reconnects: 0,
        terminated_flows: 1,
        flows: 2,
    }
    .render();
    assert!(rendered.contains("egress=3"));
    assert!(rendered.contains("terminated=1"));
    assert!(rendered.contains("unrouted=1"));
}

/// Builds an auth response frame carrying a connect token.
fn auth_response(conntrack_hash: u64, token: &str) -> Vec<u8> {
    let payload = json::encode(&json::Json::object(vec![
        ("code".into(), json::Json::Int(0)),
        ("message".into(), json::Json::string("ok")),
        (
            "data".into(),
            json::Json::object(vec![
                (
                    "conntrackHash".into(),
                    json::Json::Int(conntrack_hash as i64),
                ),
                ("connectToken".into(), json::Json::string(token)),
            ]),
        ),
    ]));
    let mut frame = vec![0x05, 0x93, 0x00];
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(&payload);
    frame
}

#[test]
fn the_tcp_tunnel_dial_uses_the_signed_handshake() {
    // The terminator's dial is carried out by the host; this checks that the
    // request the host would send is the one the fixture pins.
    let fixture = fixture();
    let sign_key = crypto::unhex(&text(&fixture, &["signKeyHex"])).expect("hex");
    let request = tcp_tunnel::AuthRequest {
        sid: "REDACTED_SID".to_string(),
        app_id: "app-42".to_string(),
        url: "tcp://vpn.example.test:443".to_string(),
        device_id: "REDACTED_DEVICE".to_string(),
        connection_id: "REDACTED_CONNECTION".to_string(),
        proc_hash: text(&fixture, &["processFingerprint"]),
        user_name: "alice".to_string(),
        lang: "zh-CN".to_string(),
        dest_addr: "vpn.example.test:443".to_string(),
        dest_ip: Some("203.0.113.7".to_string()),
        rc_applied_info: 0,
        process: Some(sangfor_core::l3::ProcessInfo {
            name: "Luotopia".to_string(),
            path: "/var/mobile/Containers/Bundle/Application/Luotopia.app".to_string(),
            platform: "iOS".to_string(),
        }),
    };
    let message = tcp_tunnel::protocol::handshake_message(
        &request,
        &sign_key,
        "vpn.example.test",
        443,
        false,
    )
    .expect("handshake");
    assert_eq!(
        crypto::hex_lower(&message),
        text(&fixture, &["tcpTunnel", "handshakeHex"])
    );
}
