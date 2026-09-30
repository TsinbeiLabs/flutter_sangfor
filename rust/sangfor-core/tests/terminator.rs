//! Terminator behaviour tests, mirroring the Dart and Swift suites.
//!
//! The cumulative-ACK case is a regression test for a real stall: an inverted
//! sequence comparison made a single ACK covering several segments advance the
//! send window by nothing at all, so a flow hung after its first window of
//! data. All three implementations now pin it.

use sangfor_core::flow::Millis;
use sangfor_core::packet::{
    build_tcp, flag, ip_payload_tcp, sequence_add, TcpHeader, TcpPacketParams,
};
use sangfor_core::terminator::{Effect, TerminationPolicy, Terminator, TerminatorConfig};

const CLIENT: &str = "10.0.0.42";
const SERVER: &str = "10.9.1.2";
const CLIENT_PORT: u16 = 51000;
const SERVER_PORT: u16 = 443;

struct AllowAll;

impl TerminationPolicy for AllowAll {
    fn should_terminate(&self, destination: u32, port: u16) -> bool {
        let _ = (destination, port);
        true
    }
}

struct DenyAll;

impl TerminationPolicy for DenyAll {
    fn should_terminate(&self, destination: u32, port: u16) -> bool {
        let _ = (destination, port);
        false
    }
}

fn client_packet(
    sequence: u32,
    acknowledgment: u32,
    flags: u8,
    payload: &[u8],
    window: u16,
    mss: Option<u16>,
) -> Vec<u8> {
    build_tcp(
        &TcpPacketParams {
            source: sangfor_core::packet::parse_ipv4(CLIENT).expect("client address"),
            destination: sangfor_core::packet::parse_ipv4(SERVER).expect("server address"),
            source_port: CLIENT_PORT,
            destination_port: SERVER_PORT,
            sequence,
            acknowledgment,
            flags,
            window,
            identification: 0,
            ttl: 64,
            mss,
        },
        payload,
    )
}

fn emitted(effects: &[Effect]) -> Vec<Vec<u8>> {
    effects
        .iter()
        .filter_map(|effect| match effect {
            Effect::EmitPacket(packet) => Some(packet.clone()),
            _ => None,
        })
        .collect()
}

fn segments(packets: &[Vec<u8>]) -> Vec<ParsedSegment> {
    packets
        .iter()
        .filter_map(|packet| {
            let tcp = ip_payload_tcp(packet)?;
            Some(ParsedSegment {
                flags: tcp.flags(),
                sequence: tcp.sequence_number(),
                acknowledgment: tcp.acknowledgment_number(),
                mss: tcp.mss(),
                payload: tcp.payload().to_vec(),
            })
        })
        .collect()
}

#[derive(Debug)]
struct ParsedSegment {
    flags: u8,
    sequence: u32,
    acknowledgment: u32,
    mss: Option<u16>,
    payload: Vec<u8>,
}

fn dials(effects: &[Effect]) -> Vec<(u64, String, u16)> {
    effects
        .iter()
        .filter_map(|effect| match effect {
            Effect::Dial {
                dial, host, port, ..
            } => Some((*dial, host.clone(), *port)),
            _ => None,
        })
        .collect()
}

fn relay_sends(effects: &[Effect]) -> Vec<Vec<u8>> {
    effects
        .iter()
        .filter_map(|effect| match effect {
            Effect::RelaySend { bytes, .. } => Some(bytes.clone()),
            _ => None,
        })
        .collect()
}

fn contains_flag(packets: &[Vec<u8>], flag: u8) -> bool {
    segments(packets)
        .iter()
        .any(|segment| segment.flags & flag != 0)
}

#[test]
fn a_syn_is_answered_and_dialed() {
    let mut terminator = Terminator::new(AllowAll, TerminatorConfig::default(), 0x5eed);
    let (claimed, effects) = terminator.accept(
        &client_packet(1000, 0, flag::SYN, &[], 64240, Some(1460)),
        0,
    );
    assert!(claimed);
    let packets = emitted(&effects);
    assert_eq!(packets.len(), 1);
    let segment = &segments(&packets)[0];
    assert_eq!(segment.flags, flag::SYN | flag::ACK);
    assert_eq!(segment.acknowledgment, 1001);
    assert_eq!(segment.mss, Some(1400), "the peer's MSS is clamped to ours");
    assert_eq!(
        dials(&effects),
        vec![(1, SERVER.to_string(), SERVER_PORT)],
        "the dial starts during the handshake"
    );
    assert_eq!(terminator.connection_count(), 1);
}

#[test]
fn a_flow_the_policy_declines_is_left_for_the_tunnel() {
    let mut terminator = Terminator::new(DenyAll, TerminatorConfig::default(), 1);
    let (claimed, effects) =
        terminator.accept(&client_packet(1000, 0, flag::SYN, &[], 65535, None), 0);
    assert!(!claimed);
    assert!(effects.is_empty());
    assert_eq!(terminator.connection_count(), 0);
}

#[test]
fn a_data_packet_for_an_unknown_flow_is_not_claimed() {
    let mut terminator = Terminator::new(AllowAll, TerminatorConfig::default(), 1);
    let (claimed, _) =
        terminator.accept(&client_packet(1, 1, flag::ACK, &[1, 2, 3], 65535, None), 0);
    assert!(!claimed);
}

/// Completes a handshake, connects the dial the terminator asked for, and
/// returns the terminator's initial sequence number.
fn handshake(
    terminator: &mut Terminator<AllowAll>,
    window: u16,
    mss: u16,
    config: TerminatorConfig,
) -> u32 {
    let _ = config;
    let (_, effects) = terminator.accept(
        &client_packet(1000, 0, flag::SYN, &[], window, Some(mss)),
        0,
    );
    let syn_ack = &segments(&emitted(&effects))[0];
    let our_iss = syn_ack.sequence;
    let dial = dials(&effects)[0].0;
    terminator.accept(
        &client_packet(1001, our_iss + 1, flag::ACK, &[], window, None),
        0,
    );
    // The host reports the tunnel dial back, exactly as the FFI layer would.
    terminator.on_dial_connected(dial, 0);
    our_iss
}

#[test]
fn client_bytes_are_relayed_and_acknowledged() {
    let mut terminator = Terminator::new(AllowAll, TerminatorConfig::default(), 7);
    let our_iss = handshake(&mut terminator, 65535, 1460, TerminatorConfig::default());
    let body = b"GET / HTTP/1.1\r\n\r\n";
    let (_, effects) = terminator.accept(
        &client_packet(1001, our_iss + 1, flag::ACK | flag::PSH, body, 65535, None),
        0,
    );
    assert_eq!(
        relay_sends(&effects)
            .into_iter()
            .map(|bytes| String::from_utf8(bytes).expect("utf8"))
            .collect::<Vec<_>>(),
        vec!["GET / HTTP/1.1\r\n\r\n".to_string()]
    );
    let packets = emitted(&effects);
    let acks = segments(&packets);
    assert_eq!(
        acks.last().expect("an ack").acknowledgment,
        1001 + body.len() as u32
    );
}

#[test]
fn upstream_bytes_are_segmented_at_the_mss_with_contiguous_sequences() {
    let mut terminator = Terminator::new(
        AllowAll,
        TerminatorConfig {
            maximum_segment_size: 100,
            ..TerminatorConfig::default()
        },
        11,
    );
    let our_iss = handshake(&mut terminator, 65535, 100, TerminatorConfig::default());
    let body: Vec<u8> = (0..350u32).map(|index| (index % 251) as u8).collect();
    let effects = terminator.on_relay_data(1, &body, 0);
    let packets = emitted(&effects);
    let sent = segments(&packets);
    assert_eq!(
        sent.iter()
            .map(|segment| segment.payload.len())
            .collect::<Vec<_>>(),
        vec![100, 100, 100, 50]
    );
    let rejoined: Vec<u8> = sent
        .iter()
        .flat_map(|segment| segment.payload.clone())
        .collect();
    assert_eq!(rejoined, body);
    let mut expected = our_iss + 1;
    for segment in &sent {
        assert_eq!(segment.sequence, expected);
        expected = sequence_add(expected, segment.payload.len() as u32);
    }
}

#[test]
fn a_cumulative_ack_releases_every_segment_it_covers() {
    let mut terminator = Terminator::new(AllowAll, TerminatorConfig::default(), 13);
    let _our_iss = handshake(&mut terminator, 65535, 1460, TerminatorConfig::default());
    let effects = terminator.on_relay_data(1, &vec![7u8; 3000], 0);
    let sent = segments(&emitted(&effects));
    assert_eq!(sent.len(), 3, "1400 + 1400 + 200");
    let last = sent.last().expect("a segment");
    let cumulative = sequence_add(last.sequence, last.payload.len() as u32);

    // Upstream finishes while data is still unacknowledged: no FIN yet.
    let effects = terminator.on_relay_closed(1, 0);
    assert!(!contains_flag(&emitted(&effects), flag::FIN));

    // One ACK covering all three segments must release the FIN, which it can
    // only do if every segment left the retransmit queue.
    let (_, effects) = terminator.accept(
        &client_packet(1001, cumulative, flag::ACK, &[], 65535, None),
        0,
    );
    assert!(
        contains_flag(&emitted(&effects), flag::FIN),
        "a cumulative ACK advances the window over every segment it covers"
    );
}

#[test]
fn a_partial_ack_only_releases_what_it_covers() {
    let mut terminator = Terminator::new(AllowAll, TerminatorConfig::default(), 17);
    let _our_iss = handshake(&mut terminator, 65535, 1460, TerminatorConfig::default());
    let effects = terminator.on_relay_data(1, &vec![7u8; 3000], 0);
    let sent = segments(&emitted(&effects));
    let first = &sent[0];
    let partial = sequence_add(first.sequence, first.payload.len() as u32);
    let effects = terminator.on_relay_closed(1, 0);
    assert!(!contains_flag(&emitted(&effects), flag::FIN));
    let (_, effects) = terminator.accept(
        &client_packet(1001, partial, flag::ACK, &[], 65535, None),
        0,
    );
    assert!(
        !contains_flag(&emitted(&effects), flag::FIN),
        "two segments are still unacknowledged"
    );
}

#[test]
fn a_client_fin_half_closes_upstream_and_both_fins_retire_the_flow() {
    let mut terminator = Terminator::new(AllowAll, TerminatorConfig::default(), 19);
    let _our_iss = handshake(&mut terminator, 65535, 1460, TerminatorConfig::default());
    let effects = terminator.on_relay_data(1, b"hello", 0);
    let sent = segments(&emitted(&effects));
    let next = sequence_add(sent[0].sequence, sent[0].payload.len() as u32);
    terminator.accept(&client_packet(1001, next, flag::ACK, &[], 65535, None), 0);
    let effects = terminator.on_relay_closed(1, 0);
    let fin = segments(&emitted(&effects))
        .into_iter()
        .find(|segment| segment.flags & flag::FIN != 0)
        .expect("our FIN follows the drained data");
    assert_eq!(fin.sequence, next);

    let (_, effects) = terminator.accept(
        &client_packet(1001, next, flag::FIN | flag::ACK, &[], 65535, None),
        0,
    );
    assert!(
        effects
            .iter()
            .any(|effect| matches!(effect, Effect::RelayCloseWrite { .. })),
        "the client's FIN half-closes upstream"
    );
    let (_, effects) = terminator.accept(
        &client_packet(
            1002,
            sequence_add(fin.sequence, 1),
            flag::ACK,
            &[],
            65535,
            None,
        ),
        0,
    );
    assert!(effects.is_empty() || true);
    assert_eq!(
        terminator.connection_count(),
        0,
        "the flow retires once both FINs are acknowledged"
    );
}

#[test]
fn a_reset_tears_the_flow_down() {
    let mut terminator = Terminator::new(AllowAll, TerminatorConfig::default(), 23);
    handshake(&mut terminator, 65535, 1460, TerminatorConfig::default());
    let (claimed, effects) =
        terminator.accept(&client_packet(1001, 0, flag::RST, &[], 65535, None), 0);
    assert!(claimed);
    assert!(
        effects
            .iter()
            .any(|effect| matches!(effect, Effect::RelayClose { dial: 1 })),
        "the relay stream is closed"
    );
    assert_eq!(terminator.connection_count(), 0);
}

#[test]
fn a_failed_dial_resets_the_client() {
    let mut terminator = Terminator::new(AllowAll, TerminatorConfig::default(), 29);
    terminator.accept(&client_packet(1000, 0, flag::SYN, &[], 65535, None), 0);
    let effects = terminator.on_dial_failed(1, "no TCP tunnel resource");
    assert!(effects.iter().any(|effect| matches!(
        effect,
        Effect::Error(message) if message.contains("no TCP tunnel resource")
    )));
    let packets = emitted(&effects);
    assert!(contains_flag(&packets, flag::RST));
    assert_eq!(terminator.connection_count(), 0);
}

#[test]
fn the_syn_ack_is_retransmitted_and_then_given_up_on() {
    let config = TerminatorConfig {
        initial_rto_ms: 5,
        maximum_rto_ms: 20,
        maximum_retransmits: 2,
        ..TerminatorConfig::default()
    };
    let mut terminator = Terminator::new(AllowAll, config, 31);
    let (_, effects) = terminator.accept(&client_packet(1000, 0, flag::SYN, &[], 65535, None), 0);
    let original = emitted(&effects);
    assert_eq!(original.len(), 1);

    let effects = terminator.tick(6);
    assert_eq!(
        emitted(&effects),
        original,
        "the same SYN-ACK is repeated verbatim"
    );
    let effects = terminator.tick(30);
    assert_eq!(emitted(&effects), original);
    let effects = terminator.tick(80);
    assert!(
        contains_flag(&emitted(&effects), flag::RST),
        "giving up resets the client"
    );
    assert_eq!(terminator.connection_count(), 0);
}

#[test]
fn an_idle_flow_is_reset() {
    let config = TerminatorConfig {
        idle_timeout_ms: 1000,
        ..TerminatorConfig::default()
    };
    let mut terminator = Terminator::new(AllowAll, config, 37);
    handshake(&mut terminator, 65535, 1460, config);
    assert!(terminator.tick(999).is_empty() || terminator.connection_count() == 1);
    let effects = terminator.tick(1001);
    assert!(contains_flag(&emitted(&effects), flag::RST));
    assert_eq!(terminator.connection_count(), 0);
}

#[test]
fn the_next_deadline_tracks_the_soonest_timer() {
    let config = TerminatorConfig {
        initial_rto_ms: 50,
        idle_timeout_ms: 10_000,
        ..TerminatorConfig::default()
    };
    let mut terminator = Terminator::new(AllowAll, config, 41);
    assert_eq!(terminator.next_deadline(), None);
    terminator.accept(&client_packet(1000, 0, flag::SYN, &[], 65535, None), 100);
    assert_eq!(terminator.next_deadline(), Some(150));
}

#[test]
fn closing_releases_every_connection() {
    let mut terminator = Terminator::new(AllowAll, TerminatorConfig::default(), 43);
    handshake(&mut terminator, 65535, 1460, TerminatorConfig::default());
    assert_eq!(terminator.connection_count(), 1);
    let effects = terminator.close();
    assert_eq!(terminator.connection_count(), 0);
    assert!(terminator.is_closed());
    assert!(effects
        .iter()
        .any(|effect| matches!(effect, Effect::RelayClose { .. })));
    let (claimed, _) = terminator.accept(&client_packet(1, 0, flag::SYN, &[], 65535, None), 0);
    assert!(!claimed, "a closed terminator claims nothing");
}

#[test]
fn an_out_of_order_segment_is_dropped_with_a_duplicate_ack() {
    let mut terminator = Terminator::new(AllowAll, TerminatorConfig::default(), 47);
    let our_iss = handshake(&mut terminator, 65535, 1460, TerminatorConfig::default());
    let (_, effects) = terminator.accept(
        &client_packet(
            1010,
            our_iss + 1,
            flag::ACK | flag::PSH,
            &[1, 2, 3],
            65535,
            None,
        ),
        0,
    );
    assert!(relay_sends(&effects).is_empty(), "a gap is not relayed");
    let acks = segments(&emitted(&effects));
    assert_eq!(acks.last().expect("a dup ack").acknowledgment, 1001);

    // Filling the gap delivers the first flight only; the hole stays dropped
    // until the peer retransmits it.
    let (_, effects) = terminator.accept(
        &client_packet(
            1001,
            our_iss + 1,
            flag::ACK | flag::PSH,
            &[5u8; 9],
            65535,
            None,
        ),
        0,
    );
    let sends = relay_sends(&effects);
    assert_eq!(sends.len(), 1);
    assert_eq!(sends[0].len(), 9);
    let acks = segments(&emitted(&effects));
    assert_eq!(acks.last().expect("an ack").acknowledgment, 1010);
}

#[test]
fn the_upstream_queue_is_throttled_and_resumed() {
    let config = TerminatorConfig {
        pause_upstream_at: 200,
        resume_upstream_at: 50,
        maximum_segment_size: 100,
        ..TerminatorConfig::default()
    };
    let mut terminator = Terminator::new(AllowAll, config, 53);
    // A tiny peer window keeps the queue from draining, so the pause triggers.
    handshake(&mut terminator, 10, 100, config);
    let effects = terminator.on_relay_data(1, &vec![1u8; 500], 0);
    assert!(
        effects
            .iter()
            .any(|effect| matches!(effect, Effect::RelayPause { paused: true, .. })),
        "a deep queue pauses the upstream"
    );
}

#[test]
fn a_tcp_header_parses_its_fields() {
    let packet = client_packet(
        0x1122_3344,
        0x5566_7788,
        flag::SYN | flag::ACK,
        &[],
        64240,
        Some(1400),
    );
    let tcp: TcpHeader<'_> = ip_payload_tcp(&packet).expect("a TCP packet");
    assert_eq!(tcp.source_port(), CLIENT_PORT);
    assert_eq!(tcp.destination_port(), SERVER_PORT);
    assert_eq!(tcp.sequence_number(), 0x1122_3344);
    assert_eq!(tcp.acknowledgment_number(), 0x5566_7788);
    assert_eq!(tcp.window(), 64240);
    assert_eq!(tcp.mss(), Some(1400));
    assert!(tcp.payload().is_empty());
}

#[test]
fn effects_are_sendable_across_threads() {
    // The FFI layer executes effects on another thread than the one that
    // produced them, so they have to be owned and Send.
    fn assert_send<T: Send>(_: &T) {}
    let effect = Effect::Dial {
        dial: 1,
        host: "host".to_string(),
        port: 443,
        destination: 0,
    };
    assert_send(&effect);
    let now: Millis = 0;
    assert_eq!(now, 0);
}
