//! One TCP-tunnel relay, from dial to close.
//!
//! The terminator speaks plain TCP: it hands over the payload of a segment and
//! expects payload back. The gateway does not. A TCP-tunnel relay opens with a
//! signed authentication message, waits for the server's hello, and only then
//! carries bytes — framed, if the hello asked for reuse mode.
//!
//! This module is that translation, and it is why [`crate::tcp_tunnel`] exists
//! separately from [`crate::terminator`]: the terminator stays a pure TCP state
//! machine, and the wire protocol lives here where it can be tested against the
//! recorded hello with no socket in sight.
//!
//! The Dart reference is `ATrustTcpTunnelConn`. Two of its rules matter enough
//! to restate:
//!
//! - nothing may be sent before the hello arrives, so the terminator's first
//!   flight is held here rather than written to the wire;
//! - reuse mode is entered only when the dial asked for zero-RTT *and* the hello
//!   offered it. Every current caller dials without zero-RTT, so relays run
//!   raw; the framed path is implemented because a hello can ask for it.

use crate::error::Result;
use crate::tcp_tunnel::{self, AuthRequest, HandshakeDecoder, PayloadDecoder};

/// Where a relay is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// The host is still dialling.
    Connecting,
    /// The opening message is on the wire and the hello has not arrived.
    Handshaking,
    /// Payload flows in both directions.
    Open,
    /// The gateway refused the relay, or the wire protocol broke.
    Failed,
}

/// What a read from the wire turned into.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Payloads for the terminator. Empty while the hello is still arriving.
    Payloads(Vec<Vec<u8>>),
    /// The hello was accepted; these payloads came in the same read. The caller
    /// should release whatever [`Relay::flush`] returns before forwarding them,
    /// so the terminator's first flight still goes out ahead of the reply.
    Opened(Vec<Vec<u8>>),
    /// The gateway refused the relay, with its own reason.
    Refused(String),
}

/// The codec and buffers for one relay.
#[derive(Debug)]
pub struct Relay {
    dial: u64,
    /// `host:port` as dialled, which is also the `destAddr` the gateway signs.
    dest_addr: String,
    /// The address the flow was actually addressed to, host order. Distinct
    /// from `dest_addr` whenever the resource was published as a domain, and
    /// the gateway signs both.
    resolved: u32,
    state: State,
    handshake: HandshakeDecoder,
    payload: PayloadDecoder,
    /// Whether payload needs length-prefixed framing. Set from the hello, since
    /// `PayloadDecoder` keeps its own mode private.
    framed: bool,
    /// Whether this dial asked for zero-RTT. The gateway's reuse offer is only
    /// taken when both sides agree, matching the Dart client.
    zero_rtt: bool,
    /// Terminator output produced before the hello arrived.
    held: Vec<u8>,
    /// Why the relay failed, for the diagnostic the plane emits.
    failure: Option<String>,
}

impl Relay {
    /// A relay whose dial has not completed yet.
    ///
    /// [resolved] is the address the flow was addressed to, which is what the
    /// gateway signs as `destIP` when [dest_addr] is a domain name.
    #[must_use]
    pub fn connecting(dial: u64, dest_addr: impl Into<String>, resolved: u32) -> Self {
        Self {
            dial,
            dest_addr: dest_addr.into(),
            resolved,
            state: State::Connecting,
            handshake: HandshakeDecoder::new(),
            payload: PayloadDecoder::new(false),
            framed: false,
            zero_rtt: false,
            held: Vec::new(),
            failure: None,
        }
    }

    /// The dial this relay belongs to.
    #[must_use]
    pub fn dial(&self) -> u64 {
        self.dial
    }

    /// `host:port` as dialled.
    #[must_use]
    pub fn dest_addr(&self) -> &str {
        &self.dest_addr
    }

    /// The address the flow was addressed to, host order.
    #[must_use]
    pub fn resolved(&self) -> u32 {
        self.resolved
    }

    /// Where the relay is.
    #[must_use]
    pub fn state(&self) -> State {
        self.state
    }

    /// True when payload may flow.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.state == State::Open
    }

    /// Why the relay failed, once it has.
    #[must_use]
    pub fn failure(&self) -> Option<&str> {
        self.failure.as_deref()
    }

    /// True when the hello put this relay in framed (reuse) mode.
    #[must_use]
    pub fn is_framed(&self) -> bool {
        self.framed
    }

    /// Builds the signed opening message and moves to [`State::Handshaking`].
    ///
    /// [zero_rtt] is what the hello's `reuse` offer is ANDed with, matching the
    /// Dart client: a server may offer reuse, but only a zero-RTT dial takes it.
    ///
    /// # Errors
    ///
    /// Returns whatever the framing rejected — an oversized auth request, or a
    /// destination the protocol cannot encode.
    pub fn start(
        &mut self,
        request: &AuthRequest,
        sign_key: &[u8],
        zero_rtt: bool,
    ) -> Result<Vec<u8>> {
        let message = tcp_tunnel::protocol::handshake_message(
            request,
            sign_key,
            request_host(&self.dest_addr),
            dest_port(&self.dest_addr),
            zero_rtt,
        )?;
        self.state = State::Handshaking;
        self.zero_rtt = zero_rtt;
        Ok(message)
    }

    /// Marks the relay failed for a reason the caller discovered, and drops any
    /// held bytes.
    pub fn abort(&mut self, message: impl Into<String>) {
        self.state = State::Failed;
        self.failure = Some(message.into());
        self.held.clear();
    }

    /// Feeds bytes read from the wire.
    ///
    /// # Errors
    ///
    /// Returns a protocol error when the wire bytes do not parse. A hello the
    /// gateway *refused* is not an error: it arrives as [`Outcome::Refused`].
    pub fn receive(&mut self, chunk: &[u8]) -> Result<Outcome> {
        if self.state == State::Failed {
            return Ok(Outcome::Payloads(Vec::new()));
        }
        if self.state != State::Open {
            let Some(leftover) = self.handshake.push(chunk)? else {
                return Ok(Outcome::Payloads(Vec::new()));
            };
            let Some(response) = self.handshake.response().cloned() else {
                return Ok(Outcome::Payloads(Vec::new()));
            };
            if response.auth_code != 0 {
                let reason = format!(
                    "TCP tunnel authentication failed (code {}): {}",
                    response.auth_code, response.auth_message
                );
                self.abort(reason.clone());
                return Ok(Outcome::Refused(reason));
            }
            if response.connect_status != 0 {
                let reason = format!(
                    "TCP tunnel connect failed (status {}): {}",
                    response.connect_status,
                    tcp_tunnel::protocol::connect_status_message(response.connect_status)
                );
                self.abort(reason.clone());
                return Ok(Outcome::Refused(reason));
            }
            // Framing needs both sides to agree: the gateway offers reuse, and
            // only a zero-RTT dial takes it. Taking the offer unconditionally
            // would put length prefixes on the wire that the gateway reads as
            // payload.
            let framed = self.zero_rtt && response.reuse;
            self.payload = PayloadDecoder::new(framed);
            self.framed = framed;
            self.state = State::Open;
            return Ok(Outcome::Opened(self.decode(&leftover)?));
        }
        Ok(Outcome::Payloads(self.decode(chunk)?))
    }

    fn decode(&mut self, chunk: &[u8]) -> Result<Vec<Vec<u8>>> {
        if chunk.is_empty() {
            return Ok(Vec::new());
        }
        self.payload.push(chunk)
    }

    /// Wraps terminator output for the wire.
    ///
    /// Returns `None` when the bytes were held because the hello has not
    /// arrived; [`Self::flush`] releases them.
    ///
    /// # Errors
    ///
    /// Returns a protocol error when the payload cannot be framed.
    pub fn send(&mut self, payload: &[u8]) -> Result<Option<Vec<u8>>> {
        if payload.is_empty() {
            return Ok(None);
        }
        if self.state != State::Open {
            self.held.extend_from_slice(payload);
            return Ok(None);
        }
        Ok(Some(self.frame(payload)?))
    }

    /// Releases everything held while handshaking, framed if the hello asked
    /// for it.
    ///
    /// # Errors
    ///
    /// Returns a protocol error when the held bytes cannot be framed.
    pub fn flush(&mut self) -> Result<Option<Vec<u8>>> {
        if self.held.is_empty() || self.state != State::Open {
            return Ok(None);
        }
        let held = std::mem::take(&mut self.held);
        Ok(Some(self.frame(&held)?))
    }

    fn frame(&self, payload: &[u8]) -> Result<Vec<u8>> {
        if !self.framed {
            return Ok(payload.to_vec());
        }
        let mut out = Vec::new();
        for frame in tcp_tunnel::protocol::data_frames(payload)? {
            out.extend_from_slice(&frame);
        }
        Ok(out)
    }

    /// The wire bytes for a half-close, or `None` in raw mode, where a
    /// half-close is the transport's business rather than the protocol's.
    #[must_use]
    pub fn close_write(&self) -> Option<Vec<u8>> {
        if self.state == State::Open && self.framed {
            return Some(tcp_tunnel::protocol::eof_frame());
        }
        None
    }
}

/// The host half of a `host:port` destination.
fn request_host(dest_addr: &str) -> &str {
    match dest_addr.rsplit_once(':') {
        Some((host, _)) => host,
        None => dest_addr,
    }
}

/// The port half of a `host:port` destination, or 0 when it is absent.
fn dest_port(dest_addr: &str) -> u16 {
    dest_addr
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l3::ProcessInfo;

    /// The address the fixture's flows are destined for.
    fn resolved() -> u32 {
        crate::packet::parse_ipv4("203.0.113.7").expect("a valid address")
    }

    /// The golden fixture, for the recorded server hello.
    fn fixture() -> serde_json::Value {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../packages/flutter_sangfor/test/fixtures/native_atrust.json");
        let raw = std::fs::read(path).expect("the golden fixture exists");
        serde_json::from_slice(&raw).expect("valid JSON")
    }

    fn hex(value: &serde_json::Value, path: &[&str]) -> Vec<u8> {
        let mut node = value;
        for key in path {
            node = node.get(key).expect("fixture key");
        }
        crate::crypto::unhex(node.as_str().expect("fixture string")).expect("fixture hex")
    }

    /// The recorded hello from the fixture: `authCode` 0, connect status 0, no
    /// reuse.
    fn recorded_hello() -> Vec<u8> {
        hex(&fixture(), &["tcpTunnel", "serverResponseHex"])
    }

    /// Builds a server hello in the layout `parse_server_response` reads:
    /// `05 81 53 00 <auth length> <auth json> 05 <connect status>` and, when the
    /// status is zero, the reuse flag and the bound address.
    fn hello(auth_code: i64, auth_message: &str, connect_status: u8, reuse: bool) -> Vec<u8> {
        let body = crate::json::encode(&crate::json::Json::object(vec![
            ("code".into(), crate::json::Json::Int(auth_code)),
            ("message".into(), crate::json::Json::string(auth_message)),
        ]));
        let mut out = vec![0x05, 0x81, 0x53, 0x00];
        out.extend_from_slice(&u16::try_from(body.len()).unwrap_or(0).to_be_bytes());
        out.extend_from_slice(&body);
        out.push(0x05);
        out.push(connect_status);
        if connect_status != 0 {
            // The parser consumes four bytes past the auth payload either way.
            out.extend_from_slice(&[0x00, 0x00]);
            return out;
        }
        out.push(u8::from(reuse));
        out.push(0x01); // an IPv4 bound address
        out.extend_from_slice(&[10, 0, 0, 1]);
        out.extend_from_slice(&443_u16.to_be_bytes());
        out
    }

    fn request(dest_addr: &str) -> AuthRequest {
        AuthRequest {
            sid: "sid-1".to_string(),
            app_id: "app-tcp".to_string(),
            url: format!("tcp://{dest_addr}"),
            device_id: "device-1".to_string(),
            connection_id: "conn-1".to_string(),
            proc_hash: "0".repeat(64),
            user_name: "user".to_string(),
            lang: "en".to_string(),
            dest_addr: dest_addr.to_string(),
            dest_ip: None,
            rc_applied_info: 0,
            process: Some(ProcessInfo {
                name: "app".to_string(),
                path: "/app".to_string(),
                platform: "windows".to_string(),
            }),
        }
    }

    fn started(dest_addr: &str) -> Relay {
        let mut relay = Relay::connecting(7, dest_addr, resolved());
        relay
            .start(&request(dest_addr), &[0xAB; 32], false)
            .expect("the opening message builds");
        relay
    }

    #[test]
    fn the_opening_message_carries_the_dialled_destination() {
        // `tests/golden.rs` pins the handshake bytes against the Dart fixture;
        // this pins what `start` derives from the relay's own `dest_addr`, which
        // is the part that test cannot see.
        let dest = "vpn.example.test:443";
        let mut relay = Relay::connecting(7, dest, resolved());
        let key = [0xAB; 32];
        let message = relay.start(&request(dest), &key, false).expect("builds");
        let record = tcp_tunnel::protocol::destination_message("vpn.example.test", 443, false)
            .expect("a destination record");
        assert!(
            message.ends_with(&record),
            "the opening message must name the host and port that were dialled"
        );
        assert_eq!(relay.state(), State::Handshaking);

        // An address destination encodes differently, and must not be mistaken
        // for a name.
        let mut relay = Relay::connecting(8, "203.0.113.7:443", resolved());
        let message = relay
            .start(&request("203.0.113.7:443"), &key, false)
            .expect("builds");
        let record = tcp_tunnel::protocol::destination_message("203.0.113.7", 443, false)
            .expect("a destination record");
        assert!(
            message.ends_with(&record),
            "an IPv4 destination is encoded as an address, not a name"
        );
    }

    #[test]
    fn nothing_goes_out_before_the_hello_arrives() {
        let mut relay = started("vpn.example.test:443");
        // The terminator's first flight arrives while the hello is in flight.
        assert!(
            relay.send(b"first flight").expect("sendable").is_none(),
            "payload must be held until the relay is open"
        );
        assert!(!relay.is_open());

        let outcome = relay.receive(&recorded_hello()).expect("the hello parses");
        assert!(
            matches!(outcome, Outcome::Opened(ref payloads) if payloads.is_empty()),
            "an accepted hello opens the relay: {outcome:?}"
        );
        assert!(relay.is_open());
        assert!(!relay.is_framed(), "a non zero-RTT dial stays in raw mode");

        let flushed = relay.flush().expect("flushable").expect("held bytes");
        assert_eq!(flushed, b"first flight", "raw mode sends payload as-is");
        assert!(
            relay.flush().expect("flushable").is_none(),
            "the hold is drained once"
        );
    }

    #[test]
    fn payload_arriving_with_the_hello_is_returned_after_it() {
        let mut relay = started("vpn.example.test:443");
        let mut hello = recorded_hello();
        hello.extend_from_slice(b"trailing");
        match relay.receive(&hello).expect("the hello parses") {
            Outcome::Opened(payloads) => assert_eq!(payloads, vec![b"trailing".to_vec()]),
            other => panic!("expected an opened relay, got {other:?}"),
        }
    }

    #[test]
    fn an_incomplete_hello_waits() {
        let mut relay = started("vpn.example.test:443");
        let hello = recorded_hello();
        let split = hello.len() / 2;
        assert!(matches!(
            relay.receive(&hello[..split]).expect("parses"),
            Outcome::Payloads(ref payloads) if payloads.is_empty()
        ));
        assert!(!relay.is_open(), "half a hello is not a hello");
        assert!(matches!(
            relay.receive(&hello[split..]).expect("parses"),
            Outcome::Opened(_)
        ));
        assert!(relay.is_open());
    }

    #[test]
    fn a_refused_hello_fails_the_relay_with_the_gateways_reason() {
        let mut relay = started("vpn.example.test:443");
        match relay.receive(&hello(3, "denied", 0, false)) {
            Ok(Outcome::Refused(reason)) => {
                assert!(
                    reason.contains("code 3"),
                    "the reason names the code: {reason}"
                );
                assert!(
                    reason.contains("denied"),
                    "the reason carries the gateway's message: {reason}"
                );
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert_eq!(relay.state(), State::Failed);
        assert!(
            relay.failure().is_some_and(|text| text.contains("code 3")),
            "the failure is recorded for the diagnostic"
        );
        // Held bytes are dropped: sending them after a refusal would hand
        // payload to a gateway that rejected the flow.
        assert!(relay.send(b"late").expect("sendable").is_none());
        assert!(relay.flush().expect("flushable").is_none());
    }

    #[test]
    fn an_unreachable_destination_fails_with_its_status() {
        let mut relay = started("vpn.example.test:443");
        match relay.receive(&hello(0, "ok", 2, false)) {
            Ok(Outcome::Refused(reason)) => assert!(
                reason.contains("status 2"),
                "the reason names the connect status: {reason}"
            ),
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert_eq!(relay.state(), State::Failed);
    }

    #[test]
    fn a_closed_relay_ignores_late_bytes() {
        let mut relay = started("vpn.example.test:443");
        relay.abort("the host gave up");
        assert_eq!(relay.state(), State::Failed);
        assert!(matches!(
            relay.receive(b"anything").expect("parses"),
            Outcome::Payloads(ref payloads) if payloads.is_empty()
        ));
    }

    #[test]
    fn raw_mode_needs_no_eof_record_on_a_half_close() {
        let mut relay = started("vpn.example.test:443");
        relay.receive(&recorded_hello()).expect("the hello parses");
        assert!(relay.is_open());
        assert!(
            relay.close_write().is_none(),
            "a raw relay half-closes at the transport, matching the Dart client"
        );
    }

    #[test]
    fn framed_mode_wraps_payload_and_ends_with_an_eof_record() {
        let mut relay = Relay::connecting(9, "vpn.example.test:443", resolved());
        relay
            .start(&request("vpn.example.test:443"), &[0xCD; 32], true)
            .expect("the opening message builds");
        // A zero-RTT dial takes the reuse offer, and this hello makes one.
        assert!(matches!(
            relay.receive(&hello(0, "ok", 0, true)).expect("parses"),
            Outcome::Opened(_)
        ));
        assert!(relay.is_framed(), "a zero-RTT dial takes the reuse offer");

        let framed = relay.send(b"abc").expect("sendable").expect("wire bytes");
        assert_eq!(
            framed,
            tcp_tunnel::protocol::data_frame(b"abc").expect("one frame"),
            "framed mode length-prefixes the payload"
        );
        assert_eq!(
            relay.close_write().expect("an eof record"),
            tcp_tunnel::protocol::eof_frame()
        );

        // Inbound frames are unwrapped.
        let inbound = tcp_tunnel::protocol::data_frame(b"xyz").expect("one frame");
        match relay.receive(&inbound).expect("parses") {
            Outcome::Payloads(payloads) => assert_eq!(payloads, vec![b"xyz".to_vec()]),
            other => panic!("expected payloads, got {other:?}"),
        }
    }

    #[test]
    fn a_non_zero_rtt_dial_stays_raw_even_when_the_gateway_offers_reuse() {
        // The Dart client ANDs the offer with its own zero-RTT flag, so an
        // ordinary dial never frames. Getting this wrong would put length
        // prefixes on the wire that the gateway reads as payload.
        let mut relay = started("vpn.example.test:443");
        assert!(matches!(
            relay.receive(&hello(0, "ok", 0, true)).expect("parses"),
            Outcome::Opened(_)
        ));
        assert!(!relay.is_framed(), "reuse is only taken on a zero-RTT dial");
        assert_eq!(
            relay.send(b"raw").expect("sendable").expect("wire bytes"),
            b"raw".to_vec()
        );
        assert!(relay.close_write().is_none());
    }
}
