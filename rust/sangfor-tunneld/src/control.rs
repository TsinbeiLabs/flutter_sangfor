//! The control protocol: JSON lines in, JSON lines out.
//!
//! Deliberately small. The process that drives the tunnel needs three things —
//! is it up, what are the counters, and please stop — and everything else is a
//! log line. Keeping the surface this narrow is what lets a Flutter app, a
//! systemd unit, a Windows service wrapper, and a human with a terminal all
//! drive the same binary without agreeing on anything beyond newline-delimited
//! JSON.
//!
//! Transport-free on purpose: [`Request::parse`] and [`reply`] know nothing about
//! where the bytes came from, so the same protocol runs over stdin for a child
//! process and over a loopback socket for a service. See [`crate::transport`].
//!
//! # Authorization
//!
//! [`Request::token`] gates `status` and `stop`. `ping` is deliberately open:
//! liveness is what a service manager probes before it has any secret, and
//! answering it leaks nothing.

use serde::{Deserialize, Serialize};

/// One control request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Request {
    /// What to do.
    pub cmd: Command,
    /// The shared secret, required for everything but [`Command::Ping`].
    #[serde(default)]
    pub token: Option<String>,
}

impl Request {
    /// A request with no token.
    #[must_use]
    pub const fn new(cmd: Command) -> Self {
        Self { cmd, token: None }
    }

    /// Parses one line.
    ///
    /// # Errors
    ///
    /// Returns the parse error, which the caller should echo back rather than
    /// drop: a client that typo'd a command name otherwise sees nothing at all
    /// and cannot tell a dead process from a bad request.
    pub fn parse(line: &str) -> Result<Self, String> {
        serde_json::from_str(line.trim()).map_err(|error| format!("unrecognised request: {error}"))
    }
}

/// The verbs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Command {
    /// Report [`Snapshot`].
    Status,
    /// End the session and exit.
    Stop,
    /// Prove the process is alive and reading. Needs no token.
    Ping,
}

/// What the tunnel reports about itself.
///
/// Nothing here is secret: counters, the assigned virtual IP, and whether the
/// interface came up. The session plan — which carries the signing key — never
/// crosses the control channel in either direction.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    /// The handshake completed and the tunnel is carrying traffic.
    pub active: bool,
    /// The virtual IP the gateway assigned.
    pub virtual_ip: Vec<String>,
    /// The interface was configured successfully.
    pub interface_configured: bool,
    /// Why the interface could not be configured, if it could not.
    pub interface_error: Option<String>,
    /// Channels currently open to the gateway.
    pub channels_open: usize,
    /// Packets read from the device.
    pub device_packets: u64,
    /// Packets written to the device.
    pub emitted_packets: u64,
    /// Packets shed because the device queue was full.
    pub device_dropped: u64,
    /// Packets the device refused.
    pub emit_failures: u64,
    /// Bytes read from gateway channels.
    pub channel_bytes_in: u64,
    /// Bytes written to gateway channels.
    pub channel_bytes_out: u64,
    /// Connect attempts that failed.
    pub connect_failures: u64,
    /// Egress packets the plane forwarded as raw IP.
    pub routed: u64,
    /// Egress packets the terminator claimed.
    pub terminated: u64,
    /// Egress packets no published resource covers.
    pub unrouted: u64,
    /// Ingress packets delivered to the local stack.
    pub ingress: u64,
    /// The interface name this process opened.
    pub interface: Option<String>,
    /// A fatal error ended the session, if one did.
    pub fatal: Option<String>,
}

/// A reply line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Reply {
    /// Whether the command was understood, authorized, and acted on.
    pub ok: bool,
    /// A snapshot, for [`Command::Status`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Snapshot>,
    /// A human-readable error, when `ok` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Reply {
    /// A successful reply carrying [snapshot].
    #[must_use]
    pub fn status(snapshot: Snapshot) -> Self {
        Self {
            ok: true,
            data: Some(snapshot),
            error: None,
        }
    }

    /// A successful reply with no payload.
    #[must_use]
    pub fn acknowledged() -> Self {
        Self {
            ok: true,
            data: None,
            error: None,
        }
    }

    /// A failure carrying [message].
    #[must_use]
    pub fn failed(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            data: None,
            error: Some(message.into()),
        }
    }

    /// Renders one line of JSON, without a trailing newline.
    #[must_use]
    pub fn render(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| r#"{"ok":false}"#.to_string())
    }
}

/// Answers [request] from [snapshot].
///
/// [token] is the secret this process was configured with; `None` means the
/// control channel is open to any local process, which the caller should have
/// logged a warning about at startup.
///
/// Pure, so the protocol can be tested without a tunnel: the only side effect of
/// [`Command::Stop`] is the returned [`Action`], which the caller performs.
#[must_use]
pub fn reply(request: &Request, snapshot: &Snapshot, token: Option<&str>) -> (Reply, Action) {
    if request.cmd == Command::Ping {
        return (Reply::acknowledged(), Action::None);
    }
    if !authorized(request.token.as_deref(), token) {
        return (
            Reply::failed("the control token is missing or wrong"),
            Action::None,
        );
    }
    match request.cmd {
        Command::Status => (Reply::status(snapshot.clone()), Action::None),
        Command::Stop => (Reply::acknowledged(), Action::Stop),
        // Ping was handled above; the arm keeps the match exhaustive.
        Command::Ping => (Reply::acknowledged(), Action::None),
    }
}

/// Constant-time-ish comparison of a supplied token against the expected one.
///
/// Not a cryptographic guard: an attacker who can reach a loopback control port
/// can also read the process's memory or just stop the service through the SCM.
/// The token exists so an unrelated local process cannot stumble into the
/// tunnel, which is a different and much more likely threat.
fn authorized(supplied: Option<&str>, expected: Option<&str>) -> bool {
    match (supplied, expected) {
        (Some(actual), Some(wanted)) => subtle_eq(actual.as_bytes(), wanted.as_bytes()),
        // No token configured: the channel is open, by configuration.
        (_, None) => true,
        (None, Some(_)) => false,
    }
}

/// Compares without short-circuiting on the first difference, so the timing does
/// not reveal how much of the token a caller got right.
fn subtle_eq(actual: &[u8], wanted: &[u8]) -> bool {
    let mut difference = (actual.len() ^ wanted.len()) as u8;
    for (index, byte) in wanted.iter().enumerate() {
        let left = actual.get(index).copied().unwrap_or(0);
        difference |= left ^ byte;
    }
    difference == 0
}

/// What the caller must do after replying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Nothing.
    None,
    /// End the session and exit.
    Stop,
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "s3cret-token";

    #[test]
    fn requests_parse_from_their_json_lines() {
        let request = Request::parse(r#"{"cmd":"status","token":"abc"}"#).expect("parses");
        assert_eq!(request.cmd, Command::Status);
        assert_eq!(request.token.as_deref(), Some("abc"));
        assert_eq!(
            Request::parse(r#"{"cmd":"stop"}"#).expect("parses").cmd,
            Command::Stop
        );
        assert_eq!(
            Request::parse(r#"{"cmd":"ping"}"#).expect("parses").cmd,
            Command::Ping
        );
    }

    #[test]
    fn surrounding_whitespace_and_a_trailing_newline_are_tolerated() {
        // A client writing lines with `writeln!` sends the newline; rejecting it
        // would make every such client look broken.
        let request = Request::parse("  {\"cmd\":\"status\"}\n").expect("parses");
        assert_eq!(request.cmd, Command::Status);
        assert!(request.token.is_none());
    }

    #[test]
    fn an_unknown_command_is_an_error_the_caller_can_echo() {
        let error = Request::parse(r#"{"cmd":"reboot"}"#).expect_err("unknown");
        assert!(error.contains("unrecognised request"), "{error}");
        assert!(Request::parse("not json").is_err());
        assert!(Request::parse("").is_err());
        // A bare verb is not a request; the wrapper object keeps room for the
        // token and for whatever comes next.
        assert!(Request::parse(r#""status""#).is_err());
    }

    #[test]
    fn status_carries_a_snapshot_and_asks_for_nothing() {
        let snapshot = Snapshot {
            active: true,
            virtual_ip: vec!["10.0.0.42".to_string()],
            routed: 7,
            ..Snapshot::default()
        };
        let (reply, action) = reply(&Request::new(Command::Status), &snapshot, None);
        assert_eq!(action, Action::None);
        assert!(reply.ok);
        assert_eq!(reply.data, Some(snapshot));
    }

    #[test]
    fn stop_is_the_only_command_with_a_side_effect() {
        assert_eq!(
            reply(&Request::new(Command::Stop), &Snapshot::default(), None).1,
            Action::Stop
        );
        assert_eq!(
            reply(&Request::new(Command::Ping), &Snapshot::default(), None).1,
            Action::None
        );
    }

    #[test]
    fn a_wrong_token_is_refused_without_touching_the_tunnel() {
        let request = Request {
            cmd: Command::Stop,
            token: Some("wrong".to_string()),
        };
        let (reply, action) = reply(&request, &Snapshot::default(), Some(TOKEN));
        assert!(!reply.ok);
        assert_eq!(
            action,
            Action::None,
            "a refused stop must not stop anything"
        );
        assert!(
            reply.error.unwrap_or_default().contains("token"),
            "the refusal says which check failed"
        );
    }

    #[test]
    fn a_missing_token_is_refused_when_one_is_configured() {
        let (reply, action) = reply(
            &Request::new(Command::Status),
            &Snapshot::default(),
            Some(TOKEN),
        );
        assert!(!reply.ok);
        assert_eq!(action, Action::None);
    }

    #[test]
    fn the_right_token_is_accepted() {
        let request = Request {
            cmd: Command::Status,
            token: Some(TOKEN.to_string()),
        };
        let (reply, _) = reply(&request, &Snapshot::default(), Some(TOKEN));
        assert!(reply.ok);
    }

    #[test]
    fn ping_needs_no_token() {
        // A service manager probes liveness before it holds any secret.
        let (reply, action) = reply(
            &Request::new(Command::Ping),
            &Snapshot::default(),
            Some(TOKEN),
        );
        assert!(reply.ok);
        assert_eq!(action, Action::None);
    }

    #[test]
    fn an_unconfigured_channel_is_open() {
        // Documented behaviour, not an oversight: a token is opt-in, and a
        // developer running the daemon by hand should not need one.
        let (reply, action) = reply(&Request::new(Command::Stop), &Snapshot::default(), None);
        assert!(reply.ok);
        assert_eq!(action, Action::Stop);
    }

    #[test]
    fn the_token_comparison_does_not_leak_its_length() {
        assert!(subtle_eq(b"abcdef", b"abcdef"));
        assert!(!subtle_eq(b"abcde", b"abcdef"));
        assert!(!subtle_eq(b"abcdefg", b"abcdef"));
        assert!(!subtle_eq(b"abcxyz", b"abcdef"));
        assert!(subtle_eq(b"", b""));
        assert!(!subtle_eq(b"", b"a"));
    }

    #[test]
    fn a_reply_round_trips_through_its_own_json() {
        let reply = Reply::status(Snapshot {
            active: true,
            interface_configured: true,
            ..Snapshot::default()
        });
        let line = reply.render();
        let parsed: Reply = serde_json::from_str(&line).expect("round-trips");
        assert_eq!(parsed, reply);
        assert!(line.contains(r#""active":true"#));
        assert!(
            !line.contains("error"),
            "absent fields are omitted, so a client can tell them from null: {line}"
        );
    }

    #[test]
    fn a_failure_names_the_problem() {
        let reply = Reply::failed("the interface could not be configured");
        assert!(!reply.ok);
        assert!(reply.data.is_none());
        assert!(reply.render().contains("could not be configured"));
    }

    #[test]
    fn the_snapshot_uses_camel_case_like_every_other_document() {
        let line = Reply::status(Snapshot::default()).render();
        for key in [
            "virtualIp",
            "interfaceConfigured",
            "channelsOpen",
            "devicePackets",
            "channelBytesIn",
            "connectFailures",
        ] {
            assert!(line.contains(key), "{key} is missing from {line}");
        }
        assert!(
            !line.contains("virtual_ip"),
            "snake_case leaked into the protocol: {line}"
        );
    }

    #[test]
    fn the_snapshot_carries_no_secret_material() {
        // The control channel is reachable by any local process that has the
        // token, and the token is opt-in. What it can read therefore has to be
        // safe to read: no session id, no signing key, no credentials.
        let line = Reply::status(Snapshot {
            active: true,
            virtual_ip: vec!["10.0.0.42".to_string()],
            interface: Some("Luotopia".to_string()),
            ..Snapshot::default()
        })
        .render();
        for forbidden in ["sid", "signKey", "password", "deviceId", "connectionId"] {
            assert!(
                !line
                    .to_ascii_lowercase()
                    .contains(&forbidden.to_ascii_lowercase()),
                "{forbidden} must not appear in a status reply: {line}"
            );
        }
    }
}
