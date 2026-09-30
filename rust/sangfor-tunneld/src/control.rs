//! The control protocol: JSON lines in, JSON lines out.
//!
//! Deliberately small. The process that launches the tunnel needs three things
//! from it — is it up, what are the counters, and please stop — and everything
//! else is a log line. Keeping the surface this narrow is what lets a Flutter
//! app, a systemd unit, and a Windows service wrapper all drive the same binary
//! without agreeing on anything beyond newline-delimited JSON.
//!
//! The transport is stdin/stdout here. A service that has no stdin needs a named
//! pipe or a socket instead; [`Command::parse`] and [`reply`] are transport-free
//! so that swap does not touch the protocol.

use serde::{Deserialize, Serialize};

/// One control request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "cmd")]
pub enum Command {
    /// Report [`Snapshot`].
    Status,
    /// End the session and exit.
    Stop,
    /// Prove the process is alive and reading.
    Ping,
}

impl Command {
    /// Parses one line.
    ///
    /// # Errors
    ///
    /// Returns the parse error, which the caller should echo back rather than
    /// drop: a client that typo'd a command name otherwise sees nothing at all
    /// and cannot tell a dead process from a bad request.
    pub fn parse(line: &str) -> Result<Self, String> {
        serde_json::from_str(line.trim()).map_err(|error| format!("unrecognised command: {error}"))
    }
}

/// What the tunnel reports about itself.
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
    /// A fatal error ended the session, if one did.
    pub fatal: Option<String>,
}

/// A reply line. `data` carries [`Snapshot`] for [`Command::Status`] and an
/// error message when something went wrong.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Reply {
    /// Whether the command was understood and acted on.
    pub ok: bool,
    /// A snapshot, for `status`.
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

/// Answers [command] from [snapshot].
///
/// Pure, so the protocol can be tested without a tunnel: the only side effect of
/// [`Command::Stop`] is the returned [`Action`], which the caller performs.
#[must_use]
pub fn reply(command: Command, snapshot: &Snapshot) -> (Reply, Action) {
    match command {
        Command::Status => (Reply::status(snapshot.clone()), Action::None),
        Command::Ping => (Reply::acknowledged(), Action::None),
        Command::Stop => (Reply::acknowledged(), Action::Stop),
    }
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

    #[test]
    fn commands_parse_from_their_json_lines() {
        assert_eq!(
            Command::parse(r#"{"cmd":"status"}"#).expect("parses"),
            Command::Status
        );
        assert_eq!(
            Command::parse(r#"{"cmd":"stop"}"#).expect("parses"),
            Command::Stop
        );
        assert_eq!(
            Command::parse(r#"{"cmd":"ping"}"#).expect("parses"),
            Command::Ping
        );
    }

    #[test]
    fn surrounding_whitespace_and_a_trailing_newline_are_tolerated() {
        // A client writing lines with `writeln!` sends the newline; rejecting it
        // would make every such client look broken.
        assert_eq!(
            Command::parse("  {\"cmd\":\"status\"}\n").expect("parses"),
            Command::Status
        );
    }

    #[test]
    fn an_unknown_command_is_an_error_the_caller_can_echo() {
        let error = Command::parse(r#"{"cmd":"reboot"}"#).expect_err("unknown");
        assert!(error.contains("unrecognised command"), "{error}");
        assert!(Command::parse("not json").is_err());
        assert!(Command::parse("").is_err());
    }

    #[test]
    fn status_carries_a_snapshot_and_asks_for_nothing() {
        let snapshot = Snapshot {
            active: true,
            virtual_ip: vec!["10.0.0.42".to_string()],
            routed: 7,
            ..Snapshot::default()
        };
        let (reply, action) = reply(Command::Status, &snapshot);
        assert_eq!(action, Action::None);
        assert!(reply.ok);
        assert_eq!(reply.data, Some(snapshot));
    }

    #[test]
    fn stop_is_the_only_command_with_a_side_effect() {
        assert_eq!(reply(Command::Stop, &Snapshot::default()).1, Action::Stop);
        assert_eq!(reply(Command::Ping, &Snapshot::default()).1, Action::None);
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
}
