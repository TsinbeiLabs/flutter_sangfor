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
//! [`Request::token`] gates everything but `ping`. `ping` is deliberately open:
//! liveness is what a service manager probes before it has any secret, and
//! answering it leaks nothing.
//!
//! # No secret material crosses this channel
//!
//! [`Command::Start`] names a plan *document* by path rather than carrying it.
//! The session plan holds the request signing key, and the control channel is
//! reachable by any local process that has the token — which, on a loopback
//! socket, is a weaker guarantee than a file's permissions. Passing a path
//! keeps the plan in the filesystem, where the launcher already had to put it
//! for `--plan`, and keeps [`Snapshot`] the only thing a client can read.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// One control request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Request {
    /// What to do.
    pub cmd: Command,
    /// The shared secret, required for everything but [`Command::Ping`].
    ///
    /// Omitted rather than sent as `null` when absent, so the wire form of a
    /// request that carries nothing but a verb is still `{"cmd":"ping"}` —
    /// which is what every client written before `planPath` existed sends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// The session plan to start from, for [`Command::Start`].
    ///
    /// A path rather than the document; see the module docs for why. The
    /// daemon must be able to read it, which for a service means a location
    /// both the caller's user and the service account can reach.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_path: Option<PathBuf>,
    /// A host configuration for this session, for [`Command::Start`].
    ///
    /// Optional. A child process gets its configuration from `--config` and
    /// needs nothing here. An *installed* daemon was configured once, at
    /// install time, but which routes to install depends on what the gateway
    /// published for this session — so the caller writes a fresh document and
    /// names it. See [`crate::service`] for the merge rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_path: Option<PathBuf>,
}

impl Request {
    /// A request with no token and no documents.
    #[must_use]
    pub const fn new(cmd: Command) -> Self {
        Self {
            cmd,
            token: None,
            plan_path: None,
            config_path: None,
        }
    }

    /// A `start` for the plan at [plan_path], with an optional per-session host
    /// configuration at [config_path].
    #[must_use]
    pub fn start(plan_path: impl Into<PathBuf>, config_path: Option<impl Into<PathBuf>>) -> Self {
        Self {
            cmd: Command::Start,
            token: None,
            plan_path: Some(plan_path.into()),
            config_path: config_path.map(Into::into),
        }
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
    /// Begin a session from `planPath`. Refused while one is already running,
    /// so a client cannot quietly tear down a tunnel somebody else started.
    Start,
    /// End the current session and stay alive, ready for the next one.
    StopSession,
}

/// What the tunnel reports about itself.
///
/// Nothing here is secret: counters, the assigned virtual IP, and whether the
/// interface came up. The session plan — which carries the signing key — never
/// crosses the control channel in either direction.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    /// A session is running. Distinct from [`Self::active`]: a daemon that has
    /// been started but not yet given a plan has no session, and a session that
    /// is still handshaking is not yet active. A client that cannot tell those
    /// apart cannot tell "wait" from "start one".
    pub session_running: bool,
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
/// logged a warning about at startup. [session_running] is whether the process
/// currently has a session, which decides whether `start` and `stopSession`
/// make sense.
///
/// Pure, so the protocol can be tested without a tunnel: the only effect of a
/// verb that changes anything is the returned [`Action`], which the caller
/// performs. A caller that races another client may still have to refuse — the
/// supervisor re-checks — but this keeps the common case honest and testable.
#[must_use]
pub fn reply(
    request: &Request,
    snapshot: &Snapshot,
    token: Option<&str>,
    session_running: bool,
) -> (Reply, Action) {
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
        Command::Start => {
            if session_running {
                return (
                    Reply::failed("a session is already running; send stopSession first"),
                    Action::None,
                );
            }
            match &request.plan_path {
                Some(path) => (
                    Reply::acknowledged(),
                    Action::Start {
                        plan: path.clone(),
                        config: request.config_path.clone(),
                    },
                ),
                None => (Reply::failed("start needs a planPath"), Action::None),
            }
        }
        // Idempotent on purpose. A client that asks to stop a session which
        // already died — the gateway kicked it, the device went away — gets an
        // acknowledgement rather than an error it has to distinguish from a
        // real failure.
        Command::StopSession => {
            if session_running {
                (Reply::acknowledged(), Action::StopSession)
            } else {
                (Reply::acknowledged(), Action::None)
            }
        }
        Command::Stop => (Reply::acknowledged(), Action::Exit),
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
///
/// Only the supervisor can carry these out — they change what the process is
/// doing, or end it — so a control client forwards one and waits for the
/// verdict rather than acting on it directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Nothing; the reply already said everything.
    None,
    /// Begin a session from the plan document at `plan`, configured by the
    /// document at `config` if one was named.
    Start {
        /// The session plan.
        plan: PathBuf,
        /// A per-session host configuration, or `None` to keep the startup one.
        config: Option<PathBuf>,
    },
    /// End the current session and keep the process alive.
    StopSession,
    /// End the current session and exit.
    Exit,
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
    fn the_supervisor_verbs_parse_with_their_arguments() {
        let request =
            Request::parse(r#"{"cmd":"start","planPath":"/tmp/p.json","token":"t"}"#).expect("ok");
        assert_eq!(request.cmd, Command::Start);
        assert_eq!(
            request.plan_path,
            Some(PathBuf::from("/tmp/p.json")),
            "camelCase on the wire, a path in hand"
        );
        assert_eq!(
            Request::parse(r#"{"cmd":"stopSession"}"#)
                .expect("parses")
                .cmd,
            Command::StopSession
        );
    }

    #[test]
    fn the_wire_format_of_the_original_verbs_did_not_change() {
        // `stop` and `status` shipped before the supervisor existed, and the
        // Dart client, the verification script, and a human at a terminal all
        // send them. Adding verbs must not have moved these.
        let line = serde_json::to_string(&Request::new(Command::Stop)).expect("serializes");
        assert_eq!(line, r#"{"cmd":"stop"}"#);
        let line = serde_json::to_string(&Request::new(Command::Status)).expect("serializes");
        assert_eq!(line, r#"{"cmd":"status"}"#);
        assert_eq!(Reply::acknowledged().render(), r#"{"ok":true}"#);
    }

    #[test]
    fn a_start_request_carries_the_plan_path() {
        let request = Request::start("/var/run/sangfor/plan.json", None::<&str>);
        assert_eq!(request.cmd, Command::Start);
        assert_eq!(
            request.plan_path,
            Some(PathBuf::from("/var/run/sangfor/plan.json"))
        );
        let line = serde_json::to_string(&request).expect("serializes");
        assert!(line.contains("planPath"), "{line}");
    }

    #[test]
    fn surrounding_whitespace_and_a_trailing_newline_are_tolerated() {
        // A client writing lines with `writeln!` sends the newline; rejecting it
        // would make every such client look broken.
        let request = Request::parse("  {\"cmd\":\"status\"}\n").expect("parses");
        assert_eq!(request.cmd, Command::Status);
        assert!(request.token.is_none());
        assert!(request.plan_path.is_none());
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
        let (reply, action) = reply(&Request::new(Command::Status), &snapshot, None, false);
        assert_eq!(action, Action::None);
        assert!(reply.ok);
        assert_eq!(reply.data, Some(snapshot));
    }

    #[test]
    fn start_is_refused_while_a_session_is_running() {
        // Replacing a live tunnel would silently drop the connections of
        // whoever started it. A client that means to reconnect sends
        // `stopSession` first, which is one more round trip and no ambiguity.
        let (reply, action) = reply(
            &Request::start("/tmp/plan.json", None::<&str>),
            &Snapshot::default(),
            None,
            true,
        );
        assert!(!reply.ok);
        assert_eq!(action, Action::None, "a refused start starts nothing");
        assert!(
            reply.error.unwrap_or_default().contains("stopSession"),
            "the refusal says what to do instead"
        );
    }

    #[test]
    fn start_needs_a_plan_to_start_from() {
        let (reply, action) = reply(
            &Request::new(Command::Start),
            &Snapshot::default(),
            None,
            false,
        );
        assert!(!reply.ok);
        assert_eq!(action, Action::None);
        assert!(
            reply.error.unwrap_or_default().contains("planPath"),
            "the refusal names the missing field"
        );
    }

    #[test]
    fn start_hands_the_path_to_the_supervisor_rather_than_reading_it() {
        // `reply` is pure: it must not touch the filesystem, or the protocol
        // could not be tested without a tunnel and a plan on disk.
        let (reply, action) = reply(
            &Request::start("/tmp/plan.json", None::<&str>),
            &Snapshot::default(),
            None,
            false,
        );
        assert!(reply.ok);
        assert_eq!(
            action,
            Action::Start {
                plan: PathBuf::from("/tmp/plan.json"),
                config: None
            }
        );
    }

    #[test]
    fn stop_session_is_idempotent() {
        // The common case is a client tearing down after the session already
        // died: the gateway kicked it, or the device went away. An error there
        // would make a normal disconnect look like a failure.
        let (running_reply, running_action) = reply(
            &Request::new(Command::StopSession),
            &Snapshot::default(),
            None,
            true,
        );
        assert!(running_reply.ok);
        assert_eq!(running_action, Action::StopSession);

        let (idle_reply, idle_action) = reply(
            &Request::new(Command::StopSession),
            &Snapshot::default(),
            None,
            false,
        );
        assert!(
            idle_reply.ok,
            "stopping nothing is not an error: {:?}",
            idle_reply.error
        );
        assert_eq!(
            idle_action,
            Action::None,
            "and asks the supervisor for nothing"
        );
    }

    #[test]
    fn stop_is_the_verb_that_ends_the_process() {
        assert_eq!(
            reply(
                &Request::new(Command::Stop),
                &Snapshot::default(),
                None,
                true
            )
            .1,
            Action::Exit
        );
        assert_eq!(
            reply(
                &Request::new(Command::Stop),
                &Snapshot::default(),
                None,
                false
            )
            .1,
            Action::Exit,
            "an idle daemon can still be told to go away"
        );
        assert_eq!(
            reply(
                &Request::new(Command::Ping),
                &Snapshot::default(),
                None,
                false
            )
            .1,
            Action::None
        );
    }

    #[test]
    fn a_wrong_token_is_refused_without_touching_the_tunnel() {
        let request = Request {
            cmd: Command::Stop,
            token: Some("wrong".to_string()),
            plan_path: None,
            config_path: None,
        };
        let (reply, action) = reply(&request, &Snapshot::default(), Some(TOKEN), true);
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
    fn starting_a_session_needs_the_token_too() {
        // `start` is the most powerful verb there is: it points the daemon at a
        // plan and therefore at a gateway, with a signing key. Leaving it open
        // would let any local process take over the tunnel.
        let request = Request {
            cmd: Command::Start,
            token: Some("wrong".to_string()),
            plan_path: Some(PathBuf::from("/tmp/plan.json")),
            config_path: None,
        };
        let (reply, action) = reply(&request, &Snapshot::default(), Some(TOKEN), false);
        assert!(!reply.ok);
        assert_eq!(action, Action::None);
    }

    #[test]
    fn a_missing_token_is_refused_when_one_is_configured() {
        let (reply, action) = reply(
            &Request::new(Command::Status),
            &Snapshot::default(),
            Some(TOKEN),
            false,
        );
        assert!(!reply.ok);
        assert_eq!(action, Action::None);
    }

    #[test]
    fn the_right_token_is_accepted() {
        let request = Request {
            cmd: Command::Status,
            token: Some(TOKEN.to_string()),
            plan_path: None,
            config_path: None,
        };
        let (reply, _) = reply(&request, &Snapshot::default(), Some(TOKEN), false);
        assert!(reply.ok);
    }

    #[test]
    fn ping_needs_no_token() {
        // A service manager probes liveness before it holds any secret.
        let (reply, action) = reply(
            &Request::new(Command::Ping),
            &Snapshot::default(),
            Some(TOKEN),
            false,
        );
        assert!(reply.ok);
        assert_eq!(action, Action::None);
    }

    #[test]
    fn an_unconfigured_channel_is_open() {
        // Documented behaviour, not an oversight: a token is opt-in, and a
        // developer running the daemon by hand should not need one.
        let (reply, action) = reply(
            &Request::new(Command::Stop),
            &Snapshot::default(),
            None,
            false,
        );
        assert!(reply.ok);
        assert_eq!(action, Action::Exit);
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
            "sessionRunning",
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
            !line.contains("virtual_ip") && !line.contains("session_running"),
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
        for forbidden in [
            "sid",
            "signKey",
            "password",
            "deviceId",
            "connectionId",
            "planPath",
        ] {
            assert!(
                !line
                    .to_ascii_lowercase()
                    .contains(&forbidden.to_ascii_lowercase()),
                "{forbidden} must not appear in a status reply: {line}"
            );
        }
    }

    #[test]
    fn an_idle_daemon_reports_that_it_has_no_session() {
        // `active` cannot say this: it is false both before a session starts
        // and while one is still handshaking, and a client that confuses the
        // two either waits forever or starts a second tunnel.
        let idle = Reply::status(Snapshot::default()).render();
        assert!(idle.contains(r#""sessionRunning":false"#), "{idle}");
        let running = Reply::status(Snapshot {
            session_running: true,
            ..Snapshot::default()
        })
        .render();
        assert!(running.contains(r#""sessionRunning":true"#), "{running}");
    }
}
