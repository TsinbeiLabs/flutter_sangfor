//! The control transport: a loopback TCP listener.
//!
//! A child process can be driven over stdin, which is what [`crate::runtime`]
//! wires up. A Windows service or a systemd unit has no stdin, and neither does
//! a daemon that has to outlive the app that started it — so the same protocol
//! is also served here over `127.0.0.1`.
//!
//! Both transports end at [`crate::runtime::dispatch`], which is the only place
//! a request is interpreted. That is what keeps them from drifting: a verb that
//! works over the socket works over stdin, and a refusal reads the same either
//! way.
//!
//! # Why a socket and not a named pipe
//!
//! A named pipe is the idiomatic Windows answer and this is not idiomatic
//! Windows code. A pipe needs an explicit `SECURITY_DESCRIPTOR`: the default
//! DACL admits the creator, LocalSystem, and Administrators, which excludes the
//! unelevated app that has to talk to the service. Getting that right is around
//! sixty lines of Win32 and a second implementation for every other platform.
//!
//! A loopback socket needs none of it, works identically on all five platforms —
//! which matters because Phase 5 puts this same binary inside an Android
//! `VpnService` process — and the client is ten lines of Dart.
//!
//! # What that costs
//!
//! Any local process can connect. The token in [`crate::control`] is what stands
//! between that and being able to *do* anything, and the blast radius without it
//! is limited by what the protocol exposes: counters, the assigned address, and
//! the session verbs. No secret crosses this channel in either direction —
//! `start` names a plan by *path* precisely so that the signing key stays in the
//! filesystem, where its permissions are the launcher's business and not this
//! socket's — and the process never impersonates a client, so there is no
//! token-theft path either. A local unprivileged process that can stop your VPN
//! can also disable the network adapter. Configure a token in anything but a
//! development run.
//!
//! What a socket still cannot do is *identify* its peer, so it cannot tell the
//! interactive user's app from any other local process. `docs/rust-core.md` §6.2
//! records why that rules out shipping this as a Windows service until the
//! control channel is a pipe with `GetNamedPipeClientProcessId` behind it.

use std::io::{self, BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::config::HostConfig as DaemonConfig;
use crate::control::{Reply, Snapshot};
use crate::runtime::{dispatch, Logger, Message};

/// How many control clients may be served at once. A stuck client must not be
/// able to exhaust the process's threads.
const MAX_CLIENTS: usize = 8;

/// Per-connection read and write deadlines. Without them one client that
/// connects and says nothing holds a thread forever.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(60);

/// A running control listener.
pub struct ControlListener {
    /// The port actually bound, which differs from the requested one when that
    /// was 0.
    pub port: u16,
    running: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl ControlListener {
    /// Stops accepting and lets the listener thread end. Client threads finish on
    /// their own deadlines.
    pub fn shutdown(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for ControlListener {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Opens the control socket [config] asks for, if it asks for one.
///
/// Returns `None` when `controlPort` is unset, or when the port could not be
/// bound. Neither is fatal: stdin still works, and for a service the SCM can
/// still stop the process. Refusing to start the tunnel over a busy port would
/// be worse than running without counters — and a daemon that will not start is
/// one an app cannot ask why.
pub fn open(
    config: &DaemonConfig,
    snapshot: Arc<Mutex<Snapshot>>,
    session_running: Arc<AtomicBool>,
    supervisor: Sender<Message>,
    log: Arc<Logger>,
) -> Option<ControlListener> {
    let port = config.control_port?;
    if config.control_token.is_none() {
        log.line(
            "WARNING: the control socket has no token, so any local process can read counters, \
             stop the tunnel, and start one of its own; set controlToken unless this is a \
             development run",
        );
    }
    match spawn(
        port,
        config.control_token.clone(),
        snapshot,
        session_running,
        supervisor,
        Arc::clone(&log),
    ) {
        Ok(bound) => {
            log.line(&format!(
                "control socket listening on 127.0.0.1:{}",
                bound.port
            ));
            Some(bound)
        }
        Err(error) => {
            log.line(&format!("the control socket could not be opened: {error}"));
            None
        }
    }
}

/// Binds `127.0.0.1:port` and serves the control protocol until stopped.
///
/// Passing 0 picks a free port, which [`ControlListener::port`] then reports —
/// useful in tests and for a launcher that does not want to hardcode one.
///
/// # Errors
///
/// Returns the bind failure. `AddrInUse` is the common one, and for a service it
/// usually means a previous instance is still holding the port.
pub fn spawn(
    port: u16,
    token: Option<String>,
    snapshot: Arc<Mutex<Snapshot>>,
    session_running: Arc<AtomicBool>,
    supervisor: Sender<Message>,
    log: Arc<Logger>,
) -> io::Result<ControlListener> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    let bound = listener.local_addr()?.port();
    // Non-blocking accept with a short wait, so `shutdown` is noticed promptly
    // instead of after the next client happens to connect.
    listener.set_nonblocking(true)?;
    let running = Arc::new(AtomicBool::new(true));
    let accept_flag = Arc::clone(&running);
    let clients = Arc::new(AtomicUsize::new(0));
    let worker = thread::Builder::new()
        .name("sangfor-control".to_string())
        .spawn(move || {
            while accept_flag.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut socket, peer)) => {
                        let live = clients.load(Ordering::SeqCst);
                        if live >= MAX_CLIENTS {
                            log.line(&format!(
                                "refusing a control client from {peer}: {live} already connected"
                            ));
                            let _ = write_reply(
                                &mut socket,
                                &Reply::failed("too many control clients"),
                            );
                            continue;
                        }
                        clients.fetch_add(1, Ordering::SeqCst);
                        let client_snapshot = Arc::clone(&snapshot);
                        let client_running = Arc::clone(&session_running);
                        let client_supervisor = supervisor.clone();
                        let client_log = Arc::clone(&log);
                        let client_token = token.clone();
                        let client_counter = Arc::clone(&clients);
                        let spawned = thread::Builder::new()
                            .name("sangfor-control-client".to_string())
                            .spawn(move || {
                                serve(
                                    socket,
                                    client_token.as_deref(),
                                    &client_snapshot,
                                    &client_running,
                                    &client_supervisor,
                                    &client_log,
                                );
                                client_counter.fetch_sub(1, Ordering::SeqCst);
                            });
                        if spawned.is_err() {
                            clients.fetch_sub(1, Ordering::SeqCst);
                            log.line("the operating system refused a control client thread");
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(error) => {
                        log.line(&format!("the control listener failed: {error}"));
                        return;
                    }
                }
            }
        })
        .map_err(|error| io::Error::other(error.to_string()))?;
    Ok(ControlListener {
        port: bound,
        running,
        worker: Some(worker),
    })
}

/// Serves one client until it disconnects, hits a deadline, or asks to stop.
///
/// Every exit path is logged with its reason. A control client being dropped
/// silently is very hard to diagnose from the far side: the app sees a closed
/// socket and cannot tell a refused token from a crashed thread from a timeout.
fn serve(
    mut socket: TcpStream,
    token: Option<&str>,
    snapshot: &Arc<Mutex<Snapshot>>,
    session_running: &AtomicBool,
    supervisor: &Sender<Message>,
    log: &Logger,
) {
    let peer = socket
        .peer_addr()
        .map(|address| address.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    // Put the connection back into blocking mode.
    //
    // The listener is non-blocking so `shutdown` is noticed promptly, and on
    // Windows an accepted socket *inherits* that mode — Linux does not do this,
    // which is why the bug only showed up against a client that paused between
    // connecting and writing. Without this, the first read returns
    // `WSAEWOULDBLOCK` instead of waiting for the request, and `serve` ends
    // before the client has said anything.
    if let Err(error) = socket.set_nonblocking(false) {
        log.line(&format!(
            "the control client at {peer} could not be served: {error}"
        ));
        return;
    }
    let _ = socket.set_read_timeout(Some(CLIENT_TIMEOUT));
    let _ = socket.set_write_timeout(Some(CLIENT_TIMEOUT));
    let reader = BufReader::new(match socket.try_clone() {
        Ok(clone) => clone,
        Err(error) => {
            log.line(&format!(
                "the control client at {peer} could not be served: {error}"
            ));
            return;
        }
    });
    for line in reader.lines() {
        let line = match line {
            Ok(line) => line,
            Err(error) => {
                log.line(&format!(
                    "the control client at {peer} ended: reading failed ({error})"
                ));
                return;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let reply = dispatch(&line, snapshot, session_running, token, supervisor);
        if let Err(error) = write_reply(&mut socket, &reply) {
            log.line(&format!(
                "the control client at {peer} ended: replying failed ({error})"
            ));
            return;
        }
    }
    log.line(&format!("the control client at {peer} disconnected"));
}

/// Writes one reply line and flushes it. A client that reads a line at a time
/// must not have to wait for a buffer to fill.
fn write_reply(socket: &mut TcpStream, reply: &Reply) -> io::Result<()> {
    socket.write_all(reply.render().as_bytes())?;
    socket.write_all(b"\n")?;
    socket.flush()
}

/// Sends one request and reads one reply. This is the client side, exported so
/// the Dart driver and the tests share one definition of the exchange.
///
/// # Errors
///
/// Returns a connect, write, read, or parse failure.
pub fn request_once(
    port: u16,
    request: &crate::control::Request,
    timeout: Duration,
) -> io::Result<Reply> {
    let socket =
        TcpStream::connect_timeout(&std::net::SocketAddr::from(([127, 0, 0, 1], port)), timeout)?;
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(timeout))?;
    let mut socket = socket;
    socket.write_all(
        format!("{}\n", serde_json::to_string(request).unwrap_or_default()).as_bytes(),
    )?;
    socket.flush()?;
    let mut line = String::new();
    BufReader::new(&mut socket).read_line(&mut line)?;
    serde_json::from_str(line.trim())
        .map_err(|error| io::Error::other(format!("the reply was not JSON: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::{Action, Command, Request};
    use crate::runtime::{Directive, Message};
    use std::sync::Arc;

    /// A listener with a supervisor stand-in that records what it was asked.
    ///
    /// The transport's job is framing, the token gate, and concurrency; whether
    /// a verb *does* the right thing is [`crate::runtime`]'s, tested there
    /// against a real session. Splitting it that way is what lets these run in
    /// microseconds instead of bringing up a tunnel each time.
    struct Harness {
        listener: ControlListener,
        session_running: Arc<AtomicBool>,
        received: Arc<Mutex<Vec<Action>>>,
    }

    impl Harness {
        fn new(token: Option<&str>) -> Self {
            let snapshot = Arc::new(Mutex::new(Snapshot {
                active: true,
                interface: Some("sangfor-test".to_string()),
                ..Snapshot::default()
            }));
            let session_running = Arc::new(AtomicBool::new(false));
            let received = Arc::new(Mutex::new(Vec::new()));

            let (tx, rx) = std::sync::mpsc::channel::<Message>();
            let sink = Arc::clone(&received);
            // Answers every directive so a client thread never blocks, and
            // records the verb so a test can assert what reached the supervisor.
            thread::Builder::new()
                .name("test-supervisor".to_string())
                .spawn(move || {
                    while let Ok(message) = rx.recv() {
                        let Message::Directive(Directive { action, respond }) = message else {
                            continue;
                        };
                        sink.lock().expect("lockable").push(action.clone());
                        let _ = respond.send(match &action {
                            Action::Start { plan: path, .. } => Reply::status(Snapshot {
                                interface: Some(path.display().to_string()),
                                ..Snapshot::default()
                            }),
                            _ => Reply::acknowledged(),
                        });
                    }
                })
                .expect("a thread");

            let listener = spawn(
                0,
                token.map(str::to_string),
                Arc::clone(&snapshot),
                Arc::clone(&session_running),
                tx,
                Logger::stderr(),
            )
            .expect("the listener binds");
            assert!(listener.port > 0, "an ephemeral port was assigned");
            Self {
                listener,
                session_running,
                received,
            }
        }

        fn port(&self) -> u16 {
            self.listener.port
        }

        fn actions(&self) -> Vec<Action> {
            self.received.lock().expect("lockable").clone()
        }
    }

    #[test]
    fn a_client_can_ping_and_read_a_snapshot() {
        let harness = Harness::new(None);
        let ping = request_once(
            harness.port(),
            &Request::new(Command::Ping),
            Duration::from_secs(5),
        )
        .expect("a reply");
        assert!(ping.ok);

        let status = request_once(
            harness.port(),
            &Request::new(Command::Status),
            Duration::from_secs(5),
        )
        .expect("a reply");
        assert!(status.ok);
        let data = status.data.expect("a snapshot");
        assert!(data.active);
        assert_eq!(data.interface.as_deref(), Some("sangfor-test"));
        assert!(
            harness.actions().is_empty(),
            "reading state does not involve the supervisor"
        );
    }

    #[test]
    fn the_snapshot_reports_whether_a_session_is_running() {
        // A client that cannot tell "idle" from "starting" either waits forever
        // or sends a second `start` and gets refused.
        let harness = Harness::new(None);
        let idle = request_once(
            harness.port(),
            &Request::new(Command::Status),
            Duration::from_secs(5),
        )
        .expect("a reply");
        assert!(!idle.data.expect("a snapshot").session_running);

        harness.session_running.store(true, Ordering::SeqCst);
        let running = request_once(
            harness.port(),
            &Request::new(Command::Status),
            Duration::from_secs(5),
        )
        .expect("a reply");
        assert!(running.data.expect("a snapshot").session_running);
    }

    #[test]
    fn a_supervisor_verb_reaches_the_supervisor_and_its_verdict_comes_back() {
        let harness = Harness::new(None);
        harness.session_running.store(true, Ordering::SeqCst);
        let reply = request_once(
            harness.port(),
            &Request::new(Command::StopSession),
            Duration::from_secs(5),
        )
        .expect("a reply");
        assert!(reply.ok);
        assert_eq!(harness.actions(), vec![Action::StopSession]);
    }

    #[test]
    fn a_start_carries_its_plan_path_across_the_socket() {
        // The path is the whole mechanism: the plan holds the signing key, so
        // it must never be inlined into a request on a channel any local
        // process can join.
        let harness = Harness::new(None);
        let reply = request_once(
            harness.port(),
            &Request::start("/var/run/sangfor/plan.json", None::<&str>),
            Duration::from_secs(5),
        )
        .expect("a reply");
        assert!(reply.ok);
        assert_eq!(
            harness.actions(),
            vec![Action::Start {
                plan: std::path::PathBuf::from("/var/run/sangfor/plan.json"),
                config: None,
            }]
        );
        let line = reply.render();
        assert!(
            !line.contains("signKey"),
            "a reply never echoes plan material: {line}"
        );
    }

    #[test]
    fn a_token_is_required_when_one_was_configured() {
        let harness = Harness::new(Some("s3cret"));
        let refused = request_once(
            harness.port(),
            &Request::new(Command::Status),
            Duration::from_secs(5),
        )
        .expect("a reply");
        assert!(!refused.ok, "no token, no snapshot");

        let allowed = request_once(
            harness.port(),
            &Request {
                cmd: Command::Status,
                token: Some("s3cret".to_string()),
                plan_path: None,
                config_path: None,
            },
            Duration::from_secs(5),
        )
        .expect("a reply");
        assert!(allowed.ok);
        assert!(allowed.data.is_some());
    }

    #[test]
    fn a_token_gates_start_too() {
        // The most powerful verb is the one that most needs gating: it points
        // the daemon at a plan, and therefore at a gateway, with a signing key.
        let harness = Harness::new(Some("s3cret"));
        let refused = request_once(
            harness.port(),
            &Request::start("/tmp/plan.json", None::<&str>),
            Duration::from_secs(5),
        )
        .expect("a reply");
        assert!(!refused.ok, "an unauthenticated start is refused");
        assert!(
            harness.actions().is_empty(),
            "and nothing reached the supervisor"
        );

        let allowed = request_once(
            harness.port(),
            &Request {
                token: Some("s3cret".to_string()),
                ..Request::start("/tmp/plan.json", None::<&str>)
            },
            Duration::from_secs(5),
        )
        .expect("a reply");
        assert!(allowed.ok);
        assert_eq!(harness.actions().len(), 1);
    }

    #[test]
    fn garbage_gets_an_error_reply_rather_than_silence() {
        let harness = Harness::new(None);
        let mut socket = TcpStream::connect(("127.0.0.1", harness.port())).expect("connects");
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("settable");
        socket.write_all(b"nonsense\n").expect("writable");
        let mut line = String::new();
        BufReader::new(&mut socket)
            .read_line(&mut line)
            .expect("a reply");
        let parsed: Reply = serde_json::from_str(line.trim()).expect("json");
        assert!(!parsed.ok);
        assert!(
            parsed.error.unwrap_or_default().contains("unrecognised"),
            "the error should say what went wrong"
        );
    }

    #[test]
    fn several_commands_on_one_connection_are_answered_in_order() {
        let harness = Harness::new(None);
        let mut socket = TcpStream::connect(("127.0.0.1", harness.port())).expect("connects");
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("settable");
        socket
            .write_all(b"{\"cmd\":\"ping\"}\n{\"cmd\":\"status\"}\n{\"cmd\":\"ping\"}\n")
            .expect("writable");
        socket.flush().expect("flushed");
        let mut reader = BufReader::new(&mut socket);
        for expected in [false, true, false] {
            let mut line = String::new();
            reader.read_line(&mut line).expect("a reply");
            let parsed: Reply = serde_json::from_str(line.trim()).expect("json");
            assert!(parsed.ok);
            assert_eq!(parsed.data.is_some(), expected, "only status carries data");
        }
    }

    #[test]
    fn shutdown_ends_the_listener() {
        let harness = Harness::new(None);
        let port = harness.port();
        drop(harness);
        // The port is released, so a second listener can take it. Retrying
        // briefly avoids racing the kernel's teardown.
        let mut bound = None;
        for _ in 0..50 {
            if let Ok(listener) = TcpListener::bind(("127.0.0.1", port)) {
                bound = Some(listener);
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(bound.is_some(), "the port should be free after shutdown");
    }

    #[test]
    fn a_configuration_with_no_control_port_opens_nothing() {
        // Stdin stays the only channel, which is the right default for a child
        // process a launcher is already talking to.
        let config = DaemonConfig::default();
        assert!(config.control_port.is_none());
        let opened = open(
            &config,
            Arc::new(Mutex::new(Snapshot::default())),
            Arc::new(AtomicBool::new(false)),
            std::sync::mpsc::channel::<Message>().0,
            Logger::stderr(),
        );
        assert!(opened.is_none());
    }

    #[test]
    fn an_unusable_port_is_reported_and_does_not_stop_the_daemon() {
        // A service that refuses to start because its counters could not be
        // served is a worse outcome than a service with no counters.
        let taken = TcpListener::bind(("127.0.0.1", 0)).expect("bindable");
        let port = taken.local_addr().expect("an address").port();
        let config = DaemonConfig {
            control_port: Some(port),
            ..DaemonConfig::default()
        };
        let opened = open(
            &config,
            Arc::new(Mutex::new(Snapshot::default())),
            Arc::new(AtomicBool::new(false)),
            std::sync::mpsc::channel::<Message>().0,
            Logger::stderr(),
        );
        assert!(
            opened.is_none(),
            "the busy port is reported, not fatal: it is still held"
        );
        assert!(taken.local_addr().is_ok(), "and the holder is untouched");
    }
}
