//! Wiring: logging, the control channel, the interface configurator, and the
//! supervisor loop.
//!
//! Most of this is glue between pieces that are tested on their own. The part
//! that is not glue is the *shape* of the process, and it is worth stating
//! plainly because it is what makes a service possible:
//!
//! ```text
//!     process lifetime  |-----------------------------------------|
//!     session lifetime        |---------|       |---------|
//!     control channel     |-----------------------------------------|
//! ```
//!
//! A session is one tunnel: a plan, a device, a host loop. A process may run
//! many of them, or none. The control channel belongs to the *process*, so it
//! is open while the daemon is idle and a client can ask it to start something
//! — which is exactly what a service installed at boot has to be able to do.
//! An earlier shape put the listener inside the session, and that made "start
//! a session" unanswerable, because there was nothing listening to answer it.
//!
//! The supervisor is a single thread owning at most one session. Every control
//! client — stdin or socket — forwards the verbs that change something to it
//! and waits for the verdict, so `start` cannot race `start` and `stopSession`
//! cannot race the session ending on its own.

use std::io::{self, BufRead, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sangfor_core::flow::Millis;
use sangfor_core::plan::SessionPlan;
use sangfor_core::plane::{ConnectionConfig, DataPlane, Statistics as PlaneStatistics};
use sangfor_core::terminator::TerminatorConfig;
use sangfor_host::{
    Host, HostConfig, HostEvent, HostHandle, HostObserver, Statistics, TlsConnector,
};
use sangfor_tls::TrustPolicy;

use crate::config::HostConfig as DaemonConfig;
use crate::control::{reply, Action, Reply, Request, Snapshot};
use crate::device::{self, OpenedDevice};
use crate::netconfig::{self, InterfaceConfig};

/// How long to wait for the gateway to assign a virtual IP before giving up on
/// configuring the interface. The handshake has its own deadline inside the
/// plane; this one only bounds the configurator thread.
const VIRTUAL_IP_TIMEOUT: Duration = Duration::from_secs(60);

/// How long a control client waits for the supervisor to carry out a verb.
///
/// Generous on purpose: `start` opens a wintun adapter, which loads a driver
/// and creates a network interface, and that is slow on a cold machine. A
/// client that gave up sooner would report a failure for a start that then
/// succeeded, which is the worst possible outcome to debug.
const DIRECTIVE_TIMEOUT: Duration = Duration::from_secs(120);

/// Where log lines go.
pub struct Logger {
    sink: Mutex<Box<dyn Write + Send>>,
}

impl Logger {
    /// Logs to stderr.
    #[must_use]
    pub fn stderr() -> Arc<Self> {
        Arc::new(Self {
            sink: Mutex::new(Box::new(io::stderr())),
        })
    }

    /// Appends to [path], falling back to stderr if it cannot be opened. A
    /// service with no console has nowhere else to put this, but losing the log
    /// is better than refusing to start the tunnel.
    #[must_use]
    pub fn file(path: &Path) -> Arc<Self> {
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            Ok(file) => Arc::new(Self {
                sink: Mutex::new(Box::new(file)),
            }),
            Err(error) => {
                let logger = Self::stderr();
                logger.line(&format!(
                    "could not open {} for logging ({error}); using stderr",
                    path.display()
                ));
                logger
            }
        }
    }

    /// Writes one timestamped line.
    pub fn line(&self, message: &str) {
        if let Ok(mut sink) = self.sink.lock() {
            let _ = writeln!(sink, "[{}] {message}", timestamp());
        }
    }
}

fn timestamp() -> String {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or_else(
        |_| "-".to_string(),
        |elapsed| format!("{}.{:03}", elapsed.as_secs(), elapsed.subsec_millis()),
    )
}

/// The daemon's view of the tunnel: it logs events, keeps [`Snapshot`] current,
/// and hands the assigned virtual IP to the configurator.
struct Observer {
    log: Arc<Logger>,
    snapshot: Arc<Mutex<Snapshot>>,
    virtual_ips: Sender<Vec<String>>,
}

impl HostObserver for Observer {
    fn on_event(&self, event: HostEvent) {
        match &event {
            HostEvent::VirtualIp(addresses) => {
                if let Ok(mut snapshot) = self.snapshot.lock() {
                    snapshot.virtual_ip = addresses.clone();
                }
                // A full queue means a configurator is already working; the
                // gateway only assigns once per session in practice.
                let _ = self.virtual_ips.send(addresses.clone());
            }
            HostEvent::ChannelOpened { role, peer, digest } => {
                if let Ok(mut snapshot) = self.snapshot.lock() {
                    snapshot.channels_open += 1;
                }
                self.log.line(&format!(
                    "{role} connected to {peer}{}",
                    digest
                        .as_ref()
                        .map_or(String::new(), |value| format!(" (pin {value})"))
                ));
            }
            HostEvent::ChannelClosed { role, reason } => {
                if let Ok(mut snapshot) = self.snapshot.lock() {
                    snapshot.channels_open = snapshot.channels_open.saturating_sub(1);
                }
                self.log.line(&format!("{role} closed: {reason}"));
            }
            HostEvent::ConnectFailed {
                role,
                host,
                port,
                error,
            } => {
                if let Ok(mut snapshot) = self.snapshot.lock() {
                    snapshot.connect_failures += 1;
                }
                self.log
                    .line(&format!("{role} could not reach {host}:{port}: {error}"));
            }
            HostEvent::Log(message) => self.log.line(message),
            HostEvent::Fatal(error) => {
                if let Ok(mut snapshot) = self.snapshot.lock() {
                    snapshot.active = false;
                    snapshot.fatal = Some(error.clone());
                }
                self.log.line(&format!("fatal: {error}"));
            }
            HostEvent::Stopped => self.log.line("the tunnel stopped"),
        }
    }
}

/// The exit status of a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// Stopped cleanly, by request or because the session ended.
    Clean,
    /// The plane reported a fatal error; the control plane must log in again.
    Fatal,
    /// The tunnel process itself failed: no device, no plan, no poller.
    Failed,
}

impl Exit {
    /// The process exit code.
    #[must_use]
    pub fn code(self) -> i32 {
        match self {
            Self::Clean => 0,
            Self::Fatal => 2,
            Self::Failed => 1,
        }
    }
}

/// A verb a control client asked for, and where its outcome goes.
///
/// The client thread blocks on [`Self::respond`], so a `start` that fails to
/// open a device is reported to whoever asked rather than only to the log.
/// That matters most for a service: the app is the only party that can tell
/// the user anything.
pub struct Directive {
    /// What to do. Never [`Action::None`]; those are answered on the spot.
    pub action: Action,
    /// Where the verdict goes.
    pub respond: Sender<Reply>,
}

/// What arrives on the supervisor's inbox.
pub enum Message {
    /// A control client wants something done.
    Directive(Directive),
    /// A session ended by itself — the device went away, or the plane hit a
    /// fatal error — and reports how.
    ///
    /// [generation] is the one [`supervise`] assigned when it started the
    /// session. Without it a stale report could clear a *newer* session: the
    /// supervisor joins a stopped session before reading the queue, but another
    /// client may already have queued a `start` ahead of the `Ended` that the
    /// dying session sent, and the two are indistinguishable otherwise.
    Ended {
        /// Which session this report is about.
        generation: u64,
        /// How it ended.
        exit: Exit,
    },
    /// stdin reached its end, so that control channel is gone for good.
    ///
    /// The supervisor needs to know: with no socket either, there is nobody
    /// left who can ask for another session, and staying alive would be a
    /// process that can never be told to stop. A child launched with `--plan`
    /// and a closed stdin is exactly this case, and exiting when its session
    /// ends is what a launcher waiting on it expects.
    StdinClosed,
}

/// A session that is already resolved and ready to run.
///
/// `main` supplies this for `--plan`, so the device is opened once, up front,
/// where a failure still produces exit code 1 and a message on stderr. A
/// session started later by `start` resolves itself inside the supervisor and
/// reports through the control channel instead.
pub struct InitialSession {
    /// The session document.
    pub plan: SessionPlan,
    /// The device, already open.
    pub device: OpenedDevice,
}

/// One running tunnel: the host loop on its own thread, and the handle that
/// ends it.
///
/// The generation it was started under is tracked by [`supervise`], not here:
/// the only thing that needs it is matching an [`Message::Ended`] to the
/// session it describes, and by then this value has been taken out of the
/// option that held it.
struct Session {
    handle: HostHandle,
    worker: JoinHandle<()>,
}

impl Session {
    /// Ends the session and waits for the host loop to finish.
    ///
    /// Joining matters: the loop owns the device, and returning before it is
    /// done would let the next session open a second adapter while the first is
    /// still being torn down.
    fn stop(self) {
        self.handle.stop();
        if self.worker.join().is_err() {
            // A panicked host loop still ended. The panic is already on stderr,
            // and there is nothing useful to do about it here.
        }
    }
}

/// Runs the process: a control loop that starts and ends sessions.
///
/// [initial] is the session `--plan` asked for, if any. Whether or not it is
/// given, the process then stays alive and serves the control channel until
/// asked to stop — that is the whole point of supervising, and it is what lets
/// one elevated process serve repeated connect/disconnect cycles without
/// re-prompting the user.
///
/// Returns how the last session ended, so a launcher can tell a clean shutdown
/// from a gateway that kicked the session.
pub fn supervise(config: DaemonConfig, initial: Option<InitialSession>) -> Exit {
    let log = config
        .log_path
        .as_deref()
        .map_or_else(Logger::stderr, Logger::file);

    let snapshot = Arc::new(Mutex::new(Snapshot::default()));
    let running = Arc::new(AtomicBool::new(false));
    let (inbox_tx, inbox) = mpsc::channel::<Message>();

    let mut listener = crate::transport::open(
        &config,
        Arc::clone(&snapshot),
        Arc::clone(&running),
        inbox_tx.clone(),
        Arc::clone(&log),
    );
    spawn_stdin_control(
        Arc::clone(&snapshot),
        Arc::clone(&running),
        config.control_token.clone(),
        inbox_tx.clone(),
    );

    let mut session: Option<Session> = None;
    let mut generation: u64 = 0;
    let mut last = Exit::Clean;
    let mut stdin_open = true;

    // Nothing can reach this process any more: no socket, no stdin, no session
    // left to report. A daemon in that state can never be told to start or to
    // stop, so it exits — which is what a launcher that piped a plan in and
    // closed stdin is waiting for. With a control socket open the daemon stays
    // up instead, idle between sessions, because that is the whole point of it.
    let unreachable = |stdin_open: bool, listener: &Option<_>, session: &Option<Session>| {
        !stdin_open && listener.is_none() && session.is_none()
    };

    if let Some(initial) = initial {
        generation += 1;
        match spawn_session(
            generation,
            initial.plan,
            initial.device,
            &config,
            &snapshot,
            Arc::clone(&log),
            inbox_tx.clone(),
        ) {
            Ok(started) => {
                session = Some(started);
                running.store(true, Ordering::SeqCst);
            }
            Err(error) => {
                log.line(&format!("the session could not start: {error}"));
                last = Exit::Failed;
            }
        }
    } else {
        log.line("idle; waiting for a start request");
    }

    let exit = loop {
        let message = match inbox.recv() {
            Ok(message) => message,
            // Every other sender is gone. Only reachable if this function's own
            // clone is dropped, so it is a safety net rather than a path the
            // loop depends on; `unreachable` above decides that deliberately.
            Err(_) => break last,
        };
        match message {
            Message::Directive(directive) => {
                let verdict = match directive.action {
                    Action::None => Reply::acknowledged(),
                    Action::Start {
                        plan,
                        config: session_config,
                    } => {
                        if session.is_some() {
                            // `reply` already refuses this; re-checking is what
                            // makes two clients racing to start safe.
                            Reply::failed("a session is already running; send stopSession first")
                        } else {
                            match resolve(&plan, session_config.as_deref(), &config) {
                                Ok((plan, opened, effective)) => {
                                    generation += 1;
                                    reset_snapshot(&snapshot, &effective);
                                    match spawn_session(
                                        generation,
                                        plan,
                                        opened,
                                        &effective,
                                        &snapshot,
                                        Arc::clone(&log),
                                        inbox_tx.clone(),
                                    ) {
                                        Ok(started) => {
                                            session = Some(started);
                                            running.store(true, Ordering::SeqCst);
                                            Reply::acknowledged()
                                        }
                                        Err(error) => Reply::failed(error.to_string()),
                                    }
                                }
                                Err(error) => Reply::failed(error),
                            }
                        }
                    }
                    Action::StopSession => {
                        if let Some(current) = session.take() {
                            log.line("ending the session on request");
                            current.stop();
                        }
                        running.store(false, Ordering::SeqCst);
                        Reply::acknowledged()
                    }
                    Action::Exit => {
                        if let Some(current) = session.take() {
                            log.line("ending the session and exiting on request");
                            current.stop();
                        }
                        running.store(false, Ordering::SeqCst);
                        // Answered before breaking: a client that asked to stop
                        // is waiting on this, and a closed socket reads as a
                        // crash rather than as a shutdown.
                        let _ = directive.respond.send(Reply::acknowledged());
                        break last;
                    }
                };
                let _ = directive.respond.send(verdict);
            }
            Message::Ended {
                generation: ended,
                exit,
            } => {
                if ended != generation {
                    // A session this process already stopped and replaced. Its
                    // report is about a tunnel that is no longer the current
                    // one, and acting on it would clear the new session's state.
                    continue;
                }
                session = None;
                running.store(false, Ordering::SeqCst);
                last = exit;
                if unreachable(stdin_open, &listener, &session) {
                    log.line(&format!(
                        "the session ended ({exit:?}); nothing left to serve"
                    ));
                    break last;
                }
                log.line(&format!(
                    "the session ended on its own ({exit:?}); staying up for the next one"
                ));
            }
            Message::StdinClosed => {
                stdin_open = false;
                if unreachable(stdin_open, &listener, &session) {
                    break last;
                }
            }
        }
    };

    if let Some(mut listener) = listener.take() {
        listener.shutdown();
    }
    exit
}

/// Reads the plan at [plan_path], merges the per-session configuration at
/// [config_path] over [base] if there is one, validates the result, and opens
/// the device for it.
///
/// Everything is resolved before the session starts, so a `start` that names a
/// missing or malformed document is refused and leaves a running process — and
/// a running session — exactly as it was.
///
/// Returns the effective configuration alongside the plan and device, because
/// both the host loop and the configurator need the merged routes rather than
/// the ones this process started with.
fn resolve(
    plan_path: &Path,
    config_path: Option<&Path>,
    base: &DaemonConfig,
) -> Result<(SessionPlan, OpenedDevice, DaemonConfig), String> {
    let document = std::fs::read(plan_path)
        .map_err(|error| format!("reading {} failed: {error}", plan_path.display()))?;
    let plan = SessionPlan::decode(&document).map_err(|error| error.to_string())?;

    let config = match config_path {
        Some(path) => {
            let document = std::fs::read(path)
                .map_err(|error| format!("reading {} failed: {error}", path.display()))?;
            let session = DaemonConfig::decode(&document).map_err(|error| error.to_string())?;
            let merged = base.for_session(session);
            merged.validate().map_err(|error| error.to_string())?;
            merged
        }
        None => base.clone(),
    };

    let opened = device::open(&config).map_err(|error| error.to_string())?;
    Ok((plan, opened, config))
}

/// Clears the previous session's report.
///
/// `fatal` above all: a client that reads a stale fatal after starting a new
/// session concludes the new one died, and reconnects in a loop.
fn reset_snapshot(snapshot: &Arc<Mutex<Snapshot>>, config: &DaemonConfig) {
    if let Ok(mut current) = snapshot.lock() {
        *current = Snapshot {
            interface: Some(config.interface.clone()),
            ..Snapshot::default()
        };
    }
}

/// Builds the plane and host for one session and runs the loop on its own
/// thread, reporting the outcome to [inbox] when it finishes.
fn spawn_session(
    generation: u64,
    plan: SessionPlan,
    opened: OpenedDevice,
    config: &DaemonConfig,
    snapshot: &Arc<Mutex<Snapshot>>,
    log: Arc<Logger>,
    inbox: Sender<Message>,
) -> Result<Session, RunError> {
    let policy = TrustPolicy {
        pins: plan.certificate_digests.clone(),
        accept_unpinned: config.accept_unpinned_certificate,
    };
    let connector = Arc::new(TlsConnector::new(
        policy,
        Duration::from_secs(config.connect_timeout_seconds.max(1)),
    ));

    // The seed only has to be stable per process, not secret: it picks initial
    // sequence numbers. Same rule as the FFI host, so both age flows alike.
    let heartbeat = plan.heartbeat_seconds.max(1.0) * 1000.0;
    let plane = DataPlane::new(
        plan.clone(),
        ConnectionConfig {
            heartbeat_interval_ms: heartbeat as Millis,
            ..ConnectionConfig::default()
        },
        TerminatorConfig::default(),
        now_ms(),
    );

    let device = Arc::clone(&opened.device);
    let mut host = Host::new(
        plane,
        device,
        connector,
        HostConfig {
            read_buffer: usize::from(plan.mtu.max(576)) + 64,
            ..HostConfig::default()
        },
    )
    .map_err(|error| RunError::Host(error.to_string()))?;

    let snapshot = Arc::clone(snapshot);
    let (vip_tx, vip_rx) = mpsc::channel();
    host.set_observer(Arc::new(Observer {
        log: Arc::clone(&log),
        snapshot: Arc::clone(&snapshot),
        virtual_ips: vip_tx,
    }));
    host.set_statistics_sink({
        let snapshot = Arc::clone(&snapshot);
        Arc::new(move |plane: &PlaneStatistics, host: &Statistics| {
            if let Ok(mut current) = snapshot.lock() {
                current.active = plane.ingress > 0 || plane.routed > 0 || current.active;
                current.device_packets = host.device_packets;
                current.emitted_packets = host.emitted_packets;
                current.device_dropped = host.device_dropped;
                current.emit_failures = host.emit_failures;
                current.channel_bytes_in = host.channel_bytes_in;
                current.channel_bytes_out = host.channel_bytes_out;
                current.channels_open = host.channels_open;
                current.connect_failures = host.connect_failures;
                current.routed = plane.routed;
                current.terminated = plane.terminated;
                current.unrouted = plane.unrouted;
                current.ingress = plane.ingress;
            }
        })
    });

    let handle = host.handle();
    if let Ok(mut current) = snapshot.lock() {
        current.interface = Some(config.interface.clone());
    }
    spawn_configurator(
        vip_rx,
        config.clone(),
        plan,
        opened,
        Arc::clone(&snapshot),
        Arc::clone(&log),
    );

    let interface = config.interface.clone();
    let kind = config.device;
    log.line(&format!("starting the tunnel on {interface} ({kind:?})"));
    let worker = thread::Builder::new()
        .name("sangfor-session".to_string())
        .spawn(move || {
            let exit = match host.run() {
                Ok(()) => {
                    let fatal = snapshot
                        .lock()
                        .ok()
                        .and_then(|current| current.fatal.clone());
                    if fatal.is_some() {
                        Exit::Fatal
                    } else {
                        Exit::Clean
                    }
                }
                Err(error) => {
                    log.line(&format!("the host loop failed: {error}"));
                    Exit::Failed
                }
            };
            let _ = inbox.send(Message::Ended { generation, exit });
        })
        .map_err(|error| RunError::Host(error.to_string()))?;

    Ok(Session { handle, worker })
}

/// Why the tunnel process could not run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunError {
    /// The host loop or the device failed.
    Host(String),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Host(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for RunError {}

/// Answers one control line, involving the supervisor only when the verb
/// changes what the process is doing.
///
/// Both transports call this, so stdin and the loopback socket cannot drift
/// apart in what they accept or how they report a refusal.
pub fn dispatch(
    line: &str,
    snapshot: &Arc<Mutex<Snapshot>>,
    running: &AtomicBool,
    token: Option<&str>,
    supervisor: &Sender<Message>,
) -> Reply {
    let request = match Request::parse(line) {
        Ok(request) => request,
        Err(error) => return Reply::failed(error),
    };
    let session_running = running.load(Ordering::SeqCst);
    let mut current = snapshot
        .lock()
        .map_or_else(|_| Snapshot::default(), |guard| guard.clone());
    // The atomic is the one source of truth; the stored snapshot does not carry
    // this field, so a reader never sees a stale copy of it.
    current.session_running = session_running;

    let (reply, action) = reply(&request, &current, token, session_running);
    if action == Action::None {
        return reply;
    }
    let (respond, verdict) = mpsc::channel();
    if supervisor
        .send(Message::Directive(Directive { action, respond }))
        .is_err()
    {
        return Reply::failed("the daemon is shutting down");
    }
    verdict.recv_timeout(DIRECTIVE_TIMEOUT).unwrap_or_else(|_| {
        Reply::failed(format!(
            "the daemon did not answer within {}s",
            DIRECTIVE_TIMEOUT.as_secs()
        ))
    })
}

/// Waits for the gateway to assign an address, then configures the interface.
///
/// Its own thread, because `netsh` takes long enough that running it on the host
/// loop would stall every flow in the tunnel.
fn spawn_configurator(
    virtual_ips: Receiver<Vec<String>>,
    config: DaemonConfig,
    plan: SessionPlan,
    opened: OpenedDevice,
    snapshot: Arc<Mutex<Snapshot>>,
    log: Arc<Logger>,
) {
    thread::Builder::new()
        .name("sangfor-netconfig".to_string())
        .spawn(move || {
            let addresses = match virtual_ips.recv_timeout(VIRTUAL_IP_TIMEOUT) {
                Ok(addresses) => addresses,
                Err(_) => {
                    log.line(
                        "the gateway never assigned a virtual IP; the interface stays unconfigured",
                    );
                    if let Ok(mut current) = snapshot.lock() {
                        current.interface_error =
                            Some("no virtual IP within the timeout".to_string());
                    }
                    return;
                }
            };
            let resolved = match InterfaceConfig::resolve(
                &config,
                &plan,
                addresses.first().map(String::as_str),
            ) {
                Ok(resolved) => resolved,
                Err(error) => {
                    log.line(&format!("the interface could not be configured: {error}"));
                    if let Ok(mut current) = snapshot.lock() {
                        current.interface_error = Some(error.to_string());
                    }
                    return;
                }
            };
            if !resolved.excluded.is_empty() {
                // Worth saying out loud: the control plane is supposed to keep
                // node endpoints out of the tunnel routes.
                log.line(&format!(
                    "dropped routes that would have captured a gateway node: {}",
                    resolved.excluded.join(", ")
                ));
            }
            log.line(&format!(
                "configuring {} with {} and {} route(s)",
                config.interface,
                resolved.address,
                resolved.routes.len()
            ));
            let outcome = netconfig::apply(&opened, &resolved);
            match &outcome {
                Ok(()) => {
                    if let Ok(mut current) = snapshot.lock() {
                        current.interface_configured = true;
                        current.interface_error = None;
                    }
                    log.line("the interface is configured");
                }
                Err(error) => {
                    if let Ok(mut current) = snapshot.lock() {
                        current.interface_error = Some(error.to_string());
                    }
                    log.line(&format!("configuring the interface failed: {error}"));
                }
            }
        })
        .ok();
}

/// Serves the control protocol on stdin/stdout.
///
/// Not joined: when the supervisor ends, `main` returns and the process exits,
/// which is the only reliable way to end a thread blocked reading a console. A
/// service has no console and gets [`crate::transport`] instead.
///
/// The thread reports [`Message::StdinClosed`] when stdin ends, including when
/// the thread could not be started at all — the supervisor counts on hearing it
/// either way, because a closed stdin is one of the two conditions under which
/// it decides nobody can reach it any more.
fn spawn_stdin_control(
    snapshot: Arc<Mutex<Snapshot>>,
    running: Arc<AtomicBool>,
    token: Option<String>,
    supervisor: Sender<Message>,
) {
    let closed = supervisor.clone();
    let spawned = thread::Builder::new()
        .name("sangfor-stdin-control".to_string())
        .spawn(move || {
            let stdin = io::stdin();
            let stdout = io::stdout();
            let mut out = stdout.lock();
            for line in stdin.lock().lines() {
                let Ok(line) = line else {
                    break;
                };
                if line.trim().is_empty() {
                    continue;
                }
                let reply = dispatch(&line, &snapshot, &running, token.as_deref(), &supervisor);
                let _ = writeln!(out, "{}", reply.render());
                let _ = out.flush();
            }
            let _ = supervisor.send(Message::StdinClosed);
        });
    if spawned.is_err() {
        let _ = closed.send(Message::StdinClosed);
    }
}

fn now_ms() -> Millis {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as Millis)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DeviceKind;

    /// A plan that names a documentation-range node, so a session comes up and
    /// then fails to connect. These tests are about the process, not the
    /// gateway.
    fn plan() -> SessionPlan {
        SessionPlan::decode(
            br#"{"schemaVersion":1,"sid":"s","deviceId":"d","connectionId":"c",
                 "username":"u","signKeyBase64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                 "lang":"en","processName":"p","processPath":"/p","processPlatform":"linux",
                 "nodes":{"major":["203.0.113.9:441"]},"majorNodeGroup":"major",
                 "routes":[],"dnsServers":[],"heartbeatSeconds":1}"#,
        )
        .expect("the plan decodes")
    }

    fn loopback_config(port: u16) -> DaemonConfig {
        DaemonConfig {
            device: DeviceKind::Loopback,
            interface: "supervisor-test".to_string(),
            control_port: Some(port),
            ..DaemonConfig::default()
        }
    }

    /// Drives a supervisor running on its own thread through its control socket.
    ///
    /// This is the test that matters: the pieces above are individually simple,
    /// and what could go wrong is the sequencing between them — a session that
    /// cannot be started twice, a `stopSession` that leaves the process unable
    /// to serve the next one, a state flag that outlives the session it
    /// describes.
    struct Supervisor {
        port: u16,
        exit: Arc<Mutex<Option<Exit>>>,
        _thread: Option<JoinHandle<()>>,
        dir: std::path::PathBuf,
    }

    impl Drop for Supervisor {
        fn drop(&mut self) {
            // Never leave a tunnel thread or a scratch directory behind.
            if let Some(thread) = self._thread.take() {
                let _ = transport_request(self.port, r#"{"cmd":"stop"}"#);
                let _ = thread.join();
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// Asks a free port of the kernel and then releases it. Racy in principle
    /// and fine in practice: nothing else in the test run binds ephemeral ports
    /// in this window.
    fn free_port() -> u16 {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bindable");
        listener.local_addr().expect("an address").port()
    }

    fn start_supervisor(name: &str, initial: bool) -> Supervisor {
        let dir =
            std::env::temp_dir().join(format!("sangfor-supervise-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let plan_path = dir.join("plan.json");
        std::fs::write(&plan_path, PLAN_DOCUMENT).expect("writable");

        let mut config = loopback_config(free_port());
        config.interface = format!("sup-{name}");
        let port = config.control_port.expect("set above");

        let opened = device::open(&config).expect("a loopback device");
        let initial_session = initial.then(|| InitialSession {
            plan: SessionPlan::decode(PLAN_DOCUMENT.as_bytes()).expect("the plan decodes"),
            device: opened,
        });

        let exit = Arc::new(Mutex::new(None));
        let reported = Arc::clone(&exit);
        let thread = thread::Builder::new()
            .name(format!("supervise-{name}"))
            .spawn(move || {
                let outcome = supervise(config, initial_session);
                *reported.lock().expect("lockable") = Some(outcome);
            })
            .expect("a thread");

        // Wait for the control socket rather than sleeping a fixed time.
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while std::time::Instant::now() < deadline {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return Supervisor {
                    port,
                    exit,
                    _thread: Some(thread),
                    dir,
                };
            }
            thread::sleep(Duration::from_millis(20));
        }
        panic!("the supervisor never opened its control socket");
    }

    /// Sends one line and reads one reply.
    fn transport_request(port: u16, request: &str) -> io::Result<String> {
        let mut socket = std::net::TcpStream::connect(("127.0.0.1", port))?;
        socket.set_read_timeout(Some(Duration::from_secs(30)))?;
        socket.set_write_timeout(Some(Duration::from_secs(30)))?;
        socket.write_all(format!("{request}\n").as_bytes())?;
        socket.flush()?;
        let mut line = String::new();
        io::BufReader::new(&mut socket).read_line(&mut line)?;
        Ok(line.trim().to_string())
    }

    fn ask(supervisor: &Supervisor, request: &str) -> Reply {
        let line = transport_request(supervisor.port, request).expect("a reply");
        serde_json::from_str(&line).unwrap_or_else(|_| panic!("the reply is JSON: {line}"))
    }

    fn session_running(supervisor: &Supervisor) -> bool {
        let reply = ask(supervisor, r#"{"cmd":"status"}"#);
        assert!(reply.ok, "status: {reply:?}");
        reply.data.expect("a snapshot").session_running
    }

    const PLAN_DOCUMENT: &str = r#"{"schemaVersion":1,"sid":"supervise","deviceId":"d",
        "connectionId":"c","username":"u",
        "signKeyBase64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "lang":"en","processName":"tunneld","processPath":"/tunneld",
        "processPlatform":"linux","nodes":{"major":["203.0.113.9:441"]},
        "majorNodeGroup":"major","routes":[],"dnsServers":[],"heartbeatSeconds":1}"#;

    #[test]
    fn an_idle_daemon_starts_a_session_and_can_start_another() {
        // The reason the supervisor exists. A service installed at boot has no
        // plan; it has to be able to answer "start one" while idle, and then do
        // it again after the user disconnects and reconnects.
        let mut supervisor = start_supervisor("reuse", false);
        assert!(
            !session_running(&supervisor),
            "a freshly started daemon has no session"
        );

        let plan_path = supervisor.dir.join("plan.json");
        let start = format!(
            r#"{{"cmd":"start","planPath":"{}"}}"#,
            plan_path.display().to_string().replace('\\', "\\\\")
        );
        let reply = ask(&supervisor, &start);
        assert!(reply.ok, "the first start: {reply:?}");
        assert!(session_running(&supervisor), "and it is running");

        let reply = ask(&supervisor, r#"{"cmd":"stopSession"}"#);
        assert!(reply.ok, "stopSession: {reply:?}");
        assert!(
            !session_running(&supervisor),
            "the session is gone but the process is not"
        );

        // The part that would silently break if the device or the snapshot were
        // left bound to the first session.
        let reply = ask(&supervisor, &start);
        assert!(reply.ok, "a second start on the same process: {reply:?}");
        assert!(session_running(&supervisor), "and it is running again");

        let reply = ask(&supervisor, r#"{"cmd":"stop"}"#);
        assert!(reply.ok, "stop: {reply:?}");
        let thread = supervisor._thread.take().expect("running");
        thread.join().expect("the supervisor ended");
        assert_eq!(
            *supervisor.exit.lock().expect("lockable"),
            Some(Exit::Clean),
            "a requested stop exits cleanly"
        );
    }

    #[test]
    fn a_second_start_is_refused_while_a_session_is_running() {
        let supervisor = start_supervisor("busy", false);
        let plan_path = supervisor
            .dir
            .join("plan.json")
            .display()
            .to_string()
            .replace('\\', "\\\\");
        let start = format!(r#"{{"cmd":"start","planPath":"{plan_path}"}}"#);
        assert!(ask(&supervisor, &start).ok, "the first start");

        let refused = ask(&supervisor, &start);
        assert!(!refused.ok, "a running session is not replaced");
        assert!(
            refused
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("stopSession"),
            "the refusal says how to proceed: {refused:?}"
        );
        assert!(
            session_running(&supervisor),
            "and the first session survived the attempt"
        );
    }

    #[test]
    fn a_start_that_names_a_missing_plan_leaves_the_daemon_usable() {
        // The failure has to be reported to the caller and must not take the
        // process down with it: a service that dies on a bad path cannot be
        // restarted by the app that just made the mistake.
        let supervisor = start_supervisor("badplan", false);
        let reply = ask(
            &supervisor,
            r#"{"cmd":"start","planPath":"Z:/absent/plan.json"}"#,
        );
        assert!(!reply.ok);
        assert!(
            reply
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("absent"),
            "the error names the path: {reply:?}"
        );
        assert!(!session_running(&supervisor));

        let ping = ask(&supervisor, r#"{"cmd":"ping"}"#);
        assert!(ping.ok, "the daemon is still serving");

        let plan_path = supervisor
            .dir
            .join("plan.json")
            .display()
            .to_string()
            .replace('\\', "\\\\");
        let reply = ask(
            &supervisor,
            &format!(r#"{{"cmd":"start","planPath":"{plan_path}"}}"#),
        );
        assert!(reply.ok, "and a good plan still starts: {reply:?}");
    }

    #[test]
    fn a_daemon_started_with_a_plan_runs_it_and_then_goes_idle() {
        // `--plan` used to mean "run this session and exit". It now means "run
        // this session first", which is what makes one elevated process serve
        // more than one connect/disconnect cycle.
        let supervisor = start_supervisor("initial", true);
        assert!(
            session_running(&supervisor),
            "the initial session is running"
        );
        let status = ask(&supervisor, r#"{"cmd":"status"}"#);
        let data = status.data.expect("a snapshot");
        assert_eq!(
            data.interface.as_deref(),
            Some("sup-initial"),
            "the snapshot describes the running session"
        );

        assert!(ask(&supervisor, r#"{"cmd":"stopSession"}"#).ok);
        assert!(!session_running(&supervisor), "and the process outlives it");
    }

    #[test]
    fn a_session_builds_and_can_be_joined() {
        // The pieces `supervise` composes, checked separately: an initial
        // session builds and its thread can be joined.
        let config = loopback_config(0);
        let opened = device::open(&config).expect("a loopback device");
        let snapshot = Arc::new(Mutex::new(Snapshot::default()));
        let (tx, _rx) = mpsc::channel::<Message>();
        let session = spawn_session(1, plan(), opened, &config, &snapshot, Logger::stderr(), tx)
            .expect("the session starts");
        assert!(session.handle.is_running());
        session.stop();
    }

    #[test]
    fn stopping_a_session_yields_its_report() {
        let config = loopback_config(0);
        let opened = device::open(&config).expect("a loopback device");
        let snapshot = Arc::new(Mutex::new(Snapshot::default()));
        let (tx, rx) = mpsc::channel::<Message>();
        let session = spawn_session(7, plan(), opened, &config, &snapshot, Logger::stderr(), tx)
            .expect("the session starts");
        session.stop();
        let message = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the session reports how it ended");
        match message {
            Message::Ended { generation, .. } => {
                assert_eq!(generation, 7, "the report names the session it is about")
            }
            Message::Directive(_) | Message::StdinClosed => {
                panic!("a session thread reports its ending and nothing else")
            }
        }
    }

    #[test]
    fn resolving_a_plan_names_the_file_that_was_missing() {
        let config = loopback_config(0);
        let error =
            resolve(Path::new("Z:/absent/plan.json"), None, &config).expect_err("no such file");
        assert!(
            error.contains("Z:/absent/plan.json") || error.contains("Z:\\absent\\plan.json"),
            "{error}"
        );
    }

    #[test]
    fn resolving_a_malformed_plan_says_so_before_a_device_opens() {
        let dir = std::env::temp_dir().join(format!("sangfor-resolve-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let path = dir.join("plan.json");
        std::fs::write(&path, b"not a plan").expect("writable");
        let error = resolve(&path, None, &loopback_config(0)).expect_err("malformed");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            error.contains("JSON") || error.contains("expected"),
            "the parse error reaches the caller: {error}"
        );
    }

    #[test]
    fn a_per_session_configuration_replaces_the_routes_the_daemon_started_with() {
        // An installed daemon is configured once, but which routes belong in
        // the tunnel depends on what the gateway published for this session.
        // Without this the daemon would install the routes it was installed
        // with, which are the ones from somebody's last connection.
        let dir =
            std::env::temp_dir().join(format!("sangfor-session-config-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let plan_path = dir.join("plan.json");
        let config_path = dir.join("session.json");
        std::fs::write(&plan_path, PLAN_DOCUMENT).expect("writable");
        std::fs::write(
            &config_path,
            br#"{"routes":["10.7.0.0/16"],"dnsServers":["10.0.0.53"],
                "controlPort":1,"controlToken":"hijack"}"#,
        )
        .expect("writable");

        let base = DaemonConfig {
            control_token: Some("real".to_string()),
            routes: vec!["10.1.0.0/16".to_string()],
            ..loopback_config(0)
        };
        let (_, _, effective) = resolve(&plan_path, Some(&config_path), &base).expect("resolves");
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(
            effective.routes,
            vec!["10.7.0.0/16"],
            "the session's routes"
        );
        assert_eq!(effective.dns_servers, vec!["10.0.0.53"]);
        assert_eq!(
            effective.control_token.as_deref(),
            Some("real"),
            "and it did not get to change the token"
        );
    }

    #[test]
    fn a_per_session_configuration_that_is_not_valid_is_refused_before_a_device_opens() {
        let dir = std::env::temp_dir().join(format!("sangfor-bad-session-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let plan_path = dir.join("plan.json");
        let config_path = dir.join("session.json");
        std::fs::write(&plan_path, PLAN_DOCUMENT).expect("writable");
        std::fs::write(&config_path, br#"{"routes":["10.0.0.0/33"]}"#).expect("writable");

        let error = resolve(&plan_path, Some(&config_path), &loopback_config(0))
            .expect_err("a route that is not a CIDR block");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(error.contains("not an IPv4 CIDR block"), "{error}");
    }

    #[test]
    fn starting_a_session_clears_the_previous_one_s_report() {
        // A stale `fatal` is worse than none: a client that reads it after
        // starting a new session concludes the new session died and reconnects
        // in a loop.
        let config = loopback_config(0);
        let snapshot = Arc::new(Mutex::new(Snapshot {
            session_running: true,
            active: true,
            fatal: Some("the gateway closed the session".to_string()),
            routed: 99,
            interface: Some("old".to_string()),
            ..Snapshot::default()
        }));
        reset_snapshot(&snapshot, &config);
        let cleared = snapshot.lock().expect("lockable").clone();
        assert!(cleared.fatal.is_none(), "the fatal report is gone");
        assert!(!cleared.active);
        assert_eq!(cleared.routed, 0, "counters describe the new session");
        assert_eq!(
            cleared.interface.as_deref(),
            Some("supervisor-test"),
            "the interface name is this process's, not the old session's"
        );
    }

    #[test]
    fn dispatch_answers_status_without_waking_the_supervisor() {
        // `status` and `ping` must work while the supervisor is busy starting a
        // session, or a client polling for readiness would deadlock against the
        // very thing it is waiting for.
        let snapshot = Arc::new(Mutex::new(Snapshot {
            active: true,
            interface: Some("dispatch-test".to_string()),
            ..Snapshot::default()
        }));
        let running = AtomicBool::new(true);
        let (tx, rx) = mpsc::channel::<Message>();
        let reply = dispatch(r#"{"cmd":"status"}"#, &snapshot, &running, None, &tx);
        assert!(reply.ok);
        let data = reply.data.expect("a snapshot");
        assert!(
            data.session_running,
            "filled in from the atomic, not the stored copy"
        );
        assert!(
            rx.try_recv().is_err(),
            "nothing was forwarded to the supervisor"
        );
    }

    #[test]
    fn dispatch_forwards_a_supervisor_verb_and_returns_its_verdict() {
        let snapshot = Arc::new(Mutex::new(Snapshot::default()));
        let running = AtomicBool::new(false);
        let (tx, rx) = mpsc::channel::<Message>();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&seen);
        let supervisor = thread::spawn(move || {
            while let Ok(Message::Directive(directive)) = rx.recv() {
                recorded
                    .lock()
                    .expect("lockable")
                    .push(directive.action.clone());
                let _ = directive.respond.send(Reply::acknowledged());
            }
        });

        // Nothing is running, so `stopSession` is answered on the spot: an idle
        // daemon has nothing to stop, and waking the supervisor for that would
        // make a normal disconnect contend with a start in progress.
        let reply = dispatch(r#"{"cmd":"stopSession"}"#, &snapshot, &running, None, &tx);
        assert!(reply.ok);
        assert!(
            seen.lock().expect("lockable").is_empty(),
            "an idle stopSession is a no-op that never reaches the supervisor"
        );

        // With a session running it does go there, and the verdict comes back.
        running.store(true, Ordering::SeqCst);
        let reply = dispatch(r#"{"cmd":"stopSession"}"#, &snapshot, &running, None, &tx);
        assert!(reply.ok);
        assert_eq!(
            *seen.lock().expect("lockable"),
            vec![Action::StopSession],
            "exactly one directive was forwarded"
        );

        drop(tx);
        supervisor.join().expect("the supervisor ran");
    }

    #[test]
    fn dispatch_reports_a_shutdown_rather_than_hanging() {
        // The supervisor is gone: the client must be told, not left waiting on
        // a verdict that will never arrive.
        let snapshot = Arc::new(Mutex::new(Snapshot::default()));
        let running = AtomicBool::new(true);
        let (tx, rx) = mpsc::channel::<Message>();
        drop(rx);
        let reply = dispatch(r#"{"cmd":"stopSession"}"#, &snapshot, &running, None, &tx);
        assert!(!reply.ok);
        assert!(
            reply.error.unwrap_or_default().contains("shutting down"),
            "the client learns the daemon is going away"
        );
    }

    #[test]
    fn dispatch_refuses_garbage_with_an_error_the_client_can_show() {
        let snapshot = Arc::new(Mutex::new(Snapshot::default()));
        let running = AtomicBool::new(false);
        let (tx, _rx) = mpsc::channel::<Message>();
        let reply = dispatch("nonsense", &snapshot, &running, None, &tx);
        assert!(!reply.ok);
        assert!(reply.error.unwrap_or_default().contains("unrecognised"));
    }
}
