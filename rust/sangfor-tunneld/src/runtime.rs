//! Wiring: logging, the control channel, the interface configurator, and the
//! run loop.
//!
//! Everything here is glue between pieces that are tested on their own, so the
//! only logic worth unit-testing is the part that decides *when* to do
//! something: [`Snapshot`] updates, and the ordering of "wait for the gateway to
//! assign an address" before "configure the interface".

use std::io::{self, BufRead, Write};
use std::path::Path;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sangfor_core::flow::Millis;
use sangfor_core::plan::SessionPlan;
use sangfor_core::plane::{ConnectionConfig, DataPlane, Statistics as PlaneStatistics};
use sangfor_core::terminator::TerminatorConfig;
use sangfor_host::{Host, HostConfig, HostEvent, HostObserver, Statistics, TlsConnector};
use sangfor_tls::TrustPolicy;

use crate::config::HostConfig as DaemonConfig;
use crate::control::{reply, Action, Command, Reply, Snapshot};
use crate::device::OpenedDevice;
use crate::netconfig::{self, InterfaceConfig};

/// How long to wait for the gateway to assign a virtual IP before giving up on
/// configuring the interface. The handshake has its own deadline inside the
/// plane; this one only bounds the configurator thread.
const VIRTUAL_IP_TIMEOUT: Duration = Duration::from_secs(60);

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

/// Runs the tunnel until it stops.
///
/// [plan] is the session document from the control plane, [config] the host
/// document from whoever launched this process, and [opened] the device that is
/// already open.
///
/// # Errors
///
/// Returns the poller's or device's error. A gateway refusing the session is not
/// an error here: it arrives as [`Exit::Fatal`].
pub fn run(
    plan: SessionPlan,
    config: DaemonConfig,
    opened: OpenedDevice,
) -> Result<Exit, RunError> {
    let log = config
        .log_path
        .as_deref()
        .map_or_else(Logger::stderr, Logger::file);

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

    let snapshot = Arc::new(Mutex::new(Snapshot::default()));
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
    spawn_configurator(
        vip_rx,
        config.clone(),
        plan,
        opened,
        Arc::clone(&snapshot),
        Arc::clone(&log),
    );
    spawn_control(Arc::clone(&snapshot), handle);

    log.line(&format!(
        "starting the tunnel on {} ({:?})",
        // The device was moved into the host, so name it from the config.
        config.interface,
        config.device
    ));
    let result = host.run();
    let fatal = snapshot
        .lock()
        .ok()
        .and_then(|current| current.fatal.clone());
    match result {
        Ok(()) => Ok(if fatal.is_some() {
            Exit::Fatal
        } else {
            Exit::Clean
        }),
        Err(error) => Err(RunError::Host(error.to_string())),
    }
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
/// Not joined: when the host loop ends, `main` returns and the process exits,
/// which is the only reliable way to end a thread blocked reading a console.
fn spawn_control(snapshot: Arc<Mutex<Snapshot>>, handle: sangfor_host::HostHandle) {
    thread::Builder::new()
        .name("sangfor-control".to_string())
        .spawn(move || {
            let stdin = io::stdin();
            let stdout = io::stdout();
            let mut out = stdout.lock();
            for line in stdin.lock().lines() {
                let Ok(line) = line else {
                    return;
                };
                if line.trim().is_empty() {
                    continue;
                }
                let (reply, action) = match Command::parse(&line) {
                    Ok(command) => {
                        let current = snapshot
                            .lock()
                            .map_or_else(|_| Snapshot::default(), |guard| guard.clone());
                        reply(command, &current)
                    }
                    Err(error) => (Reply::failed(error), Action::None),
                };
                let _ = writeln!(out, "{}", reply.render());
                let _ = out.flush();
                if action == Action::Stop {
                    handle.stop();
                    return;
                }
            }
        })
        .ok();
}

fn now_ms() -> Millis {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as Millis)
}
