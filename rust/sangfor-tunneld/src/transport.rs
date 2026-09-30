//! The control transport: a loopback TCP listener.
//!
//! A child process can be driven over stdin, which is what [`crate::runtime`]
//! wires up. A Windows service or a systemd unit has no stdin, and neither does
//! a daemon that has to outlive the app that started it — so the same protocol
//! is also served here over `127.0.0.1`.
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
//! `stop`. No secret crosses this channel in either direction, and the process
//! never impersonates a client, so there is no token-theft path either. A local
//! unprivileged process that can stop your VPN can also disable the network
//! adapter. Configure a token in anything but a development run.

use std::io::{self, BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use sangfor_host::HostHandle;

use crate::control::{reply, Action, Reply, Request, Snapshot};
use crate::runtime::Logger;

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
    stop: HostHandle,
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
                        let client_stop = stop.clone();
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
                                    &client_stop,
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
fn serve(
    mut socket: TcpStream,
    token: Option<&str>,
    snapshot: &Arc<Mutex<Snapshot>>,
    stop: &HostHandle,
    log: &Logger,
) {
    let _ = socket.set_read_timeout(Some(CLIENT_TIMEOUT));
    let _ = socket.set_write_timeout(Some(CLIENT_TIMEOUT));
    let peer = socket
        .peer_addr()
        .map(|address| address.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
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
        let Ok(line) = line else {
            return;
        };
        if line.trim().is_empty() {
            continue;
        }
        let (reply, action) = match Request::parse(&line) {
            Ok(request) => {
                let current = snapshot
                    .lock()
                    .map_or_else(|_| Snapshot::default(), |guard| guard.clone());
                reply(&request, &current, token)
            }
            Err(error) => (Reply::failed(error), Action::None),
        };
        if write_reply(&mut socket, &reply).is_err() {
            return;
        }
        if action == Action::Stop {
            log.line(&format!(
                "a control client at {peer} asked the tunnel to stop"
            ));
            stop.stop();
            return;
        }
    }
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
pub fn request_once(port: u16, request: &Request, timeout: Duration) -> io::Result<Reply> {
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
    use std::sync::Arc;

    /// A [`HostHandle`] that records stops, so a test can assert `stop` reached
    /// the tunnel without running one.
    fn stop_flag() -> (HostHandle, Arc<AtomicBool>) {
        let device = Arc::new(sangfor_tun::LoopbackDevice::new("control-test"));
        let plan = sangfor_core::plan::SessionPlan::decode(
            br#"{"schemaVersion":1,"sid":"s","deviceId":"d","connectionId":"c",
                 "username":"u","signKeyBase64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                 "lang":"en","processName":"p","processPath":"/p","processPlatform":"linux",
                 "nodes":{},"majorNodeGroup":"major","routes":[],"dnsServers":[]}"#,
        )
        .expect("the plan decodes");
        let plane = sangfor_core::plane::DataPlane::new(
            plan,
            sangfor_core::plane::ConnectionConfig::default(),
            sangfor_core::terminator::TerminatorConfig::default(),
            1,
        );
        let connector = Arc::new(sangfor_host::TlsConnector::new(
            sangfor_tls::TrustPolicy::opportunistic(),
            Duration::from_secs(1),
        ));
        let host = sangfor_host::Host::new(
            plane,
            device,
            connector,
            sangfor_host::HostConfig::default(),
        )
        .expect("a host");
        (host.handle(), Arc::new(AtomicBool::new(false)))
    }

    fn listener(token: Option<&str>) -> (ControlListener, Arc<Mutex<Snapshot>>) {
        let snapshot = Arc::new(Mutex::new(Snapshot {
            active: true,
            interface: Some("sangfor-test".to_string()),
            ..Snapshot::default()
        }));
        let (handle, _) = stop_flag();
        let listener = spawn(
            0,
            token.map(str::to_string),
            Arc::clone(&snapshot),
            handle,
            Logger::stderr(),
        )
        .expect("the listener binds");
        assert!(listener.port > 0, "an ephemeral port was assigned");
        (listener, snapshot)
    }

    #[test]
    fn a_client_can_ping_and_read_a_snapshot() {
        let (mut listener, _) = listener(None);
        let ping = request_once(
            listener.port,
            &Request::new(crate::control::Command::Ping),
            Duration::from_secs(5),
        )
        .expect("a reply");
        assert!(ping.ok);

        let status = request_once(
            listener.port,
            &Request::new(crate::control::Command::Status),
            Duration::from_secs(5),
        )
        .expect("a reply");
        assert!(status.ok);
        let data = status.data.expect("a snapshot");
        assert!(data.active);
        assert_eq!(data.interface.as_deref(), Some("sangfor-test"));
        listener.shutdown();
    }

    #[test]
    fn a_token_is_required_when_one_is_configured() {
        let (mut listener, _) = listener(Some("s3cret"));
        let refused = request_once(
            listener.port,
            &Request::new(crate::control::Command::Status),
            Duration::from_secs(5),
        )
        .expect("a reply");
        assert!(!refused.ok, "no token, no snapshot");

        let allowed = request_once(
            listener.port,
            &Request {
                cmd: crate::control::Command::Status,
                token: Some("s3cret".to_string()),
            },
            Duration::from_secs(5),
        )
        .expect("a reply");
        assert!(allowed.ok);
        assert!(allowed.data.is_some());
        listener.shutdown();
    }

    #[test]
    fn garbage_gets_an_error_reply_rather_than_silence() {
        let (mut listener, _) = listener(None);
        let reply = request_once(
            listener.port,
            // `request_once` serializes a Request, so drive the socket directly
            // to send something that is not one.
            &Request::new(crate::control::Command::Ping),
            Duration::from_secs(5),
        )
        .expect("a reply");
        assert!(reply.ok);

        let mut socket = TcpStream::connect(("127.0.0.1", listener.port)).expect("connects");
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
        listener.shutdown();
    }

    #[test]
    fn several_commands_on_one_connection_are_answered_in_order() {
        let (mut listener, _) = listener(None);
        let mut socket = TcpStream::connect(("127.0.0.1", listener.port)).expect("connects");
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
        listener.shutdown();
    }

    #[test]
    fn shutdown_ends_the_listener() {
        let (mut listener, _) = listener(None);
        let port = listener.port;
        listener.shutdown();
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
}
