//! Subprocess tests: the shipped binary, launched the way a service manager or
//! an app would launch it.
//!
//! Unit tests cover the pieces. These cover the thing that actually ships — that
//! the binary starts, reads its two documents, opens a device, serves the control
//! protocol, and exits with the right code. They need no driver, no elevation,
//! and no gateway, because `--dry-run` substitutes the in-memory device.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, ChildStderr, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const TOKEN: &str = "test-token";
const WAIT: Duration = Duration::from_secs(30);

/// The plan the daemon needs to start. It names a documentation-range node, so
/// the tunnel comes up and then fails to connect — which is fine: these tests are
/// about the process, not the session.
const PLAN: &str = r#"{"schemaVersion":1,"sid":"subprocess","deviceId":"dev",
 "connectionId":"conn","username":"user",
 "signKeyBase64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
 "lang":"en","processName":"tunneld","processPath":"/tunneld",
 "processPlatform":"windows","nodes":{"major":["203.0.113.9:441"]},
 "majorNodeGroup":"major","routes":[],"dnsServers":[],"heartbeatSeconds":2}"#;

/// A running daemon and the scratch directory it was launched from.
struct Daemon {
    child: Child,
    port: u16,
    dir: PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        // Never leave a tunnel process behind: a leaked child holding a scratch
        // directory or a port would make the next test fail confusingly.
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Starts the daemon and waits until its control socket is listening.
fn start(name: &str) -> Daemon {
    let dir = std::env::temp_dir().join(format!("sangfor-tunneld-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let plan_path = dir.join("plan.json");
    let config_path = dir.join("host.json");
    std::fs::write(&plan_path, PLAN).expect("the plan writes");
    std::fs::write(
        &config_path,
        format!(
            r#"{{"device":"loopback","interface":"{name}","controlPort":0,
               "controlToken":"{TOKEN}","routes":["10.1.0.0/16"]}}"#
        ),
    )
    .expect("the config writes");

    let mut child = Command::new(env!("CARGO_BIN_EXE_sangfor-tunneld"))
        .arg("--dry-run")
        .arg("--plan")
        .arg(&plan_path)
        .arg("--config")
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the daemon starts");

    let stderr = child.stderr.take().expect("stderr is piped");
    let port = wait_for_port(&mut child, stderr);
    Daemon { child, port, dir }
}

/// Reads the daemon's log until it reports its control port, then keeps draining
/// in the background.
///
/// The port is ephemeral (`controlPort: 0`) so it cannot be known in advance, and
/// that log line is the daemon's own contract for reporting it. Draining
/// afterwards matters: a pipe nobody reads fills, and then the daemon blocks
/// inside its own logging call.
fn wait_for_port(child: &mut Child, stderr: ChildStderr) -> u16 {
    let mut reader = BufReader::new(stderr);
    let deadline = Instant::now() + WAIT;
    let mut line = String::new();
    while Instant::now() < deadline {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => panic!("the daemon exited before opening a control socket"),
            Ok(_) => {
                if let Some(port) = parse_port(&line) {
                    std::thread::spawn(move || {
                        let mut sink = io::sink();
                        let _ = io::copy(&mut reader, &mut sink);
                    });
                    return port;
                }
            }
            Err(error) => panic!("reading the daemon's log failed: {error}"),
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!("the daemon exited early with {status}");
        }
    }
    panic!("the daemon never reported a control port");
}

fn parse_port(line: &str) -> Option<u16> {
    let marker = "control socket listening on 127.0.0.1:";
    let start = line.find(marker)? + marker.len();
    line[start..].trim().parse().ok()
}

/// Connects, sends one request, and reads one reply.
fn exchange(port: u16, request: &str) -> String {
    let mut socket = TcpStream::connect(("127.0.0.1", port)).expect("the control socket accepts");
    socket.set_read_timeout(Some(WAIT)).expect("settable");
    socket.set_write_timeout(Some(WAIT)).expect("settable");
    socket
        .write_all(format!("{request}\n").as_bytes())
        .expect("writable");
    socket.flush().expect("flushed");
    let mut line = String::new();
    BufReader::new(&mut socket)
        .read_line(&mut line)
        .expect("the daemon replies");
    line.trim().to_string()
}

fn wait_for_exit(child: &mut Child) -> i32 {
    let deadline = Instant::now() + WAIT;
    loop {
        if let Some(status) = child.try_wait().expect("queryable") {
            return status.code().unwrap_or(-1);
        }
        assert!(Instant::now() < deadline, "the daemon did not exit");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn the_first_control_client_is_answered() {
    // Regression: the first connection used to be reset before any reply, so an
    // app's opening status query failed and a retry succeeded — which reads as a
    // flaky launch rather than a bug.
    let daemon = start("first-client");
    let reply = exchange(daemon.port, r#"{"cmd":"ping"}"#);
    assert_eq!(reply, r#"{"ok":true}"#, "ping needs no token");

    let reply = exchange(
        daemon.port,
        &format!(r#"{{"cmd":"status","token":"{TOKEN}"}}"#),
    );
    assert!(reply.contains(r#""ok":true"#), "status: {reply}");
    assert!(
        reply.contains(r#""interface":"first-client""#),
        "the snapshot names the interface: {reply}"
    );
}

#[test]
fn a_client_that_arrives_after_the_daemon_has_idled_is_answered() {
    // The accept loop is non-blocking with a short wait, so a client that
    // connects long after startup takes a different path through it than one
    // that connects immediately. This is the shape a real launcher produces: the
    // service starts at boot, the app connects when the user opens it.
    let daemon = start("late-client");
    std::thread::sleep(Duration::from_secs(3));
    let reply = exchange(daemon.port, r#"{"cmd":"ping"}"#);
    assert_eq!(reply, r#"{"ok":true}"#, "an idle daemon still answers");

    let reply = exchange(
        daemon.port,
        &format!(r#"{{"cmd":"status","token":"{TOKEN}"}}"#),
    );
    assert!(reply.contains(r#""ok":true"#), "status after idle: {reply}");
}

#[test]
fn a_client_that_pauses_before_and_between_writes_is_still_served() {
    // Regression. An accepted socket inherits non-blocking mode from the
    // listener on Windows -- Linux does not do this -- so a read that ran ahead
    // of the request returned WSAEWOULDBLOCK and the daemon hung up on the
    // client. Every other test here writes the moment it connects and so won
    // that race every time; a real client that awaits an event-loop turn between
    // connecting and writing lost it, which is how this was found.
    let daemon = start("slow-client");
    let mut socket = TcpStream::connect(("127.0.0.1", daemon.port)).expect("the socket accepts");
    socket.set_read_timeout(Some(WAIT)).expect("settable");
    socket.set_write_timeout(Some(WAIT)).expect("settable");

    // Pausing before the first request is what a Dart or Kotlin client does:
    // the connect completes, and the write happens on a later turn.
    thread::sleep(Duration::from_millis(500));
    socket.write_all(b"{\"cmd\":\"ping\"}\n").expect("writable");
    socket.flush().expect("flushed");
    assert_eq!(read_line(&mut socket), r#"{"ok":true}"#);

    // And again between requests, which exercises the same read path after the
    // connection has already carried traffic.
    thread::sleep(Duration::from_millis(500));
    socket
        .write_all(format!("{{\"cmd\":\"status\",\"token\":\"{TOKEN}\"}}\n").as_bytes())
        .expect("writable");
    socket.flush().expect("flushed");
    let reply = read_line(&mut socket);
    assert!(
        reply.contains(r#""ok":true"#),
        "status after a pause: {reply}"
    );
}

/// Reads one newline-terminated reply.
fn read_line(socket: &mut TcpStream) -> String {
    let mut line = String::new();
    BufReader::new(&mut *socket)
        .read_line(&mut line)
        .expect("the daemon replies");
    line.trim().to_string()
}

#[test]
fn a_client_without_the_token_cannot_read_or_stop() {
    let mut daemon = start("token-gate");
    let reply = exchange(daemon.port, r#"{"cmd":"status"}"#);
    assert!(
        reply.contains(r#""ok":false"#),
        "no token, no snapshot: {reply}"
    );
    assert!(reply.contains("token"), "the refusal says why: {reply}");

    let reply = exchange(daemon.port, r#"{"cmd":"stop"}"#);
    assert!(
        reply.contains(r#""ok":false"#),
        "no token, no stop: {reply}"
    );
    assert!(
        daemon.child.try_wait().expect("queryable").is_none(),
        "an unauthorized stop must leave the tunnel running"
    );
}

#[test]
fn stop_ends_the_process_with_code_zero() {
    let mut daemon = start("clean-stop");
    let reply = exchange(
        daemon.port,
        &format!(r#"{{"cmd":"stop","token":"{TOKEN}"}}"#),
    );
    assert_eq!(reply, r#"{"ok":true}"#);
    assert_eq!(
        wait_for_exit(&mut daemon.child),
        0,
        "a requested stop exits cleanly"
    );
}

#[test]
fn check_validates_and_exits_without_running_a_tunnel() {
    let dir = std::env::temp_dir().join(format!("sangfor-tunneld-check-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let plan_path = dir.join("plan.json");
    std::fs::write(&plan_path, PLAN).expect("the plan writes");

    let output = Command::new(env!("CARGO_BIN_EXE_sangfor-tunneld"))
        .args([
            "--dry-run",
            "--check",
            "--plan",
            plan_path.to_str().expect("a path"),
            "--interface",
            "check-only",
        ])
        .output()
        .expect("the daemon runs");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn a_malformed_plan_is_refused_with_a_useful_code() {
    let dir = std::env::temp_dir().join(format!("sangfor-tunneld-bad-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let plan_path = dir.join("plan.json");
    std::fs::write(&plan_path, b"not a plan").expect("writable");

    let output = Command::new(env!("CARGO_BIN_EXE_sangfor-tunneld"))
        .args([
            "--dry-run",
            "--check",
            "--plan",
            plan_path.to_str().expect("a path"),
        ])
        .output()
        .expect("the daemon runs");
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(output.status.code(), Some(1), "could not run");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("sangfor-tunneld:"),
        "the failure is explained: {stderr}"
    );
}

/// Kept for tests that want the whole log rather than scanning it.
#[allow(dead_code)]
fn read_all(mut reader: impl Read) -> String {
    let mut text = String::new();
    let _ = reader.read_to_string(&mut text);
    text
}
