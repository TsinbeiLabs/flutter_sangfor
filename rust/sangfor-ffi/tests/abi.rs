//! Drives the whole data plane through the C ABI, the way a host does.
//!
//! This is the test that proves the boundary itself: effect delivery, string
//! ownership, and the packet pump all cross `extern "C"` here.

use std::ffi::{c_char, c_void, CStr};
use std::sync::Mutex;

use sangfor_ffi::*;

#[derive(Debug, Clone)]
struct Recorded {
    kind: i32,
    #[allow(dead_code)]
    id: u64,
    bytes: Vec<u8>,
    text: String,
}

static EFFECTS: Mutex<Vec<Recorded>> = Mutex::new(Vec::new());

extern "C" fn on_effect(
    _ctx: *mut c_void,
    kind: i32,
    id: u64,
    bytes: *const u8,
    len: usize,
    text: *const c_char,
) {
    let bytes = if bytes.is_null() || len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(bytes, len) }.to_vec()
    };
    let text = if text.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(text) }
            .to_string_lossy()
            .into_owned()
    };
    EFFECTS
        .lock()
        .expect("the recorder is not poisoned")
        .push(Recorded {
            kind,
            id,
            bytes,
            text,
        });
}

fn drain() -> Vec<Recorded> {
    std::mem::take(&mut *EFFECTS.lock().expect("the recorder is not poisoned"))
}

fn fixture() -> serde_json::Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../packages/flutter_sangfor/test/fixtures/native_atrust.json");
    let raw = std::fs::read(path).expect("the golden fixture exists");
    serde_json::from_slice(&raw).expect("valid JSON")
}

fn text(value: &serde_json::Value, path: &[&str]) -> String {
    let mut node = value;
    for key in path {
        node = node.get(key).expect("fixture key");
    }
    node.as_str().expect("fixture string").to_string()
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn client_syn(destination: &str) -> Vec<u8> {
    use sangfor_core::packet::{build_tcp, flag, parse_ipv4, TcpPacketParams};
    build_tcp(
        &TcpPacketParams {
            source: parse_ipv4("10.0.0.42").expect("client"),
            destination: parse_ipv4(destination).expect("server"),
            source_port: 51000,
            destination_port: 443,
            sequence: 4000,
            acknowledgment: 0,
            flags: flag::SYN,
            window: 65535,
            identification: 0,
            ttl: 64,
            mss: Some(1460),
        },
        &[],
    )
}

#[test]
fn the_c_abi_drives_a_whole_session() {
    let fixture = fixture();
    let plan = text(&fixture, &["sessionPlan"]);
    let plan_c = std::ffi::CString::new(plan).expect("the plan has no NULs");

    let mut error: *mut c_char = std::ptr::null_mut();
    // No runtime thread: this test drives time itself.
    let handle = unsafe { sangfor_start(plan_c.as_ptr(), 0, &mut error) };
    assert!(!handle.is_null(), "the plan starts a data plane");
    unsafe { sangfor_set_effect_handler(handle, on_effect, std::ptr::null_mut()) };

    // start() already asked for the node connection before the handler was
    // registered, so a tick re-arms nothing but the effect is observable
    // through the next state transition; assert on what we do receive.
    let _ = drain();

    // Feeding the node connection id 1 (the first dial) drives the handshake.
    unsafe { sangfor_on_node_connected(handle, 1) };
    let effects = drain();
    let sent = effects
        .iter()
        .find(|effect| effect.kind == EFFECT_SEND)
        .expect("the authTunnel request goes out");
    assert_eq!(
        hex(&sent.bytes),
        text(&fixture, &["l3", "authTunnelRequestHex"])
    );

    let handshake =
        sangfor_core::crypto::unhex(&text(&fixture, &["l3", "handshakeResponseHex"])).expect("hex");
    unsafe { sangfor_on_node_data(handle, 1, handshake.as_ptr(), handshake.len()) };
    let effects = drain();
    assert!(
        effects
            .iter()
            .any(|effect| effect.kind == EFFECT_VIRTUAL_IP && effect.text == "10.0.0.42"),
        "the virtual IP reaches the host"
    );

    let virtual_ip = unsafe { sangfor_virtual_ip(handle) };
    assert!(!virtual_ip.is_null());
    assert_eq!(
        unsafe { CStr::from_ptr(virtual_ip) }.to_string_lossy(),
        "10.0.0.42"
    );
    unsafe { sangfor_free(virtual_ip) };

    // A TCP-tunnel-only resource is terminated, not dropped.
    let packet = client_syn("10.9.1.2");
    let handled = unsafe { sangfor_write_packet(handle, packet.as_ptr(), packet.len()) };
    assert_eq!(handled, 0, "the plane handled the packet");
    let effects = drain();
    assert!(
        effects
            .iter()
            .any(|effect| effect.kind == EFFECT_DIAL && effect.text == "10.9.1.2:443"),
        "the terminator asks the host to dial"
    );
    assert!(
        effects
            .iter()
            .any(|effect| effect.kind == EFFECT_EMIT_PACKET && !effect.bytes.is_empty()),
        "the client gets a SYN-ACK back"
    );

    let stats = unsafe { sangfor_stats(handle) };
    assert!(!stats.is_null());
    let rendered = unsafe { CStr::from_ptr(stats) }
        .to_string_lossy()
        .into_owned();
    unsafe { sangfor_free(stats) };
    assert!(rendered.contains("\"terminated\":1"), "{rendered}");

    // An unroutable destination is declined so the host can drop it.
    let stray = client_syn("192.0.2.7");
    let handled = unsafe { sangfor_write_packet(handle, stray.as_ptr(), stray.len()) };
    assert_ne!(handled, 0, "nothing covers that destination");

    unsafe { sangfor_stop(handle) };
    // Stopping twice must be safe: hosts tear down from more than one path.
    unsafe { sangfor_stop(std::ptr::null_mut()) };
}

#[test]
fn a_bad_plan_reports_an_error_string() {
    // A document that parses but declares a schema this build cannot honour.
    let mut document: serde_json::Value =
        serde_json::from_str(&text(&fixture(), &["sessionPlan"])).expect("valid JSON");
    document["schemaVersion"] = serde_json::Value::from(99);
    let plan = std::ffi::CString::new(document.to_string()).expect("no NULs");
    let mut error: *mut c_char = std::ptr::null_mut();
    let handle = unsafe { sangfor_start(plan.as_ptr(), 0, &mut error) };
    assert!(handle.is_null());
    assert!(!error.is_null());
    let message = unsafe { CStr::from_ptr(error) }
        .to_string_lossy()
        .into_owned();
    assert!(message.contains("schema"), "{message}");
    unsafe { sangfor_free(error) };
}

#[test]
fn a_document_that_is_not_a_plan_reports_an_error_too() {
    let plan = std::ffi::CString::new("{\"schemaVersion\":99}").expect("no NULs");
    let mut error: *mut c_char = std::ptr::null_mut();
    let handle = unsafe { sangfor_start(plan.as_ptr(), 0, &mut error) };
    assert!(handle.is_null());
    assert!(!error.is_null());
    unsafe { sangfor_free(error) };
}

// The C header spells the kinds as an enum; these constants mirror it so the
// test does not depend on a generated binding.
const EFFECT_SEND: i32 = 2;
const EFFECT_EMIT_PACKET: i32 = 4;
const EFFECT_DIAL: i32 = 5;
const EFFECT_VIRTUAL_IP: i32 = 10;
