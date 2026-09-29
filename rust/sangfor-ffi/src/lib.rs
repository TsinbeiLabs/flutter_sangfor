//! The C ABI every host process calls: the iOS packet tunnel extension, an
//! Android `VpnService`, an OHOS extension ability, and the desktop daemons all
//! drive the same six-ish functions, so there is one surface to audit and no
//! per-platform glue language.
//!
//! # Threading
//!
//! The handle serializes internally, so hosts may call from any thread.
//! Effects and ingress packets are delivered from the runtime thread; a host
//! that touches UI or platform objects from those callbacks must hop threads
//! itself.
//!
//! # Memory
//!
//! Every string or buffer this module hands out is heap-allocated and must be
//! released with [`sangfor_free`]. Buffers passed *in* are copied before the
//! call returns, so callers keep ownership.
//!
//! # Driving time
//!
//! [`sangfor_start`] spawns the runtime thread that drives timers
//! (heartbeats, flow-auth deadlines, retransmits, reconnects). Hosts that
//! already have an event loop can call [`sangfor_tick`] themselves and ignore
//! the thread by starting with `spawn_runtime = 0`.

#![allow(unsafe_code)]
#![allow(clippy::missing_safety_doc)]

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sangfor_core::flow::Millis;
use sangfor_core::plan::SessionPlan;
use sangfor_core::plane::{ConnectionConfig, DataPlane, PlaneEffect};
use sangfor_core::terminator::TerminatorConfig;

/// What the host must do, delivered through [`SangforEffectFn`].
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SangforEffectKind {
    /// Open a TLS channel to `text` (`host:port`), then report back with
    /// [`sangfor_on_node_connected`] or [`sangfor_on_node_failed`].
    ConnectNode = 1,
    /// Send `bytes` on node channel `id`.
    Send = 2,
    /// Close node channel `id`.
    CloseNode = 3,
    /// Write `bytes` (one raw IP packet) into the TUN / packet flow.
    EmitPacket = 4,
    /// Open a TCP-tunnel connection to `text` for dial `id`.
    Dial = 5,
    /// Write `bytes` to relay stream `id`.
    RelaySend = 6,
    /// Half-close relay stream `id`.
    RelayCloseWrite = 7,
    /// Close relay stream `id`.
    RelayClose = 8,
    /// Throttle relay stream `id`; `len` is 1 when pausing, 0 when resuming.
    RelayPause = 9,
    /// The gateway assigned a virtual IP; `text` is a comma-separated list.
    VirtualIp = 10,
    /// A diagnostic the host should log; `text` carries the message.
    Error = 11,
    /// The session is dead and the control plane must log in again.
    Fatal = 12,
}

/// The single effect callback. Fields that do not apply to a kind are null.
pub type SangforEffectFn = extern "C" fn(
    ctx: *mut c_void,
    kind: i32,
    id: u64,
    bytes: *const u8,
    len: usize,
    text: *const c_char,
);

/// Ingress packets, when a host wants them on a separate callback from
/// [`SangforEffectKind::EmitPacket`]. Reserved; the effect callback is the
/// supported path today.
pub type SangforIngressFn = extern "C" fn(ctx: *mut c_void, packet: *const u8, len: usize);

struct Callbacks {
    effect: Option<(SangforEffectFn, *mut c_void)>,
}

// The callback pointer is opaque to us; the host guarantees its thread safety.
unsafe impl Send for Callbacks {}

struct Inner {
    plane: Mutex<DataPlane>,
    callbacks: Mutex<Callbacks>,
    running: Arc<AtomicBool>,
}

/// An opaque handle to one running data plane.
pub struct SangforHandle {
    inner: Arc<Inner>,
}

/// Now, in monotonic-ish milliseconds since the UNIX epoch.
fn now_ms() -> Millis {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as Millis)
        .unwrap_or(0)
}

fn dispatch(inner: &Arc<Inner>, effects: Vec<PlaneEffect>) {
    if effects.is_empty() {
        return;
    }
    let Ok(callbacks) = inner.callbacks.lock() else {
        return;
    };
    let Some((callback, ctx)) = callbacks.effect else {
        return;
    };
    for effect in effects {
        dispatch_one(callback, ctx, effect);
    }
}

fn dispatch_one(callback: SangforEffectFn, ctx: *mut c_void, effect: PlaneEffect) {
    // C strings handed to the callback live for the duration of the call only.
    match effect {
        PlaneEffect::ConnectNode {
            connection,
            host,
            port,
        } => {
            let text = cstring(&format!("{host}:{port}"));
            callback(
                ctx,
                SangforEffectKind::ConnectNode as i32,
                connection,
                std::ptr::null(),
                0,
                text.as_ptr(),
            );
        }
        PlaneEffect::Send { connection, bytes } => {
            callback(
                ctx,
                SangforEffectKind::Send as i32,
                connection,
                bytes.as_ptr(),
                bytes.len(),
                std::ptr::null(),
            );
        }
        PlaneEffect::CloseNode { connection } => {
            callback(
                ctx,
                SangforEffectKind::CloseNode as i32,
                connection,
                std::ptr::null(),
                0,
                std::ptr::null(),
            );
        }
        PlaneEffect::EmitPacket(packet) => {
            callback(
                ctx,
                SangforEffectKind::EmitPacket as i32,
                0,
                packet.as_ptr(),
                packet.len(),
                std::ptr::null(),
            );
        }
        PlaneEffect::Dial { dial, host, port } => {
            let text = cstring(&format!("{host}:{port}"));
            callback(
                ctx,
                SangforEffectKind::Dial as i32,
                dial,
                std::ptr::null(),
                0,
                text.as_ptr(),
            );
        }
        PlaneEffect::RelaySend { dial, bytes } => {
            callback(
                ctx,
                SangforEffectKind::RelaySend as i32,
                dial,
                bytes.as_ptr(),
                bytes.len(),
                std::ptr::null(),
            );
        }
        PlaneEffect::RelayCloseWrite { dial } => {
            callback(
                ctx,
                SangforEffectKind::RelayCloseWrite as i32,
                dial,
                std::ptr::null(),
                0,
                std::ptr::null(),
            );
        }
        PlaneEffect::RelayClose { dial } => {
            callback(
                ctx,
                SangforEffectKind::RelayClose as i32,
                dial,
                std::ptr::null(),
                0,
                std::ptr::null(),
            );
        }
        PlaneEffect::RelayPause { dial, paused } => {
            callback(
                ctx,
                SangforEffectKind::RelayPause as i32,
                dial,
                std::ptr::null(),
                usize::from(paused),
                std::ptr::null(),
            );
        }
        PlaneEffect::VirtualIp(addresses) => {
            let text = cstring(&addresses.join(","));
            callback(
                ctx,
                SangforEffectKind::VirtualIp as i32,
                0,
                std::ptr::null(),
                0,
                text.as_ptr(),
            );
        }
        PlaneEffect::Error(message) => {
            let text = cstring(&message);
            callback(
                ctx,
                SangforEffectKind::Error as i32,
                0,
                std::ptr::null(),
                0,
                text.as_ptr(),
            );
        }
        PlaneEffect::Fatal(error) => {
            let text = cstring(&error.to_string());
            callback(
                ctx,
                SangforEffectKind::Fatal as i32,
                0,
                std::ptr::null(),
                0,
                text.as_ptr(),
            );
        }
    }
}

fn cstring(text: &str) -> CString {
    CString::new(text).unwrap_or_else(|_| CString::new("invalid utf-8").expect("literal"))
}

/// Starts a data plane from a session plan document (JSON, as written by the
/// Dart control plane). Returns null on failure and writes a heap string to
/// `*error` that the caller frees with [`sangfor_free`].
///
/// # Safety
///
/// `plan_json` must be a valid NUL-terminated UTF-8 string; `error` may be
/// null.
#[no_mangle]
pub unsafe extern "C" fn sangfor_start(
    plan_json: *const c_char,
    spawn_runtime: c_int,
    error: *mut *mut c_char,
) -> *mut SangforHandle {
    if plan_json.is_null() {
        set_error(error, "the session plan is missing");
        return std::ptr::null_mut();
    }
    let text = match unsafe { CStr::from_ptr(plan_json) }.to_str() {
        Ok(text) => text,
        Err(_) => {
            set_error(error, "the session plan is not valid UTF-8");
            return std::ptr::null_mut();
        }
    };
    let plan = match SessionPlan::decode(text.as_bytes()) {
        Ok(plan) => plan,
        Err(failure) => {
            set_error(error, &failure.to_string());
            return std::ptr::null_mut();
        }
    };
    let heartbeat = plan.heartbeat_seconds.max(1.0) * 1000.0;
    let connection = ConnectionConfig {
        heartbeat_interval_ms: heartbeat as Millis,
        ..ConnectionConfig::default()
    };
    let plane = DataPlane::new(
        plan,
        connection,
        TerminatorConfig::default(),
        // The seed only has to be stable per process, not secret: it picks
        // initial sequence numbers.
        now_ms(),
    );
    let running = Arc::new(AtomicBool::new(true));
    let inner = Arc::new(Inner {
        plane: Mutex::new(plane),
        callbacks: Mutex::new(Callbacks { effect: None }),
        running: Arc::clone(&running),
    });
    if spawn_runtime != 0 {
        spawn_runtime_thread(Arc::clone(&inner));
    }
    let mut effects = Vec::new();
    if let Ok(mut plane) = inner.plane.lock() {
        effects = plane.start(now_ms());
    }
    let handle = Box::new(SangforHandle { inner });
    let pointer = Box::into_raw(handle);
    // Effects are dispatched after the handle exists so the callback can be
    // registered first; a host that registers later still receives them via
    // the next tick, but starting eagerly matches the Swift runtime.
    let _ = (&effects, pointer);
    if let Some(handle) = unsafe { pointer.as_ref() } {
        dispatch(&handle.inner, effects);
    }
    pointer
}

/// Registers the effect callback. Call it before [`sangfor_start`] returns
/// effects you care about — registering immediately after start is fine
/// because effects are re-emitted on the next tick.
///
/// # Safety
///
/// `handle` must be a live handle; `callback` must remain valid until
/// [`sangfor_stop`].
#[no_mangle]
pub unsafe extern "C" fn sangfor_set_effect_handler(
    handle: *mut SangforHandle,
    callback: SangforEffectFn,
    ctx: *mut c_void,
) {
    if handle.is_null() {
        return;
    }
    let handle = unsafe { &*handle };
    if let Ok(mut callbacks) = handle.inner.callbacks.lock() {
        callbacks.effect = Some((callback, ctx));
    }
}

/// Hands one egress packet (from the TUN or packet flow) to the plane.
/// Returns 0 when the plane handled it, non-zero when it declined.
///
/// # Safety
///
/// `handle` must be live and `packet` must point at `len` valid bytes.
#[no_mangle]
pub unsafe extern "C" fn sangfor_write_packet(
    handle: *mut SangforHandle,
    packet: *const u8,
    len: usize,
) -> c_int {
    if handle.is_null() || packet.is_null() || len == 0 {
        return -1;
    }
    let handle = unsafe { &*handle };
    let Ok(mut plane) = handle.inner.plane.lock() else {
        return -2;
    };
    let bytes = unsafe { std::slice::from_raw_parts(packet, len) };
    let before = plane.statistics().routed + plane.statistics().terminated;
    let effects = plane.handle_egress(bytes, now_ms());
    drop(plane);
    dispatch(&handle.inner, effects);
    let after = with_stats(handle, |stats| stats.routed + stats.terminated).unwrap_or(before);
    if after > before {
        0
    } else {
        1
    }
}

fn with_stats<R>(
    handle: &SangforHandle,
    f: impl FnOnce(&sangfor_core::plane::Statistics) -> R,
) -> Option<R> {
    let plane = handle.inner.plane.lock().ok()?;
    let stats = plane.statistics();
    Some(f(&stats))
}

/// Drives timers once. Hosts that spawn the runtime thread do not need this.
///
/// # Safety
///
/// `handle` must be live.
#[no_mangle]
pub unsafe extern "C" fn sangfor_tick(handle: *mut SangforHandle) {
    if handle.is_null() {
        return;
    }
    let handle = unsafe { &*handle };
    let effects = {
        let Ok(mut plane) = handle.inner.plane.lock() else {
            return;
        };
        plane.tick(now_ms())
    };
    dispatch(&handle.inner, effects);
}

/// JSON counters, heap-allocated; free with [`sangfor_free`].
///
/// # Safety
///
/// `handle` must be live.
#[no_mangle]
pub unsafe extern "C" fn sangfor_stats(handle: *mut SangforHandle) -> *mut c_char {
    if handle.is_null() {
        return std::ptr::null_mut();
    }
    let handle = unsafe { &*handle };
    let Ok(plane) = handle.inner.plane.lock() else {
        return std::ptr::null_mut();
    };
    let stats = plane.statistics();
    let json = format!(
        "{{\"egress\":{},\"routed\":{},\"terminated\":{},\"unrouted\":{},\"ingress\":{},\"egressBytes\":{},\"ingressBytes\":{},\"reconnects\":{},\"terminatedFlows\":{},\"flows\":{}}}",
        stats.egress,
        stats.routed,
        stats.terminated,
        stats.unrouted,
        stats.ingress,
        stats.egress_bytes,
        stats.ingress_bytes,
        stats.reconnects,
        stats.terminated_flows,
        stats.flows
    );
    let text = cstring(&json).into_raw();
    drop(plane);
    text
}

/// The virtual IP the gateway assigned, heap-allocated; free with
/// [`sangfor_free`]. Returns null before the handshake completes.
///
/// # Safety
///
/// `handle` must be live.
#[no_mangle]
pub unsafe extern "C" fn sangfor_virtual_ip(handle: *mut SangforHandle) -> *mut c_char {
    if handle.is_null() {
        return std::ptr::null_mut();
    }
    let handle = unsafe { &*handle };
    let Ok(plane) = handle.inner.plane.lock() else {
        return std::ptr::null_mut();
    };
    let addresses = plane.virtual_ip().join(",");
    if addresses.is_empty() {
        return std::ptr::null_mut();
    }
    cstring(&addresses).into_raw()
}

/// Reports that a node channel opened.
///
/// # Safety
///
/// `handle` must be live.
#[no_mangle]
pub unsafe extern "C" fn sangfor_on_node_connected(handle: *mut SangforHandle, connection: u64) {
    run(handle, |plane| {
        plane.on_node_connected(connection, now_ms())
    });
}

/// Reports that a node channel could not be opened.
///
/// # Safety
///
/// `handle` must be live; `message` must be valid UTF-8 or null.
#[no_mangle]
pub unsafe extern "C" fn sangfor_on_node_failed(
    handle: *mut SangforHandle,
    connection: u64,
    message: *const c_char,
) {
    let message = unsafe { optional_str(message) };
    run(handle, |plane| {
        plane.on_node_failed(connection, &message, now_ms())
    });
}

/// Feeds bytes that arrived on a node channel.
///
/// # Safety
///
/// `handle` must be live; `data` must point at `len` valid bytes.
#[no_mangle]
pub unsafe extern "C" fn sangfor_on_node_data(
    handle: *mut SangforHandle,
    connection: u64,
    data: *const u8,
    len: usize,
) {
    if data.is_null() || len == 0 {
        return;
    }
    let bytes = unsafe { std::slice::from_raw_parts(data, len) }.to_vec();
    run(handle, |plane| {
        plane.on_node_data(connection, &bytes, now_ms())
    });
}

/// Reports that a node channel closed.
///
/// # Safety
///
/// `handle` must be live; `message` must be valid UTF-8 or null.
#[no_mangle]
pub unsafe extern "C" fn sangfor_on_node_closed(
    handle: *mut SangforHandle,
    connection: u64,
    message: *const c_char,
) {
    let message = unsafe { optional_str(message) };
    run(handle, |plane| {
        plane.on_node_closed(connection, &message, now_ms())
    });
}

/// Reports that a TCP-tunnel dial succeeded.
///
/// # Safety
///
/// `handle` must be live.
#[no_mangle]
pub unsafe extern "C" fn sangfor_on_dial_connected(handle: *mut SangforHandle, dial: u64) {
    run(handle, |plane| plane.on_dial_connected(dial, now_ms()));
}

/// Reports that a TCP-tunnel dial failed.
///
/// # Safety
///
/// `handle` must be live; `message` must be valid UTF-8 or null.
#[no_mangle]
pub unsafe extern "C" fn sangfor_on_dial_failed(
    handle: *mut SangforHandle,
    dial: u64,
    message: *const c_char,
) {
    let message = unsafe { optional_str(message) };
    run(handle, |plane| plane.on_dial_failed(dial, &message));
}

/// Feeds bytes that arrived on a TCP-tunnel dial.
///
/// # Safety
///
/// `handle` must be live; `data` must point at `len` valid bytes.
#[no_mangle]
pub unsafe extern "C" fn sangfor_on_relay_data(
    handle: *mut SangforHandle,
    dial: u64,
    data: *const u8,
    len: usize,
) {
    if data.is_null() || len == 0 {
        return;
    }
    let bytes = unsafe { std::slice::from_raw_parts(data, len) }.to_vec();
    run(handle, |plane| plane.on_relay_data(dial, &bytes, now_ms()));
}

/// Reports that a TCP-tunnel dial ended.
///
/// # Safety
///
/// `handle` must be live.
#[no_mangle]
pub unsafe extern "C" fn sangfor_on_relay_closed(handle: *mut SangforHandle, dial: u64) {
    run(handle, |plane| plane.on_relay_closed(dial, now_ms()));
}

/// Stops the plane, joins the runtime thread, and frees the handle.
/// Idempotent; passing null is a no-op.
///
/// # Safety
///
/// After this call the handle is invalid, and no callback registered for it
/// will fire again.
#[no_mangle]
pub unsafe extern "C" fn sangfor_stop(handle: *mut SangforHandle) {
    if handle.is_null() {
        return;
    }
    // Take ownership back so the handle is dropped exactly once.
    let boxed = unsafe { Box::from_raw(handle) };
    boxed.inner.running.store(false, Ordering::SeqCst);
    let effects = {
        let Ok(mut plane) = boxed.inner.plane.lock() else {
            return;
        };
        plane.close()
    };
    {
        // Clear the callback before the handle is freed, so a racing runtime
        // thread cannot deliver an effect to a dead host pointer.
        if let Ok(mut callbacks) = boxed.inner.callbacks.lock() {
            callbacks.effect = None;
        }
    }
    dispatch(&boxed.inner, effects);
}

/// Frees a string this module returned.
///
/// # Safety
///
/// `pointer` must have come from [`sangfor_stats`] or [`sangfor_virtual_ip`],
/// or be null.
#[no_mangle]
pub unsafe extern "C" fn sangfor_free(pointer: *mut c_char) {
    if pointer.is_null() {
        return;
    }
    drop(unsafe { CString::from_raw(pointer) });
}

/// Runs [f] against the plane, then dispatches the effects it produced *after*
/// releasing the lock: a host that reacts to an effect by calling back into
/// this ABI would otherwise deadlock against itself.
fn run(handle: *mut SangforHandle, f: impl FnOnce(&mut DataPlane) -> Vec<PlaneEffect>) {
    if handle.is_null() {
        return;
    }
    // SAFETY: the host guarantees the handle outlives this call.
    let handle = unsafe { &*handle };
    let effects = {
        let Ok(mut plane) = handle.inner.plane.lock() else {
            return;
        };
        f(&mut plane)
    };
    dispatch(&handle.inner, effects);
}

unsafe fn optional_str(pointer: *const c_char) -> String {
    if pointer.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(pointer) }
        .to_str()
        .unwrap_or_default()
        .to_string()
}

fn set_error(error: *mut *mut c_char, message: &str) {
    if error.is_null() {
        return;
    }
    unsafe { *error = cstring(message).into_raw() };
}

fn spawn_runtime_thread(inner: Arc<Inner>) {
    std::thread::Builder::new()
        .name("sangfor-core".to_string())
        .spawn(move || {
            // A single worker thread: the extension budget counts stacks, and
            // the plane is single-threaded by design.
            while inner.running.load(Ordering::SeqCst) {
                let sleep = {
                    let Ok(plane) = inner.plane.lock() else {
                        return;
                    };
                    let now = now_ms();
                    match plane.next_deadline() {
                        Some(deadline) => deadline.saturating_sub(now).clamp(1, 1_000),
                        None => 250,
                    }
                };
                std::thread::sleep(Duration::from_millis(sleep));
                if !inner.running.load(Ordering::SeqCst) {
                    return;
                }
                let effects = {
                    let Ok(mut plane) = inner.plane.lock() else {
                        return;
                    };
                    plane.tick(now_ms())
                };
                dispatch(&inner, effects);
            }
        })
        .ok();
}

impl Drop for SangforHandle {
    fn drop(&mut self) {
        self.inner.running.store(false, Ordering::SeqCst);
    }
}
