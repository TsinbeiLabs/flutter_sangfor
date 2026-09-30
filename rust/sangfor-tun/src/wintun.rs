//! The Windows packet device, on the signed `wintun.dll` driver.
//!
//! Distribution is unchanged from the Dart path: the DLL is downloaded from
//! <https://www.wintun.net/> and staged beside the executable by
//! `app/scripts/stage_wintun.ps1`, which pins its SHA-256. This module loads it
//! at runtime rather than linking an import library, which is what upstream
//! recommends and what lets the driver live anywhere on disk.
//!
//! # Threading
//!
//! The wintun ring supports one concurrent reader and one concurrent writer,
//! which is exactly how [`crate::PacketDevice`] is used: the host's device pump
//! reads, its effect loop writes. [`WintunDevice::close`] must only run after
//! both have stopped, because it ends the session the handles refer to.

use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::process::Command;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use libloading::Library;

use crate::device::{PacketDevice, READ_POLL_INTERVAL};

/// Ring capacity: 4 MB, the value the Dart device and the upstream example use.
pub const RING_CAPACITY: u32 = 0x0040_0000;

const ERROR_NO_MORE_ITEMS: u32 = 259;
const ERROR_BUFFER_OVERFLOW: u32 = 111;
const WAIT_FAILED: u32 = 0xFFFF_FFFF;

type CreateAdapter = unsafe extern "system" fn(
    name: *const u16,
    tunnel_type: *const u16,
    requested_guid: *const c_void,
) -> *mut c_void;
type CloseAdapter = unsafe extern "system" fn(adapter: *mut c_void);
type StartSession = unsafe extern "system" fn(adapter: *mut c_void, capacity: u32) -> *mut c_void;
type EndSession = unsafe extern "system" fn(session: *mut c_void);
type GetReadWaitEvent = unsafe extern "system" fn(session: *mut c_void) -> *mut c_void;
type ReceivePacket = unsafe extern "system" fn(session: *mut c_void, size: *mut u32) -> *mut u8;
type ReleaseReceivePacket = unsafe extern "system" fn(session: *mut c_void, packet: *mut u8);
type AllocateSendPacket = unsafe extern "system" fn(session: *mut c_void, size: u32) -> *mut u8;
type SendPacket = unsafe extern "system" fn(session: *mut c_void, packet: *mut u8);
type WaitForSingleObject = unsafe extern "system" fn(handle: *mut c_void, milliseconds: u32) -> u32;
type GetLastError = unsafe extern "system" fn() -> u32;

/// The resolved entry points, plus the loaded images that own them.
#[derive(Debug)]
struct Api {
    // Held so the DLLs stay mapped; the function pointers below are only valid
    // while these do. They are dropped after the device, and function pointers
    // have no drop glue, so ordering cannot invalidate a live pointer.
    _wintun: Library,
    _kernel32: Library,
    create_adapter: CreateAdapter,
    close_adapter: CloseAdapter,
    start_session: StartSession,
    end_session: EndSession,
    get_read_wait_event: GetReadWaitEvent,
    receive_packet: ReceivePacket,
    release_receive_packet: ReleaseReceivePacket,
    allocate_send_packet: AllocateSendPacket,
    send_packet: SendPacket,
    wait_for_single_object: WaitForSingleObject,
    get_last_error: GetLastError,
}

impl Api {
    fn load(dll: &Path) -> io::Result<Self> {
        // SAFETY: `Library::new` is `LoadLibraryW` on Windows. Each `get`
        // copies a function pointer out of the loaded image; the pointers stay
        // valid because `_wintun` and `_kernel32` are kept in this struct for as
        // long as the copies are used.
        let wintun = unsafe { Library::new(dll) }.map_err(|error| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "could not load {}: {error}; download the signed DLL from \
                     https://www.wintun.net/ and stage it beside the executable",
                    dll.display()
                ),
            )
        })?;
        let kernel32 = unsafe { Library::new("kernel32.dll") }
            .map_err(|error| io::Error::other(error.to_string()))?;
        macro_rules! symbol {
            ($library:expr, $name:literal, $type:ty) => {{
                let symbol = unsafe { $library.get::<$type>(concat!($name, "\0").as_bytes()) }
                    .map_err(|error| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("wintun.dll is missing {name}: {error}", name = $name),
                        )
                    })?;
                *symbol
            }};
        }
        Ok(Self {
            create_adapter: symbol!(wintun, "WintunCreateAdapter", CreateAdapter),
            close_adapter: symbol!(wintun, "WintunCloseAdapter", CloseAdapter),
            start_session: symbol!(wintun, "WintunStartSession", StartSession),
            end_session: symbol!(wintun, "WintunEndSession", EndSession),
            get_read_wait_event: symbol!(wintun, "WintunGetReadWaitEvent", GetReadWaitEvent),
            receive_packet: symbol!(wintun, "WintunReceivePacket", ReceivePacket),
            release_receive_packet: symbol!(
                wintun,
                "WintunReleaseReceivePacket",
                ReleaseReceivePacket
            ),
            allocate_send_packet: symbol!(wintun, "WintunAllocateSendPacket", AllocateSendPacket),
            send_packet: symbol!(wintun, "WintunSendPacket", SendPacket),
            wait_for_single_object: symbol!(kernel32, "WaitForSingleObject", WaitForSingleObject),
            get_last_error: symbol!(kernel32, "GetLastError", GetLastError),
            _wintun: wintun,
            _kernel32: kernel32,
        })
    }

    fn last_error(&self) -> u32 {
        // SAFETY: no arguments, no preconditions.
        unsafe { (self.get_last_error)() }
    }
}

/// A layer-3 TUN adapter backed by wintun.
///
/// Creating one requires an elevated process: the driver install and the
/// `netsh` configuration both fail otherwise, and the failure surfaces as a
/// Win32 error rather than anything that mentions privileges.
pub struct WintunDevice {
    api: Api,
    adapter: *mut c_void,
    session: *mut c_void,
    read_wait: *mut c_void,
    name: String,
    closed: AtomicBool,
    dropped: AtomicU64,
}

// The handles are opaque driver pointers with no thread affinity, and the ring
// is built for one concurrent reader and one concurrent writer — the pattern
// `PacketDevice` documents and the one the Dart device already runs in
// production (a read isolate plus sends from the main isolate). `close` ends
// the session, so it must run only after both have stopped.
unsafe impl Send for WintunDevice {}
unsafe impl Sync for WintunDevice {}

impl WintunDevice {
    /// Opens, or creates, the adapter called [name] and starts a session.
    ///
    /// [dll] defaults to `wintun.dll` resolved by the normal Windows search
    /// order, which finds the copy staged beside the executable.
    ///
    /// # Errors
    ///
    /// - `NotFound` when the DLL cannot be loaded.
    /// - `PermissionDenied` when `WintunCreateAdapter` fails, which in practice
    ///   means the process is not elevated or the driver is blocked by policy.
    /// - The platform error for a failed session or read-wait event.
    pub fn open(
        name: impl Into<String>,
        tunnel_type: &str,
        dll: Option<&Path>,
    ) -> io::Result<Self> {
        Self::open_with_capacity(name, tunnel_type, dll, RING_CAPACITY)
    }

    /// [`Self::open`] with an explicit ring capacity.
    ///
    /// # Errors
    ///
    /// As [`Self::open`].
    pub fn open_with_capacity(
        name: impl Into<String>,
        tunnel_type: &str,
        dll: Option<&Path>,
        capacity: u32,
    ) -> io::Result<Self> {
        let name = name.into();
        let path = dll.map_or_else(|| Path::new("wintun.dll").to_path_buf(), Path::to_path_buf);
        let api = Api::load(&path)?;
        let wide_name = wide(&name);
        let wide_type = wide(tunnel_type);
        // SAFETY: both buffers are NUL-terminated and live until the call
        // returns; the GUID is null, which asks the driver for its default.
        let adapter = unsafe {
            (api.create_adapter)(wide_name.as_ptr(), wide_type.as_ptr(), ptr::null_mut())
        };
        if adapter.is_null() {
            let error = api.last_error();
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "WintunCreateAdapter failed for {name:?} (Win32 error {error}); \
                     the process must run elevated and the wintun driver must be installable"
                ),
            ));
        }
        // SAFETY: `adapter` is the handle just returned, `capacity` is a valid
        // ring size.
        let session = unsafe { (api.start_session)(adapter, capacity) };
        if session.is_null() {
            let error = api.last_error();
            // SAFETY: `adapter` is live and is not used again.
            unsafe { (api.close_adapter)(adapter) };
            return Err(io::Error::other(format!(
                "WintunStartSession failed (Win32 error {error})"
            )));
        }
        // SAFETY: `session` is live.
        let read_wait = unsafe { (api.get_read_wait_event)(session) };
        if read_wait.is_null() {
            let error = api.last_error();
            // SAFETY: both handles are live and are not used again.
            unsafe {
                (api.end_session)(session);
                (api.close_adapter)(adapter);
            }
            return Err(io::Error::other(format!(
                "WintunGetReadWaitEvent failed (Win32 error {error})"
            )));
        }
        Ok(Self {
            api,
            adapter,
            session,
            read_wait,
            name,
            closed: AtomicBool::new(false),
            dropped: AtomicU64::new(0),
        })
    }

    /// Packets dropped because the send ring was full.
    ///
    /// Non-zero means the host is producing faster than the stack is consuming,
    /// which is worth surfacing in diagnostics: it looks like packet loss on the
    /// far side of the tunnel and is not.
    #[must_use]
    pub fn dropped_packets(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Assigns a static address. Requires elevation.
    ///
    /// # Errors
    ///
    /// Returns `netsh`'s stderr when it exits non-zero.
    pub fn configure_address(
        &self,
        address: &str,
        netmask: &str,
        gateway: Option<&str>,
    ) -> io::Result<()> {
        run_netsh(&address_arguments(&self.name, address, netmask, gateway))
    }

    /// Adds a route through the adapter, active only (not persisted). Requires
    /// elevation.
    ///
    /// # Errors
    ///
    /// Returns `netsh`'s stderr when it exits non-zero.
    pub fn add_route(&self, destination: &str, prefix_length: u8) -> io::Result<()> {
        run_netsh(&route_arguments(&self.name, destination, prefix_length))
    }

    /// Sets the adapter's DNS servers. Requires elevation.
    ///
    /// # Errors
    ///
    /// Returns `netsh`'s stderr when it exits non-zero.
    pub fn set_dns_servers(&self, servers: &[String]) -> io::Result<()> {
        for arguments in dns_arguments(&self.name, servers) {
            run_netsh(&arguments)?;
        }
        Ok(())
    }
}

impl PacketDevice for WintunDevice {
    fn read_packet(&self, buffer: &mut Vec<u8>) -> io::Result<Option<usize>> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the wintun session has ended",
            ));
        }
        let deadline = std::time::Instant::now() + READ_POLL_INTERVAL;
        loop {
            let mut size: u32 = 0;
            // SAFETY: `session` is live for the lifetime of `self`; the returned
            // pointer is valid until `release_receive_packet`, which every path
            // below performs before returning.
            let packet = unsafe { (self.api.receive_packet)(self.session, &mut size) };
            if !packet.is_null() {
                buffer.clear();
                // SAFETY: the driver wrote `size` valid bytes at `packet`.
                buffer.extend_from_slice(unsafe {
                    std::slice::from_raw_parts(packet, size as usize)
                });
                // SAFETY: `packet` came from `receive_packet` on this session
                // and has not been released yet.
                unsafe { (self.api.release_receive_packet)(self.session, packet) };
                return Ok(Some(size as usize));
            }
            let error = self.api.last_error();
            if error == ERROR_NO_MORE_ITEMS {
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                if remaining.is_zero() {
                    return Ok(None);
                }
                // SAFETY: `read_wait` is the event the driver gave us for this
                // session, and the wait is bounded so a shutdown is noticed.
                let waited = unsafe {
                    (self.api.wait_for_single_object)(
                        self.read_wait,
                        u32::try_from(remaining.as_millis()).unwrap_or(u32::MAX),
                    )
                };
                if waited == WAIT_FAILED {
                    return Err(io::Error::last_os_error());
                }
                continue;
            }
            // ERROR_HANDLE_EOF once the session ends, or a ring the driver
            // considers corrupt. Either way there is nothing more to read.
            self.closed.store(true, Ordering::SeqCst);
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("WintunReceivePacket failed (Win32 error {error})"),
            ));
        }
    }

    fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
        if self.closed.load(Ordering::SeqCst) || packet.is_empty() {
            return Ok(());
        }
        let size = u32::try_from(packet.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("a {} byte packet exceeds the wintun maximum", packet.len()),
            )
        })?;
        // SAFETY: `session` is live; the returned buffer is `size` bytes and is
        // handed back to the driver by `send_packet` on every path.
        let target = unsafe { (self.api.allocate_send_packet)(self.session, size) };
        if target.is_null() {
            if self.api.last_error() == ERROR_BUFFER_OVERFLOW {
                // Upstream guidance: a full ring means shed the packet. Blocking
                // here would stall the effect loop and back up the whole tunnel.
                self.dropped.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the driver allocated `size` bytes at `target`.
        unsafe { ptr::copy_nonoverlapping(packet.as_ptr(), target, packet.len()) };
        // SAFETY: `target` came from `allocate_send_packet` and is fully
        // initialised; ownership passes to the driver.
        unsafe { (self.api.send_packet)(self.session, target) };
        Ok(())
    }

    fn close(&self) -> io::Result<()> {
        // `swap` makes this idempotent under concurrent callers: exactly one
        // ends the session.
        if self.closed.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        // SAFETY: the session and adapter are live, and the caller has stopped
        // reading and writing (see the module docs). The handles are left as
        // they are rather than nulled: a reader that already loaded one would
        // race either way, so the contract, not a null check, is what keeps
        // this sound.
        unsafe {
            (self.api.end_session)(self.session);
            (self.api.close_adapter)(self.adapter);
        }
        Ok(())
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    fn name(&self) -> &str {
        &self.name
    }
}

impl Drop for WintunDevice {
    fn drop(&mut self) {
        // Best effort: a device dropped without `close` still has to give the
        // driver its session back, or the adapter leaks until the process dies.
        let _ = self.close();
    }
}

/// A NUL-terminated UTF-16 copy of [text], as the Win32 W APIs expect.
fn wide(text: &str) -> Vec<u16> {
    std::ffi::OsStr::new(text)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// `netsh interface ip set address ...`
#[must_use]
pub fn address_arguments(
    name: &str,
    address: &str,
    netmask: &str,
    gateway: Option<&str>,
) -> Vec<String> {
    let mut arguments = vec![
        "interface".to_string(),
        "ip".to_string(),
        "set".to_string(),
        "address".to_string(),
        format!("name={name}"),
        "source=static".to_string(),
        format!("address={address}"),
        format!("mask={netmask}"),
    ];
    if let Some(gateway) = gateway {
        arguments.push(format!("gateway={gateway}"));
    }
    arguments
}

/// `netsh interface ip add route ...`, active only so a crashed tunnel does not
/// leave stale routes behind after a reboot.
#[must_use]
pub fn route_arguments(name: &str, destination: &str, prefix_length: u8) -> Vec<String> {
    vec![
        "interface".to_string(),
        "ip".to_string(),
        "add".to_string(),
        "route".to_string(),
        format!("{destination}/{prefix_length}"),
        format!("interface={name}"),
        "store=active".to_string(),
    ]
}

/// `netsh interface ip set dnsservers ...` for the first server, then
/// `add dnsservers` for the rest. An empty list produces no commands, because
/// `netsh` rejects a missing `address=`.
#[must_use]
pub fn dns_arguments(name: &str, servers: &[String]) -> Vec<Vec<String>> {
    let Some((first, rest)) = servers.split_first() else {
        return Vec::new();
    };
    let mut commands = vec![vec![
        "interface".to_string(),
        "ip".to_string(),
        "set".to_string(),
        "dnsservers".to_string(),
        format!("name={name}"),
        "source=static".to_string(),
        format!("address={first}"),
        "validate=no".to_string(),
    ]];
    for (offset, server) in rest.iter().enumerate() {
        commands.push(vec![
            "interface".to_string(),
            "ip".to_string(),
            "add".to_string(),
            "dnsservers".to_string(),
            format!("name={name}"),
            format!("address={server}"),
            format!("index={}", offset + 1),
            "validate=no".to_string(),
        ]);
    }
    commands
}

/// Runs one `netsh` invocation and turns a non-zero exit into an error that
/// carries its stderr, which is where `netsh` explains what it objected to.
fn run_netsh(arguments: &[String]) -> io::Result<()> {
    let output = Command::new("netsh").args(arguments).output()?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    Err(io::Error::other(format!(
        "netsh {} failed: {}{}",
        arguments.join(" "),
        stderr.trim(),
        if stdout.trim().is_empty() {
            String::new()
        } else {
            format!(" ({})", stdout.trim())
        }
    )))
}

/// Kept out of the device so the wait interval can be reasoned about without a
/// driver: reads block for at most this long before reporting `Ok(None)`.
#[must_use]
pub const fn read_poll_interval() -> Duration {
    READ_POLL_INTERVAL
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_address_command_matches_what_the_dart_device_runs() {
        assert_eq!(
            address_arguments("Luotopia", "10.10.0.2", "255.255.255.255", None),
            vec![
                "interface",
                "ip",
                "set",
                "address",
                "name=Luotopia",
                "source=static",
                "address=10.10.0.2",
                "mask=255.255.255.255",
            ]
        );
        assert_eq!(
            address_arguments("Luotopia", "10.10.0.2", "255.255.255.0", Some("10.10.0.1"))
                .last()
                .expect("a gateway argument"),
            "gateway=10.10.0.1"
        );
    }

    #[test]
    fn routes_are_active_only_so_they_do_not_survive_a_reboot() {
        assert_eq!(
            route_arguments("Luotopia", "172.16.0.0", 12),
            vec![
                "interface",
                "ip",
                "add",
                "route",
                "172.16.0.0/12",
                "interface=Luotopia",
                "store=active",
            ]
        );
    }

    #[test]
    fn the_first_dns_server_is_set_and_the_rest_are_appended() {
        let servers: Vec<String> = ["10.0.0.53", "10.0.0.54"]
            .iter()
            .map(|server| (*server).to_string())
            .collect();
        let commands = dns_arguments("Luotopia", &servers);
        assert_eq!(commands.len(), 2);
        assert!(commands[0].contains(&"set".to_string()));
        assert!(commands[0].contains(&"address=10.0.0.53".to_string()));
        assert!(commands[0].contains(&"validate=no".to_string()));
        assert!(commands[1].contains(&"add".to_string()));
        assert!(commands[1].contains(&"address=10.0.0.54".to_string()));
        assert!(commands[1].contains(&"index=1".to_string()));
    }

    #[test]
    fn no_dns_servers_means_no_netsh_invocation() {
        assert!(dns_arguments("Luotopia", &[]).is_empty());
    }

    #[test]
    fn wide_strings_are_nul_terminated() {
        assert_eq!(wide("ab"), vec![b'a' as u16, b'b' as u16, 0]);
        assert_eq!(wide(""), vec![0]);
    }

    #[test]
    fn a_missing_dll_explains_where_to_get_it() {
        let error = Api::load(Path::new("Z:\\definitely\\not\\wintun.dll"))
            .expect_err("the DLL is not there");
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(
            error.to_string().contains("wintun.net"),
            "the error should point at the download: {error}"
        );
    }
}
