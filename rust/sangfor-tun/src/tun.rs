//! The Linux packet device: `/dev/net/tun` with `IFF_TUN | IFF_NO_PI`.
//!
//! Address and route configuration is deliberately not here. A Linux daemon has
//! `iproute2`, `systemd-networkd`, or netlink available, and which one is
//! correct depends on how the daemon is packaged; the host layer runs it.

use std::ffi::CStr;
use std::io;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use crate::device::{PacketDevice, READ_POLL_INTERVAL};
use crate::unix_io;

const TUN_DEVICE: &str = "/dev/net/tun";
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;

/// `struct ifreq`: a 16-byte name followed by a 16-byte union. Only the name
/// and the two flag bits are used, so the union is modelled as the single
/// `c_short` the kernel reads first, padded to the real size.
#[repr(C)]
struct Ifreq {
    name: [libc::c_char; 16],
    flags: libc::c_short,
    _padding: [u8; 14],
}

/// A TUN interface created with `IFF_TUN | IFF_NO_PI`, so reads and writes are
/// raw IP packets with no four-byte prefix.
#[derive(Debug)]
pub struct TunDevice {
    /// The descriptor, or `-1` once closed. Atomic so `close` can invalidate it
    /// exactly once even though [`PacketDevice`] methods take `&self`.
    fd: AtomicI32,
    owns: bool,
    name: String,
    closed: AtomicBool,
}

impl TunDevice {
    /// Creates, or attaches to, the interface called [name].
    ///
    /// Needs `CAP_NET_ADMIN`, or an already-open descriptor handed to
    /// [`TunDevice::from_fd`] by something that has it.
    ///
    /// # Errors
    ///
    /// - The platform error from `open` or `ioctl`; `EACCES`/`EPERM` is what an
    ///   unprivileged process sees, and `ENODEV` means the `tun` module is not
    ///   loaded.
    /// - [`io::ErrorKind::InvalidInput`] for a name longer than 15 bytes.
    pub fn open(name: &str) -> io::Result<Self> {
        let path = std::ffi::CString::new(TUN_DEVICE)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "the tun path is invalid"))?;
        // SAFETY: opening a fixed path with no mode argument yields a
        // descriptor this process owns.
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let bytes = name.as_bytes();
        if bytes.len() > 15 {
            // SAFETY: `fd` is live and is not used again.
            unsafe { libc::close(fd) };
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("interface name {name:?} exceeds 15 bytes"),
            ));
        }
        let mut request = Ifreq {
            name: [0; 16],
            flags: IFF_TUN | IFF_NO_PI,
            _padding: [0; 14],
        };
        for (index, byte) in bytes.iter().enumerate() {
            request.name[index] = i8::try_from(*byte).unwrap_or(b'?' as i8);
        }
        // SAFETY: `TUNSETIFF` reads `sizeof(ifreq)` from `request` and writes
        // the assigned name back into the same buffer, which outlives the call.
        let result = unsafe { libc::ioctl(fd, TUNSETIFF, &mut request) };
        if result < 0 {
            let error = io::Error::last_os_error();
            // SAFETY: `fd` is live and is not used again.
            unsafe { libc::close(fd) };
            return Err(error);
        }
        // SAFETY: the kernel NUL-terminates the name it wrote back.
        let assigned = unsafe { CStr::from_ptr(request.name.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        Ok(Self {
            fd: AtomicI32::new(fd),
            owns: true,
            name: if assigned.is_empty() {
                name.to_string()
            } else {
                assigned
            },
            closed: AtomicBool::new(false),
        })
    }

    /// Adopts a descriptor another process opened, which is how a setuid helper
    /// or a systemd unit hands a tunnel to an unprivileged daemon. The caller
    /// keeps responsibility for closing it.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] for a negative descriptor.
    ///
    /// # Safety
    ///
    /// `fd` must be a live TUN descriptor opened `O_RDWR`, and it must stay open
    /// for as long as this device is used.
    pub unsafe fn from_fd(fd: RawFd, name: impl Into<String>) -> io::Result<Self> {
        if fd < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a tun descriptor cannot be negative",
            ));
        }
        Ok(Self {
            fd: AtomicI32::new(fd),
            owns: false,
            name: name.into(),
            closed: AtomicBool::new(false),
        })
    }

    fn descriptor(&self) -> io::Result<RawFd> {
        let fd = self.fd.load(Ordering::SeqCst);
        if fd < 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the tun device is closed",
            ));
        }
        Ok(fd)
    }
}

impl PacketDevice for TunDevice {
    fn read_packet(&self, buffer: &mut Vec<u8>) -> io::Result<Option<usize>> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the tun device is closed",
            ));
        }
        unix_io::read_packet(self.descriptor()?, buffer, READ_POLL_INTERVAL)
    }

    fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
        if self.closed.load(Ordering::SeqCst) || packet.is_empty() {
            return Ok(());
        }
        unix_io::write_packet(self.descriptor()?, packet)
    }

    fn close(&self) -> io::Result<()> {
        if self.closed.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        // Take the descriptor so it is closed exactly once, even if `Drop` runs
        // concurrently with an explicit close.
        let fd = self.fd.swap(-1, Ordering::SeqCst);
        if self.owns && fd >= 0 {
            // SAFETY: `fd` was ours and has just been retired.
            let result = unsafe { libc::close(fd) };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
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

impl Drop for TunDevice {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
