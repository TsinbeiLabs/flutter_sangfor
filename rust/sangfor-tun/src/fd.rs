//! A descriptor the platform already opened.
//!
//! Android's `VpnService.Builder.establish()` and OHOS's `VpnExtensionAbility`
//! both return a TUN descriptor to the caller; nothing is created here, so
//! there are no ioctls, no capabilities, and no `/dev` access. That is also what
//! makes this the right device for running the core inside the service's own
//! process: the descriptor crosses one ABI boundary and the data plane never
//! returns to the UI process, which is what keeps the tunnel alive when the app
//! is swiped away.

use std::io;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use crate::device::{PacketDevice, READ_POLL_INTERVAL};
use crate::unix_io;

/// A packet device over a descriptor owned by the platform service.
#[derive(Debug)]
pub struct FdDevice {
    /// The descriptor, or `-1` once an owning device has closed it.
    fd: AtomicI32,
    owns: bool,
    name: String,
    closed: AtomicBool,
}

impl FdDevice {
    /// Borrows [fd] without taking ownership.
    ///
    /// Use this when the descriptor's lifetime belongs to the platform —
    /// Android's `ParcelFileDescriptor` on the Java side, for example — where
    /// closing it from Rust would leave the service holding a stale handle.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] for a negative descriptor.
    ///
    /// # Safety
    ///
    /// `fd` must be a live, readable and writable TUN descriptor for as long as
    /// this device is used, and the caller keeps responsibility for closing it.
    pub unsafe fn borrowed(fd: RawFd, name: impl Into<String>) -> io::Result<Self> {
        Self::new(fd, name, false)
    }

    /// Takes ownership of [fd] and closes it when the device is closed or
    /// dropped.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] for a negative descriptor.
    ///
    /// # Safety
    ///
    /// The caller must own `fd` and must not close it or use it again.
    pub unsafe fn owned(fd: RawFd, name: impl Into<String>) -> io::Result<Self> {
        Self::new(fd, name, true)
    }

    fn new(fd: RawFd, name: impl Into<String>, owns: bool) -> io::Result<Self> {
        if fd < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a packet descriptor cannot be negative",
            ));
        }
        Ok(Self {
            fd: AtomicI32::new(fd),
            owns,
            name: name.into(),
            closed: AtomicBool::new(false),
        })
    }

    /// True when this device will close the descriptor itself.
    #[must_use]
    pub fn owns_descriptor(&self) -> bool {
        self.owns
    }

    /// The raw descriptor, for hosts that need to hand it to platform APIs.
    #[must_use]
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.load(Ordering::SeqCst)
    }

    fn descriptor(&self) -> io::Result<RawFd> {
        let fd = self.fd.load(Ordering::SeqCst);
        if fd < 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the packet descriptor is closed",
            ));
        }
        Ok(fd)
    }
}

impl PacketDevice for FdDevice {
    fn read_packet(&self, buffer: &mut Vec<u8>) -> io::Result<Option<usize>> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the packet descriptor is closed",
            ));
        }
        let result = unix_io::read_packet(self.descriptor()?, buffer, READ_POLL_INTERVAL);
        // Android closes the descriptor when the VPN is revoked, which arrives
        // as EBADF rather than EOF. Treat both as finished so the host stops
        // instead of spinning on a dead descriptor.
        if let Err(error) = &result {
            if error.raw_os_error() == Some(libc::EBADF) {
                self.closed.store(true, Ordering::SeqCst);
            }
        }
        result
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
        let fd = self.fd.swap(-1, Ordering::SeqCst);
        if self.owns && fd >= 0 {
            // SAFETY: `fd` was ours and has just been retired, so nothing else
            // can close it again.
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

impl Drop for FdDevice {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_negative_descriptor_is_rejected() {
        // SAFETY: the call fails before touching the descriptor.
        let error = unsafe { FdDevice::borrowed(-1, "vpn0") }.expect_err("negative fd");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        // SAFETY: as above.
        assert!(unsafe { FdDevice::owned(-1, "vpn0") }.is_err());
    }

    #[test]
    fn a_pipe_behaves_like_a_packet_descriptor() {
        // A pipe is not a TUN device, but it is a readable and writable
        // descriptor, which is all `unix_io` asks for. This exercises both paths
        // against a real kernel object with no privileges and no network.
        let mut fds = [0_i32; 2];
        // SAFETY: `fds` is a two-element array the kernel fills in.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe() failed");
        let (read_end, write_end) = (fds[0], fds[1]);

        // SAFETY: both descriptors are live and owned by this test.
        let writer = unsafe { FdDevice::owned(write_end, "writer") }.expect("owned");
        // SAFETY: as above.
        let reader = unsafe { FdDevice::borrowed(read_end, "reader") }.expect("borrowed");
        assert!(!reader.owns_descriptor());
        assert!(writer.owns_descriptor());

        let packet = [0x45_u8, 0x00, 0x00, 0x14];
        writer.write_packet(&packet).expect("writable");

        let mut buffer = Vec::new();
        let length = reader
            .read_packet(&mut buffer)
            .expect("readable")
            .expect("a packet");
        assert_eq!(length, packet.len());
        assert_eq!(buffer, packet);

        // Nothing was written, so the wait times out rather than blocking.
        assert!(reader.read_packet(&mut buffer).expect("readable").is_none());

        reader.close().expect("closable");
        assert!(reader.is_closed());
        // The reader did not own the descriptor, so it is still open here.
        writer.close().expect("closable");
        assert_eq!(writer.as_raw_fd(), -1, "an owned close retires the fd");
        // SAFETY: closing the borrowed descriptor exactly once, since `reader`
        // does not own it.
        unsafe { libc::close(read_end) };
    }

    #[test]
    fn close_is_idempotent() {
        let mut fds = [0_i32; 2];
        // SAFETY: as above.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: both descriptors are owned by this test.
        let device = unsafe { FdDevice::owned(fds[1], "writer") }.expect("owned");
        device.close().expect("closable");
        device.close().expect("closable again");
        assert!(device.is_closed());
        let error = device
            .read_packet(&mut Vec::new())
            .expect_err("a closed device does not read");
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        // SAFETY: the device never owned this end.
        unsafe { libc::close(fds[0]) };
    }
}
