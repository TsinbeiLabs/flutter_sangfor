//! Descriptor I/O shared by the Linux and handed-over-fd devices.
//!
//! Both devices end up doing the same thing — a bounded `poll`, one `read` of a
//! whole packet, one `write` — so the loop lives here once. Only how the
//! descriptor is obtained differs. This is one of the few places in the
//! workspace with `unsafe`, and every call is a single libc function whose
//! buffer and lifetime contract is spelled out above it.

use std::io;
use std::os::fd::RawFd;
use std::time::{Duration, Instant};

/// Waits until [fd] is readable, or until [timeout] elapses.
///
/// Bounded rather than infinite so a host loop can notice a shutdown without a
/// signal handler; [`crate::device::READ_POLL_INTERVAL`] is the default.
///
/// # Errors
///
/// Propagates the platform's `poll` failure. `EINTR` is retried rather than
/// reported, because a daemon with any signal handler at all would otherwise
/// see spurious errors.
pub(crate) fn wait_readable(fd: RawFd, timeout: Duration) -> io::Result<bool> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let millis = i32::try_from(remaining.as_millis())
            .unwrap_or(i32::MAX)
            .max(0);
        let mut events = [libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        }];
        // SAFETY: `events` is a valid one-element array for the call's duration,
        // and `fd` is live for the lifetime of the device.
        let result = unsafe { libc::poll(events.as_mut_ptr(), 1, millis) };
        if result > 0 {
            return Ok(events[0].revents & libc::POLLIN != 0);
        }
        if result == 0 {
            return Ok(false);
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(error);
    }
}

/// Reads one packet from [fd] into [buffer], reusing its allocation.
///
/// Returns `Ok(Some(len))` for a packet, `Ok(None)` when [timeout] elapsed with
/// nothing to read, and `Err(UnexpectedEof)` when the descriptor is finished.
///
/// # Errors
///
/// Propagates the platform's `read` failure, other than `EINTR`.
pub(crate) fn read_packet(
    fd: RawFd,
    buffer: &mut Vec<u8>,
    timeout: Duration,
) -> io::Result<Option<usize>> {
    loop {
        if !wait_readable(fd, timeout)? {
            return Ok(None);
        }
        buffer.clear();
        // A TUN descriptor yields whole packets, so one read is one packet; the
        // size only has to be large enough for the interface MTU.
        buffer.resize(65_536, 0);
        // SAFETY: the kernel writes at most `buffer.len()` bytes into the
        // allocation just made, and reads nothing from it.
        let count = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            buffer.clear();
            return Err(error);
        }
        if count == 0 {
            buffer.clear();
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the packet descriptor reached end of file",
            ));
        }
        buffer.truncate(count as usize);
        return Ok(Some(count as usize));
    }
}

/// Writes one packet to [fd].
///
/// A would-block result drops the packet and returns `Ok(())`: see
/// [`crate::device::PacketDevice::write_packet`].
///
/// # Errors
///
/// Propagates the platform's `write` failure, other than `EINTR` and `EAGAIN`.
pub(crate) fn write_packet(fd: RawFd, packet: &[u8]) -> io::Result<()> {
    let mut written = 0_usize;
    while written < packet.len() {
        // SAFETY: the kernel reads at most the remaining bytes of `packet`.
        let count = unsafe {
            libc::write(
                fd,
                packet[written..].as_ptr().cast(),
                packet.len() - written,
            )
        };
        if count < 0 {
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => return Ok(()),
                _ => return Err(error),
            }
        }
        written += count as usize;
    }
    Ok(())
}
