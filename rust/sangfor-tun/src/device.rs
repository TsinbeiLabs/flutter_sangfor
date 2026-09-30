//! The device seam, and an in-memory device for tests and dry runs.

#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// A raw IP packet device.
///
/// Implementations are blocking with a bounded wait: [`Self::read_packet`]
/// returns when a packet arrives *or* when its internal wait interval elapses,
/// so a host loop can notice a shutdown without a signal handler. That shape is
/// what wintun's read-wait event, `poll` on a descriptor, and a condvar all
/// provide natively; making it explicit keeps the host loop identical on every
/// platform.
///
/// # Concurrency
///
/// Methods take `&self`, and an implementation must tolerate **one concurrent
/// reader and one concurrent writer**. That is not a convenience: it is what
/// these devices are. The wintun ring is documented for exactly that pattern,
/// and `read`/`write` on a TUN descriptor are independent syscalls. A host that
/// serialized them behind one mutex would have a blocked reader stall the writer
/// for a whole poll interval — a latency bug that presents as a slow tunnel.
///
/// [`Self::close`] must run only after the reader and writer have stopped,
/// because it releases what they refer to.
pub trait PacketDevice: Send + Sync {
    /// Reads one packet into [buffer], reusing its allocation.
    ///
    /// - `Ok(Some(len))`: one packet of `len` bytes.
    /// - `Ok(None)`: the wait interval elapsed with nothing to read.
    /// - `Err(kind = UnexpectedEof)`: the device is finished and will never
    ///   produce another packet.
    ///
    /// # Errors
    ///
    /// Returns the platform's I/O error, with [`io::ErrorKind::UnexpectedEof`]
    /// once the device has been shut down.
    fn read_packet(&self, buffer: &mut Vec<u8>) -> io::Result<Option<usize>>;

    /// Writes one packet toward the operating system's stack.
    ///
    /// # Errors
    ///
    /// Returns the platform's I/O error. A full ring or buffer is *not* an
    /// error: implementations drop the packet and return `Ok(())`, because a
    /// tunnel that is behind should shed load rather than stall the caller.
    fn write_packet(&self, packet: &[u8]) -> io::Result<()>;

    /// Releases the device. Idempotent.
    ///
    /// # Errors
    ///
    /// Returns the platform's error if releasing failed; the device is unusable
    /// either way.
    fn close(&self) -> io::Result<()>;

    /// True once [`Self::close`] has run or the platform tore the device down.
    fn is_closed(&self) -> bool;

    /// A human-readable name, for logs and for the OS interface list.
    fn name(&self) -> &str;
}

/// How long [`PacketDevice::read_packet`] waits before reporting `Ok(None)`.
///
/// Short enough that a shutdown is noticed promptly, long enough that an idle
/// tunnel costs no CPU. The Dart wintun reader uses the same 500 ms interval.
pub const READ_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// An in-memory device: packets written to it can be read back, and packets can
/// be injected from another thread with [`LoopbackDevice::inject`].
///
/// This is the device the host's integration tests run against, and what a
/// `--dry-run` attaches so a tunnel can be started without touching the
/// machine's network configuration.
#[derive(Debug)]
pub struct LoopbackDevice {
    name: String,
    state: Arc<(Mutex<LoopbackState>, Condvar)>,
    closed: Arc<AtomicBool>,
}

impl Clone for LoopbackDevice {
    /// A second handle to the *same* device: injecting through either one feeds
    /// the same reader, and either can close it. Handy for tests that want to
    /// drive a device a host already owns.
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            state: Arc::clone(&self.state),
            closed: Arc::clone(&self.closed),
        }
    }
}

#[derive(Debug, Default)]
struct LoopbackState {
    pending: VecDeque<Vec<u8>>,
    written: VecDeque<Vec<u8>>,
    closed: bool,
}

impl LoopbackDevice {
    /// A device named [name] with nothing queued.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            state: Arc::new((Mutex::new(LoopbackState::default()), Condvar::new())),
            closed: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Queues a packet as if the operating system had produced it.
    pub fn inject(&self, packet: impl Into<Vec<u8>>) {
        let (lock, wake) = &*self.state;
        let Ok(mut state) = lock.lock() else {
            return;
        };
        state.pending.push_back(packet.into());
        wake.notify_one();
    }

    /// The packets the host wrote toward the stack, oldest first, drained.
    #[must_use]
    pub fn take_written(&self) -> Vec<Vec<u8>> {
        let (lock, _) = &*self.state;
        let Ok(mut state) = lock.lock() else {
            return Vec::new();
        };
        std::mem::take(&mut state.written).into()
    }

    /// How many packets are queued for the host to read.
    #[must_use]
    pub fn pending(&self) -> usize {
        let (lock, _) = &*self.state;
        lock.lock().map_or(0, |state| state.pending.len())
    }
}

impl PacketDevice for LoopbackDevice {
    fn read_packet(&self, buffer: &mut Vec<u8>) -> io::Result<Option<usize>> {
        let (lock, wake) = &*self.state;
        let mut state = lock.lock().map_err(|_| closed())?;
        let deadline = std::time::Instant::now() + READ_POLL_INTERVAL;
        loop {
            if state.closed {
                return Err(closed());
            }
            if let Some(packet) = state.pending.pop_front() {
                buffer.clear();
                buffer.extend_from_slice(&packet);
                return Ok(Some(packet.len()));
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            // Wake on a packet *or* on close: leaving `closed` out of the
            // predicate would make a shutdown wait out the whole interval.
            let (guard, timeout) = wake
                .wait_timeout_while(state, deadline - now, |state| {
                    state.pending.is_empty() && !state.closed
                })
                .map_err(|_| closed())?;
            state = guard;
            if timeout.timed_out() && state.pending.is_empty() {
                return Ok(None);
            }
        }
    }

    fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
        let (lock, _) = &*self.state;
        let mut state = lock.lock().map_err(|_| closed())?;
        if state.closed {
            return Err(closed());
        }
        state.written.push_back(packet.to_vec());
        Ok(())
    }

    fn close(&self) -> io::Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        let (lock, wake) = &*self.state;
        if let Ok(mut state) = lock.lock() {
            state.closed = true;
        }
        wake.notify_all();
        Ok(())
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    fn name(&self) -> &str {
        &self.name
    }
}

/// A closed device reads as end-of-file, which is also what wintun reports
/// (`ERROR_HANDLE_EOF`) once the session ends, so hosts get one spelling of
/// "finished" on every platform.
fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "the packet device is closed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_injected_packet_comes_back_unchanged() {
        let device = LoopbackDevice::new("loop0");
        let packet = vec![0x45, 0x00, 0x00, 0x14];
        device.inject(packet.clone());
        let mut buffer = Vec::new();
        let length = device
            .read_packet(&mut buffer)
            .expect("readable")
            .expect("a packet");
        assert_eq!(length, packet.len());
        assert_eq!(buffer, packet);
    }

    #[test]
    fn reads_are_idle_rather_than_blocking_forever() {
        let device = LoopbackDevice::new("loop0");
        let mut buffer = Vec::new();
        let started = std::time::Instant::now();
        assert!(device.read_packet(&mut buffer).expect("readable").is_none());
        assert!(
            started.elapsed() >= READ_POLL_INTERVAL / 2,
            "an idle read should wait for its interval, not spin"
        );
    }

    #[test]
    fn writes_are_recorded_for_the_test_to_inspect() {
        let device = LoopbackDevice::new("loop0");
        device.write_packet(&[1, 2, 3]).expect("writable");
        device.write_packet(&[4, 5]).expect("writable");
        assert_eq!(device.take_written(), vec![vec![1, 2, 3], vec![4, 5]]);
        assert!(device.take_written().is_empty(), "draining clears the log");
    }

    #[test]
    fn closing_wakes_a_blocked_reader() {
        let device = LoopbackDevice::new("loop0");
        let reader = device.clone();
        let handle = std::thread::spawn(move || {
            let mut buffer = Vec::new();
            reader
                .read_packet(&mut buffer)
                .map(|_| ())
                .map_err(|error| error.kind())
        });
        // Give the reader a moment to block, then close from this thread.
        std::thread::sleep(Duration::from_millis(20));
        let started = std::time::Instant::now();
        device.close().expect("closable");
        assert_eq!(
            handle.join().expect("the reader finished"),
            Err(io::ErrorKind::UnexpectedEof)
        );
        assert!(
            started.elapsed() < READ_POLL_INTERVAL,
            "a close must wake the reader immediately, not after the poll interval"
        );
        assert!(device.is_closed());
    }

    #[test]
    fn a_closed_device_refuses_writes() {
        let device = LoopbackDevice::new("loop0");
        device.close().expect("closable");
        let error = device.write_packet(&[1]).expect_err("closed");
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn a_reader_and_a_writer_run_concurrently() {
        // The contract the host depends on: a thread parked in `read_packet`
        // must not stop another thread from writing, and vice versa.
        const PACKETS: usize = 64;
        let device = Arc::new(LoopbackDevice::new("loop0"));

        let reader_device = Arc::clone(&device);
        let reader = std::thread::spawn(move || {
            let mut buffer = Vec::new();
            let mut seen = 0_usize;
            while seen < PACKETS {
                match reader_device.read_packet(&mut buffer) {
                    Ok(Some(_)) => seen += 1,
                    Ok(None) => continue,
                    Err(_) => break,
                }
            }
            seen
        });

        let writer_device = Arc::clone(&device);
        let writer = std::thread::spawn(move || {
            let mut sent = 0_usize;
            for index in 0..PACKETS {
                writer_device
                    .write_packet(&[index as u8, 0xBB])
                    .expect("writable while a reader is parked");
                sent += 1;
            }
            sent
        });

        // Feed the reader from this thread while the writer is running.
        for _ in 0..PACKETS {
            device.inject(vec![0xAA; 4]);
        }

        assert_eq!(writer.join().expect("the writer finished"), PACKETS);
        assert_eq!(reader.join().expect("the reader finished"), PACKETS);
        assert_eq!(device.take_written().len(), PACKETS);
    }
}
