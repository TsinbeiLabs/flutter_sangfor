//! Byte channels: the transport seam between the plane's effects and sockets.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use mio::event::Source;
use mio::{Interest, Registry, Token};
use rustls::{ClientConnection, StreamOwned};
use sangfor_tls::TrustPolicy;

/// A bidirectional byte stream the host can poll.
///
/// Non-blocking: [`Self::read`] and [`Self::write`] return
/// [`io::ErrorKind::WouldBlock`] rather than waiting, which is what lets one
/// thread serve every channel.
pub trait ByteChannel: Send {
    /// Reads whatever is available. `Ok(0)` means the peer is done.
    ///
    /// # Errors
    ///
    /// Propagates the transport's error; `WouldBlock` is normal.
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize>;

    /// Writes as much of [buffer] as the transport accepts, returning how much.
    ///
    /// # Errors
    ///
    /// Propagates the transport's error; `WouldBlock` means the caller must
    /// queue the remainder and wait for writability.
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize>;

    /// Pushes buffered bytes toward the peer.
    ///
    /// # Errors
    ///
    /// Propagates the transport's error.
    fn flush(&mut self) -> io::Result<()>;

    /// Half-closes the write side, leaving reads open.
    ///
    /// # Errors
    ///
    /// Propagates the transport's error.
    fn close_write(&mut self) -> io::Result<()>;

    /// Closes both directions. Best effort.
    ///
    /// # Errors
    ///
    /// Propagates the transport's error.
    fn close(&mut self) -> io::Result<()>;

    /// Registers with [registry] under [token] for [interest].
    ///
    /// # Errors
    ///
    /// Propagates the poller's error.
    fn register(&mut self, registry: &Registry, token: Token, interest: Interest)
        -> io::Result<()>;

    /// Changes the registration made by [`Self::register`].
    ///
    /// # Errors
    ///
    /// Propagates the poller's error.
    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interest: Interest,
    ) -> io::Result<()>;

    /// Removes the registration.
    ///
    /// # Errors
    ///
    /// Propagates the poller's error.
    fn deregister(&mut self, registry: &Registry) -> io::Result<()>;

    /// The anti-MITM digest of the peer certificate, when the transport has one.
    fn peer_digest(&self) -> Option<&str> {
        None
    }

    /// A short description for logs.
    fn describe(&self) -> String;
}

/// A TLS channel over a `mio` socket, built from a completed
/// [`sangfor_tls::Handshake`].
pub struct TlsByteChannel {
    stream: StreamOwned<ClientConnection, mio::net::TcpStream>,
    peer_digest: Option<String>,
    peer: String,
}

impl TlsByteChannel {
    /// Takes ownership of a finished handshake and puts the socket in
    /// non-blocking mode.
    ///
    /// # Errors
    ///
    /// Propagates the failure to switch the socket to non-blocking.
    pub fn new(handshake: sangfor_tls::Handshake) -> io::Result<Self> {
        let sangfor_tls::Handshake {
            connection,
            socket,
            peer_digest,
        } = handshake;
        let peer = socket
            .peer_addr()
            .map(|address| address.to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        socket.set_nonblocking(true)?;
        Ok(Self {
            stream: StreamOwned::new(connection, mio::net::TcpStream::from_std(socket)),
            peer_digest,
            peer,
        })
    }
}

impl ByteChannel for TlsByteChannel {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buffer)
    }

    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.stream.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }

    fn close_write(&mut self) -> io::Result<()> {
        // Flush any pending TLS records first: a bare TCP FIN with records
        // still buffered in rustls would truncate the stream.
        self.stream.flush()?;
        self.stream.sock.shutdown(std::net::Shutdown::Write)
    }

    fn close(&mut self) -> io::Result<()> {
        self.stream.conn.send_close_notify();
        let _ = self.stream.flush();
        self.stream.sock.shutdown(std::net::Shutdown::Both)?;
        Ok(())
    }

    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interest: Interest,
    ) -> io::Result<()> {
        registry.register(&mut self.stream.sock, token, interest)
    }

    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interest: Interest,
    ) -> io::Result<()> {
        registry.reregister(&mut self.stream.sock, token, interest)
    }

    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        registry.deregister(&mut self.stream.sock)
    }

    fn peer_digest(&self) -> Option<&str> {
        self.peer_digest.as_deref()
    }

    fn describe(&self) -> String {
        format!("tls:{}", self.peer)
    }
}

impl fmt::Debug for TlsByteChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsByteChannel")
            .field("peer", &self.peer)
            .field("peer_digest", &self.peer_digest)
            .finish_non_exhaustive()
    }
}

/// A plain TCP channel.
///
/// Not used against a real gateway — both the node channel and the TCP-tunnel
/// relay are TLS in every existing implementation. This exists so the host loop
/// can be tested against a fake gateway without a certificate, and so a
/// deployment that front-ends the tunnel with its own transport has something to
/// build on.
pub struct PlainByteChannel {
    socket: mio::net::TcpStream,
    peer: String,
}

impl PlainByteChannel {
    /// Adopts an already-connected socket and makes it non-blocking.
    ///
    /// # Errors
    ///
    /// Propagates the failure to switch the socket to non-blocking.
    pub fn new(socket: TcpStream) -> io::Result<Self> {
        let peer = socket
            .peer_addr()
            .map(|address| address.to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        socket.set_nonblocking(true)?;
        Ok(Self {
            socket: mio::net::TcpStream::from_std(socket),
            peer,
        })
    }
}

impl ByteChannel for PlainByteChannel {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.socket.read(buffer)
    }

    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.socket.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }

    fn close_write(&mut self) -> io::Result<()> {
        self.socket.flush()?;
        self.socket.shutdown(std::net::Shutdown::Write)
    }

    fn close(&mut self) -> io::Result<()> {
        let _ = self.socket.flush();
        self.socket.shutdown(std::net::Shutdown::Both)?;
        Ok(())
    }

    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interest: Interest,
    ) -> io::Result<()> {
        Source::register(&mut self.socket, registry, token, interest)
    }

    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interest: Interest,
    ) -> io::Result<()> {
        Source::reregister(&mut self.socket, registry, token, interest)
    }

    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        Source::deregister(&mut self.socket, registry)
    }

    fn describe(&self) -> String {
        format!("tcp:{}", self.peer)
    }
}

/// An opened channel, on its way back from a [`Connector`] to the host loop.
pub struct OpenedChannel {
    /// The connected, handshake-complete channel.
    pub channel: Box<dyn ByteChannel>,
}

/// Opens channels. The seam that lets the host run against a fake gateway.
pub trait Connector: Send + Sync + 'static {
    /// Connects to `host:port` and completes any handshake.
    ///
    /// Called on a worker thread, so it may block — but it must honour its own
    /// timeout, because a stalled connect otherwise ties up a thread for as long
    /// as the OS feels like waiting.
    ///
    /// # Errors
    ///
    /// Returns why the peer could not be reached or was not trusted. The host
    /// reports this to the plane, which decides whether to retry or fail the
    /// flow.
    fn connect(&self, host: &str, port: u16) -> io::Result<OpenedChannel>;
}

/// The production connector: TLS, pinned with the gateway's anti-MITM digests.
#[derive(Clone)]
pub struct TlsConnector {
    policy: TrustPolicy,
    timeout: Duration,
}

impl TlsConnector {
    /// A connector that pins with [policy] and gives up after [timeout].
    #[must_use]
    pub fn new(policy: TrustPolicy, timeout: Duration) -> Self {
        Self { policy, timeout }
    }

    /// The pin policy in force.
    #[must_use]
    pub fn policy(&self) -> &TrustPolicy {
        &self.policy
    }
}

impl Connector for TlsConnector {
    fn connect(&self, host: &str, port: u16) -> io::Result<OpenedChannel> {
        let handshake = sangfor_tls::handshake(host, port, &self.policy, self.timeout)?;
        Ok(OpenedChannel {
            channel: Box::new(TlsByteChannel::new(handshake)?),
        })
    }
}

/// A connector that shares one policy across many dials.
///
/// `TlsConnector` is already cheap to clone; this exists for hosts that build
/// the connector once at startup and hand it to several sessions.
pub type SharedConnector = Arc<dyn Connector>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    /// A connected socket pair over the loopback interface.
    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        let client = TcpStream::connect(address).expect("connect");
        let (server, _) = listener.accept().expect("accept");
        (client, server)
    }

    #[test]
    fn a_plain_channel_is_non_blocking_after_adoption() {
        let (client, mut server) = pair();
        let mut channel = PlainByteChannel::new(client).expect("adopted");

        // Nothing was written, so a read must not block the host loop.
        let mut buffer = [0_u8; 16];
        let error = channel.read(&mut buffer).expect_err("nothing to read");
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);

        server.write_all(b"frame").expect("writable");
        // Give the loopback stack a moment; a single retry is enough here
        // because both ends are on the same host.
        let mut length = 0;
        for _ in 0..100 {
            match channel.read(&mut buffer) {
                Ok(count) => {
                    length = count;
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("unexpected read error: {error}"),
            }
        }
        assert_eq!(&buffer[..length], b"frame");
        assert!(channel.describe().starts_with("tcp:127.0.0.1"));
    }

    #[test]
    fn a_half_close_stops_writes_but_keeps_reads() {
        let (client, mut server) = pair();
        let mut channel = PlainByteChannel::new(client).expect("adopted");
        channel.write_all_helper(b"before").expect("writable");
        channel.close_write().expect("half-close");

        let mut received = Vec::new();
        server.read_to_end(&mut received).expect("readable to EOF");
        assert_eq!(received, b"before");

        // The read direction is still usable.
        server.write_all(b"after").expect("writable");
        let mut buffer = [0_u8; 8];
        let mut length = 0;
        for _ in 0..100 {
            match channel.read(&mut buffer) {
                Ok(count) if count > 0 => {
                    length = count;
                    break;
                }
                Ok(_) | Err(_) => std::thread::sleep(Duration::from_millis(5)),
            }
        }
        assert_eq!(&buffer[..length], b"after");
    }

    /// `write_all` is not part of the trait, so tests get a small helper.
    impl PlainByteChannel {
        fn write_all_helper(&mut self, bytes: &[u8]) -> io::Result<()> {
            let mut written = 0;
            while written < bytes.len() {
                match self.write(&bytes[written..]) {
                    Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "no progress")),
                    Ok(count) => written += count,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => return Err(error),
                }
            }
            self.flush()
        }
    }
}
