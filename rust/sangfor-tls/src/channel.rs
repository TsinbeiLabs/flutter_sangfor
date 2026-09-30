//! The TLS byte channel: a blocking-friendly stream over a TCP socket.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use rustls::pki_types::{IpAddr as TlsIpAddr, ServerName};
use rustls::{ClientConnection, StreamOwned};

use sangfor_core::crypto;

use crate::client_config;
use crate::trust::TrustPolicy;

/// One TLS connection to a tunnel node.
///
/// Wraps `rustls`' [`StreamOwned`], so [`Read`] and [`Write`] behave like a
/// blocking socket: the handshake is complete by the time [`Self::connect`]
/// returns, a pin mismatch surfaces there rather than on the first write, and
/// `WouldBlock` propagates once the socket is put in non-blocking mode with
/// [`Self::set_nonblocking`].
///
/// A poll-driven host does not use this type. It calls [`handshake`], which
/// returns the connection and socket separately, and drives them itself — see
/// [`Handshake`].
pub struct TlsChannel {
    stream: StreamOwned<ClientConnection, TcpStream>,
    peer_digest: Option<String>,
}

/// A completed handshake, taken apart so the caller can own the pieces.
///
/// The socket is still in blocking mode with no read or write deadline, so the
/// caller can flip it to non-blocking and register it with a poller without
/// first unwinding the timeout [`handshake`] set.
pub struct Handshake {
    /// The `rustls` connection, already verified and ready for application
    /// data.
    pub connection: ClientConnection,
    /// The underlying socket.
    pub socket: TcpStream,
    /// The salted identity digest of the leaf the node presented, or `None` if
    /// it sent no certificate. Safe to log.
    pub peer_digest: Option<String>,
}

impl Handshake {
    /// Reunites the pieces into a blocking [`TlsChannel`].
    #[must_use]
    pub fn into_channel(self) -> TlsChannel {
        TlsChannel {
            stream: StreamOwned::new(self.connection, self.socket),
            peer_digest: self.peer_digest,
        }
    }
}

/// Resolves `host:port`, completes the TLS handshake, and pins the leaf,
/// returning the connection and socket separately.
///
/// This is the entry point a poll-driven host wants: it can do the blocking
/// connect on a worker thread and then move the socket into its event loop.
///
/// [timeout] bounds the TCP connect and both socket directions, so a node that
/// accepts connections and then says nothing cannot hang the caller.
///
/// # Errors
///
/// - DNS or connect failure, including timeout.
/// - A [`TrustPolicy`] rejection, as [`io::ErrorKind::PermissionDenied`]
///   carrying the [`crate::Verdict`] text. Reporting a bad pin as anything else
///   turns an attack into what looks like a network problem.
pub fn handshake(
    host: &str,
    port: u16,
    policy: &TrustPolicy,
    timeout: Duration,
) -> io::Result<Handshake> {
    let name = server_name(host)?;
    let socket = connect_tcp((host, port), timeout)?;
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(timeout))?;
    let connection = ClientConnection::new(client_config(policy), name)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
    let mut stream = StreamOwned::new(connection, socket);
    drive_handshake(&mut stream)?;
    let peer_digest = peer_digest(&stream.conn);
    // The handshake is done; leave the socket to the caller's blocking
    // preference rather than keeping the connect deadline on it.
    stream.sock.set_read_timeout(None)?;
    stream.sock.set_write_timeout(None)?;
    let (connection, socket) = stream.into_parts();
    Ok(Handshake {
        connection,
        socket,
        peer_digest,
    })
}

/// The salted digest of the peer's leaf certificate.
fn peer_digest(connection: &ClientConnection) -> Option<String> {
    connection
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .map(|der| crypto::certificate_digest(der.as_ref()))
}

impl TlsChannel {
    /// Resolves `host:port`, completes the TLS handshake, and pins the leaf.
    ///
    /// # Errors
    ///
    /// As [`handshake`].
    pub fn connect(
        host: &str,
        port: u16,
        policy: &TrustPolicy,
        timeout: Duration,
    ) -> io::Result<Self> {
        Ok(handshake(host, port, policy, timeout)?.into_channel())
    }

    /// Wraps an already-established connection. Used by tests and by hosts that
    /// dial through their own transport.
    #[must_use]
    pub fn from_stream(stream: StreamOwned<ClientConnection, TcpStream>) -> Self {
        let peer_digest = peer_digest(&stream.conn);
        Self {
            stream,
            peer_digest,
        }
    }

    /// The salted identity digest of the leaf the node presented, or `None` if
    /// the peer sent no certificate. Safe to log and to show a user: it is a
    /// hash, and it is the value the gateway advertised.
    #[must_use]
    pub fn peer_certificate_digest(&self) -> Option<&str> {
        self.peer_digest.as_deref()
    }

    /// Puts the underlying socket in or out of non-blocking mode.
    ///
    /// # Errors
    ///
    /// Propagates the platform's `setsockopt` failure.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.stream.sock.set_nonblocking(nonblocking)
    }

    /// The socket's peer address.
    #[must_use]
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.stream.sock.peer_addr().ok()
    }

    /// True while `rustls` has plaintext to hand over or records to write.
    ///
    /// A poll-driven host reads whenever [`Self::wants_read`] is true even if
    /// the socket looks idle, because buffered records are already local.
    #[must_use]
    pub fn wants_read(&self) -> bool {
        self.stream.conn.wants_read()
    }

    /// True while the connection still owes bytes to the socket.
    #[must_use]
    pub fn wants_write(&self) -> bool {
        self.stream.conn.wants_write()
    }

    /// Queues a TLS `close_notify`. The caller still has to flush it, which
    /// [`Read`]/[`Write`] on this channel do, or [`Self::flush`] does.
    pub fn close_notify(&mut self) {
        self.stream.conn.send_close_notify();
    }

    /// Borrows the underlying `rustls` connection.
    #[must_use]
    pub fn connection(&self) -> &ClientConnection {
        &self.stream.conn
    }

    /// Borrows the underlying socket.
    #[must_use]
    pub fn socket(&self) -> &TcpStream {
        &self.stream.sock
    }
}

impl fmt::Debug for TlsChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsChannel")
            .field("peer", &self.peer_addr())
            .field("peer_digest", &self.peer_digest)
            .field("handshaking", &self.stream.conn.is_handshaking())
            .finish()
    }
}

impl Read for TlsChannel {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }
}

impl Write for TlsChannel {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

/// Resolves and connects, trying every address the name produced.
fn connect_tcp(address: (&str, u16), timeout: Duration) -> io::Result<TcpStream> {
    let mut last: Option<io::Error> = None;
    for candidate in address.to_socket_addrs()? {
        match TcpStream::connect_timeout(&candidate, timeout) {
            Ok(stream) => return Ok(stream),
            Err(error) => last = Some(error),
        }
    }
    Err(last.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("{}:{} resolved to no addresses", address.0, address.1),
        )
    }))
}

/// The explicit handshake loop.
///
/// `StreamOwned` drives the handshake lazily on the first read or write, which
/// would report a certificate rejection as a failed *write*. Doing it here
/// means [`TlsChannel::connect`] either returns a verified channel or explains
/// why the node was refused.
fn drive_handshake(stream: &mut StreamOwned<ClientConnection, TcpStream>) -> io::Result<()> {
    while stream.conn.is_handshaking() {
        if stream.conn.wants_write() {
            stream.conn.write_tls(&mut stream.sock)?;
            stream.sock.flush()?;
        }
        if stream.conn.wants_read() {
            let read = stream.conn.read_tls(&mut stream.sock)?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the node closed the connection during the TLS handshake",
                ));
            }
        }
        if !stream.conn.wants_read() && !stream.conn.wants_write() {
            return Err(io::Error::other(
                "the TLS handshake stalled with nothing left to do",
            ));
        }
        if let Err(error) = stream.conn.process_new_packets() {
            return Err(classify_handshake_error(error, stream));
        }
    }
    Ok(())
}

/// Turns a `rustls` handshake error into an `io::Error` whose kind says whether
/// this was a trust decision or a transport problem.
fn classify_handshake_error(
    error: rustls::Error,
    stream: &StreamOwned<ClientConnection, TcpStream>,
) -> io::Error {
    match error {
        rustls::Error::General(message) => io::Error::new(io::ErrorKind::PermissionDenied, {
            let peer = stream
                .sock
                .peer_addr()
                .map(|address| address.to_string())
                .unwrap_or_else(|_| "unknown peer".to_string());
            format!("refused {peer}: {message}")
        }),
        rustls::Error::InvalidCertificate(reason) => {
            io::Error::new(io::ErrorKind::PermissionDenied, reason.to_string())
        }
        other => io::Error::other(other.to_string()),
    }
}

/// Builds the SNI name. aTrust nodes are often addressed by IP, and an IP is a
/// valid `ServerName` that simply sends no SNI extension — which is what the
/// Dart and Swift clients do too.
fn server_name(host: &str) -> io::Result<ServerName<'static>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ServerName::IpAddress(TlsIpAddr::from(ip)));
    }
    ServerName::try_from(host.to_owned()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{host:?} is neither a DNS name nor an IP address"),
        )
    })
}
