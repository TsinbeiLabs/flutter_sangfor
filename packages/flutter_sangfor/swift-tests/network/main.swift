import Foundation
import Network

// Exercises the Network.framework code against real loopback sockets: the direct
// stream and the proxy server. The pure-Swift suite cannot -- their failure modes
// (a completion that never fires, a relay that stalls) only show with real
// connections.

var failures = 0
func check(_ condition: Bool, _ message: String) {
  if !condition {
    failures += 1
    print("FAIL: \(message)")
  }
}

let queue = DispatchQueue(label: "network-test")

/// Accumulates what a connection receives and lets the test wait for it.
final class Inbox {
  private let lock = NSLock()
  private var buffer = Data()
  private let signal = DispatchSemaphore(value: 0)

  func add(_ data: Data) {
    lock.lock()
    buffer.append(data)
    lock.unlock()
    signal.signal()
  }

  var text: String {
    lock.lock()
    defer { lock.unlock() }
    return String(decoding: buffer, as: UTF8.self)
  }

  /// True once what arrived contains [fragment], false after [seconds].
  func wait(for fragment: String, seconds: Double = 4) -> Bool {
    let deadline = Date().addingTimeInterval(seconds)
    while Date() < deadline {
      if text.contains(fragment) { return true }
      _ = signal.wait(timeout: .now() + 0.1)
    }
    return text.contains(fragment)
  }
}

/// A loopback server that answers every read with `echo:` and the bytes read.
final class EchoServer {
  let listener: NWListener
  private(set) var port = 0
  private(set) var accepted: [NWConnection] = []

  init() throws {
    listener = try NWListener(using: .tcp, on: .any)
    let ready = DispatchSemaphore(value: 0)
    listener.stateUpdateHandler = { state in
      if case .ready = state { ready.signal() }
    }
    listener.newConnectionHandler = { [weak self] connection in
      self?.accepted.append(connection)
      connection.start(queue: queue)
      func receive() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { data, _, done, error in
          if let data, !data.isEmpty {
            connection.send(content: Data("echo:".utf8) + data, completion: .contentProcessed { _ in })
          }
          if done || error != nil {
            connection.cancel()
            return
          }
          receive()
        }
      }
      receive()
    }
    listener.start(queue: queue)
    guard ready.wait(timeout: .now() + 5) == .success, let bound = listener.port else {
      throw NSError(domain: "network-test", code: 1)
    }
    port = Int(bound.rawValue)
  }

  func closeConnections() { for connection in accepted { connection.cancel() } }
  func stop() { listener.cancel() }
}

/// A scripted tunnel stream, to stand in for a gateway connection.
final class ScriptedStream: SangforRelayStream {
  var isClosed = false
  var onData: ((Data) -> Void)?
  var onClosed: ((Error?) -> Void)?
  private(set) var sent = Data()
  func send(_ data: Data) { sent.append(data) }
  func closeWrite() {}
  func setReadsPaused(_ paused: Bool) {}
  func close() { isClosed = true }
}

let echo = try EchoServer()

// MARK: - SangforDirectStream

// A dial to a listening port reports success, and the stream relays both ways.
// The caller keeps no reference of its own until the completion hands one over.
let dialed = DispatchSemaphore(value: 0)
var stream: SangforRelayStream?
SangforDirectStream.dial(host: "127.0.0.1", port: echo.port, queue: queue, timeout: 5) { result in
  if case .success(let opened) = result { stream = opened }
  dialed.signal()
}
check(dialed.wait(timeout: .now() + 4) == .success, "a dial to a listening port completes")
check(stream != nil, "and completes with a stream")

if let stream {
  let inbox = Inbox()
  queue.sync { stream.onData = { inbox.add($0) } }
  stream.send(Data("hello".utf8))
  check(inbox.wait(for: "echo:hello"), "bytes sent reach the peer and its reply comes back")

  let closed = DispatchSemaphore(value: 0)
  queue.sync { stream.onClosed = { _ in closed.signal() } }
  echo.closeConnections()
  check(closed.wait(timeout: .now() + 4) == .success, "the stream reports the peer closing")
  stream.close()
}

// A dial that is refused reports a failure promptly instead of waiting out the
// timeout: nothing listens on the port the listener just gave up.
do {
  let gone = try EchoServer()
  let port = gone.port
  gone.stop()
  Thread.sleep(forTimeInterval: 0.3)
  let refused = DispatchSemaphore(value: 0)
  var refusedResult: Result<SangforRelayStream, Error>?
  let started = Date()
  SangforDirectStream.dial(host: "127.0.0.1", port: port, queue: queue, timeout: 10) { result in
    refusedResult = result
    refused.signal()
  }
  check(refused.wait(timeout: .now() + 4) == .success, "a refused dial completes well before its timeout")
  check(Date().timeIntervalSince(started) < 4, "and takes seconds, not the whole timeout")
  if case .success = refusedResult { check(false, "and reports a failure") }
}

// An invalid port is refused up front.
let invalid = DispatchSemaphore(value: 0)
var invalidFailed = false
SangforDirectStream.dial(host: "127.0.0.1", port: 70000, queue: queue) { result in
  if case .failure = result { invalidFailed = true }
  invalid.signal()
}
check(invalid.wait(timeout: .now() + 2) == .success && invalidFailed, "an invalid port fails at once")

// MARK: - SangforProxyServer

/// Opens a client connection to the proxy and returns it with what it receives.
func connectToProxy(port: UInt16) -> (NWConnection, Inbox)? {
  let connection = NWConnection(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: port)!, using: .tcp)
  let inbox = Inbox()
  let ready = DispatchSemaphore(value: 0)
  connection.stateUpdateHandler = { state in
    if case .ready = state { ready.signal() }
  }
  connection.start(queue: queue)
  guard ready.wait(timeout: .now() + 4) == .success else { return nil }
  func receive() {
    connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { data, _, done, error in
      if let data, !data.isEmpty { inbox.add(data) }
      if done || error != nil { return }
      receive()
    }
  }
  receive()
  return (connection, inbox)
}

let tunnelStream = ScriptedStream()
var tunnelDials: [String] = []
let proxy = SangforProxyServer(
  policy: SangforProxyPolicy(
    matcher: SangforRouteMatcher(
      policy: .followServer,
      customEntries: [],
      serverRoutes: [
        ATrustRoute(
          host: "campus.example.test", protocolName: "tcp", portMin: 443, portMax: 443,
          appId: "app", nodeGroupId: "group", addrPretend: true, enableTcpPrefL3: false)
      ]
    ),
    neverTunnelHosts: [],
    // `localhost` is a public-looking name the system sends here but no resource
    // covers: the proxy carries it directly.
    matchDomains: ["campus.example.test", "localhost"]
  ),
  queue: queue,
  tunnelDialer: { host, port, completion in
    tunnelDials.append("\(host):\(port)")
    completion(.success(tunnelStream))
  },
  log: { _ in },
  directDialTimeout: 2
)
let proxyReady = DispatchSemaphore(value: 0)
var proxyPort: UInt16 = 0
proxy.start { result in
  if case .success(let port) = result { proxyPort = port }
  proxyReady.signal()
}
check(proxyReady.wait(timeout: .now() + 5) == .success && proxyPort != 0, "the proxy listens on a loopback port")

// CONNECT to a name nothing publishes goes out directly.
if let (client, inbox) = connectToProxy(port: proxyPort) {
  client.send(
    content: Data("CONNECT localhost:\(echo.port) HTTP/1.1\r\nHost: localhost\r\n\r\n".utf8),
    completion: .contentProcessed { _ in })
  check(inbox.wait(for: "HTTP/1.1 200 Connection established"), "CONNECT to a direct host is accepted")
  client.send(content: Data("ping".utf8), completion: .contentProcessed { _ in })
  check(inbox.wait(for: "echo:ping"), "a direct CONNECT relays both ways")
  client.cancel()
} else {
  check(false, "a client can connect to the proxy")
}

// An absolute-form request is rewritten to origin form and carried directly.
if let (client, inbox) = connectToProxy(port: proxyPort) {
  client.send(
    content: Data(
      "GET http://localhost:\(echo.port)/path?q=1 HTTP/1.1\r\nHost: localhost:\(echo.port)\r\nProxy-Connection: keep-alive\r\n\r\n".utf8),
    completion: .contentProcessed { _ in })
  check(inbox.wait(for: "echo:GET /path?q=1 HTTP/1.1"), "an absolute-form request reaches the origin in origin form")
  check(!inbox.text.contains("Proxy-Connection"), "hop-by-hop headers are not forwarded")
  check(inbox.text.contains("Connection: close"), "and the connection is forced to close")
  client.cancel()
} else {
  check(false, "a second client can connect to the proxy")
}

// A published name goes through the tunnel dialer, by that name.
if let (client, inbox) = connectToProxy(port: proxyPort) {
  client.send(
    content: Data("CONNECT campus.example.test:443 HTTP/1.1\r\nHost: campus.example.test\r\n\r\n".utf8),
    completion: .contentProcessed { _ in })
  check(inbox.wait(for: "200 Connection established"), "CONNECT to a published host is accepted")
  check(tunnelDials == ["campus.example.test:443"], "and dials the tunnel by name")
  client.send(content: Data("up".utf8), completion: .contentProcessed { _ in })
  let deadline = Date().addingTimeInterval(4)
  while Date() < deadline && String(decoding: tunnelStream.sent, as: UTF8.self) != "up" {
    Thread.sleep(forTimeInterval: 0.05)
  }
  check(String(decoding: tunnelStream.sent, as: UTF8.self) == "up", "client bytes reach the tunnel stream")
  queue.sync { tunnelStream.onData?(Data("down".utf8)) }
  check(inbox.wait(for: "down"), "tunnel bytes reach the client")
  client.cancel()
} else {
  check(false, "a third client can connect to the proxy")
}

// A destination the proxy has no business serving is refused.
if let (client, inbox) = connectToProxy(port: proxyPort) {
  client.send(
    content: Data("CONNECT 10.1.2.3:443 HTTP/1.1\r\nHost: 10.1.2.3\r\n\r\n".utf8),
    completion: .contentProcessed { _ in })
  check(inbox.wait(for: "403 Forbidden"), "an address literal nothing publishes is refused")
  client.cancel()
}
if let (client, inbox) = connectToProxy(port: proxyPort) {
  client.send(
    content: Data("CONNECT elsewhere.example.org:443 HTTP/1.1\r\nHost: elsewhere.example.org\r\n\r\n".utf8),
    completion: .contentProcessed { _ in })
  check(inbox.wait(for: "403 Forbidden"), "a name outside the match domains is refused")
  client.cancel()
}

// A direct dial that cannot connect answers 502 instead of hanging the client.
do {
  let gone = try EchoServer()
  let port = gone.port
  gone.stop()
  Thread.sleep(forTimeInterval: 0.3)
  if let (client, inbox) = connectToProxy(port: proxyPort) {
    client.send(
      content: Data("CONNECT localhost:\(port) HTTP/1.1\r\nHost: localhost\r\n\r\n".utf8),
      completion: .contentProcessed { _ in })
    check(inbox.wait(for: "502 Bad Gateway", seconds: 5), "a direct dial that fails answers 502")
    client.cancel()
  }
}

// A malformed request is answered, not ignored.
if let (client, inbox) = connectToProxy(port: proxyPort) {
  client.send(content: Data("NOT A REQUEST\r\n\r\n".utf8), completion: .contentProcessed { _ in })
  check(inbox.wait(for: "400 Bad Request"), "a malformed request gets a 400")
  client.cancel()
}

let stats = proxy.statistics
check(stats.direct >= 3, "direct decisions are counted")
check(stats.tunneled == 1, "tunnel decisions are counted")
check(stats.rejected >= 2, "refusals are counted")
proxy.stop()

if failures == 0 {
  print("all network checks passed")
} else {
  print("\(failures) network check(s) failed")
  exit(1)
}
