import Foundation
import Network

// Exercises SangforDirectStream against a real loopback listener. The pure-Swift
// suite cannot: the stream is a Network.framework connection, and its failure
// modes (a completion that never fires) only show with a real one.

var failures = 0
func check(_ condition: Bool, _ message: String) {
  if !condition {
    failures += 1
    print("FAIL: \(message)")
  }
}

let queue = DispatchQueue(label: "direct-stream-test")

/// Echoes every read back with an `echo:` prefix, and closes when the client does.
let listener = try NWListener(using: .tcp, on: .any)
var accepted: [NWConnection] = []
listener.newConnectionHandler = { connection in
  accepted.append(connection)
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
let listening = DispatchSemaphore(value: 0)
listener.stateUpdateHandler = { state in
  if case .ready = state { listening.signal() }
}
listener.start(queue: queue)
guard listening.wait(timeout: .now() + 5) == .success, let port = listener.port else {
  print("FAIL: the loopback listener did not start")
  exit(1)
}

// A dial to a listening port reports success, and the stream relays both ways.
// The caller keeps no reference of its own until the completion hands one over.
let dialed = DispatchSemaphore(value: 0)
var stream: SangforRelayStream?
SangforDirectStream.dial(host: "127.0.0.1", port: Int(port.rawValue), queue: queue, timeout: 5) { result in
  if case .success(let opened) = result { stream = opened }
  dialed.signal()
}
check(dialed.wait(timeout: .now() + 4) == .success, "a dial to a listening port completes")
check(stream != nil, "and completes with a stream")

if let stream {
  let received = DispatchSemaphore(value: 0)
  var echoed = Data()
  queue.sync {
    stream.onData = { chunk in
      echoed.append(chunk)
      if String(decoding: echoed, as: UTF8.self) == "echo:hello" { received.signal() }
    }
  }
  stream.send(Data("hello".utf8))
  check(received.wait(timeout: .now() + 4) == .success, "bytes sent reach the peer and its reply comes back")

  let closed = DispatchSemaphore(value: 0)
  queue.sync { stream.onClosed = { _ in closed.signal() } }
  for connection in accepted { connection.cancel() }
  check(closed.wait(timeout: .now() + 4) == .success, "the stream reports the peer closing")
  stream.close()
}

// A dial that cannot connect reports a failure instead of hanging: nothing
// listens on the port the listener just gave up.
listener.cancel()
Thread.sleep(forTimeInterval: 0.3)
let refused = DispatchSemaphore(value: 0)
var refusedResult: Result<SangforRelayStream, Error>?
SangforDirectStream.dial(host: "127.0.0.1", port: Int(port.rawValue), queue: queue, timeout: 1.5) { result in
  refusedResult = result
  refused.signal()
}
check(refused.wait(timeout: .now() + 4) == .success, "a dial that cannot connect still completes")
if case .success = refusedResult { check(false, "and reports a failure") }

// An invalid port is refused up front.
let invalid = DispatchSemaphore(value: 0)
var invalidFailed = false
SangforDirectStream.dial(host: "127.0.0.1", port: 70000, queue: queue) { result in
  if case .failure = result { invalidFailed = true }
  invalid.signal()
}
check(invalid.wait(timeout: .now() + 2) == .success && invalidFailed, "an invalid port fails at once")

if failures == 0 {
  print("all direct stream checks passed")
} else {
  print("\(failures) direct stream check(s) failed")
  exit(1)
}
