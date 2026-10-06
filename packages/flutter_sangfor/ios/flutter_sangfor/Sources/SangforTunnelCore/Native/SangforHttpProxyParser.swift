import Foundation

/// Why a proxy request was not accepted. Each maps to one canned response.
public enum SangforProxyFailure: Equatable {
  case badRequest
}

/// One parsed proxy request.
public enum SangforProxyRequest: Equatable {
  /// `CONNECT host:port` -- answer 200 and pump bytes both ways.
  case connect(host: String, port: Int)
  /// An absolute-form request (`GET http://host/path`). [head] is the request
  /// rewritten to origin-form with `Connection: close`, ready to send upstream;
  /// [body] is whatever followed the header block in the same read.
  case forward(host: String, port: Int, head: Data, body: Data)
}

public enum SangforProxyParseResult: Equatable {
  /// The header block is not complete yet.
  case needMore
  case request(SangforProxyRequest, leftover: Data)
  case failure(SangforProxyFailure)
}

/// Incremental parser for the first request on a proxy connection.
///
/// Supports exactly what system HTTP proxy clients emit: `CONNECT` for HTTPS
/// and absolute-form requests for plain HTTP. A connection carries one request:
/// the rewritten head forces `Connection: close`, so a client cannot reuse it
/// to reach a different host behind the first decision.
public struct SangforHttpProxyParser {
  /// The most header bytes accepted before the request is refused.
  public static let maximumHeaderBytes = 64 * 1024

  private var buffer = Data()

  public init() {}

  public mutating func feed(_ chunk: Data) -> SangforProxyParseResult {
    buffer.append(chunk)
    guard let end = Self.headerEnd(in: buffer) else {
      return buffer.count > Self.maximumHeaderBytes
        ? .failure(.badRequest)
        : .needMore
    }
    let headData = buffer.prefix(end)
    let leftover = Data(buffer.suffix(from: buffer.startIndex + end + 4))
    buffer.removeAll()
    guard let text = String(data: headData, encoding: .isoLatin1) else {
      return .failure(.badRequest)
    }
    let lines = text.components(separatedBy: "\r\n")
    let requestLine = lines[0].split(separator: " ", omittingEmptySubsequences: true)
    guard requestLine.count == 3 else { return .failure(.badRequest) }
    let method = requestLine[0].uppercased()
    let target = String(requestLine[1])
    let version = String(requestLine[2])
    guard version.hasPrefix("HTTP/") else { return .failure(.badRequest) }

    if method == "CONNECT" {
      guard let (host, port) = Self.parseAuthority(target, defaultPort: 443) else {
        return .failure(.badRequest)
      }
      return .request(.connect(host: host, port: port), leftover: leftover)
    }
    return forward(
      method: method,
      target: target,
      version: version,
      headers: Array(lines.dropFirst()),
      body: leftover
    )
  }

  private func forward(
    method: String,
    target: String,
    version: String,
    headers: [String],
    body: Data
  ) -> SangforProxyParseResult {
    guard
      let components = URLComponents(string: target),
      let scheme = components.scheme?.lowercased(),
      scheme == "http" || scheme == "https",
      let host = components.host, !host.isEmpty
    else { return .failure(.badRequest) }
    let port = components.port ?? (scheme == "https" ? 443 : 80)
    guard (1...65535).contains(port) else { return .failure(.badRequest) }

    var originTarget = components.percentEncodedPath.isEmpty ? "/" : components.percentEncodedPath
    if let query = components.percentEncodedQuery { originTarget += "?" + query }

    var lines = ["\(method) \(originTarget) \(version)"]
    for line in headers where !line.isEmpty {
      let name = line.prefix { $0 != ":" }.lowercased()
      // The hop-by-hop headers belong to the proxy leg, not the origin.
      if name == "proxy-connection" || name == "proxy-authorization"
        || name == "connection" || name == "keep-alive"
      {
        continue
      }
      lines.append(line)
    }
    lines.append("Connection: close")
    let head = Data((lines.joined(separator: "\r\n") + "\r\n\r\n").utf8)
    return .request(
      .forward(host: host.lowercased(), port: port, head: head, body: body),
      leftover: Data()
    )
  }

  /// Offset of the `\r\n\r\n` that ends the header block, if present.
  static func headerEnd(in data: Data) -> Int? {
    let bytes = [UInt8](data)
    if bytes.count < 4 { return nil }
    for index in 0...(bytes.count - 4)
    where bytes[index] == 13 && bytes[index + 1] == 10
      && bytes[index + 2] == 13 && bytes[index + 3] == 10
    {
      return index
    }
    return nil
  }

  /// `host[:port]`, with IPv6 literals in brackets. Nil when malformed.
  public static func parseAuthority(
    _ authority: String,
    defaultPort: Int
  ) -> (String, Int)? {
    var host: String
    var port = defaultPort
    if authority.hasPrefix("[") {
      guard let close = authority.firstIndex(of: "]") else { return nil }
      host = String(authority[authority.index(after: authority.startIndex)..<close])
      let rest = authority[authority.index(after: close)...]
      if rest.hasPrefix(":") {
        guard let parsed = Int(rest.dropFirst()) else { return nil }
        port = parsed
      } else if !rest.isEmpty {
        return nil
      }
    } else if let colon = authority.lastIndex(of: ":") {
      host = String(authority[..<colon])
      guard let parsed = Int(authority[authority.index(after: colon)...]) else {
        return nil
      }
      port = parsed
    } else {
      host = authority
    }
    guard !host.isEmpty, (1...65535).contains(port) else { return nil }
    return (host.lowercased(), port)
  }

}

/// The few responses the proxy writes itself.
public enum SangforHttpProxyResponses {
  public static let connectionEstablished = response("200 Connection established")
  public static let badRequest = response("400 Bad Request", close: true)
  public static let forbidden = response("403 Forbidden", close: true)
  public static let badGateway = response("502 Bad Gateway", close: true)
  public static let serviceUnavailable = response("503 Service Unavailable", close: true)

  private static func response(_ status: String, close: Bool = false) -> Data {
    var text = "HTTP/1.1 \(status)\r\n"
    if close { text += "content-length: 0\r\nconnection: close\r\n" }
    return Data((text + "\r\n").utf8)
  }
}
