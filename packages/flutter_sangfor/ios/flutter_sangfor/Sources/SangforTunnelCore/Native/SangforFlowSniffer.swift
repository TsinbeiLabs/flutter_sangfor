import Foundation

/// Reads the host name a client is about to talk to from the first bytes it
/// sends: the SNI of a TLS ClientHello, or the `Host` header of an HTTP request.
///
/// A flow into the tunnel carries only an IP address, and several names often
/// sit behind one address (a shared front end) with only some of them published.
/// The address cannot say which one the client wants; the first bytes can.
public enum SangforFlowSniffer {
  public enum Result: Equatable {
    /// The host name, lower-cased, without a port.
    case name(String)
    /// The bytes so far are a prefix of something that may still name a host.
    case needMore
    /// Not TLS or HTTP, or no name in it (a ClientHello without SNI, an address
    /// literal as the `Host`): there is nothing to learn from these bytes.
    case none
  }

  /// More than this and the first flight is not going to name anyone.
  public static let maximumBytes = 8 * 1024

  public static func sniff(_ bytes: [UInt8]) -> Result {
    guard let first = bytes.first else { return .needMore }
    if first == 0x16 { return serverName(inClientHello: bytes) }
    return httpHost(in: bytes)
  }

  // MARK: TLS

  private static func serverName(inClientHello bytes: [UInt8]) -> Result {
    // Record header: type, version(2), length(2).
    guard bytes.count >= 5 else { return .needMore }
    let recordLength = Int(bytes[3]) << 8 | Int(bytes[4])
    guard recordLength > 0, recordLength <= 16 * 1024 else { return .none }
    // A record that does not hold the whole ClientHello (it can be split across
    // records, rarely) is not worth waiting for.
    guard bytes.count >= 5 + recordLength else {
      return bytes.count >= maximumBytes ? .none : .needMore
    }
    var reader = Reader(bytes: bytes, offset: 5, end: 5 + recordLength)
    guard reader.byte() == 0x01 else { return .none }  // ClientHello
    guard let handshakeLength = reader.uint24(), handshakeLength <= recordLength - 4 else {
      return .none
    }
    guard reader.skip(2 + 32) else { return .none }  // version, random
    guard let sessionIdLength = reader.byte(), reader.skip(Int(sessionIdLength)) else {
      return .none
    }
    guard let suitesLength = reader.uint16(), reader.skip(Int(suitesLength)) else { return .none }
    guard let compressionLength = reader.byte(), reader.skip(Int(compressionLength)) else {
      return .none
    }
    guard let extensionsLength = reader.uint16() else { return .none }
    let extensionsEnd = reader.offset + Int(extensionsLength)
    guard extensionsEnd <= reader.end else { return .none }
    while reader.offset + 4 <= extensionsEnd {
      guard let type = reader.uint16(), let length = reader.uint16() else { return .none }
      let next = reader.offset + Int(length)
      guard next <= extensionsEnd else { return .none }
      if type == 0x0000 {
        // server_name: list length(2), then entries of type(1) length(2) name.
        guard reader.uint16() != nil else { return .none }
        while reader.offset + 3 <= next {
          guard let nameType = reader.byte(), let nameLength = reader.uint16() else {
            return .none
          }
          if nameType == 0, let name = reader.string(Int(nameLength)) {
            return normalized(name)
          }
          guard reader.skip(Int(nameLength)) else { return .none }
        }
        return .none
      }
      reader.offset = next
    }
    return .none
  }

  // MARK: HTTP

  private static func httpHost(in bytes: [UInt8]) -> Result {
    // The request line has to look like one before any header is trusted.
    let probe = String(decoding: bytes.prefix(16), as: UTF8.self)
    let methods = ["GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT "]
    let couldBeHttp = methods.contains { probe.hasPrefix($0) || $0.hasPrefix(probe) }
    guard couldBeHttp else { return .none }
    guard let end = headerEnd(in: bytes) else {
      return bytes.count >= maximumBytes ? .none : .needMore
    }
    let head = String(decoding: bytes[..<end], as: UTF8.self)
    for line in head.components(separatedBy: "\r\n").dropFirst() {
      guard line.lowercased().hasPrefix("host:") else { continue }
      let value = line.dropFirst(5).trimmingCharacters(in: .whitespaces)
      return normalized(value)
    }
    return .none
  }

  private static func headerEnd(in bytes: [UInt8]) -> Int? {
    if bytes.count < 4 { return nil }
    for index in 0...(bytes.count - 4)
    where bytes[index] == 13 && bytes[index + 1] == 10
      && bytes[index + 2] == 13 && bytes[index + 3] == 10
    {
      return index
    }
    return nil
  }

  // MARK: Helpers

  /// A host name worth routing by: lower-cased, no port, no trailing dot, and
  /// not an address literal.
  private static func normalized(_ raw: String) -> Result {
    var name = raw.lowercased()
    if name.hasPrefix("[") { return .none }  // IPv6 literal
    if let colon = name.lastIndex(of: ":") { name = String(name[..<colon]) }
    if name.hasSuffix(".") { name.removeLast() }
    guard !name.isEmpty, name.contains("."), SangforAddressBytes.ipv4(name) == nil else {
      return .none
    }
    guard name.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "-" || $0 == "." || $0 == "_" })
    else { return .none }
    return .name(name)
  }

  private struct Reader {
    let bytes: [UInt8]
    var offset: Int
    let end: Int

    mutating func byte() -> UInt8? {
      guard offset < end else { return nil }
      defer { offset += 1 }
      return bytes[offset]
    }

    mutating func uint16() -> UInt16? {
      guard offset + 2 <= end else { return nil }
      defer { offset += 2 }
      return UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
    }

    mutating func uint24() -> Int? {
      guard offset + 3 <= end else { return nil }
      defer { offset += 3 }
      return Int(bytes[offset]) << 16 | Int(bytes[offset + 1]) << 8 | Int(bytes[offset + 2])
    }

    mutating func skip(_ count: Int) -> Bool {
      guard count >= 0, offset + count <= end else { return false }
      offset += count
      return true
    }

    mutating func string(_ count: Int) -> String? {
      guard count >= 0, offset + count <= end else { return nil }
      defer { offset += count }
      return String(decoding: bytes[offset..<offset + count], as: UTF8.self)
    }
  }
}
