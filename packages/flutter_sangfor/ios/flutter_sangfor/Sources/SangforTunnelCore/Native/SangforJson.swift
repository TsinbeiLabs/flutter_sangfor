import Foundation

/// One key/value pair of a JSON object. A list of members (rather than a
/// dictionary) is used because the gateway signs the *bytes* of the request
/// body, so key order has to be exactly the order the reference client emits.
public struct SangforJsonMember {
  public let key: String
  public let value: SangforJsonValue

  public init(_ key: String, _ value: SangforJsonValue) {
    self.key = key
    self.value = value
  }
}

/// A JSON value with deterministic, insertion-ordered objects.
public indirect enum SangforJsonValue {
  case string(String)
  case int(Int)
  case double(Double)
  case bool(Bool)
  case null
  case array([SangforJsonValue])
  case object([SangforJsonMember])

  /// Convenience for `.object`.
  public static func object(_ members: [String: SangforJsonValue]) -> Self {
    // Sorted keys: only for call sites that do not sign the result. Signed
    // bodies must build `.object([...])` with an explicit order.
    .object(members.keys.sorted().map { SangforJsonMember($0, members[$0]!) })
  }
}

/// JSON writer that reproduces Dart's `jsonEncode` byte for byte.
///
/// The aTrust request signature is an HMAC over `utf8.encode(jsonEncode(map))`,
/// so any difference in escaping, spacing, or key order invalidates it. The
/// rules mirrored here are Dart's: no insignificant whitespace, `"`/`\` and the
/// five short control escapes, every other code point below U+0020 as a
/// lowercase `\u00xx`, and everything else (including U+007F and non-ASCII)
/// passed through as UTF-8.
public enum SangforJsonEncoder {
  public static func encode(_ value: SangforJsonValue) -> Data {
    var bytes = [UInt8]()
    write(value, into: &bytes)
    return Data(bytes)
  }

  public static func encodeToString(_ value: SangforJsonValue) -> String {
    String(decoding: encode(value), as: UTF8.self)
  }

  public static func encodeToBytes(_ value: SangforJsonValue) -> [UInt8] {
    var bytes = [UInt8]()
    write(value, into: &bytes)
    return bytes
  }

  private static func write(_ value: SangforJsonValue, into bytes: inout [UInt8]) {
    switch value {
    case .null:
      bytes.append(contentsOf: Array("null".utf8))
    case .bool(let flag):
      bytes.append(contentsOf: Array((flag ? "true" : "false").utf8))
    case .int(let number):
      bytes.append(contentsOf: Array(String(number).utf8))
    case .double(let number):
      bytes.append(contentsOf: Array(formatDouble(number).utf8))
    case .string(let text):
      writeString(text, into: &bytes)
    case .array(let elements):
      bytes.append(UInt8(ascii: "["))
      for (index, element) in elements.enumerated() {
        if index > 0 { bytes.append(UInt8(ascii: ",")) }
        write(element, into: &bytes)
      }
      bytes.append(UInt8(ascii: "]"))
    case .object(let members):
      bytes.append(UInt8(ascii: "{"))
      for (index, member) in members.enumerated() {
        if index > 0 { bytes.append(UInt8(ascii: ",")) }
        writeString(member.key, into: &bytes)
        bytes.append(UInt8(ascii: ":"))
        write(member.value, into: &bytes)
      }
      bytes.append(UInt8(ascii: "}"))
    }
  }

  private static func writeString(_ text: String, into bytes: inout [UInt8]) {
    bytes.append(UInt8(ascii: "\""))
    for scalar in text.unicodeScalars {
      switch scalar {
      case "\"":
        bytes.append(contentsOf: Array("\\\"".utf8))
      case "\\":
        bytes.append(contentsOf: Array("\\\\".utf8))
      case "\u{08}":
        bytes.append(contentsOf: Array("\\b".utf8))
      case "\u{09}":
        bytes.append(contentsOf: Array("\\t".utf8))
      case "\n":
        bytes.append(contentsOf: Array("\\n".utf8))
      case "\u{0c}":
        bytes.append(contentsOf: Array("\\f".utf8))
      case "\r":
        bytes.append(contentsOf: Array("\\r".utf8))
      default:
        if scalar.value < 0x20 {
          let escape = String(
            format: "\\u%04x",
            scalar.value
          )
          bytes.append(contentsOf: Array(escape.utf8))
        } else {
          var buffer = [UInt8](repeating: 0, count: 4)
          var count = 0
          UTF8.encode(scalar, into: { byte in
            if count < buffer.count { buffer[count] = byte }
            count += 1
          })
          bytes.append(contentsOf: buffer.prefix(count))
        }
      }
    }
    bytes.append(UInt8(ascii: "\""))
  }

  /// Doubles never appear in signed request bodies; this exists so response
  /// re-encoding stays lossless enough for logging.
  private static func formatDouble(_ value: Double) -> String {
    if value == value.rounded(), abs(value) < 1e15 {
      return String(Int(value))
    }
    return String(value)
  }
}

/// Typed access to a decoded JSON document (responses from the gateway).
public struct SangforJsonObject {
  public let raw: [String: Any]

  public init(_ raw: [String: Any]) {
    self.raw = raw
  }

  /// Parses UTF-8 [data] as a JSON object, or nil when it is not one.
  public static func parse(_ data: Data) -> SangforJsonObject? {
    guard
      let object = try? JSONSerialization.jsonObject(with: data),
      let map = object as? [String: Any]
    else { return nil }
    return SangforJsonObject(map)
  }

  public static func parse(_ bytes: [UInt8]) -> SangforJsonObject? {
    parse(Data(bytes))
  }

  public func string(_ key: String) -> String? {
    raw[key] as? String
  }

  public func int(_ key: String) -> Int? {
    if let number = raw[key] as? Int { return number }
    if let number = raw[key] as? NSNumber { return number.intValue }
    if let text = raw[key] as? String { return Int(text) }
    return nil
  }

  public func bool(_ key: String) -> Bool? {
    if let flag = raw[key] as? Bool { return flag }
    if let number = raw[key] as? NSNumber { return number.boolValue }
    return nil
  }

  public func object(_ key: String) -> SangforJsonObject? {
    guard let map = raw[key] as? [String: Any] else { return nil }
    return SangforJsonObject(map)
  }

  public func array(_ key: String) -> [Any] {
    raw[key] as? [Any] ?? []
  }
}
