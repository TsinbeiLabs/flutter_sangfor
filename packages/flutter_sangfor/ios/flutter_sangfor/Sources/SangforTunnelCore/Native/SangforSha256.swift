import Foundation

/// SHA-256 (FIPS 180-4) and HMAC-SHA256 (RFC 2104) in pure Swift.
///
/// The gateway authenticates every tunnel request with an HMAC-SHA256 over the
/// canonical JSON of the unsigned body, hex-encoded and uppercased, so these
/// have to be byte exact. CryptoKit is deliberately not used: the same sources
/// are compiled and unit-tested on non-Apple hosts, where CryptoKit does not
/// exist.
public enum SangforSha256 {
  private static let constants: [UInt32] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]

  /// The digest of [message].
  public static func hash(_ message: [UInt8]) -> [UInt8] {
    var state: [UInt32] = [
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ]

    var padded = message
    let bitLength = UInt64(message.count) &* 8
    padded.append(0x80)
    while padded.count % 64 != 56 {
      padded.append(0x00)
    }
    for shift in stride(from: 56, through: 0, by: -8) {
      padded.append(UInt8(truncatingIfNeeded: bitLength >> UInt64(shift)))
    }

    var schedule = [UInt32](repeating: 0, count: 64)
    for blockStart in stride(from: 0, to: padded.count, by: 64) {
      for index in 0..<16 {
        let base = blockStart + index * 4
        schedule[index] =
          (UInt32(padded[base]) << 24)
          | (UInt32(padded[base + 1]) << 16)
          | (UInt32(padded[base + 2]) << 8)
          | UInt32(padded[base + 3])
      }
      for index in 16..<64 {
        let low = schedule[index - 15]
        let high = schedule[index - 2]
        let s0 = rotateRight(low, 7) ^ rotateRight(low, 18) ^ (low >> 3)
        let s1 = rotateRight(high, 17) ^ rotateRight(high, 19) ^ (high >> 10)
        schedule[index] =
          schedule[index - 16] &+ s0 &+ schedule[index - 7] &+ s1
      }

      var a = state[0]
      var b = state[1]
      var c = state[2]
      var d = state[3]
      var e = state[4]
      var f = state[5]
      var g = state[6]
      var h = state[7]

      for index in 0..<64 {
        let s1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25)
        let choose = (e & f) ^ (~e & g)
        let temp1 = h &+ s1 &+ choose &+ constants[index] &+ schedule[index]
        let s0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22)
        let majority = (a & b) ^ (a & c) ^ (b & c)
        let temp2 = s0 &+ majority
        h = g
        g = f
        f = e
        e = d &+ temp1
        d = c
        c = b
        b = a
        a = temp1 &+ temp2
      }

      state[0] = state[0] &+ a
      state[1] = state[1] &+ b
      state[2] = state[2] &+ c
      state[3] = state[3] &+ d
      state[4] = state[4] &+ e
      state[5] = state[5] &+ f
      state[6] = state[6] &+ g
      state[7] = state[7] &+ h
    }

    var digest = [UInt8]()
    digest.reserveCapacity(32)
    for word in state {
      digest.append(UInt8(truncatingIfNeeded: word >> 24))
      digest.append(UInt8(truncatingIfNeeded: word >> 16))
      digest.append(UInt8(truncatingIfNeeded: word >> 8))
      digest.append(UInt8(truncatingIfNeeded: word))
    }
    return digest
  }

  /// The digest of [data].
  public static func hash(_ data: Data) -> [UInt8] {
    hash([UInt8](data))
  }

  /// The digest of the UTF-8 encoding of [text].
  public static func hash(ofString text: String) -> [UInt8] {
    hash([UInt8](text.utf8))
  }

  /// HMAC-SHA256 over [message] with [key] (RFC 2104).
  public static func hmac(key: [UInt8], message: [UInt8]) -> [UInt8] {
    var normalized = key
    if normalized.count > 64 {
      normalized = hash(normalized)
    }
    while normalized.count < 64 {
      normalized.append(0x00)
    }
    var inner = [UInt8](repeating: 0x36, count: 64)
    var outer = [UInt8](repeating: 0x5c, count: 64)
    for index in 0..<64 {
      inner[index] ^= normalized[index]
      outer[index] ^= normalized[index]
    }
    inner.append(contentsOf: message)
    let innerDigest = hash(inner)
    outer.append(contentsOf: innerDigest)
    return hash(outer)
  }

  /// Hexadecimal encoding, uppercase by default to match the wire format.
  public static func hex(_ bytes: [UInt8], uppercase: Bool = true) -> String {
    var text = String()
    text.reserveCapacity(bytes.count * 2)
    for byte in bytes {
      text.append(String(format: "%02\(uppercase ? "X" : "x")", byte))
    }
    return text
  }

  /// Hexadecimal encoding of [data].
  public static func hex(_ data: Data, uppercase: Bool = true) -> String {
    hex([UInt8](data), uppercase: uppercase)
  }

  private static func rotateRight(_ value: UInt32, _ bits: UInt32) -> UInt32 {
    (value >> bits) | (value << (32 - bits))
  }
}
