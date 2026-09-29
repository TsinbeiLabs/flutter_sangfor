import Foundation

/// The certificate identity digest aTrust's anti-MITM check compares.
///
/// It is *not* a plain hash of the DER: the gateway salts the base64 of the
/// certificate before hashing, so a native data plane has to reproduce the
/// same formula or every pinned connection fails. The Dart reference lives in
/// `flutter_sangfor_atrust`'s anti-MITM verifier, and the golden fixtures pin
/// the two implementations together.
public enum SangforCertificateDigest {
  /// The salt the gateway appends to the base64 certificate before hashing.
  public static let salt = "@~*&!()-"

  /// Uppercase hex SHA-256 of `base64(der) + salt`.
  public static func hex(_ der: Data) -> String {
    SangforSha256.hex(SangforSha256.hash(ofString: der.base64EncodedString() + salt))
  }

  /// True when [der] matches one of [digests], compared case-insensitively.
  /// An empty digest list means the deployment advertised no pinning material.
  public static func matches(_ der: Data, digests: [String]) -> Bool {
    guard !digests.isEmpty else { return false }
    let actual = hex(der)
    return digests.contains {
      $0.caseInsensitiveCompare(actual) == .orderedSame
    }
  }
}
