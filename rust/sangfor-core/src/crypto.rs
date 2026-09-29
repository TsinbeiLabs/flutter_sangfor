//! Hashing, request signing, and the anti-MITM certificate digest.
//!
//! RustCrypto (`sha2`/`hmac`) rather than `ring` or `aws-lc-rs` on purpose:
//! both of those need a C toolchain per target, and this crate has to
//! cross-compile to `aarch64-unknown-linux-ohos` with nothing but the NDK's
//! clang for linking. Pure Rust keeps that a plain `cargo build`.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// The salt the gateway appends to a base64 certificate before hashing.
///
/// The anti-MITM pin is **not** a plain hash of the DER; getting this wrong
/// makes every pinned node connection fail with a certificate error that looks
/// like a network problem.
pub const CERTIFICATE_DIGEST_SALT: &str = "@~*&!()-";

/// SHA-256 of [data].
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// SHA-256 of the UTF-8 encoding of [text].
#[must_use]
pub fn sha256_str(text: &str) -> [u8; 32] {
    sha256(text.as_bytes())
}

/// HMAC-SHA256 of [message] under [key].
#[must_use]
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// Uppercase hex, the form the gateway expects in `xRequestSig` and in the
/// process fingerprint.
#[must_use]
pub fn hex_upper(bytes: &[u8]) -> String {
    hex(bytes, true)
}

/// Lowercase hex, used by the golden fixtures.
#[must_use]
pub fn hex_lower(bytes: &[u8]) -> String {
    hex(bytes, false)
}

fn hex(bytes: &[u8], uppercase: bool) -> String {
    const LOWER: &[u8; 16] = b"0123456789abcdef";
    const UPPER: &[u8; 16] = b"0123456789ABCDEF";
    let digits = if uppercase { UPPER } else { LOWER };
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(digits[(byte >> 4) as usize] as char);
        out.push(digits[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Decodes a hex string; returns `None` on odd length or a non-hex byte.
#[must_use]
pub fn unhex(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let high = hex_digit(pair[0])?;
        let low = hex_digit(pair[1])?;
        out.push((high << 4) | low);
    }
    Some(out)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// The request signature: HMAC-SHA256 over the canonical JSON body, uppercase
/// hex. Both the L3 flow auth and the TCP-tunnel dial use it.
#[must_use]
pub fn request_signature(sign_key: &[u8], canonical_body: &[u8]) -> String {
    hex_upper(&hmac_sha256(sign_key, canonical_body))
}

/// The process fingerprint the gateway binds a session to: SHA-256 of the
/// executable path, uppercase hex.
#[must_use]
pub fn process_fingerprint(process_path: &str) -> String {
    hex_upper(&sha256_str(process_path))
}

/// The anti-MITM identity digest of a DER certificate: uppercase hex SHA-256
/// of its base64 form plus [`CERTIFICATE_DIGEST_SALT`].
#[must_use]
pub fn certificate_digest(der: &[u8]) -> String {
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    hex_upper(&sha256_str(&format!("{encoded}{CERTIFICATE_DIGEST_SALT}")))
}

/// True when [der] matches one of [digests], compared case-insensitively. An
/// empty list means the deployment advertised no pinning material, which is
/// the caller's decision to accept or refuse.
#[must_use]
pub fn certificate_matches(der: &[u8], digests: &[String]) -> bool {
    if digests.is_empty() {
        return false;
    }
    let actual = certificate_digest(der);
    digests
        .iter()
        .any(|expected| expected.eq_ignore_ascii_case(&actual))
}
