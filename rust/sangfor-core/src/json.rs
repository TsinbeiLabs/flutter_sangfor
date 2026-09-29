//! Canonical JSON: an ordered value model and an encoder that reproduces
//! Dart's `jsonEncode` **byte for byte**.
//!
//! The gateway signs the exact bytes of a request body, so this is not a
//! formatting preference. Dart's rules, which [`encode`] mirrors:
//!
//! - no insignificant whitespace; empty containers as `{}` and `[]`;
//! - `"` and `\` escaped, plus the five short escapes `\b \t \n \f \r`;
//! - every other code point below U+0020 as `\u00xx` with **lowercase** hex;
//! - U+007F and all non-ASCII passed through as raw UTF-8;
//! - object key order is insertion order (the order of a `Map` literal), which
//!   is why [`Json::Object`] holds a `Vec` and not a map.
//!
//! `tests/golden.rs` checks all of it against output captured from the Dart
//! implementation.

use std::borrow::Cow;

/// A JSON value with deterministic, insertion-ordered objects.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// An integer, printed in decimal.
    Int(i64),
    /// A float. Never part of a signed request body; present so decoded
    /// responses can be re-encoded for logs.
    Double(f64),
    /// A string.
    Str(String),
    /// An array.
    Array(Vec<Json>),
    /// An object, in the order its members were added.
    Object(Vec<(Cow<'static, str>, Json)>),
}

impl Json {
    /// Builds a string value.
    #[must_use]
    pub fn string(value: impl Into<String>) -> Self {
        Json::Str(value.into())
    }

    /// Builds an object from an ordered member list.
    #[must_use]
    pub fn object(members: Vec<(Cow<'static, str>, Json)>) -> Self {
        Json::Object(members)
    }

    /// Looks a key up in an object value.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(members) => members
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value),
            _ => None,
        }
    }

    /// The value as a string slice, when it is one.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(value) => Some(value),
            _ => None,
        }
    }

    /// The value as an integer, accepting a float that carries no fraction
    /// (`serde_json` decodes `7` as an integer and `7.0` as a float).
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Json::Int(value) => Some(*value),
            Json::Double(value) if value.fract() == 0.0 => Some(*value as i64),
            Json::Str(value) => value.parse::<i64>().ok(),
            _ => None,
        }
    }

    /// The value as a boolean.
    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(value) => Some(*value),
            _ => None,
        }
    }
}

/// Encodes [value] to UTF-8, byte-identically to Dart's `jsonEncode`.
#[must_use]
pub fn encode(value: &Json) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    write_value(&mut out, value);
    out
}

/// Encodes [value] as a `String`.
#[must_use]
pub fn encode_to_string(value: &Json) -> String {
    // Safe: write_value only ever appends UTF-8 (raw bytes are copied from a
    // &str, escapes are ASCII).
    String::from_utf8(encode(value)).unwrap_or_default()
}

fn write_value(out: &mut Vec<u8>, value: &Json) {
    match value {
        Json::Null => out.extend_from_slice(b"null"),
        Json::Bool(true) => out.extend_from_slice(b"true"),
        Json::Bool(false) => out.extend_from_slice(b"false"),
        Json::Int(number) => out.extend_from_slice(number.to_string().as_bytes()),
        Json::Double(number) => out.extend_from_slice(format_double(*number).as_bytes()),
        Json::Str(text) => write_string(out, text),
        Json::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_value(out, item);
            }
            out.push(b']');
        }
        Json::Object(members) => {
            out.push(b'{');
            for (index, (key, member)) in members.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_string(out, key);
                out.push(b':');
                write_value(out, member);
            }
            out.push(b'}');
        }
    }
}

fn write_string(out: &mut Vec<u8>, text: &str) {
    out.push(b'"');
    for &byte in text.as_bytes() {
        match byte {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x09 => out.extend_from_slice(b"\\t"),
            0x0a => out.extend_from_slice(b"\\n"),
            0x0c => out.extend_from_slice(b"\\f"),
            0x0d => out.extend_from_slice(b"\\r"),
            // Dart leaves U+007F and everything non-ASCII alone; UTF-8
            // continuation bytes are all >= 0x80, so byte-wise handling here
            // cannot split a code point.
            other if other < 0x20 => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                out.extend_from_slice(b"\\u00");
                out.push(HEX[(other >> 4) as usize]);
                out.push(HEX[(other & 0x0f) as usize]);
            }
            other => out.push(other),
        }
    }
    out.push(b'"');
}

fn format_double(value: f64) -> String {
    if value.fract() == 0.0 && value.abs() < 1e15 {
        return (value as i64).to_string();
    }
    value.to_string()
}

/// Converts a `serde_json` value into the ordered model, preserving the key
/// order the document used (`serde_json` keeps insertion order with the
/// `preserve_order` feature and otherwise sorts; responses are only read, so
/// either is fine).
#[must_use]
pub fn from_serde(value: &serde_json::Value) -> Json {
    match value {
        serde_json::Value::Null => Json::Null,
        serde_json::Value::Bool(flag) => Json::Bool(*flag),
        serde_json::Value::Number(number) => match number.as_i64() {
            Some(integer) => Json::Int(integer),
            None => Json::Double(number.as_f64().unwrap_or(0.0)),
        },
        serde_json::Value::String(text) => Json::Str(text.clone()),
        serde_json::Value::Array(items) => Json::Array(items.iter().map(from_serde).collect()),
        serde_json::Value::Object(members) => Json::Object(
            members
                .iter()
                .map(|(key, value)| (Cow::Owned(key.clone()), from_serde(value)))
                .collect(),
        ),
    }
}
