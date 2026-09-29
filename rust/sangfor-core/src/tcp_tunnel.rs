//! The SOCKS5-like TCP tunnel: a signed dial, then either raw bytes or framed
//! bytes depending on what the gateway answers.
//!
//! Which mode applies is decided by the server hello, so callers read and
//! write through [`TunnelStream`] and never branch on it themselves.

use std::borrow::Cow;

use crate::crypto::request_signature;
use crate::error::{Error, Result};
use crate::json::{self, Json};
use crate::l3::ProcessInfo;
use crate::packet::{parse_ipv4, parse_ipv6};

/// A TCP-tunnel authentication request.
#[derive(Debug, Clone)]
pub struct AuthRequest {
    /// Session id.
    pub sid: String,
    /// Resource identity.
    pub app_id: String,
    /// `tcp://host:port`.
    pub url: String,
    /// Device identity.
    pub device_id: String,
    /// Per-connection identity.
    pub connection_id: String,
    /// The process fingerprint.
    pub proc_hash: String,
    /// Account name.
    pub user_name: String,
    /// UI language tag.
    pub lang: String,
    /// `host:port` as dialed.
    pub dest_addr: String,
    /// The resolved address, omitted when the gateway resolves the name itself.
    pub dest_ip: Option<String>,
    /// Remote-control applied info.
    pub rc_applied_info: i64,
    /// The process identity block.
    pub process: Option<ProcessInfo>,
}

impl AuthRequest {
    /// The unsigned body, in the exact key order the gateway signs.
    #[must_use]
    pub fn unsigned_members(&self) -> Vec<(Cow<'static, str>, Json)> {
        let mut members: Vec<(Cow<'static, str>, Json)> = vec![
            (Cow::Borrowed("sid"), Json::string(self.sid.clone())),
            (Cow::Borrowed("appId"), Json::string(self.app_id.clone())),
            (Cow::Borrowed("url"), Json::string(self.url.clone())),
            (
                Cow::Borrowed("deviceId"),
                Json::string(self.device_id.clone()),
            ),
            (
                Cow::Borrowed("connectionId"),
                Json::string(self.connection_id.clone()),
            ),
            (
                Cow::Borrowed("procHash"),
                Json::string(self.proc_hash.clone()),
            ),
            (
                Cow::Borrowed("userName"),
                Json::string(self.user_name.clone()),
            ),
            (
                Cow::Borrowed("rcAppliedInfo"),
                Json::Int(self.rc_applied_info),
            ),
            (Cow::Borrowed("lang"), Json::string(self.lang.clone())),
            (
                Cow::Borrowed("destAddr"),
                Json::string(self.dest_addr.clone()),
            ),
        ];
        if let Some(dest_ip) = &self.dest_ip {
            members.push((Cow::Borrowed("destIP"), Json::string(dest_ip.clone())));
        }
        let env = match &self.process {
            Some(process) => process_env(process),
            None => Json::Object(Vec::new()),
        };
        members.push((Cow::Borrowed("env"), env));
        members
    }

    /// The canonical bytes that get signed.
    #[must_use]
    pub fn unsigned_body(&self) -> Vec<u8> {
        json::encode(&Json::Object(self.unsigned_members()))
    }

    /// The signature: HMAC-SHA256 over [`Self::unsigned_body`], uppercase hex.
    #[must_use]
    pub fn signature(&self, sign_key: &[u8]) -> String {
        request_signature(sign_key, &self.unsigned_body())
    }
}

fn process_env(process: &ProcessInfo) -> Json {
    Json::object(vec![(
        Cow::Borrowed("application"),
        Json::object(vec![(
            Cow::Borrowed("runtime"),
            Json::object(vec![
                (
                    Cow::Borrowed("process"),
                    Json::object(vec![
                        (Cow::Borrowed("name"), Json::string(process.name.clone())),
                        (
                            Cow::Borrowed("digital_signature"),
                            Json::string("TrustAppClosed"),
                        ),
                        (
                            Cow::Borrowed("platform"),
                            Json::string(process.platform.clone()),
                        ),
                        (
                            Cow::Borrowed("fingerprint"),
                            Json::string(crate::crypto::process_fingerprint(&process.path)),
                        ),
                        (Cow::Borrowed("description"), Json::string("TrustAppClosed")),
                        (Cow::Borrowed("path"), Json::string(process.path.clone())),
                        (Cow::Borrowed("version"), Json::string("TrustAppClosed")),
                        (Cow::Borrowed("security_env"), Json::string("normal")),
                    ]),
                ),
                (Cow::Borrowed("process_trusted"), Json::string("TRUSTED")),
            ]),
        )]),
    )])
}

/// The gateway's answer to a dial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerResponse {
    /// The auth code; 0 means accepted.
    pub auth_code: i64,
    /// The auth message, when the gateway sent one.
    pub auth_message: String,
    /// The connect status; 0 means the destination is reachable.
    pub connect_status: u8,
    /// True when the gateway asked for framed (reuse) mode.
    pub reuse: bool,
    /// How many bytes of the hello were consumed.
    pub consumed: usize,
}

/// Frame construction and parsing for the TCP tunnel.
pub mod protocol {
    use super::*;

    /// The largest payload one data frame can carry.
    pub const MAX_FRAME_PAYLOAD: usize = 0xffff;

    /// The opening message: auth header, signed JSON, then the destination.
    pub fn handshake_message(
        request: &AuthRequest,
        sign_key: &[u8],
        host: &str,
        port: u16,
        zero_rtt: bool,
    ) -> Result<Vec<u8>> {
        let mut members = request.unsigned_members();
        members.push((
            Cow::Borrowed("xRequestSig"),
            Json::string(request.signature(sign_key)),
        ));
        let body = json::encode(&Json::Object(members));
        if body.len() > MAX_FRAME_PAYLOAD {
            return Err(Error::Malformed("TCP tunnel auth request"));
        }
        let mut message = vec![crate::PROTOCOL_VERSION, 0x01, 0x81, 0x53, 0x03];
        message.extend_from_slice(&(body.len() as u16).to_be_bytes());
        message.extend_from_slice(&body);
        message.extend_from_slice(&destination_message(host, port, zero_rtt)?);
        Ok(message)
    }

    /// The destination record: address type, address, port.
    pub fn destination_message(host: &str, port: u16, zero_rtt: bool) -> Result<Vec<u8>> {
        let mut message = vec![crate::PROTOCOL_VERSION, 0x01, u8::from(zero_rtt)];
        if let Some(address) = parse_ipv4(host) {
            message.push(0x01);
            message.extend_from_slice(&address.to_be_bytes());
        } else if let Some(address) = parse_ipv6(host) {
            message.push(0x04);
            message.extend_from_slice(&address);
        } else {
            let bytes = host.as_bytes();
            if bytes.len() > 255 {
                return Err(Error::Malformed("TCP tunnel destination host"));
            }
            message.push(0x03);
            message.push(u8::try_from(bytes.len()).unwrap_or(0));
            message.extend_from_slice(bytes);
        }
        message.extend_from_slice(&port.to_be_bytes());
        Ok(message)
    }

    /// One framed data record.
    pub fn data_frame(data: &[u8]) -> Result<Vec<u8>> {
        if data.len() > MAX_FRAME_PAYLOAD {
            return Err(Error::Malformed("TCP tunnel data frame"));
        }
        let mut frame = vec![0x01, 0x00];
        frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
        frame.extend_from_slice(data);
        Ok(frame)
    }

    /// Splits [data] into as many frames as the 16-bit length allows.
    pub fn data_frames(data: &[u8]) -> Result<Vec<Vec<u8>>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }
        let mut frames = Vec::new();
        for chunk in data.chunks(MAX_FRAME_PAYLOAD) {
            frames.push(data_frame(chunk)?);
        }
        Ok(frames)
    }

    /// The end-of-stream marker used in framed mode.
    #[must_use]
    pub fn eof_frame() -> Vec<u8> {
        vec![0x01, 0x01, 0x00, 0x00]
    }

    /// Parses one complete data frame, or `None` when more bytes are needed.
    pub fn parse_data_frame(bytes: &[u8]) -> Result<Option<(Vec<u8>, bool, usize)>> {
        if bytes.len() < 4 {
            return Ok(None);
        }
        if bytes[0] != 0x01 {
            return Err(Error::Malformed("TCP tunnel data frame header"));
        }
        if bytes[1] == 0x01 {
            return Ok(Some((Vec::new(), true, bytes.len())));
        }
        if bytes[1] != 0x00 {
            return Err(Error::Malformed("TCP tunnel data frame type"));
        }
        let length = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        if bytes.len() < 4 + length {
            return Ok(None);
        }
        Ok(Some((bytes[4..4 + length].to_vec(), false, 4 + length)))
    }

    /// A human-readable reason for a non-zero connect status.
    #[must_use]
    pub fn connect_status_message(status: u8) -> String {
        match status {
            0x00 => "success".to_string(),
            0x01 => "tcp tunnel server failure".to_string(),
            0x02 => "tcp tunnel connection not allowed".to_string(),
            0x03 => "network is unreachable".to_string(),
            0x04 => "host is unreachable".to_string(),
            0x05 => "connection refused".to_string(),
            0x06 => "tcp tunnel TTL expired".to_string(),
            0x07 => "tcp tunnel command not supported".to_string(),
            0x08 => "tcp tunnel address type not supported".to_string(),
            other => format!("tcp tunnel connect failed with status 0x{other:x}"),
        }
    }

    /// Parses a complete server hello, or `None` when more bytes are needed.
    pub fn parse_server_response(bytes: &[u8]) -> Result<Option<ServerResponse>> {
        if bytes.len() < 6 {
            return Ok(None);
        }
        if bytes[0] != crate::PROTOCOL_VERSION || bytes[1] != 0x81 {
            return Err(Error::Malformed("TCP tunnel server hello"));
        }
        if bytes[2] != 0x53 || bytes[3] != 0x00 {
            return Err(Error::Malformed("TCP tunnel auth response"));
        }
        let auth_length = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
        if bytes.len() < 6 + auth_length + 4 {
            return Ok(None);
        }
        let auth_payload = &bytes[6..6 + auth_length];
        let mut offset = 6 + auth_length;
        if bytes[offset] != crate::PROTOCOL_VERSION {
            return Err(Error::Malformed("TCP tunnel connect reply version"));
        }
        let connect_status = bytes[offset + 1];
        let (auth_code, auth_message) = parse_auth_payload(auth_payload);
        if connect_status != 0 {
            return Ok(Some(ServerResponse {
                auth_code,
                auth_message,
                connect_status,
                reuse: false,
                consumed: offset + 4,
            }));
        }
        let reuse = bytes[offset + 2] == 0x01;
        let address_length = match bytes[offset + 3] {
            0x01 => 4,
            0x04 => 16,
            other => {
                let _ = other;
                return Err(Error::Malformed("TCP tunnel bind address type"));
            }
        };
        offset += 4 + address_length + 2;
        if bytes.len() < offset {
            return Ok(None);
        }
        Ok(Some(ServerResponse {
            auth_code,
            auth_message,
            connect_status,
            reuse,
            consumed: offset,
        }))
    }

    fn parse_auth_payload(payload: &[u8]) -> (i64, String) {
        if payload.is_empty() {
            return (0, String::new());
        }
        match serde_json::from_slice::<serde_json::Value>(payload) {
            Ok(parsed) => (
                parsed
                    .get("code")
                    .and_then(serde_json::Value::as_i64)
                    .unwrap_or(-1),
                parsed
                    .get("message")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
                    .to_string(),
            ),
            Err(_) => (-1, "invalid auth response".to_string()),
        }
    }
}

/// Incremental parser for the server hello, then the payload that follows it.
#[derive(Debug, Default)]
pub struct HandshakeDecoder {
    buffer: Vec<u8>,
    response: Option<ServerResponse>,
}

impl HandshakeDecoder {
    /// A decoder at the start of a dial.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The parsed hello, once it has arrived.
    #[must_use]
    pub fn response(&self) -> Option<&ServerResponse> {
        self.response.as_ref()
    }

    /// Feeds a chunk. Returns the bytes that follow the hello once it has
    /// completed; `None` while more bytes are needed.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Option<Vec<u8>>> {
        if self.response.is_some() {
            return Ok(Some(chunk.to_vec()));
        }
        self.buffer.extend_from_slice(chunk);
        match protocol::parse_server_response(&self.buffer)? {
            None => Ok(None),
            Some(response) => {
                let consumed = response.consumed.min(self.buffer.len());
                let leftover = self.buffer.split_off(consumed);
                self.buffer.clear();
                self.response = Some(response);
                Ok(Some(leftover))
            }
        }
    }
}

/// Splits an inbound byte stream into payloads, honouring framed mode.
///
/// In raw mode every chunk is payload. In framed mode records are
/// length-prefixed and an EOF record ends the stream.
#[derive(Debug, Default)]
pub struct PayloadDecoder {
    buffer: Vec<u8>,
    framed: bool,
    finished: bool,
}

impl PayloadDecoder {
    /// A decoder for [framed] streams.
    #[must_use]
    pub fn new(framed: bool) -> Self {
        Self {
            buffer: Vec::new(),
            framed,
            finished: false,
        }
    }

    /// True once an EOF record arrived.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// Feeds a chunk and returns the payloads it completed.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<Vec<u8>>> {
        if self.finished {
            return Ok(Vec::new());
        }
        if !self.framed {
            return Ok(if chunk.is_empty() {
                Vec::new()
            } else {
                vec![chunk.to_vec()]
            });
        }
        self.buffer.extend_from_slice(chunk);
        let mut payloads = Vec::new();
        loop {
            match protocol::parse_data_frame(&self.buffer)? {
                None => break,
                Some((data, eof, consumed)) => {
                    self.buffer.drain(..consumed);
                    if eof {
                        self.finished = true;
                        break;
                    }
                    if !data.is_empty() {
                        payloads.push(data);
                    }
                }
            }
        }
        Ok(payloads)
    }
}
