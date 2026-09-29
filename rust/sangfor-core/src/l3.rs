//! The L3 tunnel protocol: frames, the initial handshake, per-flow
//! authentication, and the virtual-IP payloads.
//!
//! Layout notes, all of which the golden fixtures pin:
//!
//! - a frame is `05 <command> [status] <len16> <payload>`; only the auth (0x93)
//!   and second-VIP (0x96) responses carry the status byte;
//! - the opening request is `05 01 D0 53 00 <len16> {"sid":...}` followed by a
//!   fixed ten-byte trailer;
//! - a data request is `05 14 <tokenLen> <token> 00 00 01 <len16> <packet>`;
//! - a flow auth request is `05 13 <len16> <signed JSON>`;
//! - the handshake response is a method ack, an auth header and JSON payload,
//!   then a VIP header and its address bytes.

use std::borrow::Cow;

use crate::crypto::request_signature;
use crate::error::{Error, Result};
use crate::json::{self, Json};
use crate::packet::ipv6_text;

/// L3 tunnel commands. The high bit marks a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    /// Per-flow authentication request.
    AuthRequest = 0x13,
    /// One raw IP packet, addressed by its flow token.
    DataRequest = 0x14,
    /// Keepalive.
    HeartbeatRequest = 0x15,
    /// Per-flow authentication response.
    AuthResponse = 0x93,
    /// Inbound packets.
    DataResponse = 0x94,
    /// Keepalive answer.
    HeartbeatResponse = 0x95,
    /// A second virtual IP was assigned.
    SecondVipResponse = 0x96,
}

impl Command {
    /// Decodes a command byte.
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0x13 => Command::AuthRequest,
            0x14 => Command::DataRequest,
            0x15 => Command::HeartbeatRequest,
            0x93 => Command::AuthResponse,
            0x94 => Command::DataResponse,
            0x95 => Command::HeartbeatResponse,
            0x96 => Command::SecondVipResponse,
            _ => return None,
        })
    }

    /// True when the frame header carries a one-byte status field.
    #[must_use]
    pub fn has_status(self) -> bool {
        matches!(self, Command::AuthResponse | Command::SecondVipResponse)
    }
}

/// One decoded frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// The command.
    pub command: Command,
    /// The status byte, 0 for commands that do not carry one.
    pub status: u8,
    /// The payload.
    pub payload: Vec<u8>,
}

/// Builds the request that opens a tunnel and asks for the client virtual IP.
pub fn auth_tunnel_request(sid: &str) -> Result<Vec<u8>> {
    let body = json::encode(&Json::object(vec![(
        Cow::Borrowed("sid"),
        Json::string(sid),
    )]));
    if body.len() > 0xffff {
        return Err(Error::Malformed("authTunnel payload"));
    }
    let mut frame = vec![crate::PROTOCOL_VERSION, 0x01, 0xD0, 0x53, 0x00];
    frame.extend_from_slice(&(body.len() as u16).to_be_bytes());
    frame.extend_from_slice(&body);
    frame.extend_from_slice(&[0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    Ok(frame)
}

/// Builds the frame that carries one raw IP packet for an authenticated flow.
pub fn data_request(token: &str, packet: &[u8]) -> Result<Vec<u8>> {
    let token_bytes = token.as_bytes();
    if token_bytes.len() > 255 {
        return Err(Error::Malformed("flow token"));
    }
    if packet.len() > 0xffff {
        return Err(Error::Malformed("data payload"));
    }
    let mut frame = vec![crate::PROTOCOL_VERSION, Command::DataRequest as u8];
    frame.push(u8::try_from(token_bytes.len()).unwrap_or(0));
    frame.extend_from_slice(token_bytes);
    frame.extend_from_slice(&[0x00, 0x00, 0x01]);
    frame.extend_from_slice(&(packet.len() as u16).to_be_bytes());
    frame.extend_from_slice(packet);
    Ok(frame)
}

/// The keepalive frame.
#[must_use]
pub fn heartbeat_request() -> Vec<u8> {
    vec![
        crate::PROTOCOL_VERSION,
        Command::HeartbeatRequest as u8,
        0x00,
        0x00,
    ]
}

/// Decodes exactly one complete frame.
pub fn decode_frame(bytes: &[u8]) -> Result<Frame> {
    if bytes.len() < 4 {
        return Err(Error::Malformed("frame header"));
    }
    if bytes[0] != crate::PROTOCOL_VERSION {
        return Err(Error::Malformed("frame version"));
    }
    let command = Command::from_u8(bytes[1]).ok_or(Error::Malformed("frame command"))?;
    let mut offset = 2;
    let mut status = 0u8;
    if command.has_status() {
        if bytes.len() < 5 {
            return Err(Error::Malformed("frame status"));
        }
        status = bytes[offset];
        offset += 1;
    }
    let length = usize::from(u16::from_be_bytes([bytes[offset], bytes[offset + 1]]));
    offset += 2;
    if bytes.len() != offset + length {
        return Err(Error::Malformed("frame payload"));
    }
    Ok(Frame {
        command,
        status,
        payload: bytes[offset..].to_vec(),
    })
}

/// Turns transport chunks into frames, holding back partial ones.
#[derive(Debug, Default)]
pub struct FrameDecoder {
    buffer: Vec<u8>,
}

impl FrameDecoder {
    /// A decoder with an empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a chunk and returns every frame that is now complete.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<Frame>> {
        self.buffer.extend_from_slice(chunk);
        let mut frames = Vec::new();
        while let Some((frame, consumed)) = self.decode_one()? {
            frames.push(frame);
            self.buffer.drain(..consumed);
        }
        Ok(frames)
    }

    /// Drops any buffered bytes.
    pub fn reset(&mut self) {
        self.buffer.clear();
    }

    fn decode_one(&self) -> Result<Option<(Frame, usize)>> {
        if self.buffer.len() < 2 {
            return Ok(None);
        }
        if self.buffer[0] != crate::PROTOCOL_VERSION {
            return Err(Error::Malformed("frame version"));
        }
        let command = Command::from_u8(self.buffer[1]).ok_or(Error::Malformed("frame command"))?;
        let header_len = if command.has_status() { 5 } else { 4 };
        if self.buffer.len() < header_len {
            return Ok(None);
        }
        let length_offset = if command.has_status() { 3 } else { 2 };
        let length = usize::from(u16::from_be_bytes([
            self.buffer[length_offset],
            self.buffer[length_offset + 1],
        ]));
        let total = header_len + length;
        if self.buffer.len() < total {
            return Ok(None);
        }
        Ok(Some((decode_frame(&self.buffer[..total])?, total)))
    }
}

/// The result of the initial tunnel handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeResult {
    /// The auth status byte (0 on success).
    pub auth_status: u8,
    /// The device id the gateway echoed, when it sent one.
    pub device_id: Option<String>,
    /// The virtual IP addresses assigned to this client.
    pub virtual_ip: Vec<String>,
}

/// Incremental parser for the authTunnel response sequence.
#[derive(Debug, Default)]
pub struct HandshakeParser {
    buffer: Vec<u8>,
    phase: u8,
    auth_length: usize,
    vip_length: usize,
    device_id: Option<String>,
}

impl HandshakeParser {
    /// A parser at the start of the sequence.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds a chunk. Returns the result plus the unconsumed leftover bytes
    /// once the whole sequence has arrived.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Option<(HandshakeResult, Vec<u8>)>> {
        self.buffer.extend_from_slice(chunk);
        loop {
            match self.phase {
                0 => {
                    if self.buffer.len() < 2 {
                        return Ok(None);
                    }
                    if self.buffer[0] != crate::PROTOCOL_VERSION || self.buffer[1] != 0xD0 {
                        return Err(Error::Malformed("auth method response"));
                    }
                    self.buffer.drain(..2);
                    self.phase = 1;
                }
                1 => {
                    if self.buffer.len() < 4 {
                        return Ok(None);
                    }
                    if self.buffer[0] != 0x53 {
                        return Err(Error::Malformed("auth response version"));
                    }
                    let status = self.buffer[1];
                    self.auth_length =
                        usize::from(u16::from_be_bytes([self.buffer[2], self.buffer[3]]));
                    self.buffer.drain(..4);
                    if status != 0 {
                        return Err(Error::TunnelAuthFailed(format!("status {status}")));
                    }
                    self.phase = 2;
                }
                2 => {
                    if self.buffer.len() < self.auth_length {
                        return Ok(None);
                    }
                    let payload: Vec<u8> = self.buffer.drain(..self.auth_length).collect();
                    if !payload.is_empty() {
                        let parsed: serde_json::Value = serde_json::from_slice(&payload)
                            .map_err(|_| Error::Malformed("auth payload"))?;
                        let code = parsed
                            .get("code")
                            .and_then(serde_json::Value::as_i64)
                            .unwrap_or(0);
                        if code != 0 {
                            let message = parsed
                                .get("message")
                                .and_then(serde_json::Value::as_str)
                                .unwrap_or("");
                            return Err(Error::TunnelAuthFailed(format!("code {code}: {message}")));
                        }
                        self.device_id = parsed
                            .get("data")
                            .and_then(|data| data.get("deviceId"))
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_string);
                    }
                    self.phase = 3;
                }
                3 => {
                    if self.buffer.len() < 4 {
                        return Ok(None);
                    }
                    let header: [u8; 4] = [
                        self.buffer[0],
                        self.buffer[1],
                        self.buffer[2],
                        self.buffer[3],
                    ];
                    self.vip_length = parse_vip_header(&header)?;
                    self.buffer.drain(..4);
                    self.phase = 4;
                }
                _ => {
                    if self.buffer.len() < self.vip_length {
                        return Ok(None);
                    }
                    let payload: Vec<u8> = self.buffer.drain(..self.vip_length).collect();
                    let virtual_ip = parse_virtual_ip(&payload)?;
                    let leftover = std::mem::take(&mut self.buffer);
                    return Ok(Some((
                        HandshakeResult {
                            auth_status: 0,
                            device_id: self.device_id.take(),
                            virtual_ip,
                        },
                        leftover,
                    )));
                }
            }
        }
    }
}

/// The length of the virtual-IP payload that follows an initial VIP header.
pub fn parse_vip_header(header: &[u8; 4]) -> Result<usize> {
    if header[0] != crate::PROTOCOL_VERSION {
        return Err(Error::Malformed("VIP version"));
    }
    if header[1] != 0 {
        return Err(Error::TunnelAuthFailed(format!("VIP status {}", header[1])));
    }
    match header[3] {
        1 => Ok(6),
        4 => Ok(18),
        5 => Ok(22),
        _ => Err(Error::Malformed("VIP address type")),
    }
}

/// The addresses carried by an initial VIP payload.
pub fn parse_virtual_ip(data: &[u8]) -> Result<Vec<String>> {
    match data.len() {
        6 => Ok(vec![crate::packet::ipv4_text(u32::from_be_bytes([
            data[0], data[1], data[2], data[3],
        ]))]),
        18 => {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&data[..16]);
            Ok(vec![ipv6_text(&bytes)])
        }
        22 => {
            let mut six = [0u8; 16];
            six.copy_from_slice(&data[4..20]);
            Ok(vec![
                crate::packet::ipv4_text(u32::from_be_bytes([data[0], data[1], data[2], data[3]])),
                ipv6_text(&six),
            ])
        }
        _ => Err(Error::Malformed("VIP data")),
    }
}

/// The addresses of a second-VIP (0x96) response body.
#[must_use]
pub fn extract_vips(payload: &[u8]) -> Vec<String> {
    let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(payload) else {
        return Vec::new();
    };
    let data = parsed.get("data");
    let mut addresses = Vec::new();
    for key in ["vip", "vip6"] {
        let value = parsed
            .get(key)
            .and_then(serde_json::Value::as_str)
            .or_else(|| {
                data.and_then(|d| d.get(key))
                    .and_then(serde_json::Value::as_str)
            })
            .unwrap_or("");
        if !value.is_empty() {
            addresses.push(value.to_string());
        }
    }
    addresses
}

/// The five-tuple of a flow, as the gateway expects it in an auth request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpInfo {
    /// Address family as an ethertype (0x0800 for IPv4).
    pub atype: u16,
    /// IP protocol number.
    pub protocol: u8,
    /// Destination address, dotted quad.
    pub destination_address: String,
    /// Destination port.
    pub destination_port: u16,
    /// Source address, dotted quad.
    pub source_address: String,
    /// Source port.
    pub source_port: u16,
}

impl IpInfo {
    /// Field order is part of the signed bytes.
    fn json(&self) -> Json {
        Json::object(vec![
            (Cow::Borrowed("atype"), Json::Int(i64::from(self.atype))),
            (
                Cow::Borrowed("protocol"),
                Json::Int(i64::from(self.protocol)),
            ),
            (
                Cow::Borrowed("destAddr"),
                Json::string(self.destination_address.clone()),
            ),
            (
                Cow::Borrowed("destPort"),
                Json::Int(i64::from(self.destination_port)),
            ),
            (
                Cow::Borrowed("srcAddr"),
                Json::string(self.source_address.clone()),
            ),
            (
                Cow::Borrowed("srcPort"),
                Json::Int(i64::from(self.source_port)),
            ),
        ])
    }
}

/// The process identity reported with every signed request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    /// Executable name.
    pub name: String,
    /// Executable path; its SHA-256 is the fingerprint.
    pub path: String,
    /// Platform name as the gateway spells it (`iOS`, `Android`, ...).
    pub platform: String,
}

impl ProcessInfo {
    /// The `env` block of a signed request, in the reference order.
    fn env_json(&self) -> Json {
        Json::object(vec![(
            Cow::Borrowed("application"),
            Json::object(vec![(
                Cow::Borrowed("runtime"),
                Json::object(vec![
                    (
                        Cow::Borrowed("process"),
                        Json::object(vec![
                            (Cow::Borrowed("name"), Json::string(self.name.clone())),
                            (
                                Cow::Borrowed("digital_signature"),
                                Json::string("TrustAppClosed"),
                            ),
                            (
                                Cow::Borrowed("platform"),
                                Json::string(self.platform.clone()),
                            ),
                            (
                                Cow::Borrowed("fingerprint"),
                                Json::string(crate::crypto::process_fingerprint(&self.path)),
                            ),
                            (Cow::Borrowed("description"), Json::string("TrustAppClosed")),
                            (Cow::Borrowed("path"), Json::string(self.path.clone())),
                            (Cow::Borrowed("version"), Json::string("TrustAppClosed")),
                            (Cow::Borrowed("security_env"), Json::string("normal")),
                        ]),
                    ),
                    (Cow::Borrowed("process_trusted"), Json::string("TRUSTED")),
                ]),
            )]),
        )])
    }
}

/// A per-flow L3 authentication request.
#[derive(Debug, Clone)]
pub struct AuthRequest {
    /// Session id.
    pub sid: String,
    /// Resource identity.
    pub app_id: String,
    /// `protocol:address:port`.
    pub url: String,
    /// Device identity.
    pub device_id: String,
    /// Per-connection identity.
    pub connection_id: String,
    /// UI language tag.
    pub lang: String,
    /// The flow id, echoed back by the gateway.
    pub conntrack_hash: i64,
    /// The flow five-tuple.
    pub ip: IpInfo,
    /// Optional process hash.
    pub proc_hash: Option<String>,
    /// Optional app token.
    pub app_token: Option<String>,
    /// Remote-control applied info.
    pub rc_applied_info: i64,
    /// The process identity block.
    pub process: Option<ProcessInfo>,
    /// Optional domain.
    pub domain: Option<String>,
}

impl AuthRequest {
    /// The unsigned body, in the exact key order the gateway signs.
    #[must_use]
    pub fn unsigned_members(&self) -> Vec<(Cow<'static, str>, Json)> {
        let mut members: Vec<(Cow<'static, str>, Json)> = vec![
            (Cow::Borrowed("sid"), Json::string(self.sid.clone())),
            (Cow::Borrowed("appId"), Json::string(self.app_id.clone())),
        ];
        if let Some(proc_hash) = &self.proc_hash {
            members.push((Cow::Borrowed("procHash"), Json::string(proc_hash.clone())));
        }
        if let Some(app_token) = &self.app_token {
            members.push((Cow::Borrowed("appToken"), Json::string(app_token.clone())));
        }
        members.extend([
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
                Cow::Borrowed("rcAppliedInfo"),
                Json::Int(self.rc_applied_info),
            ),
            (Cow::Borrowed("lang"), Json::string(self.lang.clone())),
        ]);
        if let Some(process) = &self.process {
            members.push((Cow::Borrowed("env"), process.env_json()));
        }
        members.push((
            Cow::Borrowed("conntrackHash"),
            Json::Int(self.conntrack_hash),
        ));
        members.push((Cow::Borrowed("ip"), self.ip.json()));
        if let Some(domain) = &self.domain {
            members.push((Cow::Borrowed("domain"), Json::string(domain.clone())));
        }
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

    /// The signed request frame (command 0x13).
    pub fn frame(&self, sign_key: &[u8]) -> Result<Vec<u8>> {
        let mut members = self.unsigned_members();
        members.push((
            Cow::Borrowed("xRequestSig"),
            Json::string(self.signature(sign_key)),
        ));
        let payload = json::encode(&Json::Object(members));
        if payload.len() > 0xffff {
            return Err(Error::Malformed("auth request payload"));
        }
        let mut frame = vec![crate::PROTOCOL_VERSION, Command::AuthRequest as u8];
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(&payload);
        Ok(frame)
    }
}
