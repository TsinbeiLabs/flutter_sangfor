//! IPv4/TCP parsing and construction, with full checksums.
//!
//! Tunnel interfaces differ in whether they verify checksums (wintun does not
//! offload, `NEPacketTunnelFlow` delivers what the stack expects to see), so
//! every packet is computed completely instead of relying on offload.

use crate::error::{Error, Result};

/// IP protocol number for ICMP.
pub const ICMP: u8 = 1;
/// IP protocol number for TCP.
pub const TCP: u8 = 6;
/// IP protocol number for UDP.
pub const UDP: u8 = 17;
/// IP protocol number for ICMPv6.
pub const ICMP6: u8 = 58;

/// TCP flag bits (RFC 793).
pub mod flag {
    /// Finish.
    pub const FIN: u8 = 0x01;
    /// Synchronize.
    pub const SYN: u8 = 0x02;
    /// Reset.
    pub const RST: u8 = 0x04;
    /// Push.
    pub const PSH: u8 = 0x08;
    /// Acknowledge.
    pub const ACK: u8 = 0x10;
}

const IPV4_HEADER_LEN: usize = 20;
const TCP_HEADER_LEN: usize = 20;

/// Routing metadata for one packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PacketMeta {
    /// Address family as the gateway spells it (4 for IPv4).
    pub atype: u8,
    /// IP protocol number.
    pub protocol: u8,
    /// Source address, dotted quad.
    pub source_address: u32,
    /// Source port, 0 for ICMP.
    pub source_port: u16,
    /// Destination address, dotted quad.
    pub destination_address: u32,
    /// Destination port, 0 for ICMP.
    pub destination_port: u16,
}

impl PacketMeta {
    /// The same flow seen from the other side.
    #[must_use]
    pub fn reversed(&self) -> Self {
        Self {
            atype: self.atype,
            protocol: self.protocol,
            source_address: self.destination_address,
            source_port: self.destination_port,
            destination_address: self.source_address,
            destination_port: self.source_port,
        }
    }

    /// The protocol name used in an auth request's `url` field.
    #[must_use]
    pub fn protocol_name(&self) -> &'static str {
        protocol_name(self.protocol)
    }

    /// The destination in dotted-quad form.
    #[must_use]
    pub fn destination_text(&self) -> String {
        ipv4_text(self.destination_address)
    }

    /// The source in dotted-quad form.
    #[must_use]
    pub fn source_text(&self) -> String {
        ipv4_text(self.source_address)
    }
}

/// The protocol name the gateway expects for an IP protocol number.
#[must_use]
pub fn protocol_name(protocol: u8) -> &'static str {
    match protocol {
        TCP => "tcp",
        UDP => "udp",
        ICMP => "icmp",
        ICMP6 => "icmp6",
        _ => "ip",
    }
}

/// The TCP header of an IPv4 packet, when it carries one.
#[must_use]
pub fn ip_payload_tcp(packet: &[u8]) -> Option<TcpHeader<'_>> {
    let ip = Ipv4Packet::parse(packet)?;
    if ip.protocol() != TCP {
        return None;
    }
    TcpHeader::parse(ip.payload())
}

/// Parses the routing metadata of a raw IP packet, or `None` when the packet
/// is malformed or carries a protocol the tunnel cannot describe.
#[must_use]
pub fn build_packet_meta(packet: &[u8]) -> Option<PacketMeta> {
    let ip = Ipv4Packet::parse(packet)?;
    let (source_address, destination_address) = (ip.source_address(), ip.destination_address());
    match ip.protocol() {
        ICMP => Some(PacketMeta {
            atype: 4,
            protocol: ICMP,
            source_address,
            source_port: 0,
            destination_address,
            destination_port: 0,
        }),
        TCP => {
            let tcp = TcpHeader::parse(ip.payload())?;
            Some(PacketMeta {
                atype: 4,
                protocol: TCP,
                source_address,
                source_port: tcp.source_port(),
                destination_address,
                destination_port: tcp.destination_port(),
            })
        }
        UDP => {
            let payload = ip.payload();
            if payload.len() < 8 {
                return None;
            }
            Some(PacketMeta {
                atype: 4,
                protocol: UDP,
                source_address,
                source_port: u16::from_be_bytes([payload[0], payload[1]]),
                destination_address,
                destination_port: u16::from_be_bytes([payload[2], payload[3]]),
            })
        }
        _ => None,
    }
}

/// A parsed IPv4 header. Borrows the packet buffer.
#[derive(Debug, Clone, Copy)]
pub struct Ipv4Packet<'a> {
    bytes: &'a [u8],
    header_len: usize,
    total_len: usize,
}

impl<'a> Ipv4Packet<'a> {
    /// Parses [packet], or `None` when it is not a well-formed IPv4 datagram.
    #[must_use]
    pub fn parse(packet: &'a [u8]) -> Option<Self> {
        if packet.len() < IPV4_HEADER_LEN || packet[0] >> 4 != 4 {
            return None;
        }
        let header_len = usize::from(packet[0] & 0x0f) * 4;
        if header_len < IPV4_HEADER_LEN || packet.len() < header_len {
            return None;
        }
        let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
        if total_len < header_len {
            return None;
        }
        Some(Self {
            bytes: packet,
            header_len,
            total_len: total_len.min(packet.len()),
        })
    }

    /// The IP header length, options included.
    #[must_use]
    pub fn header_len(&self) -> usize {
        self.header_len
    }

    /// The datagram's total length as declared in its header.
    #[must_use]
    pub fn total_len(&self) -> usize {
        self.total_len
    }

    /// The protocol number.
    #[must_use]
    pub fn protocol(&self) -> u8 {
        self.bytes[9]
    }

    /// Time to live.
    #[must_use]
    pub fn ttl(&self) -> u8 {
        self.bytes[8]
    }

    /// The source address as a host-order integer.
    #[must_use]
    pub fn source_address(&self) -> u32 {
        u32::from_be_bytes([
            self.bytes[12],
            self.bytes[13],
            self.bytes[14],
            self.bytes[15],
        ])
    }

    /// The destination address as a host-order integer.
    #[must_use]
    pub fn destination_address(&self) -> u32 {
        u32::from_be_bytes([
            self.bytes[16],
            self.bytes[17],
            self.bytes[18],
            self.bytes[19],
        ])
    }

    /// The transport header and payload.
    #[must_use]
    pub fn payload(&self) -> &'a [u8] {
        &self.bytes[self.header_len..self.total_len]
    }
}

/// A parsed TCP header. Borrows the segment buffer.
#[derive(Debug, Clone, Copy)]
pub struct TcpHeader<'a> {
    bytes: &'a [u8],
    data_offset: usize,
}

impl<'a> TcpHeader<'a> {
    /// Parses [bytes] as a TCP header, or `None` when it is too short or its
    /// data offset is impossible.
    #[must_use]
    pub fn parse(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() < TCP_HEADER_LEN {
            return None;
        }
        let data_offset = usize::from(bytes[12] >> 4) * 4;
        if data_offset < TCP_HEADER_LEN || bytes.len() < data_offset {
            return None;
        }
        Some(Self { bytes, data_offset })
    }

    /// The source port.
    #[must_use]
    pub fn source_port(&self) -> u16 {
        u16::from_be_bytes([self.bytes[0], self.bytes[1]])
    }

    /// The destination port.
    #[must_use]
    pub fn destination_port(&self) -> u16 {
        u16::from_be_bytes([self.bytes[2], self.bytes[3]])
    }

    /// The sequence number.
    #[must_use]
    pub fn sequence_number(&self) -> u32 {
        u32::from_be_bytes([self.bytes[4], self.bytes[5], self.bytes[6], self.bytes[7]])
    }

    /// The acknowledgment number.
    #[must_use]
    pub fn acknowledgment_number(&self) -> u32 {
        u32::from_be_bytes([self.bytes[8], self.bytes[9], self.bytes[10], self.bytes[11]])
    }

    /// The flag byte.
    #[must_use]
    pub fn flags(&self) -> u8 {
        self.bytes[13]
    }

    /// The receive window the sender advertises, without scaling.
    #[must_use]
    pub fn window(&self) -> u16 {
        u16::from_be_bytes([self.bytes[14], self.bytes[15]])
    }

    /// The segment payload.
    #[must_use]
    pub fn payload(&self) -> &'a [u8] {
        &self.bytes[self.data_offset..]
    }

    /// The MSS option the sender offered, or `None` when it sent none.
    #[must_use]
    pub fn mss(&self) -> Option<u16> {
        let end = self.data_offset.min(self.bytes.len());
        let mut index = TCP_HEADER_LEN;
        while index < end {
            let kind = self.bytes[index];
            if kind == 0 {
                break;
            }
            if kind == 1 {
                index += 1;
                continue;
            }
            if index + 1 >= end {
                break;
            }
            let length = usize::from(self.bytes[index + 1]);
            if length < 2 || index + length > end {
                break;
            }
            if kind == 2 && length == 4 {
                return Some(u16::from_be_bytes([
                    self.bytes[index + 2],
                    self.bytes[index + 3],
                ]));
            }
            index += length;
        }
        None
    }
}

/// Parameters for [`build_tcp`].
#[derive(Debug, Clone, Copy)]
pub struct TcpPacketParams {
    /// Source address, host order.
    pub source: u32,
    /// Destination address, host order.
    pub destination: u32,
    /// Source port.
    pub source_port: u16,
    /// Destination port.
    pub destination_port: u16,
    /// Sequence number.
    pub sequence: u32,
    /// Acknowledgment number.
    pub acknowledgment: u32,
    /// Flag byte.
    pub flags: u8,
    /// Advertised receive window.
    pub window: u16,
    /// IP identification field.
    pub identification: u16,
    /// Time to live.
    pub ttl: u8,
    /// MSS option to include, if any.
    pub mss: Option<u16>,
}

impl Default for TcpPacketParams {
    fn default() -> Self {
        Self {
            source: 0,
            destination: 0,
            source_port: 0,
            destination_port: 0,
            sequence: 0,
            acknowledgment: 0,
            flags: 0,
            window: 0,
            identification: 0,
            ttl: 64,
            mss: None,
        }
    }
}

/// Assembles one IPv4/TCP packet with both checksums computed.
pub fn build_tcp(params: &TcpPacketParams, payload: &[u8]) -> Vec<u8> {
    let option_len = usize::from(params.mss.is_some()) * 4;
    let tcp_len = TCP_HEADER_LEN + option_len + payload.len();
    let mut packet = vec![0u8; IPV4_HEADER_LEN + tcp_len];

    packet[0] = 0x45;
    let total_len = u16::try_from(packet.len()).unwrap_or(u16::MAX);
    packet[2..4].copy_from_slice(&total_len.to_be_bytes());
    packet[4..6].copy_from_slice(&params.identification.to_be_bytes());
    packet[8] = params.ttl;
    packet[9] = TCP;
    packet[12..16].copy_from_slice(&params.source.to_be_bytes());
    packet[16..20].copy_from_slice(&params.destination.to_be_bytes());
    let ip_checksum = ipv4_header_checksum(&packet);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let tcp = IPV4_HEADER_LEN;
    packet[tcp..tcp + 2].copy_from_slice(&params.source_port.to_be_bytes());
    packet[tcp + 2..tcp + 4].copy_from_slice(&params.destination_port.to_be_bytes());
    packet[tcp + 4..tcp + 8].copy_from_slice(&params.sequence.to_be_bytes());
    packet[tcp + 8..tcp + 12].copy_from_slice(&params.acknowledgment.to_be_bytes());
    packet[tcp + 12] = u8::try_from((TCP_HEADER_LEN + option_len) / 4).unwrap_or(5) << 4;
    packet[tcp + 13] = params.flags;
    packet[tcp + 14..tcp + 16].copy_from_slice(&params.window.to_be_bytes());
    if let Some(mss) = params.mss {
        packet[tcp + TCP_HEADER_LEN] = 2;
        packet[tcp + TCP_HEADER_LEN + 1] = 4;
        packet[tcp + TCP_HEADER_LEN + 2..tcp + TCP_HEADER_LEN + 4]
            .copy_from_slice(&mss.to_be_bytes());
    }
    if !payload.is_empty() {
        let start = tcp + TCP_HEADER_LEN + option_len;
        packet[start..start + payload.len()].copy_from_slice(payload);
    }
    let tcp_checksum = tcp_checksum(&packet, IPV4_HEADER_LEN);
    packet[tcp + 16..tcp + 18].copy_from_slice(&tcp_checksum.to_be_bytes());
    packet
}

/// The ones'-complement checksum of an IPv4 header. The checksum field must be
/// zero; a valid header verifies to `0xffff` when it is included.
#[must_use]
pub fn ipv4_header_checksum(packet: &[u8]) -> u16 {
    let header_len = if packet.len() >= IPV4_HEADER_LEN {
        usize::from(packet[0] & 0x0f) * 4
    } else {
        packet.len()
    };
    let header_len = header_len.min(packet.len());
    let mut sum: u32 = 0;
    let mut index = 0;
    while index + 1 < header_len {
        if index != 10 {
            sum += u32::from(u16::from_be_bytes([packet[index], packet[index + 1]]));
        }
        index += 2;
    }
    fold(sum)
}

/// The TCP checksum over the pseudo-header, TCP header, and payload. The
/// checksum field inside the header must be zero.
#[must_use]
pub fn tcp_checksum(packet: &[u8], header_len: usize) -> u16 {
    if packet.len() < header_len + TCP_HEADER_LEN {
        return 0;
    }
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    let tcp_len = total_len
        .saturating_sub(header_len)
        .min(packet.len() - header_len);
    let mut sum: u32 = 0;
    // Pseudo-header: source, destination, zero, protocol, TCP length.
    sum += u32::from(u16::from_be_bytes([packet[12], packet[13]]));
    sum += u32::from(u16::from_be_bytes([packet[14], packet[15]]));
    sum += u32::from(u16::from_be_bytes([packet[16], packet[17]]));
    sum += u32::from(u16::from_be_bytes([packet[18], packet[19]]));
    sum += u32::from(packet[9]);
    sum += tcp_len as u32;
    let tcp = &packet[header_len..header_len + tcp_len];
    let mut index = 0;
    while index + 1 < tcp.len() {
        sum += u32::from(u16::from_be_bytes([tcp[index], tcp[index + 1]]));
        index += 2;
    }
    if tcp.len() % 2 == 1 {
        sum += u32::from(tcp[tcp.len() - 1]) << 8;
    }
    fold(sum)
}

fn fold(sum: u32) -> u16 {
    let mut value = sum;
    while value >> 16 != 0 {
        value = (value & 0xffff) + (value >> 16);
    }
    u16::from_be_bytes((!value as u16).to_be_bytes())
}

/// Splits a concatenated inbound raw-IP stream into complete packets,
/// returning them with the unconsumed tail.
pub fn split_incoming_packets(stream: &[u8]) -> Result<(Vec<&[u8]>, &[u8])> {
    let mut packets = Vec::new();
    let mut offset = 0;
    while offset < stream.len() {
        let remaining = stream.len() - offset;
        let version = stream[offset] >> 4;
        let packet_len = match version {
            4 => {
                if remaining < 4 {
                    return Ok((packets, &stream[offset..]));
                }
                let header_len = usize::from(stream[offset] & 0x0f) * 4;
                let total =
                    usize::from(u16::from_be_bytes([stream[offset + 2], stream[offset + 3]]));
                if header_len < IPV4_HEADER_LEN || total < header_len {
                    return Err(Error::Malformed("IPv4 packet length"));
                }
                total
            }
            6 => {
                if remaining < 6 {
                    return Ok((packets, &stream[offset..]));
                }
                40 + usize::from(u16::from_be_bytes([stream[offset + 4], stream[offset + 5]]))
            }
            _ => return Err(Error::Malformed("IP version")),
        };
        if remaining < packet_len {
            return Ok((packets, &stream[offset..]));
        }
        packets.push(&stream[offset..offset + packet_len]);
        offset += packet_len;
    }
    Ok((packets, &stream[offset..]))
}

/// Adds in TCP sequence space (32-bit wraparound).
#[must_use]
pub fn sequence_add(base: u32, value: u32) -> u32 {
    base.wrapping_add(value)
}

/// The signed distance from `from` to `to` in TCP sequence space: positive when
/// `to` is ahead.
#[must_use]
pub fn sequence_difference(from: u32, to: u32) -> i32 {
    (to.wrapping_sub(from)) as i32
}

/// Parses a dotted-quad address, or `None` when [text] is not one.
#[must_use]
pub fn parse_ipv4(text: &str) -> Option<u32> {
    let mut octets = text.split('.');
    let mut value: u32 = 0;
    for _ in 0..4 {
        let part = octets.next()?;
        if part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let octet: u32 = part.parse().ok()?;
        if octet > 255 {
            return None;
        }
        value = (value << 8) | octet;
    }
    if octets.next().is_some() {
        return None;
    }
    Some(value)
}

/// Renders a host-order IPv4 address as dotted quad.
#[must_use]
pub fn ipv4_text(address: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (address >> 24) & 0xff,
        (address >> 16) & 0xff,
        (address >> 8) & 0xff,
        address & 0xff
    )
}

/// Parses a textual IPv6 address into its sixteen bytes. Handles `::`
/// compression and a trailing embedded IPv4 quad.
#[must_use]
pub fn parse_ipv6(text: &str) -> Option<[u8; 16]> {
    if !text.contains(':') {
        return None;
    }
    let (head, embedded) = match text.rfind(':') {
        Some(index) if text[index + 1..].contains('.') => {
            let embedded = parse_ipv4(&text[index + 1..])?;
            (format!("{}:0:0", &text[..index]), Some(embedded))
        }
        _ => (text.to_string(), None),
    };
    let halves: Vec<&str> = head.splitn(2, "::").collect();
    let parse_groups = |part: &str| -> Option<Vec<u16>> {
        if part.is_empty() {
            return Some(Vec::new());
        }
        part.split(':')
            .map(|group| {
                if group.is_empty() || group.len() > 4 {
                    None
                } else {
                    u16::from_str_radix(group, 16).ok()
                }
            })
            .collect()
    };
    let leading = parse_groups(halves[0])?;
    let trailing = if halves.len() == 2 {
        parse_groups(halves[1])?
    } else {
        Vec::new()
    };
    let total = leading.len() + trailing.len();
    if total > 8 {
        return None;
    }
    let mut groups = leading;
    groups.extend(std::iter::repeat_n(0u16, 8 - total));
    groups.extend(trailing);
    let mut bytes = [0u8; 16];
    for (index, group) in groups.iter().enumerate() {
        bytes[index * 2..index * 2 + 2].copy_from_slice(&group.to_be_bytes());
    }
    if let Some(embedded) = embedded {
        bytes[12..16].copy_from_slice(&embedded.to_be_bytes());
    }
    Some(bytes)
}

/// Compressed textual form of an IPv6 address.
#[must_use]
pub fn ipv6_text(bytes: &[u8; 16]) -> String {
    let groups: Vec<u16> = bytes
        .chunks(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect();
    let mut best_start = 0usize;
    let mut best_len = 0usize;
    let mut start = 0usize;
    let mut len = 0usize;
    for (index, group) in groups.iter().enumerate() {
        if *group == 0 {
            if len == 0 {
                start = index;
            }
            len += 1;
            if len > best_len {
                best_start = start;
                best_len = len;
            }
        } else {
            len = 0;
        }
    }
    let render = |slice: &[u16]| {
        slice
            .iter()
            .map(|group| format!("{group:x}"))
            .collect::<Vec<_>>()
            .join(":")
    };
    if best_len <= 1 {
        return render(&groups);
    }
    let head = render(&groups[..best_start]);
    let tail = render(&groups[best_start + best_len..]);
    match (head.is_empty(), tail.is_empty()) {
        (true, true) => "::".to_string(),
        (true, false) => format!("::{tail}"),
        (false, true) => format!("{head}::"),
        (false, false) => format!("{head}::{tail}"),
    }
}
