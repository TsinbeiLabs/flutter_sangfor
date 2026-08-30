import 'dart:typed_data';

const int ipv4Version = 4;
const int ipv6Version = 6;

const int tcpProtocol = 6;
const int udpProtocol = 17;
const int icmpProtocol = 1;
const int icmp6Protocol = 58;

const int ipv4HeaderMinLength = 20;
const int tcpHeaderMinLength = 20;
const int udpHeaderMinLength = 8;

const int tcpSynFlag = 0x02;
const int tcpAckFlag = 0x10;
const int tcpFinFlag = 0x01;
const int tcpRstFlag = 0x04;

class ATrustIPv4Packet {
  ATrustIPv4Packet(this.data);

  final Uint8List data;

  bool get valid =>
      data.length >= ipv4HeaderMinLength && (data[0] >> 4) == ipv4Version;

  int get version => data[0] >> 4;

  int get headerLength => (data[0] & 0x0f) * 4;

  int get totalLength =>
      ByteData.sublistView(data, 2, 4).getUint16(0, Endian.big);

  int get protocol => data[9];

  String get sourceIP => '${data[12]}.${data[13]}.${data[14]}.${data[15]}';

  String get destinationIP => '${data[16]}.${data[17]}.${data[18]}.${data[19]}';

  Uint8List get payload => Uint8List.sublistView(data, headerLength);
}

class ATrustTCPPacket {
  ATrustTCPPacket(this.data);

  final Uint8List data;

  bool get valid => data.length >= tcpHeaderMinLength;

  int get flags => data[13];

  int get sourcePort =>
      ByteData.sublistView(data, 0, 2).getUint16(0, Endian.big);

  int get destinationPort =>
      ByteData.sublistView(data, 2, 4).getUint16(0, Endian.big);

  int get sequenceNumber =>
      ByteData.sublistView(data, 4, 8).getUint32(0, Endian.big);

  int get acknowledgmentNumber =>
      ByteData.sublistView(data, 8, 12).getUint32(0, Endian.big);
}

class ATrustUDPPacket {
  ATrustUDPPacket(this.data);

  final Uint8List data;

  bool get valid => data.length >= udpHeaderMinLength;

  int get sourcePort =>
      ByteData.sublistView(data, 0, 2).getUint16(0, Endian.big);

  int get destinationPort =>
      ByteData.sublistView(data, 2, 4).getUint16(0, Endian.big);
}

class ATrustPacketMeta {
  const ATrustPacketMeta({
    required this.atype,
    required this.protocol,
    required this.sourceAddress,
    required this.sourcePort,
    required this.destinationAddress,
    required this.destinationPort,
  });

  final int atype;
  final int protocol;
  final String sourceAddress;
  final int sourcePort;
  final String destinationAddress;
  final int destinationPort;

  String get key => '$atype:$protocol:$sourceAddress:$sourcePort-'
      '$destinationAddress:$destinationPort';

  ATrustPacketMeta get reversed => ATrustPacketMeta(
        atype: atype,
        protocol: protocol,
        sourceAddress: destinationAddress,
        sourcePort: destinationPort,
        destinationAddress: sourceAddress,
        destinationPort: sourcePort,
      );
}

ATrustPacketMeta? buildPacketMeta(Uint8List packet) {
  if (packet.isEmpty) return null;
  final ip = ATrustIPv4Packet(packet);
  if (!ip.valid) return null;

  switch (ip.protocol) {
    case icmpProtocol:
      return ATrustPacketMeta(
        atype: 4,
        protocol: icmpProtocol,
        sourceAddress: ip.sourceIP,
        sourcePort: 0,
        destinationAddress: ip.destinationIP,
        destinationPort: 0,
      );
    case tcpProtocol:
      final tcp = ATrustTCPPacket(ip.payload);
      if (!tcp.valid) return null;
      return ATrustPacketMeta(
        atype: 4,
        protocol: tcpProtocol,
        sourceAddress: ip.sourceIP,
        sourcePort: tcp.sourcePort,
        destinationAddress: ip.destinationIP,
        destinationPort: tcp.destinationPort,
      );
    case udpProtocol:
      final udp = ATrustUDPPacket(ip.payload);
      if (!udp.valid) return null;
      return ATrustPacketMeta(
        atype: 4,
        protocol: udpProtocol,
        sourceAddress: ip.sourceIP,
        sourcePort: udp.sourcePort,
        destinationAddress: ip.destinationIP,
        destinationPort: udp.destinationPort,
      );
    default:
      return null;
  }
}

(List<Uint8List>, Uint8List) splitIncomingIPPackets(Uint8List stream) {
  final packets = <Uint8List>[];
  var offset = 0;
  while (offset < stream.length) {
    final remaining = stream.length - offset;
    final version = stream[offset] >> 4;
    int packetLen;

    if (version == ipv4Version) {
      if (remaining < 4) {
        return (packets, Uint8List.sublistView(stream, offset));
      }
      final headerLen = (stream[offset] & 0x0f) * 4;
      packetLen = ByteData.sublistView(stream, offset + 2, offset + 4)
          .getUint16(0, Endian.big);
      if (headerLen < 20 || packetLen < headerLen) {
        throw FormatException(
          'invalid IPv4 packet length $packetLen with header length $headerLen',
        );
      }
    } else if (version == ipv6Version) {
      if (remaining < 6) {
        return (packets, Uint8List.sublistView(stream, offset));
      }
      packetLen = 40 +
          ByteData.sublistView(stream, offset + 4, offset + 6)
              .getUint16(0, Endian.big);
    } else {
      throw FormatException('unexpected IP version $version');
    }

    if (remaining < packetLen) {
      return (packets, Uint8List.sublistView(stream, offset));
    }
    packets.add(Uint8List.fromList(stream.sublist(offset, offset + packetLen)));
    offset += packetLen;
  }
  return (packets, Uint8List.sublistView(stream, offset));
}

String protocolName(int protocol) => switch (protocol) {
      tcpProtocol => 'tcp',
      udpProtocol => 'udp',
      icmpProtocol => 'icmp',
      icmp6Protocol => 'icmp6',
      _ => 'ip',
    };

int authIPType(int atype) => switch (atype) {
      6 => 0x86DD,
      _ => 0x0800,
    };
