import Foundation

import SangforTunnelCore

/// Thin consumer wrapper: the entire packet tunnel implementation lives in
/// the `SangforTunnelCore` library provided by flutter_sangfor.
final class PacketTunnelProvider: SangforPacketTunnelProvider {}
