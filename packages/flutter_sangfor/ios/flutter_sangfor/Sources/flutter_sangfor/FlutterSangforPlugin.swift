import Flutter
import NetworkExtension
import UIKit

public class FlutterSangforPlugin: NSObject, FlutterPlugin {
  private var state = "disconnected"
  private var tunnelProviderManager: NETunnelProviderManager?

  public static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(name: "flutter_sangfor", binaryMessenger: registrar.messenger())
    let instance = FlutterSangforPlugin()
    registrar.addMethodCallDelegate(instance, channel: channel)
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    switch call.method {
    case "getState":
      result(state)
    case "getCapabilities":
      result([
        "platform": "ios",
        "supportsVpn": true,
        "supportsTun": true,
        "supportsSocks5": true,
        "supportedAuthTypes": []
      ])
    case "disconnect":
      state = "disconnected"
      result(nil)
    case "connect":
      result(FlutterError(code: "unsupported", message: "The aTrust transport is not implemented on iOS yet.", details: nil))
    case "vpnPrepare":
      // On iOS, the VPN permission is requested when loading the tunnel
      // preferences for the first time; NETunnelProviderManager.load handles it.
      result(true)
    case "vpnStart":
      let args = call.arguments as? [String: Any] ?? [:]
      let address = args["address"] as? String ?? "10.0.0.2"
      let prefixLength = args["prefixLength"] as? Int ?? 32
      let routes = args["routes"] as? [String] ?? []
      let dnsServers = args["dnsServers"] as? [String] ?? []
      startVpn(
        address: address,
        prefixLength: prefixLength,
        routes: routes,
        dnsServers: dnsServers
      ) { started, error in
        if let error = error {
          result(FlutterError(code: "vpn_start_failed", message: error.localizedDescription, details: nil))
        } else {
          self.state = "connected"
          result(started)
        }
      }
    case "vpnStop":
      stopVpn { _ in
        self.state = "disconnected"
        result(nil)
      }
    default:
      result(FlutterMethodNotImplemented)
    }
  }

  private func startVpn(
    address: String,
    prefixLength: Int,
    routes: [String],
    dnsServers: [String],
    completion: @escaping (Bool, Error?) -> Void
  ) {
    NETunnelProviderManager.loadAllFromPreferences { managers, error in
      if let error = error {
        completion(false, error)
        return
      }
      let manager: NETunnelProviderManager
      if let existing = managers?.first {
        manager = existing
      } else {
        manager = NETunnelProviderManager()
      }
      let protocolConf = NETunnelProviderProtocol()
      protocolConf.providerBundleIdentifier = Bundle.main.bundleIdentifier.map { "\($0).SangforPacketTunnelProvider" }
      protocolConf.providerConfiguration = [
        "address": address,
        "prefixLength": prefixLength,
        "routes": routes,
        "dnsServers": dnsServers
      ]
      manager.protocolConfiguration = protocolConf
      manager.localizedDescription = "flutter_sangfor"
      manager.isEnabled = true
      manager.saveToPreferences { saveError in
        if let saveError = saveError {
          completion(false, saveError)
          return
        }
        manager.loadFromPreferences { loadError in
          if let loadError = loadError {
            completion(false, loadError)
            return
          }
          do {
            try manager.connection.startVPNTunnel(options: [
              "address": address as NSString,
              "prefixLength": prefixLength as NSNumber,
              "routes": routes as NSArray,
              "dnsServers": dnsServers as NSArray
            ])
            self.tunnelProviderManager = manager
            completion(true, nil)
          } catch {
            completion(false, error)
          }
        }
      }
    }
  }

  private func stopVpn(completion: @escaping (Error?) -> Void) {
    guard let manager = tunnelProviderManager else {
      completion(nil)
      return
    }
    manager.connection.stopVPNTunnel()
    completion(nil)
  }
}
