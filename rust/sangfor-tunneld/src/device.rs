//! Opening the packet device the configuration asked for, and the interface
//! configuration that goes with it.

use std::io;
#[cfg(windows)]
use std::path::Path;
use std::sync::Arc;

use sangfor_tun::{LoopbackDevice, PacketDevice};

use crate::config::{DeviceKind, HostConfig};
use crate::netconfig::InterfaceConfig;

/// Assigns an address, routes, and DNS servers to the interface.
///
/// Present only where this process is the one that configures the interface.
/// Android and OHOS configured theirs before handing over the descriptor, and a
/// Linux daemon's packaging decides between `iproute2`, `systemd-networkd`, and
/// netlink, so those platforms leave it `None`.
pub type InterfaceConfigurer = Arc<dyn Fn(&InterfaceConfig) -> io::Result<()> + Send + Sync>;

/// An opened device, plus whatever this platform needs to configure it.
pub struct OpenedDevice {
    /// The device the host loop pumps.
    pub device: Arc<dyn PacketDevice>,
    /// How to configure the interface, when this process owns that step.
    pub configure: Option<InterfaceConfigurer>,
}

impl std::fmt::Debug for OpenedDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The device is a trait object and the configurator a closure, so this
        // reports what is useful about them rather than their internals.
        f.debug_struct("OpenedDevice")
            .field("name", &self.device.name())
            .field("closed", &self.device.is_closed())
            .field("configures_interface", &self.configure.is_some())
            .finish()
    }
}

/// The tunnel type wintun reports to Windows, which is what appears in the
/// adapter's description. Matches the Dart device's default.
pub const WINTUN_TUNNEL_TYPE: &str = "Sangfor";

/// Opens the device [config] asks for.
///
/// # Errors
///
/// - `PermissionDenied` from wintun when the process is not elevated, or from
///   `/dev/net/tun` without `CAP_NET_ADMIN`. This is the common failure and the
///   message says so, because the underlying Win32 and errno values do not.
/// - `NotFound` when `wintun.dll` is not where the configuration points.
/// - `InvalidInput` for an `fd` device with no descriptor to adopt.
/// - `Unsupported` for a device kind this build does not include, which happens
///   when a configuration written for another platform is used here.
pub fn open(config: &HostConfig) -> io::Result<OpenedDevice> {
    match config.device {
        DeviceKind::Loopback => Ok(OpenedDevice {
            device: Arc::new(LoopbackDevice::new(config.interface.clone())),
            configure: None,
        }),
        #[cfg(windows)]
        DeviceKind::Wintun => open_wintun(config),
        #[cfg(target_os = "linux")]
        DeviceKind::Tun => Ok(OpenedDevice {
            device: Arc::new(sangfor_tun::TunDevice::open(&config.interface)?),
            configure: None,
        }),
        #[cfg(unix)]
        DeviceKind::Fd => open_fd(config),
        #[allow(unreachable_patterns)]
        other => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "this build has no {other:?} device; the platform features are chosen at \
                 compile time, so a configuration for another platform will not run here"
            ),
        )),
    }
}

/// Opens a wintun adapter and returns the `netsh` configurator that goes with
/// it.
#[cfg(windows)]
fn open_wintun(config: &HostConfig) -> io::Result<OpenedDevice> {
    let dll = config
        .wintun_dll
        .as_deref()
        .unwrap_or(Path::new("wintun.dll"));
    let adapter = Arc::new(
        sangfor_tun::WintunDevice::open(&config.interface, WINTUN_TUNNEL_TYPE, Some(dll))
            .map_err(with_elevation_hint)?,
    );
    let configure = {
        let adapter = Arc::clone(&adapter);
        let interface = config.interface.clone();
        Arc::new(move |resolved: &InterfaceConfig| {
            adapter.configure_address(
                &resolved.address,
                &resolved.netmask,
                resolved.gateway.as_deref(),
            )?;
            for route in &resolved.routes {
                let Some((network, prefix)) = crate::config::parse_cidr(route) else {
                    continue;
                };
                adapter.add_route(&sangfor_core::packet::ipv4_text(network), prefix)?;
            }
            adapter.set_dns_servers(&resolved.dns_servers)?;
            let _ = &interface;
            Ok(())
        })
    };
    Ok(OpenedDevice {
        device: adapter as Arc<dyn PacketDevice>,
        configure: Some(configure),
    })
}

/// The wintun error for a process that is not elevated is a bare Win32 code, so
/// the message here says what to actually do about it.
#[cfg(windows)]
fn with_elevation_hint(error: io::Error) -> io::Error {
    if error.kind() == io::ErrorKind::PermissionDenied {
        return io::Error::new(
            error.kind(),
            format!(
                "{error}; creating a wintun adapter requires an elevated process, and the \
                 signed wintun.dll must be staged beside the executable"
            ),
        );
    }
    error
}

/// Adopts the descriptor the platform service handed over.
#[cfg(unix)]
#[allow(unsafe_code)]
fn open_fd(config: &HostConfig) -> io::Result<OpenedDevice> {
    let fd = config
        .fd
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no descriptor to adopt"))?;
    // SAFETY: `fd` came from the host configuration, which the platform service
    // wrote when it opened the descriptor, and that service outlives this
    // process. It is a TUN descriptor open for reading and writing, and it is
    // borrowed rather than owned: the service still expects to close it, so
    // closing it here would leave it holding a stale handle.
    let device = unsafe { sangfor_tun::FdDevice::borrowed(fd, config.interface.clone()) }?;
    Ok(OpenedDevice {
        device: Arc::new(device),
        configure: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_loopback_device_opens_anywhere_without_privileges() {
        // This is what makes the daemon runnable in CI and on a developer
        // machine: the whole tunnel comes up with no driver and no elevation.
        let config = HostConfig {
            device: DeviceKind::Loopback,
            interface: "sangfor-test".to_string(),
            ..HostConfig::default()
        };
        let opened = open(&config).expect("a loopback device needs nothing");
        assert_eq!(opened.device.name(), "sangfor-test");
        assert!(
            opened.configure.is_none(),
            "an in-memory device has no interface to configure"
        );
    }

    #[test]
    fn a_loopback_device_pumps_packets_through_the_trait() {
        // The host loop only ever sees `dyn PacketDevice`, so this is the path
        // that has to work.
        let opened = open(&HostConfig {
            device: DeviceKind::Loopback,
            ..HostConfig::default()
        })
        .expect("opens");
        opened
            .device
            .write_packet(&[0x45, 0x00, 0x00, 0x14])
            .expect("writable");
        assert!(!opened.device.is_closed());
        opened.device.close().expect("closable");
        assert!(opened.device.is_closed());
    }

    #[cfg(windows)]
    #[test]
    fn a_missing_driver_explains_where_to_get_it() {
        let config = HostConfig {
            device: DeviceKind::Wintun,
            wintun_dll: Some(std::path::PathBuf::from("Z:\\absent\\wintun.dll")),
            ..HostConfig::default()
        };
        let error = open(&config).expect_err("the driver is not there");
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(
            error.to_string().contains("wintun.net"),
            "the error should point at the download: {error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_fd_device_without_a_descriptor_is_rejected_before_any_syscall() {
        let config = HostConfig {
            device: DeviceKind::Fd,
            fd: None,
            ..HostConfig::default()
        };
        let error = open(&config).expect_err("nothing to adopt");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
