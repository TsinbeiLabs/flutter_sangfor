//! Command-line parsing.
//!
//! Hand-rolled rather than `clap`: the surface is six flags, and a dependency
//! here would be larger than the binary it configures.

use std::path::PathBuf;

use crate::config::{ConfigError, DeviceKind, HostConfig};

/// What the command line asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// The session plan document. `-` reads stdin.
    pub plan: PathBuf,
    /// The host configuration document, or `None` to use the defaults. `-`
    /// reads stdin, which is only legal when the plan does not.
    pub config: Option<PathBuf>,
    /// Overrides the document's `device`.
    pub device: Option<DeviceKind>,
    /// Overrides the document's `interface`.
    pub interface: Option<String>,
    /// Additional routes, appended to the document's.
    pub routes: Vec<String>,
    /// Run against an in-memory device and skip interface configuration. The
    /// tunnel comes up and can be exercised with no driver and no privileges.
    pub dry_run: bool,
    /// Validate both documents and open the device, then exit without running
    /// the tunnel. A service wrapper uses this to answer "can this even start"
    /// before it commits to a session.
    pub check: bool,
    /// Print usage and exit.
    pub help: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            plan: PathBuf::from("-"),
            config: None,
            device: None,
            interface: None,
            routes: Vec::new(),
            dry_run: false,
            check: false,
            help: false,
        }
    }
}

impl Options {
    /// Applies the command-line overrides to [config].
    ///
    /// Flags win over the document, so a launcher can keep one config file and
    /// still vary the interface per instance.
    #[must_use]
    pub fn apply_to(&self, config: HostConfig) -> HostConfig {
        HostConfig {
            device: if self.dry_run {
                DeviceKind::Loopback
            } else {
                self.device.unwrap_or(config.device)
            },
            interface: self.interface.clone().unwrap_or(config.interface),
            routes: {
                let mut routes = config.routes;
                routes.extend(self.routes.iter().cloned());
                routes
            },
            ..config
        }
    }
}

/// Parses [arguments], which must not include the program name.
///
/// # Errors
///
/// Returns the first problem, ready to print next to [`USAGE`].
pub fn parse(arguments: &[String]) -> Result<Options, ConfigError> {
    let mut options = Options::default();
    let mut index = 0;
    while index < arguments.len() {
        let flag = arguments[index].as_str();
        index += 1;
        match flag {
            "--help" | "-h" => options.help = true,
            "--dry-run" => options.dry_run = true,
            "--check" => options.check = true,
            "--plan" | "--config" | "--device" | "--interface" | "--route" => {
                let value = arguments
                    .get(index)
                    .ok_or_else(|| ConfigError::Malformed(format!("{flag} needs a value")))?;
                index += 1;
                match flag {
                    "--plan" => options.plan = PathBuf::from(value),
                    "--config" => options.config = Some(PathBuf::from(value)),
                    "--device" => options.device = Some(parse_device(value)?),
                    "--interface" => options.interface = Some(value.clone()),
                    _ => options.routes.push(value.clone()),
                }
            }
            other => {
                return Err(ConfigError::Malformed(format!(
                    "{other:?} is not a recognised flag"
                )))
            }
        }
    }
    Ok(options)
}

fn parse_device(text: &str) -> Result<DeviceKind, ConfigError> {
    match text {
        "wintun" => Ok(DeviceKind::Wintun),
        "tun" => Ok(DeviceKind::Tun),
        "fd" => Ok(DeviceKind::Fd),
        "loopback" => Ok(DeviceKind::Loopback),
        other => Err(ConfigError::Malformed(format!(
            "{other:?} is not a device; expected wintun, tun, fd, or loopback"
        ))),
    }
}

/// The usage text.
pub const USAGE: &str = "\
sangfor-tunneld -- run the aTrust data plane in its own process

USAGE:
    sangfor-tunneld --plan <path|-> [--config <path|->] [OPTIONS]

OPTIONS:
    --plan <path>        The session plan from the control plane. `-` is stdin.
    --config <path>      The host configuration. `-` is stdin. Omit it to use
                         the built-in defaults, which the flags below override.
    --device <kind>      wintun | tun | fd | loopback. Overrides the config.
    --interface <name>   The adapter or interface name. Overrides the config.
    --route <cidr>       An extra route to install. May be repeated.
    --dry-run            Use an in-memory device and configure no interface.
    --check              Validate the documents and open the device, then exit.
    -h, --help           Print this text.

The session plan carries the protocol's inputs and is written by the Dart
control plane. The host configuration carries which device to open and which
routes and DNS servers to install, and is written by whatever launches this
process. See docs/rust-core.md.

CONTROL:
    With stdin open, one JSON object per line:
        {\"cmd\":\"status\"}   counters and state
        {\"cmd\":\"ping\"}    liveness
        {\"cmd\":\"stop\"}    end the session and exit
    Replies are one JSON object per line on stdout; logs go to stderr.

EXIT CODES:
    0  stopped cleanly
    1  the process could not run (no device, bad document, no poller)
    2  the session died; the control plane must log in again";

#[cfg(test)]
mod tests {
    use super::*;

    fn args(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn no_arguments_means_both_documents_come_from_stdin() {
        let options = parse(&[]).expect("parses");
        assert_eq!(options.plan, PathBuf::from("-"));
        assert!(options.config.is_none(), "no document means the defaults");
        assert!(!options.dry_run);
        assert!(!options.help);
    }

    #[test]
    fn every_flag_is_read() {
        let options = parse(&args(
            "--plan plan.json --config host.json --device wintun \
             --interface Luotopia --route 10.1.0.0/16 --route 10.9.0.0/16",
        ))
        .expect("parses");
        assert_eq!(options.plan, PathBuf::from("plan.json"));
        assert_eq!(options.config, Some(PathBuf::from("host.json")));
        assert_eq!(options.device, Some(DeviceKind::Wintun));
        assert_eq!(options.interface.as_deref(), Some("Luotopia"));
        assert_eq!(options.routes, vec!["10.1.0.0/16", "10.9.0.0/16"]);
    }

    #[test]
    fn a_flag_without_a_value_is_an_error_naming_the_flag() {
        let error = parse(&args("--interface")).expect_err("no value");
        assert!(error.to_string().contains("--interface"), "{error}");
        assert!(error.to_string().contains("needs a value"), "{error}");
    }

    #[test]
    fn an_unknown_flag_is_rejected_rather_than_ignored() {
        let error = parse(&args("--planes plan.json")).expect_err("typo");
        assert!(
            error.to_string().contains("not a recognised flag"),
            "{error}"
        );
    }

    #[test]
    fn an_unknown_device_is_rejected_with_the_valid_choices() {
        let error = parse(&args("--device utun")).expect_err("no such device");
        let message = error.to_string();
        assert!(message.contains("wintun"), "{message}");
        assert!(message.contains("loopback"), "{message}");
    }

    #[test]
    fn check_is_a_flag_of_its_own() {
        assert!(parse(&args("--check")).expect("parses").check);
        assert!(!parse(&[]).expect("parses").check);
    }

    #[test]
    fn help_is_recognised_in_both_spellings() {
        assert!(parse(&args("--help")).expect("parses").help);
        assert!(parse(&args("-h")).expect("parses").help);
    }

    #[test]
    fn a_dry_run_forces_the_loopback_device() {
        // The point of `--dry-run` is that it works with no driver and no
        // elevation, so it must win over both the document and `--device`.
        let options = parse(&args("--dry-run --device wintun")).expect("parses");
        let config = options.apply_to(HostConfig {
            device: DeviceKind::Tun,
            ..HostConfig::default()
        });
        assert_eq!(config.device, DeviceKind::Loopback);
    }

    #[test]
    fn flags_win_over_the_document() {
        let options = parse(&args("--interface Overridden --route 192.0.2.0/24")).expect("parses");
        let config = options.apply_to(HostConfig {
            interface: "FromDocument".to_string(),
            routes: vec!["10.0.0.0/8".to_string()],
            dns_servers: vec!["10.0.0.53".to_string()],
            ..HostConfig::default()
        });
        assert_eq!(config.interface, "Overridden");
        assert_eq!(
            config.routes,
            vec!["10.0.0.0/8".to_string(), "192.0.2.0/24".to_string()],
            "command-line routes are appended, not substituted"
        );
        assert_eq!(
            config.dns_servers,
            vec!["10.0.0.53".to_string()],
            "untouched fields keep the document's values"
        );
    }

    #[test]
    fn the_usage_text_documents_every_flag() {
        for flag in [
            "--plan",
            "--config",
            "--device",
            "--interface",
            "--route",
            "--dry-run",
            "--check",
            "--help",
        ] {
            assert!(USAGE.contains(flag), "{flag} is undocumented");
        }
        for command in ["status", "ping", "stop"] {
            assert!(
                USAGE.contains(command),
                "the {command} command is undocumented"
            );
        }
    }
}
