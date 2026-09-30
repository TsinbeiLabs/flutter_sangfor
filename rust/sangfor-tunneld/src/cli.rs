//! Command-line parsing.
//!
//! Hand-rolled rather than `clap`: the surface is six flags, and a dependency
//! here would be larger than the binary it configures.

use std::path::PathBuf;

use crate::config::{ConfigError, DeviceKind, HostConfig};

/// What the command line asked for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Options {
    /// The session plan document to run first, or `None` to start idle and wait
    /// for a `start` request.
    ///
    /// Starting idle is what a service does: it is installed once, at boot,
    /// with no session, and an app hands it a plan each time the user connects.
    pub plan: Option<PathBuf>,
    /// The host configuration document, or `None` to use the defaults.
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
    /// Install this binary as an elevated logon task, then exit. Needs an
    /// elevated shell once; after that the daemon starts elevated at every
    /// logon with no prompt. See [`crate::service`].
    pub install: bool,
    /// Remove the logon task [`Self::install`] created, then exit.
    pub uninstall: bool,
    /// Print the commands [`Self::install`] and [`Self::uninstall`] would run,
    /// without running them. For a packager that would rather do it itself, and
    /// for anyone who wants to see what they are agreeing to first.
    pub print_install: bool,
    /// Print usage and exit.
    pub help: bool,
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
            "--install" => options.install = true,
            "--uninstall" => options.uninstall = true,
            "--print-install" => options.print_install = true,
            "--plan" | "--config" | "--device" | "--interface" | "--route" => {
                let value = arguments
                    .get(index)
                    .ok_or_else(|| ConfigError::Malformed(format!("{flag} needs a value")))?;
                index += 1;
                match flag {
                    "--plan" => options.plan = Some(document_path(flag, value)?),
                    "--config" => options.config = Some(document_path(flag, value)?),
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

/// Checks a document path, rejecting `-`.
///
/// stdin is the control channel: a daemon with no plan starts idle and waits to
/// be told to run one, and a launcher that piped its plan into stdin has
/// nothing left to pipe commands through. Reading a document from there would
/// quietly take the control channel away, and the two cannot be shared — the
/// reader that gets there first leaves the other an empty stream.
fn document_path(flag: &str, value: &str) -> Result<PathBuf, ConfigError> {
    if value == "-" {
        return Err(ConfigError::Malformed(format!(
            "{flag} cannot read stdin, because stdin is the control channel; write the document \
             to a file and pass its path"
        )));
    }
    Ok(PathBuf::from(value))
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
    sangfor-tunneld [--plan <path>] [--config <path>] [OPTIONS]

OPTIONS:
    --plan <path>        A session plan to run first. Omit it to start idle and
                         wait for a `start` request, which is what a service does.
    --config <path>      The host configuration. Omit it to use the built-in
                         defaults, which the flags below override.
    --device <kind>      wintun | tun | fd | loopback. Overrides the config.
    --interface <name>   The adapter or interface name. Overrides the config.
    --route <cidr>       An extra route to install. May be repeated.
    --dry-run            Use an in-memory device and configure no interface.
    --check              Validate the documents and open the device, then exit.
    --install            Install this binary as an elevated logon task, then exit.
    --uninstall          Remove that logon task, then exit.
    --print-install      Print what --install and --uninstall would run.
    -h, --help           Print this text.

Neither document may be `-`: stdin is the control channel, and a daemon that
read its plan from there would have nothing left to receive commands on.

INSTALLING (Windows):
    Creating the adapter needs an elevated process, and the app is not one.
    --install registers a logon task with /RL HIGHEST, so this binary starts
    elevated at every logon with no prompt, in the user's own session — where
    the app can reach its control socket. Run it once from an elevated shell.
    It is a logon task and not a service on purpose; see the `service` module.

The session plan carries the protocol's inputs and is written by the Dart
control plane. The host configuration carries which device to open and which
routes and DNS servers to install, and is written by whatever launches this
process. See docs/rust-core.md.

LIFETIME:
    The process outlives its sessions. It starts one if --plan was given, then
    stays up serving the control channel until told to stop, so one elevated
    process can serve repeated connect/disconnect cycles.

CONTROL:
    On stdin, and on the loopback socket when the config sets controlPort. One
    JSON object per line, answered by one JSON object per line:
        {\"cmd\":\"ping\"}                          liveness; needs no token
        {\"cmd\":\"status\"}                        counters and state
        {\"cmd\":\"start\",\"planPath\":\"<path>\"}    run a session from a plan
        {\"cmd\":\"stopSession\"}                   end the session, stay up
        {\"cmd\":\"stop\"}                          end the session and exit
    `start` also accepts `configPath`, a host configuration for that session:
    an installed daemon was configured once, but the routes depend on what the
    gateway published this time. Logs go to stderr, or to logPath.

    `start` names documents by path rather than carrying them, so the signing
    key never crosses a channel any local process can join.

EXIT CODES:
    0  stopped cleanly
    1  the process could not run (no device, bad document, no poller)
    2  the last session died; the control plane must log in again";

#[cfg(test)]
mod tests {
    use super::*;

    fn args(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn no_arguments_means_an_idle_daemon_on_the_default_configuration() {
        let options = parse(&[]).expect("parses");
        assert!(
            options.plan.is_none(),
            "no plan: the daemon starts idle and waits to be told"
        );
        assert!(options.config.is_none(), "no document means the defaults");
        assert!(!options.dry_run);
        assert!(!options.help);
    }

    #[test]
    fn a_document_cannot_come_from_stdin_because_stdin_is_the_control_channel() {
        // Reading a plan from stdin would consume the stream the control
        // protocol needs, and the daemon would then be a process nobody can
        // talk to. Refusing says so instead of failing mysteriously later.
        for flag in ["--plan", "--config"] {
            let error = parse(&args(&format!("{flag} -"))).expect_err("rejected");
            let message = error.to_string();
            assert!(message.contains(flag), "{message}");
            assert!(
                message.contains("control channel"),
                "the refusal explains the conflict: {message}"
            );
        }
    }

    #[test]
    fn every_flag_is_read() {
        let options = parse(&args(
            "--plan plan.json --config host.json --device wintun \
             --interface Luotopia --route 10.1.0.0/16 --route 10.9.0.0/16",
        ))
        .expect("parses");
        assert_eq!(options.plan, Some(PathBuf::from("plan.json")));
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
    fn the_install_flags_are_recognised_and_off_by_default() {
        let defaults = parse(&[]).expect("parses");
        assert!(!defaults.install && !defaults.uninstall && !defaults.print_install);
        assert!(parse(&args("--install")).expect("parses").install);
        assert!(parse(&args("--uninstall")).expect("parses").uninstall);
        assert!(
            parse(&args("--print-install"))
                .expect("parses")
                .print_install
        );
    }

    #[test]
    fn print_install_is_not_mistaken_for_install() {
        // One is a prefix of the other, and a parser that matched on prefixes
        // would run the installer when asked to show it.
        let options = parse(&args("--print-install")).expect("parses");
        assert!(options.print_install);
        assert!(!options.install, "printing a command must not run it");
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
            "--install",
            "--uninstall",
            "--print-install",
            "--help",
        ] {
            assert!(USAGE.contains(flag), "{flag} is undocumented");
        }
        // Asserted in their wire form: `stop` is a substring of `stopSession`,
        // so matching the bare verb would pass whether or not it was documented.
        for command in [
            r#""cmd":"ping""#,
            r#""cmd":"status""#,
            r#""cmd":"start""#,
            r#""cmd":"stopSession""#,
            r#""cmd":"stop""#,
        ] {
            assert!(
                USAGE.contains(command),
                "the {command} command is undocumented"
            );
        }
        for field in ["planPath", "configPath"] {
            assert!(
                USAGE.contains(field),
                "how `start` names its documents is documented"
            );
        }
    }

    #[test]
    fn the_usage_text_says_the_process_outlives_its_sessions() {
        // The one thing a reader most needs to know and would otherwise get
        // wrong: sending `stopSession` does not end the daemon, and a daemon
        // with no `--plan` is not broken.
        assert!(USAGE.contains("outlives its sessions"), "{USAGE}");
    }

    #[test]
    fn the_usage_text_says_why_the_install_is_a_task_and_not_a_service() {
        // Somebody will ask. The answer is not obvious and the wrong guess —
        // `sc create` — fails in a way that looks like a bug in this binary.
        assert!(USAGE.contains("logon task"), "{USAGE}");
        assert!(USAGE.contains("not a service"), "{USAGE}");
    }
}
