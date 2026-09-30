//! Installing the daemon so it runs elevated without prompting every time.
//!
//! Creating a wintun adapter needs an elevated process, and the app runs
//! `asInvoker`. So *something* elevated has to own the device. This module
//! generates the commands for that; it does not run them, because running them
//! needs the elevation it exists to obtain.
//!
//! # A logon task, not a service
//!
//! `sc create` is the obvious answer and it is the wrong one here, for a reason
//! that has nothing to do with effort:
//!
//! - A service binary must call `StartServiceCtrlDispatcher` and report
//!   `SERVICE_RUNNING` to the SCM, or the SCM kills it after roughly thirty
//!   seconds with error 1053. That is new platform code whose only test is
//!   installing a service.
//! - A service runs as LocalSystem, in session 0. The loopback control socket
//!   cannot identify its peer, so the token is the only gate — and a token a
//!   LocalSystem service can read is a token every user on the machine can
//!   read, because the service is installed once for all of them.
//!
//! A logon task with `/RL HIGHEST` avoids both. It runs in the *user's* session,
//! elevated, so `127.0.0.1` is the loopback the app is already on and the
//! control protocol works unchanged. Its configuration lives in that user's
//! profile, so the token in it is readable by that user and by administrators —
//! which is a real boundary rather than a decorative one. And it needs no new
//! code in the daemon at all: the task starts the same binary with the same
//! flags, and the daemon's stdin is simply closed, which [`crate::runtime`]
//! already handles.
//!
//! What it does not give you is a tunnel that outlives logoff. For a VPN that a
//! single signed-in user drives, that is the right trade.
//!
//! # What is and is not tested
//!
//! [`Install::install`] and its siblings return command lines as data, and the
//! tests assert on that data: the task name, the elevated flag, the quoting of
//! a path with spaces in it, the document written beside the binary. Running
//! them requires an elevated shell and a machine willing to have a logon task
//! installed, so [`CommandLine::run`] is a thin wrapper whose only job is to
//! hand `schtasks` an exit code to interpret — see [`explain`].

use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitStatus};

use crate::config::{DeviceKind, HostConfig};

/// The program that creates, queries, and removes a logon task.
pub const SCHTASKS: &str = "schtasks";

/// The default task name.
pub const DEFAULT_NAME: &str = "SangforTunnel";

/// The default loopback port for an installed daemon.
///
/// Fixed, not ephemeral: a child process reports its port in its log, which the
/// launcher reads from a pipe it owns. An installed daemon's log is a file
/// nobody is watching, so the app has to know where to connect.
pub const DEFAULT_CONTROL_PORT: u16 = 7166;

/// A command line, as data rather than as a side effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandLine {
    /// The program to run.
    pub program: String,
    /// Its arguments, unquoted; [`Self::render`] and [`Self::run`] quote them.
    pub arguments: Vec<String>,
}

impl CommandLine {
    /// Renders the command the way Windows would parse it back.
    ///
    /// The rules are MSVCRT's: an argument is quoted if it holds a space, a
    /// tab, or a quote, and an embedded quote becomes `\"`. Getting this wrong
    /// is invisible until a path with a space in it — which is every path under
    /// `C:\Program Files` — arrives at `schtasks` truncated at the first one.
    #[must_use]
    pub fn render(&self) -> String {
        let mut parts = vec![quote(&self.program)];
        parts.extend(self.arguments.iter().map(|argument| quote(argument)));
        parts.join(" ")
    }

    /// Runs the command and waits for it.
    ///
    /// # Errors
    ///
    /// Returns the spawn failure, which for `schtasks` almost always means the
    /// process could not be started at all. A non-zero exit status is *not* an
    /// error here; pass it to [`explain`], which knows what `schtasks` means by
    /// each of them.
    pub fn run(&self) -> std::io::Result<ExitStatus> {
        ProcessCommand::new(&self.program)
            .args(&self.arguments)
            .status()
    }
}

/// Quotes one argument for a Windows command line, by MSVCRT's rules.
///
/// The rules are not "wrap it in quotes": a run of backslashes immediately
/// before a quote is half-consumed escaping it, so a path that *ends* in a
/// backslash would otherwise swallow the closing quote and glue the next
/// argument onto it. Every backslash in such a run is doubled, and a literal
/// quote is preceded by one more.
///
/// Getting this wrong is invisible until a path with a space in it — which is
/// every path under `C:\Program Files` — arrives at `schtasks` truncated at the
/// first one.
fn quote(argument: &str) -> String {
    if !argument.is_empty()
        && !argument.contains(' ')
        && !argument.contains('\t')
        && !argument.contains('"')
    {
        return argument.to_string();
    }
    let mut quoted = String::with_capacity(argument.len() + 2);
    quoted.push('"');
    let mut backslashes = 0usize;
    for character in argument.chars() {
        match character {
            '\\' => backslashes += 1,
            '"' => {
                for _ in 0..backslashes * 2 {
                    quoted.push('\\');
                }
                backslashes = 0;
                quoted.push('\\');
                quoted.push('"');
            }
            other => {
                for _ in 0..backslashes {
                    quoted.push('\\');
                }
                backslashes = 0;
                quoted.push(other);
            }
        }
    }
    // A trailing run has to be doubled too, or it escapes the closing quote.
    for _ in 0..backslashes * 2 {
        quoted.push('\\');
    }
    quoted.push('"');
    quoted
}

/// Parses a Windows command line back into argv. The inverse of [`quote`].
///
/// Test-only: nothing in the daemon reads a command line, it only writes them.
/// It lives here rather than in a dependency because the alternative is trusting
/// the quoting function to a parser that agrees with it by construction, which
/// proves nothing — and quoting is the kind of thing that is wrong only for the
/// paths a developer does not have.
#[cfg(test)]
fn split_arguments(rendered: &str) -> Vec<String> {
    let mut argv = Vec::new();
    let mut current = String::new();
    let mut in_argument = false;
    let mut quoted = false;
    let mut backslashes = 0usize;

    let flush_backslashes = |current: &mut String, count: usize| {
        for _ in 0..count {
            current.push('\\');
        }
    };
    for character in rendered.chars() {
        match character {
            '\\' => {
                backslashes += 1;
                in_argument = true;
            }
            '"' => {
                // Half the pending run is literal; an odd count means the last
                // one escaped this quote, so it does not toggle the state.
                flush_backslashes(&mut current, backslashes / 2);
                if backslashes % 2 == 1 {
                    current.push('"');
                } else {
                    quoted = !quoted;
                }
                backslashes = 0;
                in_argument = true;
            }
            ' ' if !quoted => {
                flush_backslashes(&mut current, backslashes);
                backslashes = 0;
                if in_argument {
                    argv.push(std::mem::take(&mut current));
                    in_argument = false;
                }
            }
            other => {
                flush_backslashes(&mut current, backslashes);
                backslashes = 0;
                current.push(other);
                in_argument = true;
            }
        }
    }
    flush_backslashes(&mut current, backslashes);
    if in_argument {
        argv.push(current);
    }
    argv
}

/// An installed daemon: where its binary and configuration live, and what to
/// run to put it there.
///
/// Build one with [`Install::new`], write [`Install::host_config`] to
/// [`Install::host_config_path`], then run [`Install::install`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Install {
    /// The task name, which is also what `schtasks /Query` looks up.
    pub name: String,
    /// The daemon binary.
    pub executable: PathBuf,
    /// Where the host configuration and the log live.
    ///
    /// In the user's profile rather than `ProgramData`: the configuration holds
    /// the control token, and a file every user can read is not a secret.
    pub directory: PathBuf,
    /// The loopback port the daemon serves its control protocol on.
    pub control_port: u16,
    /// The interface name to give the adapter.
    pub interface: String,
    /// The packet device.
    pub device: DeviceKind,
}

impl Install {
    /// An installation for [executable], keeping its state in [directory].
    #[must_use]
    pub fn new(executable: impl Into<PathBuf>, directory: impl Into<PathBuf>) -> Self {
        Self {
            name: DEFAULT_NAME.to_string(),
            executable: executable.into(),
            directory: directory.into(),
            control_port: DEFAULT_CONTROL_PORT,
            interface: "Luotopia".to_string(),
            device: DeviceKind::Wintun,
        }
    }

    /// The directory an installed daemon should keep its state in: the user's
    /// own, so the control token in it is not readable by every account.
    ///
    /// # Errors
    ///
    /// Returns an error naming the variable that was missing, which on Windows
    /// means the environment is not a normal user session.
    pub fn default_directory() -> Result<PathBuf, String> {
        // `LOCALAPPDATA` rather than `APPDATA`: the configuration names a
        // per-machine adapter and a loopback port, and roaming it to another
        // machine would have it fight whatever is installed there.
        let base = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .ok_or_else(|| {
                "LOCALAPPDATA is not set, so there is no per-user directory to install into"
                    .to_string()
            })?;
        Ok(base.join("sangfor-tunneld"))
    }

    /// Where the host configuration goes.
    #[must_use]
    pub fn host_config_path(&self) -> PathBuf {
        self.directory.join("host.json")
    }

    /// Where the daemon's log goes.
    ///
    /// A file, not stderr: a task has no console, and without this the only
    /// record of why a session failed is nowhere.
    #[must_use]
    pub fn log_path(&self) -> PathBuf {
        self.directory.join("tunneld.log")
    }

    /// The host configuration document to write to [`Self::host_config_path`].
    ///
    /// [token] must be unpredictable: it is the only thing between a local
    /// process and the ability to start, stop, and read a tunnel. It is written
    /// to a file in the user's profile, so its strength is bounded by that
    /// file's permissions — which is a real boundary for a per-user install and
    /// would not be one for a machine-wide service.
    ///
    /// The document deliberately carries no routes. Which destinations belong in
    /// the tunnel depends on what the gateway published for a session, so the
    /// app supplies them per `start` rather than freezing one user's last
    /// connection into the installation.
    #[must_use]
    pub fn host_config(&self, token: &str) -> HostConfig {
        HostConfig {
            device: self.device,
            interface: self.interface.clone(),
            control_port: Some(self.control_port),
            control_token: Some(token.to_string()),
            log_path: Some(self.log_path()),
            // Recorded so a daemon started from somewhere else can say so, and
            // so an app that cannot reach it can tell "the binary moved" from
            // "the task has not run yet". Without it an app update that
            // relocates the executable leaves a logon task pointing at nothing,
            // and the only symptom is a tunnel that stops working at logon.
            installed_from: Some(self.executable.clone()),
            ..HostConfig::default()
        }
    }

    /// The arguments the task runs the daemon with.
    #[must_use]
    pub fn daemon_arguments(&self) -> Vec<String> {
        vec![
            "--config".to_string(),
            self.host_config_path().display().to_string(),
        ]
    }

    /// The `/TR` value: the daemon's command line, as one string.
    ///
    /// Quoted here rather than left to `schtasks`, because `/TR` takes the
    /// whole command line as a single argument and anything unquoted inside it
    /// is parsed by the task scheduler's own rules.
    #[must_use]
    pub fn task_command_line(&self) -> String {
        let mut parts = vec![quote(&self.executable.display().to_string())];
        parts.extend(
            self.daemon_arguments()
                .iter()
                .map(|argument| quote(argument)),
        );
        parts.join(" ")
    }

    /// Creates the logon task, replacing one of the same name.
    ///
    /// Needs an elevated shell once. After that the daemon starts elevated at
    /// every logon with no prompt, which is the entire point.
    #[must_use]
    pub fn install(&self) -> CommandLine {
        CommandLine {
            program: SCHTASKS.to_string(),
            arguments: vec![
                "/Create".to_string(),
                "/TN".to_string(),
                self.name.clone(),
                "/TR".to_string(),
                self.task_command_line(),
                "/SC".to_string(),
                "ONLOGON".to_string(),
                // The flag that makes it elevated. Without it the task runs
                // exactly as unelevated as the app does, and opening the
                // adapter fails the same way it does today.
                "/RL".to_string(),
                "HIGHEST".to_string(),
                // Replace an existing task of this name, so re-installing after
                // an upgrade is one command rather than a delete and a create.
                "/F".to_string(),
            ],
        }
    }

    /// Removes the logon task. Does not stop a daemon that is already running;
    /// send it `stop` over the control socket first, or end the task with
    /// [`Self::end`].
    #[must_use]
    pub fn uninstall(&self) -> CommandLine {
        CommandLine {
            program: SCHTASKS.to_string(),
            arguments: vec![
                "/Delete".to_string(),
                "/TN".to_string(),
                self.name.clone(),
                "/F".to_string(),
            ],
        }
    }

    /// Asks whether the task is installed.
    #[must_use]
    pub fn query(&self) -> CommandLine {
        CommandLine {
            program: SCHTASKS.to_string(),
            arguments: vec!["/Query".to_string(), "/TN".to_string(), self.name.clone()],
        }
    }

    /// Starts the task now rather than waiting for the next logon.
    ///
    /// This is how the app brings the daemon up on the first connect after an
    /// install: the task exists but has not run yet, and asking the user to log
    /// off would be an absurd instruction.
    #[must_use]
    pub fn start_now(&self) -> CommandLine {
        CommandLine {
            program: SCHTASKS.to_string(),
            arguments: vec!["/Run".to_string(), "/TN".to_string(), self.name.clone()],
        }
    }

    /// Ends the task's running instance.
    ///
    /// A last resort: it kills the daemon rather than letting it tear the
    /// interface down, which can leave the adapter behind. Send `stop` over the
    /// control socket when the daemon is still answering.
    #[must_use]
    pub fn end(&self) -> CommandLine {
        CommandLine {
            program: SCHTASKS.to_string(),
            arguments: vec!["/End".to_string(), "/TN".to_string(), self.name.clone()],
        }
    }

    /// Writes [`Self::host_config`], creating [`Self::directory`] first.
    ///
    /// # Errors
    ///
    /// Returns the write failure. The directory is in the user's profile, so
    /// this needs no elevation — unlike [`Self::install`].
    pub fn write_host_config(&self, token: &str) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.directory)?;
        let document = serde_json::to_vec_pretty(&self.host_config(token))
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        std::fs::write(self.host_config_path(), document)
    }
}

/// Turns a `schtasks` exit status into something a user can act on.
///
/// `schtasks` writes its own diagnostics to stdout and reports a bare code, so
/// the two failures worth distinguishing — "you are not elevated" and "the task
/// is already there" — otherwise look identical to the caller.
pub fn explain(status: ExitStatus, command: &CommandLine) -> Result<(), String> {
    if status.success() {
        return Ok(());
    }
    let code = status.code();
    let rendered = command.render();
    let hint = match code {
        // ERROR_ACCESS_DENIED. `schtasks /Create ... /RL HIGHEST` refuses from
        // an unelevated shell, which is the ordinary way to hit this.
        Some(1) => "this needs an elevated shell: run it from a terminal started as administrator",
        Some(5) => "access was denied; an elevated shell is required to create a logon task",
        // The task is not there, which for `/Delete` and `/End` means there was
        // nothing to do.
        Some(267011) | Some(2) => "no task by that name is installed",
        _ => "see the schtasks output above",
    };
    Err(format!("{rendered} failed ({code:?}): {hint}"))
}

/// The length in bytes of a generated control token.
const TOKEN_BYTES: usize = 32;

/// Generates a control token for an installed daemon.
///
/// 32 bytes from the operating system's CSPRNG, hex encoded. Unpredictable
/// rather than merely unique: the token is the only thing between a local
/// process and the ability to start, stop, and read a tunnel, so deriving it
/// from anything the caller already has — a machine name, a timestamp, a user
/// name — would make it something an attacker can guess instead of steal.
///
/// # Errors
///
/// Returns the reason the platform's random source failed, which in practice
/// means the process is somewhere with no entropy available.
pub fn generate_token() -> Result<String, String> {
    let mut bytes = [0u8; TOKEN_BYTES];
    getrandom::getrandom(&mut bytes)
        .map_err(|error| format!("the operating system would not provide random bytes: {error}"))?;
    Ok(hex(&bytes))
}

/// Lowercase hex, without a formatting dependency.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(DIGITS[usize::from(byte >> 4)] as char);
        text.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    text
}

/// The install directory to use when the caller has no opinion.
///
/// Falls back to a directory beside the executable, which is wrong for the
/// token but keeps the daemon runnable when there is no user profile — a
/// service account, or a test.
#[must_use]
pub fn directory_for(executable: &Path) -> PathBuf {
    Install::default_directory().unwrap_or_else(|_| {
        executable
            .parent()
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
            .join("sangfor-tunneld")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn install() -> Install {
        Install {
            name: "SangforTunnel".to_string(),
            executable: PathBuf::from(r"C:\Program Files\Luotopia\sangfor-tunneld.exe"),
            directory: PathBuf::from(r"C:\Users\alice\AppData\Local\sangfor-tunneld"),
            control_port: 7166,
            interface: "Luotopia".to_string(),
            device: DeviceKind::Wintun,
        }
    }

    #[test]
    fn an_argument_with_a_space_is_quoted_and_one_without_is_not() {
        assert_eq!(quote("schtasks"), "schtasks");
        assert_eq!(quote("/TN"), "/TN");
        assert_eq!(
            quote(r"C:\Program Files\x.exe"),
            r#""C:\Program Files\x.exe""#,
            "every install path has a space in it"
        );
        assert_eq!(quote("a\tb"), "\"a\tb\"");
        assert_eq!(quote(""), "\"\"", "an empty argument still needs quotes");
    }

    #[test]
    fn a_quote_inside_an_argument_is_escaped() {
        // The `/TR` value is a command line inside an argument, so it is full
        // of quotes. Passing it through unescaped would end the argument at the
        // first one and hand `schtasks` the tail as separate flags.
        assert_eq!(
            quote(r#""C:\x.exe" --config y"#),
            r#""\"C:\x.exe\" --config y""#
        );
    }

    #[test]
    fn a_trailing_backslash_does_not_escape_the_closing_quote() {
        // The case naive quoting gets wrong. One backslash before the closing
        // quote escapes it, so the argument never ends and the next one is
        // swallowed into it — a task whose command line is missing its flags.
        let quoted = quote(r"C:\Program Files\Luotopia");
        assert_eq!(quoted, r#""C:\Program Files\Luotopia""#);

        let quoted = quote(r"C:\Program Files\Luotopia\");
        assert_eq!(
            quoted, r#""C:\Program Files\Luotopia\\""#,
            "the run is doubled so the quote still closes the argument"
        );
        assert_eq!(
            split_arguments(&format!("{quoted} --config x")),
            vec![
                r"C:\Program Files\Luotopia\".to_string(),
                "--config".to_string(),
                "x".to_string()
            ],
            "and the next argument survives"
        );
    }

    #[test]
    fn backslashes_that_are_not_before_a_quote_stay_literal() {
        // Windows paths are mostly backslashes, and doubling all of them would
        // produce a path the filesystem has never heard of.
        assert_eq!(
            split_arguments(&quote(r"C:\a\b c\d")),
            vec![r"C:\a\b c\d".to_string()]
        );
    }

    #[test]
    fn the_task_runs_the_daemon_against_its_configuration() {
        // The expectation is built with the same `PathBuf::join` the code uses,
        // so this asserts the *quoting* — which is the subject — rather than
        // which separator the host platform happens to compile with. The exact
        // Windows spelling is pinned separately, on Windows.
        let install = install();
        let config = install.host_config_path().display().to_string();
        assert_eq!(
            install.task_command_line(),
            format!(
                r#""C:\Program Files\Luotopia\sangfor-tunneld.exe" --config {}"#,
                quote(&config)
            ),
            "the executable is quoted because its path has a space"
        );
    }

    #[cfg(windows)]
    #[test]
    fn the_install_paths_are_spelled_the_way_windows_spells_them() {
        // Pinned only where the module is used: `--install` refuses to run
        // anywhere else, and `PathBuf::join` produces a forward slash on a host
        // that is not Windows. Asserting the separator everywhere would fail on
        // every Linux runner for a reason that has nothing to do with the code.
        assert_eq!(
            install().task_command_line(),
            r#""C:\Program Files\Luotopia\sangfor-tunneld.exe" --config "#.to_string()
                + r"C:\Users\alice\AppData\Local\sangfor-tunneld\host.json"
        );
        assert_eq!(
            install().log_path(),
            PathBuf::from(r"C:\Users\alice\AppData\Local\sangfor-tunneld\tunneld.log")
        );
        assert_eq!(
            install().host_config_path(),
            PathBuf::from(r"C:\Users\alice\AppData\Local\sangfor-tunneld\host.json")
        );
    }

    #[test]
    fn a_user_profile_with_a_space_in_it_is_quoted_too() {
        // `C:\Users\John Smith\...` is ordinary, and an unquoted path like that
        // arrives at the daemon as two arguments: `C:\Users\John` and
        // `Smith\AppData\...`. The task then starts a daemon with no
        // configuration, which fails at the next logon with nothing on screen.
        let install = Install {
            directory: PathBuf::from(r"C:\Users\John Smith\AppData\Local\sangfor-tunneld"),
            ..install()
        };
        let expected = quote(&install.host_config_path().display().to_string());
        assert!(
            expected.starts_with('"') && expected.ends_with('"'),
            "the path is quoted because it has a space in it: {expected}"
        );
        assert!(
            install.task_command_line().contains(&expected),
            "the task command carries it: {}",
            install.task_command_line()
        );
    }

    #[test]
    fn the_install_command_creates_an_elevated_logon_task() {
        let command = install().install();
        assert_eq!(command.program, "schtasks");
        let arguments = command.arguments.join(" ");
        for expected in [
            "/Create",
            "/TN SangforTunnel",
            "/SC ONLOGON",
            "/RL HIGHEST",
            "/F",
        ] {
            assert!(
                arguments.contains(expected),
                "{expected} is missing from {arguments}"
            );
        }
        assert!(
            arguments.contains("/TR"),
            "the task is told what to run: {arguments}"
        );
    }

    #[test]
    fn the_elevated_flag_is_the_whole_point_and_is_not_optional() {
        // Without `/RL HIGHEST` the task runs as unelevated as the app does and
        // opening the adapter fails exactly the way it fails today. This is the
        // one argument that justifies the module existing.
        assert!(install()
            .install()
            .arguments
            .contains(&"HIGHEST".to_string()));
    }

    #[test]
    fn reinstalling_replaces_the_task_rather_than_failing() {
        // An upgrade has to be one command. Without `/F`, `schtasks /Create`
        // prompts to confirm the overwrite — and a prompt nobody is watching is
        // a hung installer.
        assert!(install().install().arguments.contains(&"/F".to_string()));
    }

    #[test]
    fn uninstall_query_start_and_end_all_name_the_task() {
        let install = install();
        for command in [
            install.uninstall(),
            install.query(),
            install.start_now(),
            install.end(),
        ] {
            let arguments = command.arguments.join(" ");
            assert!(
                arguments.contains("/TN SangforTunnel"),
                "{arguments} does not name the task"
            );
        }
        assert!(install
            .uninstall()
            .arguments
            .contains(&"/Delete".to_string()));
        assert!(install.query().arguments.contains(&"/Query".to_string()));
        assert!(install.start_now().arguments.contains(&"/Run".to_string()));
        assert!(install.end().arguments.contains(&"/End".to_string()));
    }

    #[test]
    fn the_configuration_names_a_fixed_port_and_a_log_file() {
        // A child process reports an ephemeral port on a pipe its launcher
        // owns. An installed daemon's stderr goes nowhere, so the app has to
        // know the port in advance and the log has to be a file.
        let config = install().host_config("s3cret-token");
        assert_eq!(config.control_port, Some(7166));
        assert_eq!(config.control_token.as_deref(), Some("s3cret-token"));
        // Compared against the same join the code uses; the literal Windows
        // spelling is pinned in the `#[cfg(windows)]` test above.
        assert_eq!(config.log_path, Some(install().log_path()));
        assert_eq!(config.device, DeviceKind::Wintun);
        assert_eq!(config.interface, "Luotopia");
        assert_eq!(
            config.installed_from,
            Some(install().executable.clone()),
            "the configuration records which binary it was installed from, so a \
             relocated executable can be noticed instead of failing silently at \
             the next logon"
        );
    }

    #[test]
    fn the_installed_configuration_carries_no_routes() {
        // Routes describe a session, and an installation outlives every
        // session. Freezing one user's last connection into the install would
        // silently tunnel the wrong destinations for everybody after it.
        let config = install().host_config("s3cret-token");
        assert!(config.routes.is_empty());
        assert!(config.dns_servers.is_empty());
        assert!(
            config.address.is_none(),
            "the gateway assigns the address per session"
        );
    }

    #[test]
    fn the_installed_configuration_survives_a_round_trip_through_its_document() {
        // `write_host_config` serializes it and the daemon parses it back with
        // `deny_unknown_fields`, so a field the two disagree about is a daemon
        // that will not start.
        let original = install().host_config("s3cret-token");
        let document = serde_json::to_vec(&original).expect("serializes");
        let parsed = HostConfig::decode(&document).expect("the daemon accepts its own document");
        assert_eq!(parsed, original);
    }

    #[test]
    fn writing_the_configuration_creates_the_directory() {
        let directory =
            std::env::temp_dir().join(format!("sangfor-install-{}-nested", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        let install = Install {
            directory: directory.clone(),
            ..install()
        };
        install
            .write_host_config("s3cret-token")
            .expect("the configuration writes");
        let written = std::fs::read(install.host_config_path()).expect("readable");
        let _ = std::fs::remove_dir_all(&directory);
        assert!(
            String::from_utf8_lossy(&written).contains("s3cret-token"),
            "the token is in the document the daemon will read"
        );
    }

    #[test]
    fn a_successful_command_needs_no_explanation() {
        let command = install().query();
        assert!(explain(exit(0), &command).is_ok());
    }

    #[test]
    fn a_refused_install_says_that_it_needs_an_elevated_shell() {
        // The single most likely failure, and the one whose raw exit code says
        // least: an unelevated shell running `schtasks /Create ... /RL HIGHEST`.
        let error = explain(exit(1), &install().install()).expect_err("refused");
        assert!(error.contains("elevated"), "{error}");
        assert!(
            error.contains("administrator"),
            "and says what to do about it: {error}"
        );
    }

    #[test]
    fn a_missing_task_is_reported_as_such() {
        let error = explain(exit(2), &install().uninstall()).expect_err("nothing to delete");
        assert!(error.contains("no task by that name"), "{error}");
    }

    #[test]
    fn an_unexplained_failure_still_shows_the_command() {
        // A user pasting this into a report needs to see what was run.
        let error = explain(exit(87), &install().install()).expect_err("failed");
        assert!(error.contains("schtasks"), "{error}");
        assert!(error.contains("SangforTunnel"), "{error}");
        assert!(error.contains("87"), "the code is in it: {error}");
    }

    #[test]
    fn the_rendered_command_is_what_a_shell_would_parse_back() {
        let rendered = install().install().render();
        assert!(
            rendered.starts_with("schtasks /Create"),
            "the program is first and needs no quoting: {rendered}"
        );
        // `/TR` takes a whole command line as one argument, so the quotes inside
        // it are escaped rather than passed through. That is not decoration: an
        // unescaped quote would end the argument, and `schtasks` would read the
        // rest of the daemon's command line as flags of its own.
        assert!(
            rendered.contains(r#"/TR "\"C:\Program Files\Luotopia\sangfor-tunneld.exe\" --config"#),
            "the nested command line survives as one argument: {rendered}"
        );
        assert!(
            rendered.contains("/RL HIGHEST /F"),
            "the trailing flags are intact: {rendered}"
        );
    }

    #[test]
    fn rendering_then_parsing_back_yields_the_arguments_that_were_given() {
        // The round trip is the property that matters: `render` exists so a
        // human and a packager can run the same command by hand, and a
        // rendering that does not parse back to the same argv is a command that
        // does something else.
        for install in [
            install(),
            Install {
                // A user profile with a space in it, which is ordinary.
                directory: PathBuf::from(r"C:\Users\John Smith\AppData\Local\sangfor-tunneld"),
                ..install()
            },
            Install {
                // A trailing backslash, which is the case naive quoting breaks.
                executable: PathBuf::from(r"C:\Program Files\Luotopia\"),
                ..install()
            },
        ] {
            for command in [
                install.install(),
                install.uninstall(),
                install.query(),
                install.start_now(),
                install.end(),
            ] {
                let mut expected = vec![command.program.clone()];
                expected.extend(command.arguments.iter().cloned());
                assert_eq!(
                    split_arguments(&command.render()),
                    expected,
                    "{} does not parse back to what it was built from",
                    command.render()
                );
            }
        }
    }

    #[test]
    fn the_default_directory_is_inside_the_user_s_profile() {
        // Not ProgramData: the configuration holds the control token, and a
        // file every local user can read is not a secret. This is the specific
        // property a LocalSystem service cannot have.
        let Ok(directory) = Install::default_directory() else {
            // No user profile — a service account or a minimal container. The
            // caller falls back; there is nothing to assert here.
            return;
        };
        assert!(directory.ends_with("sangfor-tunneld"), "{directory:?}");
        assert!(directory.is_absolute(), "{directory:?}");
        let local = std::env::var_os("LOCALAPPDATA").expect("present, since the call succeeded");
        assert!(
            directory.starts_with(PathBuf::from(local)),
            "{directory:?} is under LOCALAPPDATA"
        );
    }

    /// An exit status with [code]. Built through a real process rather than a
    /// fabricated one: `ExitStatus` cannot be constructed directly, and
    /// inventing one would mean testing against a type the tests alone use.
    fn exit(code: i32) -> ExitStatus {
        if cfg!(windows) {
            ProcessCommand::new("cmd")
                .args(["/C", &format!("exit {code}")])
                .status()
        } else {
            ProcessCommand::new("sh")
                .args(["-c", &format!("exit {code}")])
                .status()
        }
        .expect("a shell can exit with a code")
    }

    #[test]
    fn a_generated_token_is_long_enough_to_guess_and_different_every_time() {
        let first = generate_token().expect("a token");
        let second = generate_token().expect("a token");
        assert_eq!(first.len(), TOKEN_BYTES * 2, "hex, one pair per byte");
        assert_ne!(
            first, second,
            "two tokens from the same process must not collide"
        );
        assert!(
            first.chars().all(|c| c.is_ascii_hexdigit()),
            "{first} is hex and nothing else, so it survives a config file, a
             command line, and a JSON string unchanged"
        );
    }

    #[test]
    fn hex_encodes_every_nibble() {
        assert_eq!(hex(&[]), "");
        assert_eq!(hex(&[0x00]), "00");
        assert_eq!(hex(&[0xff]), "ff");
        assert_eq!(hex(&[0x0f, 0xf0]), "0ff0", "neither nibble is dropped");
        assert_eq!(hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }
}
