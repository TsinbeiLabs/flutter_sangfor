//! The tunnel process entry point.
//!
//! Thin on purpose: read two documents, hand everything to
//! [`sangfor_tunneld::runtime::supervise`], and turn the outcome into an exit
//! code. Anything with logic in it lives in the library where it can be tested.

use std::path::Path;
use std::process::ExitCode;

use sangfor_core::plan::SessionPlan;
use sangfor_tunneld::cli::{self, USAGE};
use sangfor_tunneld::config::HostConfig;
use sangfor_tunneld::device;
use sangfor_tunneld::runtime::{self, Exit, InitialSession};
use sangfor_tunneld::service;

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match launch(&arguments) {
        Ok(code) => ExitCode::from(code as u8),
        Err(message) => {
            eprintln!("sangfor-tunneld: {message}");
            ExitCode::from(Exit::Failed.code() as u8)
        }
    }
}

/// Runs the process and returns its exit code.
///
/// Split out from [`main`] so the failure path is one place: every way this can
/// go wrong becomes a message on stderr and code 1, rather than a panic in a
/// process a service manager is watching.
fn launch(arguments: &[String]) -> Result<i32, String> {
    let options = cli::parse(arguments).map_err(|error| format!("{error}\n\n{USAGE}"))?;
    if options.help {
        println!("{USAGE}");
        return Ok(Exit::Clean.code());
    }
    // Handled before anything is read: installing is about the binary, not
    // about a session, and requiring a plan to install one would be circular.
    if options.install || options.uninstall || options.print_install {
        return service_command(&options);
    }

    // Both documents are read and decoded before anything is opened, so a
    // failure says which document was wrong rather than leaving a half-set-up
    // interface behind.
    let plan = match &options.plan {
        Some(path) => Some(SessionPlan::decode(&read_document(path)?).map_err(|e| e.to_string())?),
        None => None,
    };
    let config = match &options.config {
        Some(path) => HostConfig::decode(&read_document(path)?).map_err(|e| e.to_string())?,
        None => HostConfig::default(),
    };
    let config = options.apply_to(config);
    config.validate().map_err(|error| error.to_string())?;

    if options.check {
        // Opening the device is the point of `--check`: it is the step that
        // needs a privilege the process may not have, and the one whose failure
        // the operating system reports least usefully. Closing it again matters
        // too — `--check` must not leave a half-set-up interface behind.
        let opened = device::open(&config).map_err(|error| error.to_string())?;
        let _ = opened.device.close();
        return Ok(Exit::Clean.code());
    }

    // An idle daemon does not touch the device: each session opens its own, and
    // creating an adapter at startup only to destroy it would make the
    // interface flicker in the network list on every service start.
    let initial = match plan {
        Some(plan) => {
            let opened = device::open(&config).map_err(|error| error.to_string())?;
            Some(InitialSession {
                plan,
                device: opened,
            })
        }
        None => None,
    };
    Ok(runtime::supervise(config, initial).code())
}

/// Installs, removes, or describes the elevated logon task, then exits.
///
/// The command lines come from [`service::Install`] as data, which is what
/// makes them testable; this function only sequences them and turns a failure
/// into a message. See that module for why it is a task and not a service.
fn service_command(options: &cli::Options) -> Result<i32, String> {
    if !cfg!(windows) {
        return Err(
            "installing as a logon task is a Windows mechanism; on Linux install a systemd unit \
             or a tmpfiles entry that runs this binary with --config"
                .to_string(),
        );
    }
    if [options.install, options.uninstall, options.print_install]
        .iter()
        .filter(|flag| **flag)
        .count()
        > 1
    {
        return Err(
            "--install, --uninstall, and --print-install each do one thing; pass only one"
                .to_string(),
        );
    }

    let executable = std::env::current_exe()
        .map_err(|error| format!("this process cannot find its own executable: {error}"))?;
    let directory = service::directory_for(&executable);
    let install = service::Install::new(executable, directory);

    if options.print_install {
        for command in [install.install(), install.uninstall()] {
            println!("{}", command.render());
        }
        println!("# configuration: {}", install.host_config_path().display());
        println!("# log:           {}", install.log_path().display());
        println!("# control port:  {}", install.control_port);
        return Ok(Exit::Clean.code());
    }

    if options.uninstall {
        let command = install.uninstall();
        let status = command
            .run()
            .map_err(|error| format!("{} could not be run: {error}", command.program))?;
        service::explain(status, &command)?;
        println!("removed the {} logon task", install.name);
        println!(
            "left {} in place; remove it if the control token in it should not stay on disk",
            install.host_config_path().display()
        );
        return Ok(Exit::Clean.code());
    }

    // Install: write the configuration first, because a task that starts
    // before its configuration exists fails at the next logon with nothing on
    // screen to explain why.
    let token = service::generate_token()?;
    install
        .write_host_config(&token)
        .map_err(|error| format!("the configuration could not be written: {error}"))?;
    let command = install.install();
    let status = command
        .run()
        .map_err(|error| format!("{} could not be run: {error}", command.program))?;
    // The configuration is already written by the time this can fail. Leaving
    // it in place is deliberate: it holds a token nothing can use until the
    // task exists, and removing it would also remove the record of what was
    // attempted, which is the first thing somebody debugging will want.
    service::explain(status, &command)?;
    println!("installed {} as an elevated logon task", install.name);
    println!("  configuration: {}", install.host_config_path().display());
    println!("  log:           {}", install.log_path().display());
    println!("  control port:  {}", install.control_port);
    println!(
        "the task starts at the next logon; run `{}` to start it now",
        install.start_now().render()
    );
    Ok(Exit::Clean.code())
}

/// Reads a whole document from [path].
fn read_document(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|error| format!("reading {} failed: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn help_exits_cleanly_without_touching_a_device() {
        // `--help` must not try to open wintun: it is what a user runs to find
        // out why the tunnel will not start, often without elevation.
        assert_eq!(launch(&args("--help")).expect("exits"), 0);
    }

    #[test]
    fn a_bad_flag_exits_with_the_usage_beside_it() {
        let error = launch(&args("--nope")).expect_err("rejected");
        assert!(error.contains("not a recognised flag"), "{error}");
        assert!(error.contains("USAGE"), "the usage follows: {error}");
    }

    #[test]
    fn a_missing_plan_file_names_the_path() {
        let error = launch(&args("--plan Z:/absent/plan.json")).expect_err("no such file");
        assert!(
            error.contains("Z:/absent/plan.json") || error.contains("Z:\\absent\\plan.json"),
            "{error}"
        );
    }

    #[test]
    fn a_plan_that_is_not_json_is_rejected_before_any_device_opens() {
        let path = std::env::temp_dir().join("sangfor-tunneld-bad-plan.json");
        std::fs::write(&path, b"not a plan").expect("writable");
        let error = launch(&args(&format!("--plan {}", path.display()))).expect_err("bad plan");
        assert!(
            error.contains("malformed") || error.contains("JSON") || error.contains("expected"),
            "the error should say what was wrong: {error}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_dry_run_check_starts_without_a_driver_or_privileges() {
        // The point of `--dry-run --check`: it proves both documents parse, the
        // plan decodes, and a device opens, on a machine with no wintun.dll and
        // no elevation — which is every CI runner.
        let plan_path = std::env::temp_dir().join("sangfor-tunneld-dry-plan.json");
        std::fs::write(&plan_path, plan_document()).expect("writable");
        let config_path = std::env::temp_dir().join("sangfor-tunneld-dry-host.json");
        std::fs::write(
            &config_path,
            br#"{"device":"loopback","interface":"sangfor-dry","routes":["10.1.0.0/16"]}"#,
        )
        .expect("writable");

        let code = launch(&args(&format!(
            "--dry-run --check --plan {} --config {}",
            plan_path.display(),
            config_path.display()
        )));
        let _ = std::fs::remove_file(&plan_path);
        let _ = std::fs::remove_file(&config_path);
        assert_eq!(code.expect("the tunnel could start"), 0);
    }

    #[test]
    fn check_works_without_a_plan_too() {
        // A service wrapper asks "can this process ever start" before it has a
        // session to offer, so the check must not require one.
        let config_path = std::env::temp_dir().join("sangfor-tunneld-check-only.json");
        std::fs::write(
            &config_path,
            br#"{"device":"loopback","interface":"sangfor-check"}"#,
        )
        .expect("writable");
        let code = launch(&args(&format!(
            "--check --config {}",
            config_path.display()
        )));
        let _ = std::fs::remove_file(&config_path);
        assert_eq!(code.expect("the device could open"), 0);
    }

    #[test]
    fn a_route_the_operating_system_could_not_use_is_caught_here() {
        // Validated before the device opens, so a bad entry cannot leave an
        // interface half-configured with no clue which line caused it.
        let plan_path = std::env::temp_dir().join("sangfor-tunneld-route-plan.json");
        std::fs::write(&plan_path, plan_document()).expect("writable");
        let error = launch(&args(&format!(
            "--dry-run --check --plan {} --route not-a-cidr",
            plan_path.display()
        )))
        .expect_err("a route that is not a CIDR block");
        let _ = std::fs::remove_file(&plan_path);
        assert!(error.contains("not an IPv4 CIDR block"), "{error}");
    }

    #[cfg(windows)]
    #[test]
    fn print_install_describes_the_commands_without_running_them() {
        // `--install` mutates the machine, so it cannot be tested here.
        // `--print-install` produces the same command lines as data, which is
        // the part worth checking and the part a packager needs.
        assert_eq!(launch(&args("--print-install")).expect("prints"), 0);
    }

    #[cfg(windows)]
    #[test]
    fn two_install_verbs_at_once_are_refused() {
        // Neither is a no-op, and running both would leave the machine in
        // whichever state the second happened to produce.
        let error = launch(&args("--install --uninstall")).expect_err("ambiguous");
        assert!(error.contains("pass only one"), "{error}");
    }

    #[cfg(not(windows))]
    #[test]
    fn installing_as_a_logon_task_is_refused_with_the_alternative_named() {
        // A logon task is a Windows mechanism. Failing silently, or worse,
        // pretending to succeed, would leave a Linux user with no tunnel and no
        // idea what to install instead.
        let error = launch(&args("--print-install")).expect_err("not this platform");
        assert!(error.contains("systemd"), "{error}");
    }

    /// A minimal valid plan: the fields `SessionPlan::decode` insists on.
    fn plan_document() -> Vec<u8> {
        br#"{"schemaVersion":1,"sid":"sid","deviceId":"device","connectionId":"conn",
             "username":"user","signKeyBase64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
             "lang":"en","processName":"tunneld","processPath":"/tunneld",
             "processPlatform":"windows","nodes":{"major":["203.0.113.9:441"]},
             "majorNodeGroup":"major","routes":[],"dnsServers":[]}"#
            .to_vec()
    }
}
