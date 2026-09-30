//! The tunnel process entry point.
//!
//! Thin on purpose: read two documents, open a device, hand everything to
//! [`sangfor_tunneld::runtime::run`], and turn the outcome into an exit code.
//! Anything with logic in it lives in the library where it can be tested.

use std::io::Read;
use std::path::Path;
use std::process::ExitCode;

use sangfor_core::plan::SessionPlan;
use sangfor_tunneld::cli::{self, USAGE};
use sangfor_tunneld::config::HostConfig;
use sangfor_tunneld::device;
use sangfor_tunneld::runtime::{self, Exit};

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
    // Checked before anything is read: both documents would compete for the same
    // stream, and the second reader would silently get an empty one.
    if options.plan == Path::new("-") && options.config.as_deref() == Some(Path::new("-")) {
        return Err(
            "the plan and the host configuration cannot both be stdin; give one of them a path"
                .to_string(),
        );
    }

    let plan_document = read_document(&options.plan, true)?;
    let config_document = match &options.config {
        Some(path) => Some(read_document(path, false)?),
        None => None,
    };

    let plan = SessionPlan::decode(&plan_document).map_err(|error| error.to_string())?;
    let config = match &config_document {
        Some(document) => HostConfig::decode(document).map_err(|error| error.to_string())?,
        None => HostConfig::default(),
    };
    let config = options.apply_to(config);
    config.validate().map_err(|error| error.to_string())?;

    let opened = device::open(&config).map_err(|error| error.to_string())?;
    if options.check {
        // The device is open, both documents parsed, and nothing was configured:
        // `--check` must not leave a half-set-up interface behind.
        let _ = opened.device.close();
        return Ok(Exit::Clean.code());
    }
    match runtime::run(plan, config, opened) {
        Ok(exit) => Ok(exit.code()),
        Err(error) => Err(error.to_string()),
    }
}

/// Reads a whole document from [path], where `-` means stdin.
///
/// [required] decides what an empty stdin means: a missing plan is fatal, while
/// a missing host configuration just leaves the defaults in place.
fn read_document(path: &Path, required: bool) -> Result<Vec<u8>, String> {
    if path == Path::new("-") {
        let mut buffer = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buffer)
            .map_err(|error| format!("reading the document from stdin failed: {error}"))?;
        if buffer.is_empty() && required {
            return Err("nothing was written to stdin".to_string());
        }
        return Ok(buffer);
    }
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
    fn the_plan_and_the_configuration_cannot_both_be_stdin() {
        // Both would compete for the same stream, and the second reader would
        // silently get an empty document.
        let error = launch(&args("--plan - --config -")).expect_err("ambiguous");
        assert!(error.contains("cannot both be stdin"), "{error}");
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
