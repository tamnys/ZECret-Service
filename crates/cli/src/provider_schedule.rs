//! Offline export of uninstalled watchdog unit files from an existing ledger.
//! Credentials, trust roots and executables are recorded as paths, never loaded.

#[cfg(unix)]
use super::{provider_watchdog, required};
#[cfg(unix)]
use std::{path::PathBuf, time::Duration};

pub(super) const USAGE: &str = r"zrpc lifecycle export-watchdog \
  --original-binding FILE \
  --experiment-id EXACT_RETAINED_EXPERIMENT_ID \
  --api-key-file FILE \
  --trust-root DER_FILE [--trust-root DER_FILE ...] \
  --invocation-budget-ms POSITIVE_INTEGER \
  --max-response-bytes POSITIVE_INTEGER \
  --max-input-file-bytes POSITIVE_INTEGER \
  --inventory-page-size INTEGER_1_THROUGH_100 \
  --usage-page-size INTEGER_1_THROUGH_5000 \
  --max-inventory-records POSITIVE_INTEGER \
  --max-usage-records-per-app POSITIVE_INTEGER \
  --maximum-detection-interval-ms POSITIVE_INTEGER \
  --deletion-latency-upper-bound-ms POSITIVE_INTEGER \
  --scheduler-delay-allowance-ms NONNEGATIVE_INTEGER \
  --reconciliation-budget-ms POSITIVE_INTEGER \
  --deletion-dispatch-budget-ms POSITIVE_INTEGER \
  --fee-upper-bounds-microusd NONNEGATIVE_INTEGER \
  --executable ABSOLUTE_PATH \
  --service-user NONROOT_NUMERIC_UID \
  --unit-name STEM \
  --ledger-mount-point ABSOLUTE_HOST_MOUNT \
  --process-runtime-bound-ms POSITIVE_INTEGER \
  --manager-delay-allowance-ms NONNEGATIVE_INTEGER \
  --output-directory ABSOLUTE_NEW_DIRECTORY
zrpc lifecycle export-watchdog --help
Every option is required. This OFFLINE export writes uninstalled systemd files for review.
It opens the existing ledger only; it never reads the API key, trust roots or executable, and makes no network request.
The selected service UID must be greater than zero and less than 4294967295.
The ledger mountpoint must be a non-root absolute systemd mount path containing both the original binding and mutable ledger.
Use literal ASCII letters, digits, slash, hyphen, underscore, dot or colon in that path.
The process runtime bound must cover the invocation budget; manager delay may explicitly be zero.
Supplied timing bounds remain operator assumptions, not measured scheduler or deletion guarantees.
Output must be a new directory. Existing output is never overwritten; retained ledger history is unchanged.
The generated service performs REAL provider deletion when explicitly installed and triggered.
Export installs or activates no jobs and grants no deployment, spending, cleanup or private-mode acceptance.";

#[cfg(unix)]
struct Settings {
    watchdog: provider_watchdog::Settings,
    executable: PathBuf,
    service_user: u32,
    unit_name: String,
    ledger_mount_point: PathBuf,
    process_runtime_bound: Duration,
    manager_delay_allowance: Duration,
    output_directory: PathBuf,
}

#[cfg(unix)]
fn milliseconds(args: &mut Vec<String>, flag: &str) -> Result<Duration, String> {
    required(args, flag)?
        .parse::<u64>()
        .map(Duration::from_millis)
        .map_err(|_| "schedule duration requires a nonnegative representable integer".to_owned())
}

#[cfg(unix)]
fn parse_settings(mut args: Vec<String>) -> Result<Settings, String> {
    let executable = PathBuf::from(required(&mut args, "--executable")?);
    let service_user = required(&mut args, "--service-user")?
        .parse::<u32>()
        .ok()
        .filter(|uid| *uid != 0 && *uid != u32::MAX)
        .ok_or_else(|| "service user requires a nonroot numeric UID below 4294967295".to_owned())?;
    let unit_name = required(&mut args, "--unit-name")?;
    let ledger_mount_point = PathBuf::from(required(&mut args, "--ledger-mount-point")?);
    let process_runtime_bound = milliseconds(&mut args, "--process-runtime-bound-ms")?;
    let manager_delay_allowance = milliseconds(&mut args, "--manager-delay-allowance-ms")?;
    let output_directory = PathBuf::from(required(&mut args, "--output-directory")?);
    if !executable.is_absolute()
        || !output_directory.is_absolute()
        || !ledger_mount_point.is_absolute()
    {
        return Err("schedule executable, mountpoint and output paths must be absolute".to_owned());
    }
    let watchdog = provider_watchdog::parse_settings(args)?;
    if process_runtime_bound.is_zero()
        || process_runtime_bound < watchdog.provider.invocation_budget
    {
        return Err("process runtime bound must cover the invocation budget".to_owned());
    }
    Ok(Settings {
        watchdog,
        executable,
        service_user,
        unit_name,
        ledger_mount_point,
        process_runtime_bound,
        manager_delay_allowance,
        output_directory,
    })
}

pub(super) fn run(args: Vec<String>) -> Result<(), String> {
    if args.as_slice() == ["--help"] {
        println!("{USAGE}");
        return Ok(());
    }
    run_inner(args)
}

#[cfg(unix)]
fn run_inner(args: Vec<String>) -> Result<(), String> {
    use zrpc_lifecycle::{persistence::LedgerStore, schedule};

    let settings = parse_settings(args)?;
    let store = LedgerStore::open(&settings.watchdog.provider.original_binding)
        .map_err(|error| error.to_string())?;
    let provider = settings.watchdog.provider;
    // This path deliberately constructs no ProviderClient and loads no provider
    // files. Export cannot authenticate, observe, delete or activate a job.
    let bundle = schedule::generate(
        &store,
        schedule::BundleInput {
            experiment_id: settings.watchdog.experiment_id,
            executable: settings.executable,
            service_user: settings.service_user,
            unit_name: settings.unit_name,
            ledger_mount_point: settings.ledger_mount_point,
            api_key_file: provider.api_key_file,
            trust_root_der_files: provider.trust_root_der_files,
            invocation_budget: provider.invocation_budget,
            max_input_file_bytes: provider.max_input_file_bytes,
            max_response_bytes: provider.max_response_bytes,
            limits: settings.watchdog.limits,
            policy: settings.watchdog.policy,
            process_runtime_bound: settings.process_runtime_bound,
            manager_delay_allowance: settings.manager_delay_allowance,
        },
    )
    .map_err(|error| error.to_string())?;
    schedule::write_new(&bundle, &settings.output_directory).map_err(|error| error.to_string())?;
    super::print_json(bundle)
}

#[cfg(not(unix))]
fn run_inner(_args: Vec<String>) -> Result<(), String> {
    Err("watchdog export requires the Unix ledger store".to_owned())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn arguments() -> Vec<String> {
        // Parser fixtures only. These durations and UID are not deployment defaults.
        [
            "--original-binding",
            "/operator/original.json",
            "--experiment-id",
            "synthetic_experiment",
            "--api-key-file",
            "/operator/key",
            "--trust-root",
            "/operator/root.der",
            "--invocation-budget-ms",
            "2",
            "--max-response-bytes",
            "1",
            "--max-input-file-bytes",
            "1",
            "--inventory-page-size",
            "30",
            "--usage-page-size",
            "500",
            "--max-inventory-records",
            "1",
            "--max-usage-records-per-app",
            "1",
            "--maximum-detection-interval-ms",
            "5",
            "--deletion-latency-upper-bound-ms",
            "1",
            "--scheduler-delay-allowance-ms",
            "4",
            "--reconciliation-budget-ms",
            "1",
            "--deletion-dispatch-budget-ms",
            "1",
            "--fee-upper-bounds-microusd",
            "0",
            "--executable",
            "/operator/zrpc",
            "--service-user",
            "1000",
            "--unit-name",
            "synthetic-watchdog",
            "--ledger-mount-point",
            "/operator",
            "--process-runtime-bound-ms",
            "2",
            "--manager-delay-allowance-ms",
            "0",
            "--output-directory",
            "/operator/new-bundle",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    fn changed(flag: &str, value: &str) -> Vec<String> {
        let mut args = arguments();
        let index = args.iter().position(|arg| arg == flag).unwrap();
        args[index + 1] = value.into();
        args
    }

    #[test]
    fn every_export_setting_is_required_and_duplicates_fail() {
        let base = arguments();
        assert!(parse_settings(base.clone()).is_ok());
        for index in (0..base.len()).step_by(2) {
            let mut missing = base.clone();
            missing.drain(index..index + 2);
            assert!(parse_settings(missing).is_err());
            let mut missing_value = base.clone();
            missing_value.remove(index + 1);
            assert!(parse_settings(missing_value).is_err());
            if base[index] != "--trust-root" {
                let mut duplicate = base.clone();
                duplicate.extend_from_slice(&base[index..index + 2]);
                assert!(parse_settings(duplicate).is_err());
            }
        }
        let mut repeated_roots = base;
        repeated_roots.extend(["--trust-root".into(), "/operator/second.der".into()]);
        assert_eq!(
            parse_settings(repeated_roots)
                .unwrap()
                .watchdog
                .provider
                .trust_root_der_files
                .len(),
            2
        );
    }

    #[test]
    fn export_specific_bounds_and_paths_are_validated_before_files() {
        for value in [
            "0",
            "-1",
            "4294967295",
            "4294967296",
            "root",
            "SYNTHETIC_SECRET_MARKER",
        ] {
            let Err(error) = parse_settings(changed("--service-user", value)) else {
                panic!("invalid UID accepted")
            };
            assert!(!error.contains("SYNTHETIC_SECRET_MARKER"));
        }
        for flag in ["--process-runtime-bound-ms", "--manager-delay-allowance-ms"] {
            for value in ["-1", "18446744073709551616", "SYNTHETIC_SECRET_MARKER"] {
                let Err(error) = parse_settings(changed(flag, value)) else {
                    panic!("invalid timing accepted")
                };
                assert!(!error.contains("SYNTHETIC_SECRET_MARKER"));
            }
        }
        for value in ["0", "1"] {
            assert!(parse_settings(changed("--process-runtime-bound-ms", value)).is_err());
        }
        assert!(parse_settings(changed("--manager-delay-allowance-ms", "0")).is_ok());
        for flag in [
            "--executable",
            "--output-directory",
            "--ledger-mount-point",
            "--original-binding",
            "--api-key-file",
            "--trust-root",
        ] {
            assert!(parse_settings(changed(flag, "relative/path")).is_err());
        }
        // Reuse the watchdog policy's pre-I/O phase validation.
        assert!(parse_settings(changed("--invocation-budget-ms", "1")).is_err());
    }

    #[test]
    fn export_never_accepts_activation_or_provider_authority_options() {
        for flag in [
            "--install",
            "--activate",
            "--now",
            "--endpoint",
            "--api-key",
            "--expected-generation",
            "--initialize",
            "--reset",
            "--simulate",
        ] {
            let mut args = arguments();
            args.extend([flag.into(), "SYNTHETIC_SECRET_MARKER".into()]);
            let Err(error) = parse_settings(args) else {
                panic!("unsupported option accepted")
            };
            assert_eq!(error, "unknown or repeated argument");
            assert!(!error.contains("SYNTHETIC_SECRET_MARKER"));
        }
    }
}
