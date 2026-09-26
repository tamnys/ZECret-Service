//! Explicitly selected, single-invocation cleanup of an existing experiment.
//! No scheduler installation, future-run authority, deployment or clock input.

#[cfg(unix)]
use super::{
    exhausted,
    provider_settings::{ProviderSettings, positive_usize},
    required,
};
#[cfg(unix)]
use std::time::Duration;
#[cfg(unix)]
use zrpc_lifecycle::{observation::ObservationLimits, watchdog::WatchdogPolicy};

pub(super) const USAGE: &str = r"zrpc lifecycle watchdog-once \
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
  --fee-upper-bounds-microusd NONNEGATIVE_INTEGER
zrpc lifecycle watchdog-once --help
This is a REAL provider watchdog action, never simulation. Every option is required.
It may DELETE each already tracked CVM once, including one linked retry of its latest retained intent.
The exact experiment ID selects the whole retained experiment at its current locked generation.
Deletion is due at original deadline minus deletion latency and scheduler allowance, at $45 conservative cost, or earlier when the retained rates and fee reserve require it.
Startup-due cleanup skips optional scans. Otherwise reconciliation is bounded and preempted when cleanup becomes due.
All pages and targets share one original invocation budget; the dispatch budget covers the whole target set.
Timing values are operator assumptions, not evidence that jobs or latency guarantees exist.
Exit 0 means this invocation completed its required work; it never proves disk deletion, billing finality or private-mode acceptance.
Failure can leave committed observations, intents or outcomes. Inspect the retained ledger; do not reset history.
One invocation installs no jobs, authorizes no future run, and creates no resources. Deployment remains disabled.";

#[cfg(unix)]
struct Settings {
    provider: ProviderSettings,
    experiment_id: String,
    limits: ObservationLimits,
    policy: WatchdogPolicy,
}

#[cfg(unix)]
fn duration(args: &mut Vec<String>, flag: &str, allow_zero: bool) -> Result<Duration, String> {
    let milliseconds = required(args, flag)?
        .parse::<u64>()
        .map_err(|_| "watchdog duration requires a representable integer".to_owned())?;
    if !allow_zero && milliseconds == 0 {
        return Err("watchdog duration must be positive".to_owned());
    }
    Ok(Duration::from_millis(milliseconds))
}

#[cfg(unix)]
fn parse_settings(mut args: Vec<String>) -> Result<Settings, String> {
    let provider = ProviderSettings::parse(&mut args)?;
    let experiment_id = required(&mut args, "--experiment-id")?;
    if experiment_id.trim().is_empty() {
        return Err("an exact retained experiment ID is required".to_owned());
    }
    let inventory_page_size = required(&mut args, "--inventory-page-size")?
        .parse::<u64>()
        .map_err(|_| "invalid inventory page size".to_owned())?;
    if !(1..=100).contains(&inventory_page_size) {
        return Err(
            "inventory page size must be within the provider range 1 through 100".to_owned(),
        );
    }
    let usage_page_size = required(&mut args, "--usage-page-size")?
        .parse::<u64>()
        .map_err(|_| "invalid usage page size".to_owned())?;
    if !(1..=5000).contains(&usage_page_size) {
        return Err("usage page size must be within the provider range 1 through 5000".to_owned());
    }
    let limits = ObservationLimits {
        inventory_page_size,
        usage_page_size,
        max_inventory_records: positive_usize(&mut args, "--max-inventory-records")?,
        max_usage_records_per_app: positive_usize(&mut args, "--max-usage-records-per-app")?,
    };
    let policy = WatchdogPolicy {
        maximum_detection_interval: duration(&mut args, "--maximum-detection-interval-ms", false)?,
        deletion_latency_upper_bound: duration(
            &mut args,
            "--deletion-latency-upper-bound-ms",
            false,
        )?,
        scheduler_delay_allowance: duration(&mut args, "--scheduler-delay-allowance-ms", true)?,
        reconciliation_budget: duration(&mut args, "--reconciliation-budget-ms", false)?,
        deletion_dispatch_budget: duration(&mut args, "--deletion-dispatch-budget-ms", false)?,
        fee_upper_bounds_microusd: required(&mut args, "--fee-upper-bounds-microusd")?
            .parse::<u64>()
            .map_err(|_| {
                "fee upper bounds require a nonnegative representable integer".to_owned()
            })?,
    };
    exhausted(&args)?;
    // Validate the whole timing relationship before reading the ledger or any
    // credential/trust file. These values carry no deployment approval.
    policy
        .validate(provider.invocation_budget)
        .map_err(|error| error.to_string())?;
    Ok(Settings {
        provider,
        experiment_id,
        limits,
        policy,
    })
}

pub(super) async fn run(args: Vec<String>) -> Result<(), String> {
    if args.as_slice() == ["--help"] {
        println!("{USAGE}");
        return Ok(());
    }
    run_inner(args).await
}

#[cfg(unix)]
async fn run_inner(args: Vec<String>) -> Result<(), String> {
    let report = execute(parse_settings(args)?).await?;
    let completed = report.invocation_completed;
    super::print_json(report)?;
    // Execution has released the client and writer lock. Returning Err after a
    // report would make main append a second JSON document to the same output.
    if !completed {
        std::process::exit(1);
    }
    Ok(())
}

#[cfg(unix)]
async fn execute(settings: Settings) -> Result<zrpc_lifecycle::watchdog::WatchdogReport, String> {
    use zrpc_lifecycle::{persistence::LedgerStore, watchdog};
    let mut store = LedgerStore::open(&settings.provider.original_binding)
        .map_err(|error| error.to_string())?;
    let workspace = store
        .ledger()
        .map_err(|error| error.to_string())?
        .binding()
        .workspace_id()
        .to_owned();
    let client = settings.provider.load(&workspace)?;
    watchdog::run_once(
        client,
        &mut store,
        &settings.experiment_id,
        settings.policy,
        settings.limits,
    )
    .await
    .map_err(|error| error.to_string())
}

#[cfg(not(unix))]
async fn run_inner(_args: Vec<String>) -> Result<(), String> {
    Err("provider watchdog requires the Unix ledger store".to_owned())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn arguments() -> Vec<String> {
        // Explicit parser-only relationships, never deployment defaults.
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
            "1",
            "--deletion-latency-upper-bound-ms",
            "1",
            "--scheduler-delay-allowance-ms",
            "0",
            "--reconciliation-budget-ms",
            "1",
            "--deletion-dispatch-budget-ms",
            "1",
            "--fee-upper-bounds-microusd",
            "0",
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
    fn every_setting_is_required_and_only_trust_root_files_may_repeat() {
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
                .provider
                .trust_root_der_files
                .len(),
            2
        );
    }

    #[test]
    fn unsupported_authority_and_secret_inputs_fail_without_echo() {
        for flag in [
            "--now",
            "--endpoint",
            "--target",
            "--cvm-id",
            "--expected-generation",
            "--install-jobs",
            "--retry-count",
            "--simulate",
            "--api-key",
            "--initialize",
            "--reset",
        ] {
            let mut args = arguments();
            args.extend([flag.into(), "SYNTHETIC_SECRET_MARKER".into()]);
            let Err(error) = parse_settings(args) else {
                panic!("unsupported option accepted")
            };
            assert!(!error.contains("SYNTHETIC_SECRET_MARKER"));
        }
        assert!(parse_settings(changed("--experiment-id", " ")).is_err());
    }

    #[test]
    fn durations_limits_and_phase_budget_are_checked_before_io() {
        for flag in [
            "--invocation-budget-ms",
            "--max-response-bytes",
            "--max-input-file-bytes",
            "--max-inventory-records",
            "--max-usage-records-per-app",
            "--maximum-detection-interval-ms",
            "--deletion-latency-upper-bound-ms",
            "--reconciliation-budget-ms",
            "--deletion-dispatch-budget-ms",
        ] {
            for value in ["0", "-1", "SYNTHETIC_SECRET_MARKER", "18446744073709551616"] {
                let Err(error) = parse_settings(changed(flag, value)) else {
                    panic!("invalid value accepted")
                };
                assert!(!error.contains("SYNTHETIC_SECRET_MARKER"));
            }
        }
        for flag in [
            "--scheduler-delay-allowance-ms",
            "--fee-upper-bounds-microusd",
        ] {
            for value in ["-1", "invalid", "18446744073709551616"] {
                assert!(parse_settings(changed(flag, value)).is_err());
            }
            assert!(parse_settings(changed(flag, "0")).is_ok());
        }
        for (flag, values) in [
            ("--inventory-page-size", ["0", "101"]),
            ("--usage-page-size", ["0", "5001"]),
        ] {
            for value in values {
                assert!(parse_settings(changed(flag, value)).is_err());
            }
        }
        // The valid fixture has R=1 and D=1: an invocation budget of 1 cannot
        // cover both phases even though each individual integer is valid.
        assert!(parse_settings(changed("--invocation-budget-ms", "1")).is_err());
        for flag in ["--original-binding", "--api-key-file", "--trust-root"] {
            assert!(parse_settings(changed(flag, "relative/path")).is_err());
        }
    }
}
