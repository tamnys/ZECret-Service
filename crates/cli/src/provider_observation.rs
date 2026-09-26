//! Explicit operator reads of the original ledger's provider resources.
//! Reconciliation saves an authenticated observation to the existing ledger.
//! Neither command initializes or recovers a ledger, modifies provider state,
//! attributes charges, or accepts a caller-selected clock.

use super::{exhausted, print_json, required, take_value};
use std::{num::NonZeroUsize, path::PathBuf, time::Duration};

const USAGE: &str = r"zrpc lifecycle (observe|reconcile) \
  --original-binding FILE \
  --api-key-file FILE \
  --trust-root DER_FILE [--trust-root DER_FILE ...] \
  --invocation-budget-ms POSITIVE_INTEGER \
  --max-response-bytes POSITIVE_INTEGER \
  --max-input-file-bytes POSITIVE_INTEGER \
  --inventory-page-size INTEGER_1_THROUGH_100 \
  --usage-page-size INTEGER_1_THROUGH_5000 \
  --max-inventory-records POSITIVE_INTEGER \
  --max-usage-records-per-app POSITIVE_INTEGER
zrpc lifecycle --help
Every option is required; no limits or credentials are inferred.
Use absolute file paths. Each trust-root file contains one independently selected DER trust anchor.
observe leaves the ledger unchanged; reconcile commits the observation and advances modeled cost/time.
Usage remains unjoined; billing, disk deletion, and cleanup remain unverified. Reconciliation grants no deletion retry authority.
Both commands perform provider reads only and never deploy, delete, or install jobs.";

struct Settings {
    original_binding: PathBuf,
    api_key_file: PathBuf,
    trust_root_der_files: Vec<PathBuf>,
    invocation_budget: Duration,
    max_response_bytes: NonZeroUsize,
    max_input_file_bytes: NonZeroUsize,
    inventory_page_size: u64,
    usage_page_size: u64,
    max_inventory_records: NonZeroUsize,
    max_usage_records_per_app: NonZeroUsize,
}

fn positive_usize(args: &mut Vec<String>, flag: &str) -> Result<NonZeroUsize, String> {
    required(args, flag)?
        .parse::<NonZeroUsize>()
        .map_err(|_| "option requires a positive representable integer".to_owned())
}

fn parse_settings(mut args: Vec<String>) -> Result<Settings, String> {
    let original_binding = PathBuf::from(required(&mut args, "--original-binding")?);
    let api_key_file = PathBuf::from(required(&mut args, "--api-key-file")?);
    let mut trust_root_der_files = Vec::new();
    while let Some(path) = take_value(&mut args, "--trust-root")? {
        trust_root_der_files.push(PathBuf::from(path));
    }
    if trust_root_der_files.is_empty() {
        return Err("required option: --trust-root".to_owned());
    }
    let invocation_budget_ms = required(&mut args, "--invocation-budget-ms")?
        .parse::<u64>()
        .map_err(|_| "option requires a positive representable integer".to_owned())?;
    if invocation_budget_ms == 0 {
        return Err("option requires a positive representable integer".to_owned());
    }
    let max_response_bytes = positive_usize(&mut args, "--max-response-bytes")?;
    let max_input_file_bytes = positive_usize(&mut args, "--max-input-file-bytes")?;
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
    let max_inventory_records = positive_usize(&mut args, "--max-inventory-records")?;
    let max_usage_records_per_app = positive_usize(&mut args, "--max-usage-records-per-app")?;
    exhausted(&args)?;
    if !original_binding.is_absolute()
        || !api_key_file.is_absolute()
        || trust_root_der_files.iter().any(|path| !path.is_absolute())
    {
        return Err("provider observation requires absolute input file paths".to_owned());
    }
    Ok(Settings {
        original_binding,
        api_key_file,
        trust_root_der_files,
        invocation_budget: Duration::from_millis(invocation_budget_ms),
        max_response_bytes,
        max_input_file_bytes,
        inventory_page_size,
        usage_page_size,
        max_inventory_records,
        max_usage_records_per_app,
    })
}

pub async fn run(mut args: Vec<String>) -> Result<(), String> {
    if args.as_slice() == ["--help"] {
        println!("{USAGE}");
        return Ok(());
    }
    let persist = match args.first().map(String::as_str) {
        Some("observe") => false,
        Some("reconcile") => true,
        _ => {
            return Err(
                "supported lifecycle commands: observe, reconcile; use lifecycle --help".to_owned(),
            );
        }
    };
    args.remove(0);
    observe(parse_settings(args)?, persist).await
}

#[cfg(unix)]
async fn observe(settings: Settings, persist: bool) -> Result<(), String> {
    use zrpc_lifecycle::{
        observation::{ObservationLimits, ObservationSession},
        persistence::LedgerStore,
        provider_inputs::ProviderFiles,
    };

    let mut store =
        LedgerStore::open(&settings.original_binding).map_err(|error| error.to_string())?;
    let session = ObservationSession::new(&store).map_err(|error| error.to_string())?;
    let client = ProviderFiles {
        workspace_id: session
            .workspace_id()
            .map_err(|error| error.to_string())?
            .to_owned(),
        api_key_file: settings.api_key_file,
        trust_root_der_files: settings.trust_root_der_files,
        max_input_file_bytes: settings.max_input_file_bytes,
        invocation_budget: settings.invocation_budget,
        max_response_bytes: settings.max_response_bytes,
    }
    .load()
    .map_err(|error| error.to_string())?;
    let observation = session
        .observe(
            client,
            ObservationLimits {
                inventory_page_size: settings.inventory_page_size,
                usage_page_size: settings.usage_page_size,
                max_inventory_records: settings.max_inventory_records,
                max_usage_records_per_app: settings.max_usage_records_per_app,
            },
        )
        .await
        .map_err(|error| error.to_string())?;
    let mut output = report(&observation);
    if persist {
        let committed = store
            .commit_observation(observation)
            .map_err(|error| error.to_string())?;
        output["source_committed_reference"] = output["committed_reference"].take();
        output["committed_reference"] =
            serde_json::to_value(committed).map_err(|error| error.to_string())?;
        output["mode"] = "provider_observation_reconciliation".into();
        output["persisted"] = true.into();
        output["local_ledger_updated"] = true.into();
        output["committed_cost_floor_microusd"] = store
            .ledger()
            .map_err(|error| error.to_string())?
            .conservative_cost_floor_microusd()
            .into();
    }
    print_json(output)
}

#[cfg(not(unix))]
async fn observe(_settings: Settings, _persist: bool) -> Result<(), String> {
    Err("provider observation requires the Unix ledger store".to_owned())
}

#[cfg(unix)]
fn cvm_projection(cvm: &zrpc_lifecycle::provider_wire::Cvm) -> serde_json::Value {
    serde_json::json!({
        "id": cvm.id,
        "status": cvm.status,
        "app_id": cvm.app_id,
        "instance_id": cvm.instance_id,
        "vm_uuid": cvm.vm_uuid,
        "workspace_id": cvm.workspace_id,
        "created_at": cvm.created_at,
        "deleted_at": cvm.deleted_at,
    })
}

#[cfg(unix)]
fn identity_label(
    value: Option<zrpc_lifecycle::observation::IdentityMatch>,
) -> Option<&'static str> {
    use zrpc_lifecycle::observation::IdentityMatch;
    value.map(|value| match value {
        IdentityMatch::CvmFieldsMatch => "cvm_fields_match",
        IdentityMatch::Incomplete => "incomplete",
    })
}

#[cfg(unix)]
fn usage_projection(row: &zrpc_lifecycle::provider_wire::UsageRow) -> serde_json::Value {
    serde_json::json!({
        "instance_id": row.instance_id,
        "project_id": row.project_id,
        "team_id": row.team_id,
        "timestamp": row.timestamp,
        "event_type": row.event_type,
        "usage_type": row.usage_type,
        "billing_start": row.billing_start,
        "billing_end": row.billing_end,
        "billing_key": row.billing_key,
        "billing_hour": row.billing_hour,
        "billing_day": row.billing_day,
        "cost_canonical_decimal": row.cost.canonical_identity(),
    })
}

#[cfg(unix)]
fn report(observation: &zrpc_lifecycle::observation::ReadObservation) -> serde_json::Value {
    use serde_json::json;
    use zrpc_lifecycle::provider_http::CvmDetail;

    let items: Vec<_> = observation
        .inventory()
        .items()
        .iter()
        .map(cvm_projection)
        .collect();
    let tracked: Vec<_> = observation
        .tracked()
        .iter()
        .map(|read| {
            let detail = match read.detail() {
                CvmDetail::Present(cvm) => json!({
                    "http_status": 200,
                    "cvm": cvm_projection(cvm),
                }),
                CvmDetail::NotFound => json!({"http_status": 404}),
            };
            json!({
                "original_target": read.target(),
                "inventory_identity": identity_label(read.inventory_identity()),
                "detail_identity": identity_label(read.detail_identity()),
                "detail": detail,
                "cvm_absence_observed": read.cvm_absence_observed(),
            })
        })
        .collect();
    let usage_by_app: Vec<_> = observation
        .unjoined_usage_by_app()
        .iter()
        .map(|(app_id, scan)| {
            let rows: Vec<_> = scan.rows().iter().map(usage_projection).collect();
            json!({
                "app_id": app_id,
                "scan_reached_empty_page": true,
                "usage_unjoined": true,
                "rows": rows,
            })
        })
        .collect();
    json!({
        "mode": "provider_read_observation",
        "persisted": false,
        "local_ledger_updated": false,
        "deletion_retry_authorized": false,
        "private_accepted": false,
        "query_sent": false,
        "deployment_enabled": false,
        "provider_mutations_performed": false,
        "original_binding": observation.original_binding(),
        "committed_reference": observation.reference(),
        "usage_cutoff_unix_seconds": observation.usage_cutoff_unix_seconds(),
        "finished_at_unix_seconds": observation.finished_at_unix_seconds(),
        "known_cost_floor_microusd": observation.known_cost_floor_microusd(),
        "provider_usage_added_to_cost_floor": false,
        "inventory_atomic_snapshot": false,
        "inventory": {
            "scan_complete": true,
            "total": observation.inventory().total(),
            "pages": observation.inventory().pages(),
            "items": items,
        },
        "tracked": tracked,
        "untracked_inventory_ids": observation.untracked_inventory_ids(),
        "usage_by_app": usage_by_app,
        "usage_unjoined": true,
        "billing_reconciled": observation.billing_reconciled(),
        "independent_disk_deletion_verified": observation.independent_disk_deletion_verified(),
        "cleanup_complete": observation.cleanup_complete(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments() -> Vec<String> {
        // Values exercise parsing only; they are not deployment defaults.
        [
            "--original-binding",
            "/operator/original.json",
            "--api-key-file",
            "/operator/key",
            "--trust-root",
            "/operator/root.der",
            "--invocation-budget-ms",
            "1",
            "--max-response-bytes",
            "2",
            "--max-input-file-bytes",
            "3",
            "--inventory-page-size",
            "30",
            "--usage-page-size",
            "500",
            "--max-inventory-records",
            "4",
            "--max-usage-records-per-app",
            "5",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    fn change_value(flag: &str, value: &str) -> Vec<String> {
        let mut args = arguments();
        let index = args.iter().position(|arg| arg == flag).unwrap();
        args[index + 1] = value.to_owned();
        args
    }

    #[test]
    fn all_settings_are_required_and_only_trust_roots_may_repeat() {
        let base = arguments();
        for index in (0..base.len()).step_by(2) {
            let mut missing = base.clone();
            missing.drain(index..index + 2);
            assert!(parse_settings(missing).is_err(), "{}", base[index]);
            if base[index] != "--trust-root" {
                let mut repeated = base.clone();
                repeated.extend_from_slice(&base[index..index + 2]);
                assert!(parse_settings(repeated).is_err(), "{}", base[index]);
            }
        }
        let mut args = base;
        args.extend(["--trust-root".to_owned(), "/operator/second.der".to_owned()]);
        let settings = parse_settings(args).unwrap();
        assert_eq!(settings.trust_root_der_files.len(), 2);
        assert_eq!(settings.invocation_budget, Duration::from_millis(1));
        assert_eq!(settings.max_inventory_records.get(), 4);
        assert_eq!(settings.max_usage_records_per_app.get(), 5);
    }

    #[test]
    fn missing_values_unknown_options_and_secret_argv_are_rejected_without_echo() {
        for index in (0..arguments().len()).step_by(2) {
            let mut missing_value = arguments();
            missing_value.remove(index + 1);
            assert!(parse_settings(missing_value).is_err());
        }
        for option in [
            "--api-key",
            "--endpoint",
            "--now",
            "--simulate",
            "--initialize",
            "--delete",
        ] {
            let mut args = arguments();
            args.extend([option.to_owned(), "SENSITIVE-INPUT-MARKER".to_owned()]);
            let Err(error) = parse_settings(args) else {
                panic!("unsupported option accepted")
            };
            assert!(!error.contains("SENSITIVE-INPUT-MARKER"));
        }
    }

    #[test]
    fn positive_limits_and_documented_page_ranges_are_validated_before_io() {
        for flag in [
            "--invocation-budget-ms",
            "--max-response-bytes",
            "--max-input-file-bytes",
            "--max-inventory-records",
            "--max-usage-records-per-app",
        ] {
            for invalid in ["0", "-1", "not-a-number", "184467440737095516160"] {
                assert!(
                    parse_settings(change_value(flag, invalid)).is_err(),
                    "{flag} {invalid}"
                );
            }
        }
        for (flag, values) in [
            ("--inventory-page-size", ["0", "101", "-1"]),
            ("--usage-page-size", ["0", "5001", "-1"]),
        ] {
            for invalid in values {
                assert!(parse_settings(change_value(flag, invalid)).is_err());
            }
        }
        assert!(parse_settings(change_value("--inventory-page-size", "100")).is_ok());
        assert!(parse_settings(change_value("--usage-page-size", "5000")).is_ok());
        for flag in ["--original-binding", "--api-key-file", "--trust-root"] {
            assert!(parse_settings(change_value(flag, "relative/path")).is_err());
            assert!(parse_settings(change_value(flag, "")).is_err());
        }
    }
}
