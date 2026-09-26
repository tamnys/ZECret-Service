//! Explicit operator action for one previously tracked target. No automatic
//! cleanup, initialization, retry loop, deployment or scheduler activation.

use super::{exhausted, print_json, provider_settings::ProviderSettings, required};

pub(super) const USAGE: &str = r"zrpc lifecycle delete-tracked \
  --original-binding FILE \
  --expected-generation INTEGER \
  --cvm-id EXACT_TRACKED_ID \
  --api-key-file FILE \
  --trust-root DER_FILE [--trust-root DER_FILE ...] \
  --invocation-budget-ms POSITIVE_INTEGER \
  --max-response-bytes POSITIVE_INTEGER \
  --max-input-file-bytes POSITIVE_INTEGER
zrpc lifecycle delete-tracked --help
This is a REAL provider deletion request, never simulation. Every option is required.
It selects one existing tracked CVM at the specified ledger generation and records intent before DELETE.
Exit 0 means a 204 or 404 response was durably recorded; it does not prove storage deletion or billing finality.
Any prior intent blocks this first-attempt command. Use retry-tracked only after inspecting the retained ledger.
Failure may leave a committed intent or outcome. Inspect the retained ledger; do not reset it.
No resources are created, and no jobs are installed. Deployment remains disabled.";

pub(super) const RETRY_USAGE: &str = r"zrpc lifecycle retry-tracked \
  --original-binding FILE \
  --expected-generation INTEGER \
  --cvm-id EXACT_TRACKED_ID \
  --prior-intent-generation POSITIVE_INTEGER \
  --api-key-file FILE \
  --trust-root DER_FILE [--trust-root DER_FILE ...] \
  --invocation-budget-ms POSITIVE_INTEGER \
  --max-response-bytes POSITIVE_INTEGER \
  --max-input-file-bytes POSITIVE_INTEGER
zrpc lifecycle retry-tracked --help
This is a REAL provider deletion retry, never simulation. Every option is required.
Inspect the retained ledger first. Select the latest intent for this exact tracked CVM and the current ledger generation.
Fresh authenticated workspace and target-detail reads precede a new linked durable intent and at most one DELETE.
Earlier pending intents and outcomes remain unchanged. The original deadline, costs and rates are retained.
Exit 0 means a 204 or 404 response was durably recorded; it does not prove storage deletion or billing finality.
There is no automatic retry, caller-supplied readback, or provider-idempotency guarantee. Reconciliation grants no retry authority.
Failure may leave a new committed intent or outcome. Inspect the retained ledger again; do not blindly replay or reset it.
No resources are created, and no jobs are installed. Deployment remains disabled.";

#[derive(Clone, Copy)]
pub(super) enum Command {
    FirstAttempt,
    Retry,
}

struct Settings {
    provider: ProviderSettings,
    expected_generation: u64,
    cvm_id: String,
    prior_intent_generation: Option<u64>,
}

fn parse_settings(mut args: Vec<String>, command: Command) -> Result<Settings, String> {
    let provider = ProviderSettings::parse(&mut args)?;
    let expected_generation = required(&mut args, "--expected-generation")?
        .parse::<u64>()
        .map_err(|_| {
            "expected generation requires a nonnegative representable integer".to_owned()
        })?;
    let cvm_id = required(&mut args, "--cvm-id")?;
    if cvm_id.trim().is_empty() {
        return Err("an exact tracked CVM ID is required".to_owned());
    }
    let prior_intent_generation = match command {
        Command::FirstAttempt => None,
        Command::Retry => {
            let generation = required(&mut args, "--prior-intent-generation")?
                .parse::<u64>()
                .ok()
                .filter(|generation| *generation > 0)
                .ok_or_else(|| {
                    "prior intent generation requires a positive representable integer".to_owned()
                })?;
            Some(generation)
        }
    };
    exhausted(&args)?;
    Ok(Settings {
        provider,
        expected_generation,
        cvm_id,
        prior_intent_generation,
    })
}

pub(super) async fn run(args: Vec<String>, command: Command) -> Result<(), String> {
    if args.as_slice() == ["--help"] {
        println!(
            "{}",
            match command {
                Command::FirstAttempt => USAGE,
                Command::Retry => RETRY_USAGE,
            }
        );
        return Ok(());
    }
    let (report, success) = delete(parse_settings(args, command)?).await?;
    print_json(report)?;
    // The completed dispatch has already released its client and writer lock.
    // Do not return Err here: main would append a second JSON error document.
    if !success {
        std::process::exit(1);
    }
    Ok(())
}

#[cfg(unix)]
async fn delete(settings: Settings) -> Result<(serde_json::Value, bool), String> {
    use zrpc_lifecycle::{persistence::LedgerStore, provider_http::deletion::PreparationReadback};

    let mut store = LedgerStore::open(&settings.provider.original_binding)
        .map_err(|error| error.to_string())?;
    let source = store
        .planning_reference()
        .map_err(|error| error.to_string())?;
    let binding = store
        .ledger()
        .map_err(|error| error.to_string())?
        .binding()
        .clone();
    let client = settings.provider.load(binding.workspace_id())?;
    // The library checks the current store, generation, workspace, target,
    // prior intent, route and wall clock before authenticating to the provider.
    let report = match settings.prior_intent_generation {
        None => client
            .delete_tracked(&mut store, settings.expected_generation, &settings.cvm_id)
            .await,
        Some(prior_intent_generation) => client
            .retry_tracked(
                &mut store,
                settings.expected_generation,
                &settings.cvm_id,
                prior_intent_generation,
            )
            .await,
    }
    .map_err(|error| format!(
        "deletion failed; an intent may already be committed; inspect the retained ledger before explicitly selecting any retry; do not blindly replay: {error}"
    ))?;
    let (mut output, success) = outcome_projection(
        report.provider_outcome(),
        report.outcome_journal(),
        report.prior_intent_generation(),
    );
    output["original_binding"] = serde_json::to_value(binding).map_err(|_| "report unavailable")?;
    output["source_committed_reference"] =
        serde_json::to_value(source).map_err(|_| "report unavailable")?;
    output["target"] = serde_json::to_value(report.target()).map_err(|_| "report unavailable")?;
    output["intent_generation"] = report.intent_generation().into();
    output["preparation_readback"] = match report.preparation_readback() {
        PreparationReadback::CvmFieldsMatch => "cvm_fields_match",
        PreparationReadback::IncompleteCvmFields => "incomplete_cvm_fields",
        PreparationReadback::DetailNotFound => "detail_not_found",
    }
    .into();
    output["transport_issue"] = report
        .transport_issue()
        .map(|error| error.to_string())
        .into();
    Ok((output, success))
}

#[cfg(not(unix))]
async fn delete(_settings: Settings) -> Result<(serde_json::Value, bool), String> {
    Err("provider deletion requires the Unix ledger store".to_owned())
}

#[cfg(unix)]
fn outcome_projection(
    outcome: zrpc_lifecycle::controller::DeletionOutcome,
    journal: zrpc_lifecycle::provider_http::deletion::OutcomeJournal,
    prior_intent_generation: Option<u64>,
) -> (serde_json::Value, bool) {
    use serde_json::json;
    use zrpc_lifecycle::{controller::DeletionOutcome, provider_http::deletion::OutcomeJournal};
    let success = matches!(
        outcome,
        DeletionOutcome::Initiated204 | DeletionOutcome::NotFound404
    ) && journal == OutcomeJournal::Committed;
    let journal_projection = match journal {
        OutcomeJournal::Committed => json!({"state": "committed"}),
        OutcomeJournal::ClockRejected => json!({"state": "clock_rejected"}),
        OutcomeJournal::NotConfirmed(error) => {
            json!({"state": "not_confirmed", "issue": error.to_string()})
        }
    };
    (
        json!({
            "mode": if prior_intent_generation.is_some() {
                "explicit_tracked_deletion_retry"
            } else {
                "explicit_tracked_deletion"
            },
            "prior_intent_generation": prior_intent_generation,
            "simulation": false,
            "command_succeeded": success,
            "delete_exchange_attempted": true,
            "provider_outcome": outcome,
            "outcome_journal": journal_projection,
            "outcome_committed": journal == OutcomeJournal::Committed,
            "deletion_retry_authorized": false,
            "private_accepted": false,
            "query_sent": false,
            "deployment_enabled": false,
            "billing_reconciled": false,
            "independent_disk_deletion_verified": false,
            "cleanup_complete": false,
        }),
        success,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(command: Command) -> Vec<String> {
        // Parser inputs only, not deployment policies or credentials.
        let mut args: Vec<String> = [
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
            "--expected-generation",
            "0",
            "--cvm-id",
            "synthetic-cvm",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        if matches!(command, Command::Retry) {
            args.extend(["--prior-intent-generation".into(), "1".into()]);
        }
        args
    }

    #[test]
    fn exact_target_and_all_inputs_required_only_trust_roots_may_repeat() {
        for command in [Command::FirstAttempt, Command::Retry] {
            let base = arguments(command);
            for index in (0..base.len()).step_by(2) {
                let mut missing = base.clone();
                missing.drain(index..index + 2);
                assert!(parse_settings(missing, command).is_err(), "{}", base[index]);
                let mut missing_value = base.clone();
                missing_value.remove(index + 1);
                assert!(parse_settings(missing_value, command).is_err());
                if base[index] != "--trust-root" {
                    let mut duplicate = base.clone();
                    duplicate.extend_from_slice(&base[index..index + 2]);
                    assert!(parse_settings(duplicate, command).is_err());
                }
            }
            let mut repeated_root = base;
            repeated_root.extend(["--trust-root".into(), "/operator/second.der".into()]);
            let parsed = parse_settings(repeated_root, command).unwrap();
            assert_eq!(parsed.expected_generation, 0);
            assert_eq!(parsed.cvm_id, "synthetic-cvm");
            assert_eq!(parsed.provider.trust_root_der_files.len(), 2);
            assert_eq!(
                parsed.prior_intent_generation,
                match command {
                    Command::FirstAttempt => None,
                    Command::Retry => Some(1),
                }
            );
        }
    }

    #[test]
    fn malformed_bounds_paths_and_unsupported_authority_options_are_rejected_without_echo() {
        for (flag, invalid) in [
            ("--expected-generation", "-1"),
            ("--expected-generation", "18446744073709551616"),
            ("--expected-generation", "SENSITIVE-MARKER"),
            ("--cvm-id", " "),
            ("--original-binding", "relative"),
            ("--api-key-file", "relative"),
            ("--trust-root", "relative"),
            ("--invocation-budget-ms", "0"),
            ("--max-response-bytes", "0"),
            ("--max-input-file-bytes", "0"),
        ] {
            for command in [Command::FirstAttempt, Command::Retry] {
                let mut args = arguments(command);
                let index = args.iter().position(|arg| arg == flag).unwrap();
                args[index + 1] = invalid.into();
                let Err(error) = parse_settings(args, command) else {
                    panic!("invalid settings accepted")
                };
                assert!(!error.contains("SENSITIVE-MARKER"));
            }
        }
        for option in [
            "--now",
            "--endpoint",
            "--api-key",
            "--retry",
            "--automatic",
            "--retry-count",
            "--readback",
            "--evidence",
            "--initialize",
            "--recover",
            "--install-jobs",
            "--deploy",
            "--simulate",
            "--inventory-page-size",
        ] {
            for command in [Command::FirstAttempt, Command::Retry] {
                let mut args = arguments(command);
                args.extend([option.to_owned(), "SENSITIVE-MARKER".into()]);
                let Err(error) = parse_settings(args, command) else {
                    panic!("unsupported option accepted")
                };
                assert!(!error.contains("SENSITIVE-MARKER"));
            }
        }
    }

    #[test]
    fn retry_requires_positive_prior_generation_and_cannot_modify_first_attempt_command() {
        let retry_args = arguments(Command::Retry);
        assert!(parse_settings(retry_args.clone(), Command::FirstAttempt).is_err());
        let index = retry_args
            .iter()
            .position(|arg| arg == "--prior-intent-generation")
            .unwrap();
        // Generation zero is the original snapshot and cannot contain an intent.
        for value in ["0", "-1", "18446744073709551616", "SENSITIVE-MARKER"] {
            let mut args = retry_args.clone();
            args[index + 1] = value.into();
            let Err(error) = parse_settings(args, Command::Retry) else {
                panic!("invalid prior generation accepted")
            };
            assert!(!error.contains("SENSITIVE-MARKER"));
        }
        let mut args = retry_args;
        args[index + 1] = u64::MAX.to_string();
        assert_eq!(
            parse_settings(args, Command::Retry)
                .unwrap()
                .prior_intent_generation,
            Some(u64::MAX)
        );
    }

    #[cfg(unix)]
    #[test]
    fn only_durable_204_or_404_succeeds_and_no_result_proves_cleanup() {
        use zrpc_lifecycle::{
            controller::DeletionOutcome, persistence::StoreError,
            provider_http::deletion::OutcomeJournal,
        };
        for outcome in [
            DeletionOutcome::Initiated204,
            DeletionOutcome::NotFound404,
            DeletionOutcome::Rejected { status: 403 },
            DeletionOutcome::TransportUncertain,
        ] {
            for journal in [
                OutcomeJournal::Committed,
                OutcomeJournal::ClockRejected,
                OutcomeJournal::NotConfirmed(StoreError::Io),
            ] {
                for prior_intent_generation in [None, Some(7)] {
                    let (output, success) =
                        outcome_projection(outcome, journal, prior_intent_generation);
                    assert_eq!(
                        output["prior_intent_generation"],
                        serde_json::json!(prior_intent_generation)
                    );
                    assert_eq!(
                        output["mode"],
                        if prior_intent_generation.is_some() {
                            "explicit_tracked_deletion_retry"
                        } else {
                            "explicit_tracked_deletion"
                        }
                    );
                    assert_eq!(
                        success,
                        matches!(
                            outcome,
                            DeletionOutcome::Initiated204 | DeletionOutcome::NotFound404
                        ) && journal == OutcomeJournal::Committed
                    );
                    assert_eq!(output["command_succeeded"], success);
                    assert_eq!(
                        output["outcome_committed"],
                        journal == OutcomeJournal::Committed
                    );
                    assert_eq!(
                        output["provider_outcome"],
                        serde_json::to_value(outcome).unwrap()
                    );
                    for field in [
                        "simulation",
                        "deletion_retry_authorized",
                        "private_accepted",
                        "query_sent",
                        "deployment_enabled",
                        "billing_reconciled",
                        "independent_disk_deletion_verified",
                        "cleanup_complete",
                    ] {
                        assert_eq!(output[field], false, "{field}");
                    }
                }
            }
        }
    }
}
