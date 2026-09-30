//! Offline, original-bound systemd artifacts. Generation opens no credential,
//! trust root or executable and performs no provider/manager operation. Export
//! creates a new private directory only; installation is a separate operator act.

mod encoding;
mod timing;
pub use timing::ScheduleTiming;

use crate::{
    LifecycleError,
    activation::RequiredReceipt,
    controller::ExperimentBinding,
    observation::ObservationLimits,
    persistence::{CommittedLedgerReference, LedgerStore},
    provider_scan::{InventoryAccumulator, UsageAccumulator},
    watchdog::{PolicyDecision, WatchdogPolicy},
};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    fs::{self, DirBuilder, File, OpenOptions},
    io::Write,
    num::NonZeroUsize,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const INVALID: LifecycleError = LifecycleError("invalid offline watchdog bundle input");
const OUTPUT: LifecycleError = LifecycleError(
    "watchdog bundle export failed; preserve and inspect any partial output; no replacement is allowed",
);
// Documented systemd unit-name limit, including its type suffix:
// https://github.com/systemd/systemd/blob/v255/man/systemd.unit.xml
const SYSTEMD_UNIT_NAME_BYTES: usize = 255;

/// All values are selected explicitly. This neither opens the provider inputs
/// nor asserts that the destination Linux host has the user/binary/files.
pub struct BundleInput {
    pub experiment_id: String,
    pub executable: PathBuf,
    pub service_user: u32,
    pub unit_name: String,
    pub ledger_mount_point: PathBuf,
    pub api_key_file: PathBuf,
    pub trust_root_der_files: Vec<PathBuf>,
    pub invocation_budget: Duration,
    pub max_input_file_bytes: NonZeroUsize,
    pub max_response_bytes: NonZeroUsize,
    pub limits: ObservationLimits,
    pub policy: WatchdogPolicy,
    pub process_runtime_bound: Duration,
    pub manager_delay_allowance: Duration,
}

/// Read-only serialized proposal, not deserializable execution authority. Unit
/// text is suitable for later operator review; no installer consumes this type.
#[derive(Debug, Serialize)]
pub struct WatchdogBundle {
    mode: &'static str,
    systemd_contract_version: &'static str,
    original_binding: ExperimentBinding,
    committed_ledger: CommittedLedgerReference,
    generated_at_unix_millis: u64,
    service_user: u32,
    ledger_mount_point: PathBuf,
    ledger_mount_unit: String,
    executable: PathBuf,
    command_arguments: Vec<String>,
    timing: ScheduleTiming,
    decision_at_generation: PolicyDecision,
    files: BTreeMap<String, String>,
    required_receipts: Vec<RequiredReceipt>,
    jobs_installed: bool,
    credentials_read: bool,
    network_used: bool,
    timing_verified: bool,
    activation_authorized: bool,
    deployment_enabled: bool,
    private_accepted: bool,
}

fn path_text(path: &Path) -> Result<&str, LifecycleError> {
    let value = path.to_str().ok_or(INVALID)?;
    if !path.is_absolute()
        || value.split('/').any(|part| matches!(part, "." | ".."))
        || value
            .chars()
            .any(|c| c.is_control() || matches!(c, '\u{2028}' | '\u{2029}'))
    {
        return Err(INVALID);
    }
    Ok(value)
}

fn validate_name(name: &str) -> Result<(), LifecycleError> {
    // A literal, non-template subset of systemd's documented unit-name syntax
    // avoids aliases, specifier expansion and file/directory syntax entirely.
    if !name
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric)
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        || name
            .len()
            .checked_add("-mount-ready.service".len())
            .is_none_or(|len| len > SYSTEMD_UNIT_NAME_BYTES)
    {
        return Err(INVALID);
    }
    Ok(())
}

/// The systemd path-to-mount-unit encoding for literal mountpoint paths. The
/// selected path is deliberately restricted to characters that need no quoting
/// or specifier expansion in ConditionPathIsMountPoint=. Escaped hyphens still
/// distinguish a literal hyphen from a path separator in the mount unit name.
fn mount_unit_name(path: &Path) -> Result<String, LifecycleError> {
    let value = path_text(path)?;
    if value == "/"
        || value.ends_with('/')
        || value.contains("//")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/-_.:".contains(&byte))
    {
        return Err(INVALID);
    }
    let mut unit = String::new();
    for (index, byte) in value.as_bytes()[1..].iter().copied().enumerate() {
        match byte {
            b'/' => unit.push('-'),
            b'-' | b'.' if index == 0 || byte == b'-' => {
                unit.push_str(&format!("\\x{byte:02x}"));
            }
            _ => unit.push(char::from(byte)),
        }
    }
    unit.push_str(".mount");
    if unit.len() > SYSTEMD_UNIT_NAME_BYTES {
        return Err(INVALID);
    }
    Ok(unit)
}

pub fn generate(store: &LedgerStore, input: BundleInput) -> Result<WatchdogBundle, LifecycleError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .ok_or(INVALID)?;
    generate_at(store, input, now)
}

fn generate_at(
    store: &LedgerStore,
    input: BundleInput,
    now: u64,
) -> Result<WatchdogBundle, LifecycleError> {
    validate_name(&input.unit_name)?;
    // UID zero is privileged; all-ones is the OS invalid-UID sentinel. Require
    // an explicitly selected non-root account; existence/ownership are checked
    // on the external host before any later installation, not inferred here.
    if matches!(input.service_user, 0 | u32::MAX) || input.trust_root_der_files.is_empty() {
        return Err(INVALID);
    }
    path_text(&input.executable)?;
    path_text(&input.api_key_file)?;
    for path in &input.trust_root_der_files {
        path_text(path)?;
    }
    InventoryAccumulator::new(
        input.limits.inventory_page_size,
        input.limits.max_inventory_records,
    )?;
    UsageAccumulator::new(
        input.limits.usage_page_size,
        input.limits.max_usage_records_per_app,
    )?;
    let reference = store.planning_reference().map_err(|_| INVALID)?;
    let ledger_mount_unit = mount_unit_name(&input.ledger_mount_point)?;
    if !reference
        .original_binding_path()
        .starts_with(&input.ledger_mount_point)
        || !reference
            .snapshot_path()
            .starts_with(&input.ledger_mount_point)
    {
        return Err(INVALID);
    }
    let ledger = store.ledger().map_err(|_| INVALID)?;
    if input.experiment_id != ledger.binding().experiment_id() {
        return Err(INVALID);
    }
    let decision = input.policy.evaluate(ledger, now)?;
    let timing = timing::derive(
        &input.policy,
        input.invocation_budget,
        input.process_runtime_bound,
        input.manager_delay_allowance,
        &decision,
    )?;
    let mut args = vec![
        path_text(&input.executable)?.to_owned(),
        "lifecycle".into(),
        "watchdog-once".into(),
    ];
    let mut option = |flag: &str, value: String| {
        args.extend([flag.to_owned(), value]);
    };
    option(
        "--original-binding",
        path_text(reference.original_binding_path())?.to_owned(),
    );
    option("--experiment-id", input.experiment_id);
    option("--api-key-file", path_text(&input.api_key_file)?.to_owned());
    for path in &input.trust_root_der_files {
        option("--trust-root", path_text(path)?.to_owned());
    }
    for (flag, value) in [
        ("--invocation-budget-ms", timing.invocation_budget_ms),
        (
            "--maximum-detection-interval-ms",
            timing.maximum_detection_interval_ms,
        ),
        (
            "--deletion-latency-upper-bound-ms",
            timing.deletion_latency_ms,
        ),
        (
            "--scheduler-delay-allowance-ms",
            timing.catch_up_allowance_ms,
        ),
        (
            "--reconciliation-budget-ms",
            timing.reconciliation_budget_ms,
        ),
        ("--deletion-dispatch-budget-ms", timing.dispatch_budget_ms),
        (
            "--fee-upper-bounds-microusd",
            input.policy.fee_upper_bounds_microusd,
        ),
        ("--inventory-page-size", input.limits.inventory_page_size),
        ("--usage-page-size", input.limits.usage_page_size),
    ] {
        option(flag, value.to_string());
    }
    for (flag, value) in [
        ("--max-input-file-bytes", input.max_input_file_bytes),
        ("--max-response-bytes", input.max_response_bytes),
        (
            "--max-inventory-records",
            input.limits.max_inventory_records,
        ),
        (
            "--max-usage-records-per-app",
            input.limits.max_usage_records_per_app,
        ),
    ] {
        option(flag, value.to_string());
    }
    let command = encoding::exec_command(&args)?;
    let service = format!("{}.service", input.unit_name);
    let gate = format!("{}-mount-ready.service", input.unit_name);
    let periodic = format!("{}-periodic.timer", input.unit_name);
    let deadline = format!("{}-deadline.timer", input.unit_name);
    let ledger_mount_point = path_text(&input.ledger_mount_point)?;
    let mut files = BTreeMap::new();
    files.insert(
        service.clone(),
        format!(
            "# UNINSTALLED: operator review and activation required.\n\
         [Unit]\nDescription=Zcash RPC experiment watchdog\nBindsTo={ledger_mount_unit}\nAfter={ledger_mount_unit}\nConditionPathIsMountPoint={ledger_mount_point}\nRequiresMountsFor={ledger_mount_point}\nStartLimitIntervalSec=0\n\n\
         [Service]\nType=oneshot\nUser={}\nUMask=0077\nNoNewPrivileges=yes\n\
         ExecStart={}\nTimeoutStartSec={}ms\nTimeoutStartFailureMode=kill\n\
         Restart=no\nRemainAfterExit=no\n",
            input.service_user, command, timing.process_runtime_bound_ms,
        ),
    );
    files.insert(
        gate.clone(),
        format!(
            "# UNINSTALLED: operator review and activation required.\n\
         [Unit]\nDescription=Zcash RPC experiment watchdog mount gate\nBindsTo={ledger_mount_unit}\nAfter={ledger_mount_unit}\nConditionPathIsMountPoint={ledger_mount_point}\nWants={periodic} {deadline}\nBefore={periodic} {deadline}\n\n\
         [Service]\nType=oneshot\nUser={}\nUMask=0077\nNoNewPrivileges=yes\nExecStart=/usr/bin/true\nRemainAfterExit=yes\nRestart=no\n\n\
         [Install]\nWantedBy={ledger_mount_unit}\n",
            input.service_user,
        ),
    );
    // Wants initiates a check when either timer is started. BindsTo/After keeps
    // each timer behind the gate, including a manual start, and stops it when
    // the mount-bound gate goes away. Timer units order themselves before their
    // triggered service. OnUnitInactiveSec follows a failed service's inactive
    // timestamp.
    let timer = |role: &str, trigger: &str| {
        format!(
            "# UNINSTALLED: operator review and activation required.\n\
         [Unit]\nDescription=Zcash RPC experiment {role}\nBindsTo={gate}\nAfter={gate}\nWants={service}\n\n\
         [Timer]\n{trigger}\nUnit={service}\nAccuracySec=1us\nRandomizedDelaySec=0\n"
        )
    };
    files.insert(
        periodic,
        timer(
            "periodic watchdog",
            &format!("OnUnitInactiveSec={}us", timing.periodic_gap_microseconds),
        ),
    );
    files.insert(
        deadline,
        timer(
            "absolute deadline",
            &format!(
                "OnCalendar={}\nPersistent=true",
                timing.absolute_calendar_utc
            ),
        ),
    );
    Ok(WatchdogBundle {
        mode: "offline_uninstalled_watchdog_bundle",
        systemd_contract_version: "255",
        original_binding: ledger.binding().clone(),
        committed_ledger: reference,
        generated_at_unix_millis: now,
        service_user: input.service_user,
        ledger_mount_point: input.ledger_mount_point,
        ledger_mount_unit,
        executable: input.executable,
        command_arguments: args,
        timing,
        decision_at_generation: decision,
        files,
        required_receipts: vec![
            RequiredReceipt::ReviewedLiveProviderAdapter,
            RequiredReceipt::ExternalPersistentStoreAndCredentialAccess,
            RequiredReceipt::PeriodicAndAbsoluteJobInstallation,
            RequiredReceipt::MeasuredDetectionAndDeletionLatency,
            RequiredReceipt::CompleteResourceReadbackAndIndependentDiskEvidence,
            RequiredReceipt::FinalBillingReconciliation,
            RequiredReceipt::SuccessfulLiveDeletionTest,
            RequiredReceipt::IndependentBackstop,
            RequiredReceipt::ExplicitOperatorActivation,
        ],
        jobs_installed: false,
        credentials_read: false,
        network_used: false,
        timing_verified: false,
        activation_authorized: false,
        deployment_enabled: false,
        private_accepted: false,
    })
}

/// Create files only in a new absolute private directory. Never write into the
/// retained ledger, replace an output, copy credentials, invoke an executable or
/// contact systemd. The manifest is published last; any failure leaves evidence
/// for inspection and requires a different new destination, not an overwrite.
/// The operator must control parent directories (as with the ledger itself).
pub fn write_new(bundle: &WatchdogBundle, output_directory: &Path) -> Result<(), LifecycleError> {
    path_text(output_directory)?;
    let store = bundle
        .committed_ledger
        .snapshot_path()
        .parent()
        .ok_or(INVALID)?;
    let parent = output_directory
        .parent()
        .ok_or(INVALID)?
        .canonicalize()
        .map_err(|_| OUTPUT)?;
    let destination = parent.join(output_directory.file_name().ok_or(INVALID)?);
    if destination.starts_with(fs::canonicalize(store).map_err(|_| OUTPUT)?) {
        return Err(INVALID);
    }
    // Serialize before creating the output so an in-memory failure leaves no
    // partial directory. Private fields and no Deserialize prevent forged names.
    let manifest = serde_json::to_vec_pretty(bundle).map_err(|_| OUTPUT)?;
    DirBuilder::new()
        .mode(0o700)
        .create(&destination)
        .map_err(|_| OUTPUT)?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(&destination)
        .map_err(|_| OUTPUT)?;
    let write = |name: &str, bytes: &[u8]| -> Result<(), LifecycleError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(destination.join(name))
            .map_err(|_| OUTPUT)?;
        file.write_all(bytes).map_err(|_| OUTPUT)?;
        file.sync_all().map_err(|_| OUTPUT)
    };
    for (name, content) in &bundle.files {
        write(name, content.as_bytes())?;
    }
    write("manifest.json", &manifest)?;
    directory.sync_all().map_err(|_| OUTPUT)?;
    File::open(parent)
        .and_then(|parent| parent.sync_all())
        .map_err(|_| OUTPUT)?;
    Ok(())
}

#[cfg(test)]
mod tests;
