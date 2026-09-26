use super::*;
use crate::{
    MAX_LIFETIME_SECONDS,
    controller::{ExperimentLedger, TrackedCvm},
    persistence::create_original_binding,
};
use std::{
    os::unix::fs::{PermissionsExt, symlink},
    sync::atomic::{AtomicU64, Ordering},
};

const START: u64 = 1_767_225_600;
const EXPERIMENT: &str = "synthetic %n $USER experiment";
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let base =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.codex-tmp/schedule-tests");
        fs::create_dir_all(&base).unwrap();
        let path = base.canonicalize().unwrap().join(format!(
            "{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        let fixture = Self(path);
        let binding = ExperimentBinding::new(
            EXPERIMENT.into(),
            "synthetic_workspace".into(),
            START,
            START + MAX_LIFETIME_SECONDS,
        )
        .unwrap();
        let mut ledger = ExperimentLedger::new(binding, 17).unwrap();
        ledger.begin_attempt("first".into(), START).unwrap();
        ledger
            .track_cvm(
                "synthetic_workspace",
                "first",
                TrackedCvm {
                    cvm_id: "synthetic-cvm".into(),
                    app_id: "synthetic-app".into(),
                    instance_id: "synthetic-instance".into(),
                    created_at_unix_seconds: START,
                    compute_and_disk_microusd_per_hour: 243_120,
                },
            )
            .unwrap();
        create_original_binding(&fixture.original(), &fixture.state(), &ledger).unwrap();
        drop(LedgerStore::initialize(&fixture.original()).unwrap());
        fixture
    }
    fn original(&self) -> PathBuf {
        self.0.join("original %n $USER.json")
    }
    fn state(&self) -> PathBuf {
        self.0.join("state")
    }
    fn open(&self) -> LedgerStore {
        LedgerStore::open(&self.original()).unwrap()
    }
    fn input(&self) -> BundleInput {
        BundleInput {
            experiment_id: EXPERIMENT.into(),
            executable: self.0.join("missing binary %n"),
            service_user: 1000,
            unit_name: "synthetic-watchdog".into(),
            api_key_file: self.0.join("unread-key"),
            trust_root_der_files: vec![self.0.join("missing root.der")],
            invocation_budget: Duration::from_millis(3000),
            max_input_file_bytes: NonZeroUsize::new(1).unwrap(),
            max_response_bytes: NonZeroUsize::new(1).unwrap(),
            limits: ObservationLimits {
                inventory_page_size: 30,
                usage_page_size: 500,
                max_inventory_records: NonZeroUsize::new(1).unwrap(),
                max_usage_records_per_app: NonZeroUsize::new(1).unwrap(),
            },
            policy: WatchdogPolicy {
                maximum_detection_interval: Duration::from_secs(120),
                deletion_latency_upper_bound: Duration::from_secs(60),
                scheduler_delay_allowance: Duration::from_secs(60),
                reconciliation_budget: Duration::from_secs(1),
                deletion_dispatch_budget: Duration::from_secs(2),
                fee_upper_bounds_microusd: 0,
            },
            process_runtime_bound: Duration::from_secs(5),
            manager_delay_allowance: Duration::from_secs(1),
        }
    }
    fn bytes(&self) -> Vec<(PathBuf, Vec<u8>)> {
        let mut result = vec![(self.original(), fs::read(self.original()).unwrap())];
        for entry in fs::read_dir(self.state()).unwrap() {
            let path = entry.unwrap().path();
            result.push((path.clone(), fs::read(path).unwrap()));
        }
        result.sort_by(|a, b| a.0.cmp(&b.0));
        result
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn generated_jobs_share_one_service_and_preserve_original_policy_and_current_history() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    // A prior pending intent does not reset the export's scope or deadline.
    drop(
        store
            .prepare_deletion(0, "synthetic_workspace", "synthetic-cvm", START)
            .unwrap(),
    );
    let before = fixture.bytes();
    let bundle = generate_at(
        &store,
        fixture.input(),
        (START + MAX_LIFETIME_SECONDS + 1) * 1000,
    )
    .unwrap();
    assert_eq!(bundle.committed_ledger.generation(), 1);
    assert_eq!(bundle.original_binding, *store.ledger().unwrap().binding());
    assert!(bundle.decision_at_generation.deletion_required());
    assert_eq!(bundle.files.len(), 3);
    let service = &bundle.files["synthetic-watchdog.service"];
    for directive in [
        "Type=oneshot\n",
        "User=1000\n",
        "UMask=0077\n",
        "NoNewPrivileges=yes\n",
        "TimeoutStartSec=5000ms\n",
        "TimeoutStartFailureMode=kill\n",
        "StartLimitIntervalSec=0\n",
        "Restart=no\n",
        "RemainAfterExit=no\n",
    ] {
        assert!(service.contains(directive), "{directive}");
    }
    assert!(service.contains("original %%n $$USER.json"));
    assert!(service.contains("synthetic %%n $$USER experiment"));
    for name in [
        "synthetic-watchdog-periodic.timer",
        "synthetic-watchdog-deadline.timer",
    ] {
        let timer = &bundle.files[name];
        assert!(timer.contains("Wants=synthetic-watchdog.service\n"));
        assert!(timer.contains("Unit=synthetic-watchdog.service\n"));
        assert!(timer.contains("AccuracySec=1us\nRandomizedDelaySec=0\n"));
        assert!(timer.contains("WantedBy=timers.target\n"));
    }
    assert!(
        bundle.files["synthetic-watchdog-periodic.timer"]
            .contains("OnUnitInactiveSec=52999999us\n")
    );
    assert!(
        bundle.files["synthetic-watchdog-deadline.timer"]
            .contains("OnCalendar=2026-01-07 23:58:00.000000 UTC\nPersistent=true\n")
    );
    let args = &bundle.command_arguments;
    assert!(
        !args
            .iter()
            .any(|a| a == "--expected-generation" || a == "--now" || a == "--simulate")
    );
    for (flag, value) in [
        ("--original-binding", fixture.original().to_str().unwrap()),
        ("--experiment-id", EXPERIMENT),
        ("--invocation-budget-ms", "3000"),
        ("--scheduler-delay-allowance-ms", "60000"),
    ] {
        assert_eq!(
            args[args.iter().position(|a| a == flag).unwrap() + 1],
            value
        );
    }
    assert_eq!(fixture.bytes(), before);
    let value = serde_json::to_value(&bundle).unwrap();
    for field in [
        "jobs_installed",
        "credentials_read",
        "network_used",
        "timing_verified",
        "activation_authorized",
        "deployment_enabled",
        "private_accepted",
    ] {
        assert_eq!(value[field], false);
    }
}

#[test]
fn credential_fifo_and_missing_executable_and_trust_root_are_never_opened() {
    let fixture = Fixture::new();
    let input = fixture.input();
    let name = std::ffi::CString::new(input.api_key_file.to_str().unwrap()).unwrap();
    // A reader would block without a writer. Export only retains the path.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let store = fixture.open();
    assert!(generate(&store, input).is_ok());
}

#[test]
fn export_creates_private_new_files_without_overwrite_or_ledger_mutation() {
    let fixture = Fixture::new();
    let store = fixture.open();
    let before = fixture.bytes();
    let bundle = generate(&store, fixture.input()).unwrap();
    let output = fixture.0.join("new-bundle");
    write_new(&bundle, &output).unwrap();
    assert_eq!(
        fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(fs::read_dir(&output).unwrap().count(), 4);
    for (name, text) in &bundle.files {
        let path = output.join(name);
        assert_eq!(fs::read_to_string(&path).unwrap(), *text);
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let manifest = fs::read(output.join("manifest.json")).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&manifest).unwrap(),
        serde_json::to_value(&bundle).unwrap()
    );
    assert!(write_new(&bundle, &output).is_err());
    assert_eq!(fs::read(output.join("manifest.json")).unwrap(), manifest);
    assert_eq!(fixture.bytes(), before);
    assert!(write_new(&bundle, &fixture.state().join("nested-output")).is_err());
    let alias = fixture.0.join("state-alias");
    symlink(fixture.state(), &alias).unwrap();
    assert!(write_new(&bundle, &alias.join("nested-output")).is_err());
    let alias_output = fixture.0.join("existing-output-alias");
    symlink(&output, &alias_output).unwrap();
    assert!(write_new(&bundle, &alias_output).is_err());
    assert!(write_new(&bundle, Path::new("relative")).is_err());
    assert_eq!(fixture.bytes(), before);
}

#[test]
fn mismatched_identity_invalid_paths_names_user_and_limits_are_rejected() {
    let fixture = Fixture::new();
    let store = fixture.open();
    let mut wrong = fixture.input();
    wrong.experiment_id = "different".into();
    assert!(generate(&store, wrong).is_err());
    for user in [0, u32::MAX] {
        let mut input = fixture.input();
        input.service_user = user;
        assert!(generate(&store, input).is_err());
    }
    for name in [
        "",
        "../escape",
        "unit.service",
        "unit@instance",
        "unit\n[Service]",
        "unit%n",
        "unit/name",
        "-name",
    ] {
        let mut input = fixture.input();
        input.unit_name = name.into();
        assert!(generate(&store, input).is_err());
    }
    let mut too_long = fixture.input();
    too_long.unit_name = "a".repeat(SYSTEMD_UNIT_NAME_BYTES - "-periodic.timer".len() + 1);
    assert!(generate(&store, too_long).is_err());
    for path in [
        "relative",
        "/operator/../key",
        "/operator/./key",
        "/operator/key\nExecStart=other",
    ] {
        let mut input = fixture.input();
        input.api_key_file = path.into();
        assert!(generate(&store, input).is_err());
    }
    let mut input = fixture.input();
    input.trust_root_der_files.clear();
    assert!(generate(&store, input).is_err());
    let mut input = fixture.input();
    input.limits.inventory_page_size = 101;
    assert!(generate(&store, input).is_err());
    let mut input = fixture.input();
    input.limits.usage_page_size = 5001;
    assert!(generate(&store, input).is_err());
}

#[test]
fn pending_or_changed_history_cannot_emit_a_bundle() {
    let fixture = Fixture::new();
    let store = fixture.open();
    fs::write(fixture.state().join("pending.json"), b"{}").unwrap();
    assert!(generate(&store, fixture.input()).is_err());
    drop(store);
    let fixture = Fixture::new();
    let store = fixture.open();
    fs::write(store.planning_reference().unwrap().snapshot_path(), b"{}").unwrap();
    assert!(generate(&store, fixture.input()).is_err());
}
