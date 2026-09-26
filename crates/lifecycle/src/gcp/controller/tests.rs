//! Synthetic provider and filesystem tests. No Google or hardware calls.
use super::*;
use crate::gcp::{
    digest,
    package::{Artifact, DeploymentSpec, Pricing},
    store::Journal,
};
use serde_json::json;
use std::{collections::BTreeMap, fs, path::PathBuf};

struct Fixture {
    root: PathBuf,
    state: PathBuf,
    package: Package,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("zrpc-gcp-synthetic-{}", uuid().unwrap()));
        fs::create_dir(&root).unwrap();
        let artifact_path = root.join("synthetic-artifact");
        fs::write(&artifact_path, b"SYNTHETIC - NOT A BOOTABLE IMAGE").unwrap();
        let a = Artifact {
            path: artifact_path,
            sha256: digest(b"SYNTHETIC - NOT A BOOTABLE IMAGE"),
        };
        let components = [
            "compute",
            "boot_disk",
            "public_data_disk",
            "image",
            "staging",
            "external_ip",
            "network",
            "taxes",
        ]
        .map(|k| (k.to_owned(), 1))
        .into();
        let spec = DeploymentSpec {
            schema_version: 1,
            experiment: "synthetic-evaluation".into(),
            project: "synthetic-project".into(),
            region: "us-central1".into(),
            zone: "us-central1-a".into(),
            machine_type: "c3-standard-4".into(),
            boot_disk_gib: 10,
            public_data_disk_gib: 10,
            subnet_cidr: "10.42.0.0/24".into(),
            wrapper_port: 8443,
            staging_bucket: "synthetic-staging-bucket".into(),
            start_unix_seconds: 1000,
            deadline_unix_seconds: 1000 + crate::MAX_LIFETIME_SECONDS,
            raw_image_tar_gz: a.clone(),
            release_manifest: a.clone(),
            boot_policy: a.clone(),
            memory_measurement: a.clone(),
            reproducibility_report: a.clone(),
            secure_boot_pk_der: a.clone(),
            secure_boot_kek_der: a.clone(),
            secure_boot_db_der: a.clone(),
            pricing: Pricing {
                source: "https://example.invalid/synthetic-quote".into(),
                quoted_at: 900,
                expires_at: 2000,
                projected_total_microusd: 8,
                components_microusd: components,
                evidence: a,
            },
        };
        let package = Package::prepare(spec, 1000).unwrap();
        let state = root.join("journal");
        Store::initialize(&state, &package).unwrap();
        Self {
            root,
            state,
            package,
        }
    }
    fn mock(&self) -> Mock {
        Mock {
            state: self.state.clone(),
            objects: BTreeMap::new(),
            operations: BTreeMap::new(),
            calls: Vec::new(),
            deletes: Vec::new(),
            fail_after_create: false,
            outage: false,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
struct Mock {
    state: PathBuf,
    objects: BTreeMap<String, Value>,
    operations: BTreeMap<String, Operation>,
    calls: Vec<String>,
    deletes: Vec<String>,
    fail_after_create: bool,
    outage: bool,
}
impl Mock {
    fn assert_committed(&self, request: &str) {
        let mut files = fs::read_dir(&self.state)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.file_name().unwrap().to_str().unwrap().len() == 25)
            .collect::<Vec<_>>();
        files.sort();
        let j: Journal = serde_json::from_slice(&fs::read(files.last().unwrap()).unwrap()).unwrap();
        assert!(
            j.resources.iter().any(|r| [&r.create, &r.delete]
                .iter()
                .any(|i| i.as_ref().is_some_and(|i| i.request_id == request))),
            "mutation observed before durable intent"
        );
        assert!(!self.state.join("pending.json").exists());
    }
    fn op(&self, r: &ResourcePlan, request: &str, id: &str) -> Operation {
        Operation {
            name: format!("operation-{request}"),
            status: "DONE".into(),
            target_link: format!("https://www.googleapis.com/compute/v1/{}", r.path),
            target_id: Some(id.into()),
            client_operation_id: Some(request.into()),
            error: None,
        }
    }
}
impl Provider for Mock {
    async fn preflight(&mut self, _: &Package) -> Result<()> {
        if self.outage {
            Err(Error("synthetic outage"))
        } else {
            Ok(())
        }
    }
    async fn get(&mut self, r: &ResourcePlan) -> Result<Option<Value>> {
        if self.outage {
            return Err(Error("synthetic outage"));
        }
        Ok(self.objects.get(&r.path).cloned())
    }
    async fn create(&mut self, _: &Package, r: &ResourcePlan, request: &str) -> Result<Mutation> {
        self.assert_committed(request);
        self.calls.push(request.into());
        let id = (self.objects.len() + 1).to_string();
        let object = if r.kind == ResourceKind::StagingObject {
            json!({"name":r.path.split("/o/").nth(1).unwrap(),"generation":id,"metadata":r.create_body})
        } else {
            json!({"id":id,"name":r.create_body["name"],"description":r.create_body["description"]})
        };
        self.objects.insert(r.path.clone(), object.clone());
        let response = if r.kind == ResourceKind::StagingObject {
            Mutation::Object(object)
        } else {
            let op = self.op(r, request, &id);
            self.operations.insert(request.into(), op.clone());
            Mutation::Operation(op)
        };
        if self.fail_after_create {
            self.fail_after_create = false;
            return Err(Error(
                "synthetic connection lost after provider accepted creation",
            ));
        }
        Ok(response)
    }
    async fn delete(&mut self, r: &ResourcePlan, id: &str, request: &str) -> Result<Mutation> {
        self.assert_committed(request);
        self.deletes.push(r.path.clone());
        self.objects.remove(&r.path);
        if r.kind == ResourceKind::StagingObject {
            return Ok(Mutation::Object(Value::Null));
        }
        let op = self.op(r, request, id);
        self.operations.insert(request.into(), op.clone());
        Ok(Mutation::Operation(op))
    }
    async fn operation(&mut self, _: &ResourcePlan, name: &str) -> Result<Operation> {
        self.operations
            .values()
            .find(|o| o.name == name)
            .cloned()
            .ok_or(Error("unknown synthetic operation"))
    }
    async fn recover_operation(
        &mut self,
        _: &ResourcePlan,
        request: &str,
    ) -> Result<Option<Operation>> {
        Ok(self.operations.get(request).cloned())
    }
}
async fn deploy_all(store: &mut Store, provider: &mut Mock, package: &Package) {
    for _ in &package.resources {
        assert_eq!(
            deploy_once(store, provider, 1000).await.unwrap(),
            Progress::Pending
        );
    }
    assert_eq!(
        deploy_once(store, provider, 1000).await.unwrap(),
        Progress::DeployedForSyntheticEvaluation
    );
}

#[tokio::test]
async fn create_intents_are_durable_and_cleanup_tracks_every_owned_resource() {
    let f = Fixture::new();
    let mut store = Store::open(&f.state).unwrap();
    let mut provider = f.mock();
    deploy_all(&mut store, &mut provider, &f.package).await;
    assert_eq!(provider.calls.len(), f.package.resources.len());
    for _ in &f.package.resources {
        assert_eq!(
            teardown_once(&mut store, &mut provider, 1001)
                .await
                .unwrap(),
            Progress::Pending
        );
    }
    assert_eq!(
        teardown_once(&mut store, &mut provider, 1001)
            .await
            .unwrap(),
        Progress::ResourcesAbsentBillingUnreconciled
    );
    assert_eq!(
        provider.deletes,
        f.package
            .resources
            .iter()
            .rev()
            .map(|r| r.path.clone())
            .collect::<Vec<_>>()
    );
    assert!(store.journal().resources.iter().all(|r| r.observed_absent));
    assert!(store.journal().billing_evidence_sha256.is_none());
}
#[tokio::test]
async fn billing_reference_is_post_cleanup_append_only_and_never_changes_status() {
    let f = Fixture::new();
    let mut store = Store::open(&f.state).unwrap();
    let mut provider = f.mock();
    let hash = digest(b"synthetic billing evidence, not reconciliation");

    let mut early = store.journal().clone();
    early.billing_evidence_sha256 = Some(hash.clone());
    assert!(store.commit(early).is_err());

    deploy_all(&mut store, &mut provider, &f.package).await;
    let mut before_cleanup = store.journal().clone();
    before_cleanup.teardown_started = true;
    before_cleanup.billing_evidence_sha256 = Some(hash.clone());
    assert!(store.commit(before_cleanup).is_err());

    for _ in &f.package.resources {
        assert_eq!(
            teardown_once(&mut store, &mut provider, 1001)
                .await
                .unwrap(),
            Progress::Pending
        );
    }
    assert_eq!(
        teardown_once(&mut store, &mut provider, 1002)
            .await
            .unwrap(),
        Progress::ResourcesAbsentBillingUnreconciled
    );
    let mut malformed = store.journal().clone();
    malformed.billing_evidence_sha256 = Some("not-a-sha256".into());
    assert!(store.commit(malformed).is_err());

    let mut recorded = store.journal().clone();
    recorded.billing_evidence_sha256 = Some(hash.clone());
    store.commit(recorded).unwrap();
    let mut replaced = store.journal().clone();
    replaced.billing_evidence_sha256 = Some(digest(b"replacement"));
    assert!(store.commit(replaced).is_err());
    let mut removed = store.journal().clone();
    removed.billing_evidence_sha256 = None;
    assert!(store.commit(removed).is_err());
    assert_eq!(
        teardown_once(&mut store, &mut provider, 1002)
            .await
            .unwrap(),
        Progress::ResourcesAbsentBillingUnreconciled
    );
    drop(store);
    assert_eq!(
        Store::open(&f.state)
            .unwrap()
            .journal()
            .billing_evidence_sha256,
        Some(hash)
    );
}
#[tokio::test]
async fn interrupted_creation_resumes_from_original_intent_after_restart() {
    let f = Fixture::new();
    let mut provider = f.mock();
    provider.fail_after_create = true;
    let id;
    {
        let mut store = Store::open(&f.state).unwrap();
        assert!(deploy_once(&mut store, &mut provider, 1000).await.is_err());
        id = store.journal().resources[0]
            .create
            .as_ref()
            .unwrap()
            .request_id
            .clone();
    }
    let mut store = Store::open(&f.state).unwrap();
    assert_eq!(
        store.journal().resources[0]
            .create
            .as_ref()
            .unwrap()
            .request_id,
        id
    );
    assert_eq!(
        deploy_once(&mut store, &mut provider, 1001).await.unwrap(),
        Progress::Pending
    );
    assert_eq!(
        provider
            .calls
            .iter()
            .filter(|request| **request == id)
            .count(),
        1
    );
    assert_eq!(store.journal().original_start, 1000);
}
#[tokio::test]
async fn compute_operation_recovery_preserves_request_identity() {
    let f = Fixture::new();
    let mut provider = f.mock();
    let mut store = Store::open(&f.state).unwrap();
    deploy_once(&mut store, &mut provider, 1000).await.unwrap();
    provider.fail_after_create = true;
    assert!(deploy_once(&mut store, &mut provider, 1000).await.is_err());
    let id = store.journal().resources[1]
        .create
        .as_ref()
        .unwrap()
        .request_id
        .clone();
    drop(store);
    let mut store = Store::open(&f.state).unwrap();
    deploy_once(&mut store, &mut provider, 1001).await.unwrap();
    assert!(store.journal().resources[1].create.as_ref().unwrap().done);
    assert_eq!(provider.calls.iter().filter(|r| **r == id).count(), 1);
}
#[tokio::test]
async fn rejects_early_late_and_tampered_deploy_without_provider_mutations() {
    let f = Fixture::new();
    let mut p = f.mock();
    let mut store = Store::open(&f.state).unwrap();
    assert!(deploy_once(&mut store, &mut p, 999).await.is_err());
    assert!(deploy_once(&mut store, &mut p, 2000).await.is_err());
    fs::write(
        &f.package.spec.raw_image_tar_gz.path,
        b"changed executable image",
    )
    .unwrap();
    assert!(deploy_once(&mut store, &mut p, 1000).await.is_err());
    assert!(p.calls.is_empty());
}
#[tokio::test]
async fn cleanup_survives_expired_quote_missing_image_and_outage() {
    let f = Fixture::new();
    let mut p = f.mock();
    let mut store = Store::open(&f.state).unwrap();
    deploy_all(&mut store, &mut p, &f.package).await;
    fs::remove_file(&f.package.spec.raw_image_tar_gz.path).unwrap();
    p.outage = true;
    assert!(teardown_once(&mut store, &mut p, 900000).await.is_err());
    assert!(store.journal().teardown_started);
    assert!(p.deletes.is_empty());
    p.outage = false;
    assert_eq!(
        teardown_once(&mut store, &mut p, 900001).await.unwrap(),
        Progress::Pending
    );
    assert_eq!(
        store.journal().original_deadline,
        f.package.spec.deadline_unix_seconds
    );
}
#[tokio::test]
async fn replacement_and_untracked_resources_are_never_deleted() {
    let f = Fixture::new();
    let mut p = f.mock();
    let mut store = Store::open(&f.state).unwrap();
    deploy_all(&mut store, &mut p, &f.package).await;
    let instance = f.package.resources.last().unwrap();
    p.objects.get_mut(&instance.path).unwrap()["id"] = json!("999");
    assert!(teardown_once(&mut store, &mut p, 1001).await.is_err());
    assert!(p.deletes.is_empty());
}
#[test]
fn locked_store_and_original_binding_cannot_reset() {
    let f = Fixture::new();
    let mut store = Store::open(&f.state).unwrap();
    assert!(Store::open(&f.state).is_err());
    assert!(Store::initialize(&f.state, &f.package).is_err());
    let mut next = store.journal().clone();
    next.original_deadline += 1;
    assert!(store.commit(next).is_err());
    let mut next = store.journal().clone();
    next.resources[0].create = Some(intent(1000).unwrap());
    store.commit(next).unwrap();
    let mut next = store.journal().clone();
    next.resources[0].create = None;
    assert!(store.commit(next).is_err());
}
#[test]
fn package_rejects_payload_mutation_and_does_not_apply_phala_cost_limit() {
    let f = Fixture::new();
    let mut package = f.package.clone();
    package.resources.last_mut().unwrap().create_body["serviceAccounts"] =
        json!([{"email":"default"}]);
    assert!(package.validate(1000).is_err());
    let mut spec = f.package.spec.clone();
    spec.pricing
        .components_microusd
        .insert("compute".into(), 500_000_000);
    spec.pricing.projected_total_microusd = 500_000_007;
    assert!(Package::prepare(spec, 1000).is_ok());
}
#[test]
fn journal_recovers_published_pending_commit_and_rejects_truncation() {
    let f = Fixture::new();
    let mut store = Store::open(&f.state).unwrap();
    let mut next = store.journal().clone();
    next.teardown_started = true;
    store.commit(next).unwrap();
    drop(store);
    fs::hard_link(
        f.state.join("00000000000000000001.json"),
        f.state.join("pending.json"),
    )
    .unwrap();
    assert!(Store::open(&f.state).is_err());
    Store::recover(&f.state).unwrap();
    assert!(Store::open(&f.state).unwrap().journal().teardown_started);
    fs::write(f.state.join("pending.json"), b"{truncated").unwrap();
    assert!(Store::recover(&f.state).is_err());
}
#[test]
fn operation_scope_uses_documented_global_regional_and_zonal_collections() {
    let f = Fixture::new();
    for (index, scope) in [
        (1, "global"),
        (2, "regions/us-central1"),
        (5, "zones/us-central1-a"),
    ] {
        assert_eq!(
            crate::gcp::provider::operation_path(&f.package.resources[index], "operation-example")
                .unwrap(),
            format!("/compute/v1/projects/synthetic-project/{scope}/operations/operation-example")
        );
    }
}

#[test]
fn live_creation_stays_blocked_until_compute_deletion_contract_is_resolved() {
    let error = crate::gcp::ensure_live_creation_ready().unwrap_err();
    assert!(error.0.contains("incarnation"));
}

#[test]
fn watchdog_deadline_includes_inflight_controller_and_exports_no_installer() {
    use crate::gcp::{provider::Runtime, watchdog::Controls};
    let f = Fixture::new();
    let artifact = f.package.spec.release_manifest.clone();
    let runtime = Runtime {
        gcloud: artifact.clone(),
        gcloud_distribution_receipt: artifact.clone(),
        gcloud_config_directory: f.root.join("credentials"),
        trust_roots_der: vec![artifact.clone()],
        invocation_budget_ms: 11_000,
        response_limit_bytes: 4096,
    };
    let runtime_bytes = serde_json::to_vec(&runtime).unwrap();
    let runtime_path = f.root.join("runtime.json");
    fs::write(&runtime_path, &runtime_bytes).unwrap();
    let controls = Controls {
        package_sha256: f.package.sha256().unwrap(),
        executable: artifact.clone(),
        runtime_file: Artifact {
            path: runtime_path,
            sha256: digest(&runtime_bytes),
        },
        state_directory: f.state.clone(),
        controller_machine_id: "a".repeat(32),
        controller_uid: 1000,
        poll_interval_seconds: 20,
        deletion_duration_seconds: 100,
        systemd_delay_seconds: 3,
        deletion_rehearsal: artifact.clone(),
        independent_backstop: artifact,
    };
    assert_eq!(
        controls.deletion_start(&f.package).unwrap(),
        f.package.spec.deadline_unix_seconds - (11 + 20 + 100 + 3)
    );
    let units = controls
        .units(&f.package, &f.root.join("controls.json"))
        .unwrap();
    assert_eq!(units.len(), 3);
    assert!(units.values().any(|s| s.contains("Persistent=true")));
    assert!(units.values().any(|s| s.contains("watchdog-once --state")));
    assert!(
        units
            .values()
            .all(|s| !s.contains("systemctl enable") && !s.contains(" deploy "))
    );
}
