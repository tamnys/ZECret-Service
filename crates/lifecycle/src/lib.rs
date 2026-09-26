//! Cost accounting, local persistence and explicitly invoked provider reads.
//! No provider mutation, scheduler, deployment or private-query path is exposed.

use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt, fs, io::Write, path::Path};

#[cfg(unix)]
pub mod activation;
pub mod amount;
pub mod controller;
#[cfg(unix)]
pub mod persistence;
pub mod provider_http;
#[cfg(unix)]
pub mod provider_inputs;
mod provider_request;
pub mod provider_wire;

// Authorities: design section 13 sets the lifetime, preflight ceiling and
// deletion trigger. The operator's subsequent $50 total cap supersedes its
// original approximately $60 overall ceiling; credited funds do not authorize spending.
pub const MAX_LIFETIME_SECONDS: u64 = 168 * 60 * 60;
pub const PLAN_CEILING_MICROUSD: u64 = 50_000_000;
pub const TOTAL_CEILING_MICROUSD: u64 = 50_000_000;
pub const DELETE_THRESHOLD_MICROUSD: u64 = 45_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleError(pub &'static str);

impl fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for LifecycleError {}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QuoteSource {
    SyntheticFixture,
    /// An operator transcription, not evidence of provider verification.
    OperatorSupplied,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Quote {
    pub source: QuoteSource,
    pub reference: String,
    pub quoted_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub instance_type: String,
    pub vcpu: u64,
    pub memory_gib: u64,
    pub disk_gib: u64,
    pub confirmed_disk_limit_gib: u64,
    pub availability_confirmed: bool,
    pub compute_microusd_per_hour: u64,
    pub disk_microusd_per_gib_hour: u64,
    pub network_total_upper_bound_microusd: Option<u64>,
    pub tax_and_payment_total_upper_bound_microusd: Option<u64>,
    pub other_total_upper_bound_microusd: Option<u64>,
    pub network_allowance_reviewed: bool,
    pub all_charge_categories_reviewed: bool,
    /// Cash commitments are disclosed separately; credits do not lower usage.
    pub minimum_account_funding_microusd: Option<u64>,
    pub preauthorization_microusd: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExistingResourceCost {
    pub resource_id: String,
    pub remaining_microusd_per_hour: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalControls {
    pub absolute_deadline_job_reference: String,
    pub watchdog_reference: String,
    pub independent_backstop_reference: String,
    pub successful_deletion_test_reference: String,
    /// Operator-selected interval; no scheduler is installed by this crate.
    pub maximum_poll_interval_seconds: u64,
    pub deletion_latency_upper_bound_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanInput {
    pub quote: Quote,
    pub evaluated_at_unix_seconds: u64,
    pub start_unix_seconds: u64,
    pub deletion_deadline_unix_seconds: Option<u64>,
    pub accrued_experiment_microusd: u64,
    pub existing_resources: Vec<ExistingResourceCost>,
    pub external_controls: Option<ExternalControls>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CostPlan {
    pub quote_source: QuoteSource,
    pub arithmetic_only: bool,
    pub deployment_enabled: bool,
    pub duration_seconds: u64,
    pub projected_compute_microusd: u64,
    pub projected_disk_microusd: u64,
    pub projected_existing_microusd: u64,
    pub fee_upper_bounds_microusd: u64,
    pub accrued_experiment_microusd: u64,
    pub projected_total_microusd: u64,
    pub remaining_overall_ceiling_microusd: u64,
    pub minimum_account_funding_microusd: u64,
    pub preauthorization_microusd: u64,
    pub blockers: Vec<String>,
}

fn add(a: u64, b: u64) -> Result<u64, LifecycleError> {
    a.checked_add(b).ok_or(LifecycleError("cost overflow"))
}

/// Round *up* to a microdollar so partial hours never understate cost.
fn duration_cost(rate: u64, seconds: u64) -> Result<u64, LifecycleError> {
    let numerator = u128::from(rate) * u128::from(seconds);
    u64::try_from(numerator.div_ceil(3600)).map_err(|_| LifecycleError("cost overflow"))
}

fn nonempty(value: &str) -> bool {
    !value.trim().is_empty()
}

pub fn plan(input: &PlanInput) -> Result<CostPlan, LifecycleError> {
    let q = &input.quote;
    let deadline = input
        .deletion_deadline_unix_seconds
        .ok_or(LifecycleError("absolute deletion deadline required"))?;
    let duration = deadline
        .checked_sub(input.start_unix_seconds)
        .filter(|duration| *duration > 0 && *duration <= MAX_LIFETIME_SECONDS)
        .ok_or(LifecycleError(
            "hosting duration must be positive and at most 168 hours",
        ))?;
    if input.evaluated_at_unix_seconds > input.start_unix_seconds
        || q.quoted_at_unix_seconds > input.evaluated_at_unix_seconds
        || q.expires_at_unix_seconds <= input.start_unix_seconds
        || q.expires_at_unix_seconds <= q.quoted_at_unix_seconds
        || !nonempty(&q.reference)
    {
        return Err(LifecycleError("missing, expired, or inconsistent quote"));
    }
    // The baseline is the approved size, not permission to silently upgrade.
    if q.instance_type != "tdx.large"
        || q.vcpu != 4
        || q.memory_gib != 8
        || q.disk_gib != 80
        || q.disk_gib > q.confirmed_disk_limit_gib
        || !q.availability_confirmed
    {
        return Err(LifecycleError(
            "unconfirmed or changed baseline resource shape; revised plan required",
        ));
    }
    if !q.network_allowance_reviewed || !q.all_charge_categories_reviewed {
        return Err(LifecycleError(
            "network allowances and all charge categories must be reviewed",
        ));
    }
    if q.compute_microusd_per_hour == 0 || q.disk_microusd_per_gib_hour == 0 {
        return Err(LifecycleError(
            "usage rates must exclude promotional credits",
        ));
    }
    let network = q
        .network_total_upper_bound_microusd
        .ok_or(LifecycleError("network cost upper bound required"))?;
    let tax_payment = q
        .tax_and_payment_total_upper_bound_microusd
        .ok_or(LifecycleError("tax and payment fee upper bound required"))?;
    let other = q
        .other_total_upper_bound_microusd
        .ok_or(LifecycleError("other fees upper bound required"))?;
    let funding = q
        .minimum_account_funding_microusd
        .ok_or(LifecycleError("minimum account funding must be confirmed"))?;
    let preauthorization = q
        .preauthorization_microusd
        .ok_or(LifecycleError("preauthorization must be confirmed"))?;
    let controls = input.external_controls.as_ref().ok_or(LifecycleError(
        "external deadline and cleanup controls required",
    ))?;
    if !nonempty(&controls.absolute_deadline_job_reference)
        || !nonempty(&controls.watchdog_reference)
        || !nonempty(&controls.independent_backstop_reference)
        || !nonempty(&controls.successful_deletion_test_reference)
        || controls.maximum_poll_interval_seconds == 0
    {
        return Err(LifecycleError(
            "external deadline, watchdog, backstop, and successful deletion evidence required",
        ));
    }
    let disk_rate = q
        .disk_microusd_per_gib_hour
        .checked_mul(q.disk_gib)
        .ok_or(LifecycleError("cost overflow"))?;
    let compute = duration_cost(q.compute_microusd_per_hour, duration)?;
    let disk = duration_cost(disk_rate, duration)?;
    let mut existing_rate = 0;
    let mut resource_ids = std::collections::BTreeSet::new();
    for resource in &input.existing_resources {
        if !nonempty(&resource.resource_id) || !resource_ids.insert(&resource.resource_id) {
            return Err(LifecycleError(
                "existing resource IDs must be nonempty and unique",
            ));
        }
        existing_rate = add(existing_rate, resource.remaining_microusd_per_hour)?;
    }
    // Existing resources keep billing while the new VM is waiting to start.
    // Accrued cost is the amount through evaluation; project the remaining
    // existing-resource cost from evaluation through the deletion deadline.
    let existing_duration = deadline
        .checked_sub(input.evaluated_at_unix_seconds)
        .ok_or(LifecycleError("evaluation occurs after deletion deadline"))?;
    let existing = duration_cost(existing_rate, existing_duration)?;
    let fees = add(add(network, tax_payment)?, other)?;
    let total = add(
        add(add(add(compute, disk)?, existing)?, fees)?,
        input.accrued_experiment_microusd,
    )?;
    if total > PLAN_CEILING_MICROUSD {
        return Err(LifecycleError(
            "projected infrastructure usage exceeds the $50 planning ceiling",
        ));
    }
    if input.accrued_experiment_microusd >= DELETE_THRESHOLD_MICROUSD {
        return Err(LifecycleError(
            "accrued cost already requires teardown at $45",
        ));
    }
    let hourly = add(add(q.compute_microusd_per_hour, disk_rate)?, existing_rate)?;
    let detection_and_deletion = add(
        controls.maximum_poll_interval_seconds,
        controls.deletion_latency_upper_bound_seconds,
    )?;
    let delayed_cost = duration_cost(hourly, detection_and_deletion)?;
    // Derived bound: the modeled detection/deletion delay cannot consume the
    // $5 margin between the design's $45 trigger and the operator's $50 total cap.
    // This arithmetic is not a guaranteed cap or proof that a job will run.
    if add(add(DELETE_THRESHOLD_MICROUSD, delayed_cost)?, fees)? > TOTAL_CEILING_MICROUSD {
        return Err(LifecycleError(
            "modeled watchdog/deletion delay and fees exceed the $50 total ceiling margin",
        ));
    }
    let mut blockers = vec![
        "M0: deployment is disabled; no cloud resource or scheduler is created".to_owned(),
        "Gates A-E require independently reviewed live evidence".to_owned(),
        "External control references are operator assertions, not scheduler verification".to_owned(),
        "Provider quote, inventory, residual resources, and actual charges require operator verification".to_owned(),
        "Polling and deadline jobs are not guaranteed provider-enforced spending caps".to_owned(),
    ];
    if q.source == QuoteSource::SyntheticFixture {
        blockers.push(
            "SIMULATION: synthetic quote and controls cannot authorize deployment".to_owned(),
        );
    }
    Ok(CostPlan {
        quote_source: q.source,
        arithmetic_only: true,
        deployment_enabled: false,
        duration_seconds: duration,
        projected_compute_microusd: compute,
        projected_disk_microusd: disk,
        projected_existing_microusd: existing,
        fee_upper_bounds_microusd: fees,
        accrued_experiment_microusd: input.accrued_experiment_microusd,
        projected_total_microusd: total,
        remaining_overall_ceiling_microusd: TOTAL_CEILING_MICROUSD - total,
        minimum_account_funding_microusd: funding,
        preauthorization_microusd: preauthorization,
        blockers,
    })
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManifestSource {
    SyntheticFixture,
    OperatorSupplied,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    VirtualMachine,
    PersistentDisk,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResourceState {
    Running,
    Stopped,
    Deleted,
    DeletionFailed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    pub id: String,
    pub kind: ResourceKind,
    pub state: ResourceState,
    pub microusd_per_hour: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentManifest {
    pub source: ManifestSource,
    pub experiment_id: String,
    pub started_at_unix_seconds: u64,
    pub deletion_deadline_unix_seconds: Option<u64>,
    pub initial_cost_microusd: u64,
    pub quote_reference: String,
    pub resources: Vec<Resource>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WatchdogAction {
    ContinueMonitoring,
    DeleteAll,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchdogDecision {
    pub simulation: bool,
    pub action: WatchdogAction,
    pub conservative_cost_microusd: u64,
    pub reasons: Vec<String>,
    pub provider_action_performed: bool,
}

/// A decision only. It never schedules a job or calls a provider API.
pub fn watchdog(
    manifest: &DeploymentManifest,
    now_unix_seconds: u64,
    observed_accrued_microusd: u64,
) -> Result<WatchdogDecision, LifecycleError> {
    let mut reasons = Vec::new();
    let mut rate = 0;
    for resource in &manifest.resources {
        rate = add(rate, resource.microusd_per_hour)?;
    }
    let elapsed = now_unix_seconds
        .checked_sub(manifest.started_at_unix_seconds)
        .ok_or(LifecycleError("watchdog clock precedes experiment start"))?;
    // Includes all original rates even after stop/delete: conservative history
    // until real billing data is inspected. Stopped storage is never free.
    let cost = add(
        manifest.initial_cost_microusd,
        duration_cost(rate, elapsed)?,
    )?
    .max(observed_accrued_microusd);
    let valid_deadline = manifest.deletion_deadline_unix_seconds.filter(|deadline| {
        deadline
            .checked_sub(manifest.started_at_unix_seconds)
            .is_some_and(|duration| duration > 0 && duration <= MAX_LIFETIME_SECONDS)
    });
    match valid_deadline {
        None => reasons.push("missing or invalid deadline; delete immediately".to_owned()),
        Some(deadline) if now_unix_seconds >= deadline => {
            reasons.push("absolute deletion deadline reached".to_owned())
        }
        Some(_) => (),
    }
    if cost >= DELETE_THRESHOLD_MICROUSD {
        reasons.push("conservative cumulative cost reached $45".to_owned());
    }
    let action = if !reasons.is_empty() {
        WatchdogAction::DeleteAll
    } else {
        WatchdogAction::ContinueMonitoring
    };
    Ok(WatchdogDecision {
        simulation: manifest.source == ManifestSource::SyntheticFixture,
        action,
        conservative_cost_microusd: cost,
        reasons,
        provider_action_performed: false,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanupReport {
    pub simulation: bool,
    pub provider_action_performed: bool,
    pub deletion_confirmed_in_simulator: bool,
    pub deleted_ids: Vec<String>,
    pub residual_ids: Vec<String>,
    pub failed_ids: Vec<String>,
    pub actual_charges_verified: bool,
}

/// Deliberately named and limited in-memory fixture adapter. No real adapter is
/// implemented; no environment variable can select one.
#[derive(Debug, Default)]
pub struct SimulatedProvider {
    resources: BTreeMap<String, Resource>,
    delete_failures: std::collections::BTreeSet<String>,
}

impl SimulatedProvider {
    pub fn new(resources: Vec<Resource>) -> Result<Self, LifecycleError> {
        let mut provider = Self::default();
        for resource in resources {
            if !nonempty(&resource.id) || provider.resources.contains_key(&resource.id) {
                return Err(LifecycleError("resource IDs must be nonempty and unique"));
            }
            provider.resources.insert(resource.id.clone(), resource);
        }
        Ok(provider)
    }

    pub fn fail_deletion(&mut self, resource_id: String) {
        self.delete_failures.insert(resource_id);
    }
}

pub fn cleanup_with_simulator(
    manifest: &mut DeploymentManifest,
    provider: &mut SimulatedProvider,
) -> Result<CleanupReport, LifecycleError> {
    if manifest.source != ManifestSource::SyntheticFixture {
        return Err(LifecycleError(
            "M0 teardown accepts only synthetic fixture manifests; no provider adapter exists",
        ));
    }
    let mut deleted = Vec::new();
    let mut failed = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for resource in &manifest.resources {
        if !nonempty(&resource.id) || !seen.insert(&resource.id) {
            return Err(LifecycleError("resource IDs must be nonempty and unique"));
        }
    }
    for resource in &mut manifest.resources {
        if provider.delete_failures.contains(&resource.id) {
            failed.push(resource.id.clone());
            resource.state = ResourceState::DeletionFailed;
            continue;
        }
        // Idempotent absence is a successful simulator deletion.
        if let Some(actual) = provider.resources.get_mut(&resource.id) {
            actual.state = ResourceState::Deleted;
        }
        resource.state = ResourceState::Deleted;
        deleted.push(resource.id.clone());
    }
    // Inspect the experiment-scoped inventory, not only the creation manifest:
    // this catches a resource created just before a partial-creation failure.
    // Unrecorded resources are reported, never silently deleted by wildcard.
    let residual: Vec<String> = provider
        .resources
        .values()
        .filter(|resource| resource.state != ResourceState::Deleted)
        .map(|resource| resource.id.clone())
        .collect();
    Ok(CleanupReport {
        simulation: true,
        provider_action_performed: false,
        deletion_confirmed_in_simulator: residual.is_empty() && failed.is_empty(),
        deleted_ids: deleted,
        residual_ids: residual,
        failed_ids: failed,
        actual_charges_verified: false,
    })
}

pub fn simulated_teardown(
    manifest: &mut DeploymentManifest,
) -> Result<CleanupReport, LifecycleError> {
    let mut provider = SimulatedProvider::new(manifest.resources.clone())?;
    cleanup_with_simulator(manifest, &mut provider)
}

/// Store only an operator lifecycle manifest, never customer query data.
/// The caller must persist each newly returned resource ID before creating the
/// next resource. M0 has no creation operation.
pub fn write_manifest(
    path: &Path,
    manifest: &DeploymentManifest,
) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = serde_json::to_vec_pretty(manifest)?;
    let file_name = path
        .file_name()
        .ok_or(LifecycleError("manifest path has no filename"))?;
    let pending = path.with_file_name(format!("{}.pending", file_name.to_string_lossy()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pending)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(&pending, path)?;
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> PlanInput {
        serde_json::from_str(include_str!("../../../deploy/plan.fixture.json")).unwrap()
    }
    fn manifest() -> DeploymentManifest {
        serde_json::from_str(include_str!("../../../deploy/manifest.fixture.json")).unwrap()
    }

    #[test]
    fn baseline_is_exact_and_never_enables_deployment() {
        let report = plan(&input()).unwrap();
        assert_eq!(report.projected_compute_microusd, 38_976_000);
        assert_eq!(report.projected_disk_microusd, 1_868_160);
        assert_eq!(report.projected_total_microusd, 40_844_160);
        assert_eq!(report.remaining_overall_ceiling_microusd, 9_155_840);
        assert!(!report.deployment_enabled);
        let mut actual = input();
        actual.quote.source = QuoteSource::OperatorSupplied;
        assert!(!plan(&actual).unwrap().deployment_enabled);
    }

    #[test]
    fn all_cost_categories_and_existing_resources_count() {
        let mut input = input();
        input.accrued_experiment_microusd = 1_000_000;
        input.quote.network_total_upper_bound_microusd = Some(1_000_000);
        input.quote.tax_and_payment_total_upper_bound_microusd = Some(2_000_000);
        input.quote.other_total_upper_bound_microusd = Some(1_000_000);
        input.existing_resources.push(ExistingResourceCost {
            resource_id: "fixture-existing-disk".into(),
            remaining_microusd_per_hour: 1000,
        });
        assert_eq!(plan(&input).unwrap().projected_total_microusd, 46_012_160);
        input.quote.other_total_upper_bound_microusd = Some(6_000_000);
        assert!(plan(&input).is_err());
    }

    #[test]
    fn deletion_delay_and_fees_must_fit_five_dollar_reserve() {
        let mut candidate = input();
        // The fixture's one-hour poll interval costs $0.24312. At the existing
        // $45 trigger, $4.75688 of fees exactly exhausts the new $50 total cap.
        candidate.quote.tax_and_payment_total_upper_bound_microusd = Some(4_756_880);
        let report = plan(&candidate).unwrap();
        assert_eq!(report.projected_total_microusd, 45_601_040);

        // One additional microdollar still fits the $50 projected-usage gate,
        // and would fit the former $15 reserve, but exceeds the new $5 reserve.
        candidate.quote.tax_and_payment_total_upper_bound_microusd = Some(4_756_881);
        assert_eq!(
            plan(&candidate).unwrap_err().0,
            "modeled watchdog/deletion delay and fees exceed the $50 total ceiling margin"
        );
    }

    #[test]
    fn existing_resources_bill_while_waiting_for_new_vm_start() {
        let mut candidate = input();
        let waiting_seconds = 24 * 60 * 60;
        candidate.start_unix_seconds += waiting_seconds;
        candidate.deletion_deadline_unix_seconds =
            Some(candidate.deletion_deadline_unix_seconds.unwrap() + waiting_seconds);
        candidate.quote.expires_at_unix_seconds = candidate.start_unix_seconds + 1;
        candidate.existing_resources.push(ExistingResourceCost {
            resource_id: "fixture-running-before-new-vm".into(),
            remaining_microusd_per_hour: 1_000,
        });
        let report = plan(&candidate).unwrap();
        assert_eq!(report.projected_existing_microusd, 192_000);
        assert_eq!(report.projected_total_microusd, 41_036_160);
        candidate.existing_resources[0].remaining_microusd_per_hour = 50_000;
        assert_eq!(
            plan(&candidate).unwrap_err().0,
            "projected infrastructure usage exceeds the $50 planning ceiling"
        );
    }

    #[test]
    fn missing_unknown_or_expired_inputs_fail_closed() {
        let mut candidate = input();
        candidate.deletion_deadline_unix_seconds = None;
        assert!(plan(&candidate).is_err());
        let mut candidate = input();
        candidate.external_controls = None;
        assert!(plan(&candidate).is_err());
        let mut candidate = input();
        candidate
            .external_controls
            .as_mut()
            .unwrap()
            .successful_deletion_test_reference
            .clear();
        assert!(plan(&candidate).is_err());
        let mut candidate = input();
        candidate.quote.network_total_upper_bound_microusd = None;
        assert!(plan(&candidate).is_err());
        let mut candidate = input();
        candidate.quote.preauthorization_microusd = None;
        assert!(plan(&candidate).is_err());
        let mut candidate = input();
        candidate.quote.expires_at_unix_seconds = candidate.start_unix_seconds - 1;
        assert!(plan(&candidate).is_err());
        let mut candidate = input();
        candidate.quote.reference.clear();
        assert!(plan(&candidate).is_err());
    }

    #[test]
    fn lifetime_and_unbudgeted_size_changes_rejected() {
        let mut candidate = input();
        candidate.deletion_deadline_unix_seconds =
            Some(candidate.start_unix_seconds + MAX_LIFETIME_SECONDS + 1);
        assert!(plan(&candidate).is_err());
        let mut candidate = input();
        candidate.quote.memory_gib = 16;
        assert!(plan(&candidate).is_err());
        let mut candidate = input();
        candidate.quote.confirmed_disk_limit_gib = 79;
        assert!(plan(&candidate).is_err());
    }

    #[test]
    fn cost_overflow_and_unbounded_polling_fail() {
        let mut candidate = input();
        candidate.quote.disk_microusd_per_gib_hour = u64::MAX;
        assert!(plan(&candidate).is_err());
        let mut candidate = input();
        candidate
            .external_controls
            .as_mut()
            .unwrap()
            .maximum_poll_interval_seconds = u64::MAX;
        assert!(plan(&candidate).is_err());
        assert_eq!(duration_cost(1, 1).unwrap(), 1);
    }

    #[test]
    fn watchdog_deletes_at_deadline_or_cost_and_never_stops() {
        let manifest = manifest();
        let start = manifest.started_at_unix_seconds;
        assert_eq!(
            watchdog(&manifest, start, 0).unwrap().action,
            WatchdogAction::ContinueMonitoring
        );
        assert_eq!(
            watchdog(&manifest, start + MAX_LIFETIME_SECONDS, 0)
                .unwrap()
                .action,
            WatchdogAction::DeleteAll
        );
        assert_eq!(
            watchdog(&manifest, start, DELETE_THRESHOLD_MICROUSD)
                .unwrap()
                .action,
            WatchdogAction::DeleteAll
        );
        let mut missing_deadline = manifest.clone();
        missing_deadline.deletion_deadline_unix_seconds = None;
        assert_eq!(
            watchdog(&missing_deadline, start, 0).unwrap().action,
            WatchdogAction::DeleteAll
        );
        let mut stopped = manifest;
        stopped
            .resources
            .iter_mut()
            .for_each(|r| r.state = ResourceState::Stopped);
        assert_eq!(
            watchdog(&stopped, start + 3600, 0)
                .unwrap()
                .conservative_cost_microusd,
            243_120
        );
    }

    #[test]
    fn partial_creation_is_cleaned_and_cleanup_is_idempotent() {
        let mut manifest = manifest();
        manifest.resources.pop(); // VM created, disk creation failed.
        let mut provider = SimulatedProvider::new(manifest.resources.clone()).unwrap();
        let first = cleanup_with_simulator(&mut manifest, &mut provider).unwrap();
        assert!(first.deletion_confirmed_in_simulator);
        assert!(!first.provider_action_performed);
        assert!(!first.actual_charges_verified);
        assert!(
            cleanup_with_simulator(&mut manifest, &mut provider)
                .unwrap()
                .deletion_confirmed_in_simulator
        );
    }

    #[test]
    fn deletion_failure_and_unrecorded_disk_are_reported() {
        let mut manifest = manifest();
        let mut inventory = manifest.resources.clone();
        inventory.push(Resource {
            id: "fixture-unrecorded-disk".into(),
            kind: ResourceKind::PersistentDisk,
            state: ResourceState::Stopped,
            microusd_per_hour: 1,
        });
        let mut provider = SimulatedProvider::new(inventory).unwrap();
        provider.fail_deletion(manifest.resources[0].id.clone());
        let result = cleanup_with_simulator(&mut manifest, &mut provider).unwrap();
        assert!(!result.deletion_confirmed_in_simulator);
        assert_eq!(result.failed_ids.len(), 1);
        assert_eq!(result.residual_ids.len(), 2);
        assert!(
            result
                .residual_ids
                .contains(&"fixture-unrecorded-disk".to_owned())
        );
    }

    #[test]
    fn real_manifests_cannot_be_deleted_with_simulator() {
        let mut manifest = manifest();
        manifest.source = ManifestSource::OperatorSupplied;
        assert!(simulated_teardown(&mut manifest).is_err());
    }
}
