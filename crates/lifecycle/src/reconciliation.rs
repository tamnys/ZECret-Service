//! Append-only local statements about completed provider read observations.
//! These serializable DTOs are historical data, not authenticated capabilities.
//! Restoring them cannot create a `ReadObservation`, attribute usage to a CVM,
//! prove disk deletion or billing finality, or authorize a deletion retry.

use crate::{LifecycleError, amount::ExactUsd, controller::TrackedCvm, nonempty};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedCvm {
    pub id: String,
    pub status: String,
    pub app_id: Option<String>,
    pub instance_id: Option<String>,
    pub vm_uuid: Option<String>,
    pub workspace_id: Option<String>,
    pub created_at: Option<String>,
    pub deleted_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "cvm",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ObservedDetail {
    Present(ObservedCvm),
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedTarget {
    pub target: TrackedCvm,
    pub inventory: Option<ObservedCvm>,
    pub detail: ObservedDetail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedUsage {
    pub instance_id: String,
    pub project_id: i64,
    pub team_id: i64,
    pub timestamp: String,
    pub event_type: String,
    pub usage_type: String,
    pub billing_start: String,
    pub billing_end: String,
    pub billing_key: String,
    pub billing_hour: String,
    pub billing_day: String,
    pub cost_canonical_decimal: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationRecord {
    pub source_generation: u64,
    pub committed_generation: u64,
    pub usage_start_unix_seconds: u64,
    pub usage_cutoff_unix_seconds: u64,
    pub finished_at_unix_seconds: u64,
    pub recorded_at_unix_seconds: u64,
    pub known_cost_floor_microusd: u64,
    pub inventory_total: u64,
    pub inventory_pages: u64,
    pub untracked_inventory_ids: Vec<String>,
    pub tracked: Vec<ObservedTarget>,
    #[serde(deserialize_with = "unique_usage_apps")]
    pub usage_by_app: BTreeMap<String, Vec<ObservedUsage>>,
}

const INVALID: LifecycleError = LifecycleError("invalid historical provider observation");

fn unique_usage_apps<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, Vec<ObservedUsage>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Apps;
    impl<'de> serde::de::Visitor<'de> for Apps {
        type Value = BTreeMap<String, Vec<ObservedUsage>>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("an object with unique app identifiers")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(
            self,
            mut map: M,
        ) -> Result<Self::Value, M::Error> {
            let mut apps = BTreeMap::new();
            while let Some((app, rows)) = map.next_entry::<String, Vec<ObservedUsage>>()? {
                if apps.insert(app, rows).is_some() {
                    return Err(serde::de::Error::custom(
                        "duplicate observation app identifier",
                    ));
                }
            }
            Ok(apps)
        }
    }
    deserializer.deserialize_map(Apps)
}

impl ObservedCvm {
    #[cfg(unix)]
    fn from_wire(cvm: &crate::provider_wire::Cvm) -> Self {
        Self {
            id: cvm.id.clone(),
            status: cvm.status.clone(),
            app_id: cvm.app_id.clone(),
            instance_id: cvm.instance_id.clone(),
            vm_uuid: cvm.vm_uuid.clone(),
            workspace_id: cvm.workspace_id.clone(),
            created_at: cvm.created_at.clone(),
            deleted_at: cvm.deleted_at.clone(),
        }
    }

    fn validate(&self, target: &TrackedCvm, workspace: &str) -> Result<(), LifecycleError> {
        if self.id != target.cvm_id
            || !nonempty(&self.status)
            || self.app_id.as_ref().is_some_and(|id| id != &target.app_id)
            || self
                .instance_id
                .as_ref()
                .is_some_and(|id| id != &target.instance_id)
            || self
                .workspace_id
                .as_deref()
                .is_some_and(|id| id != workspace)
            || self.vm_uuid.as_ref().is_some_and(|id| !nonempty(id))
        {
            return Err(INVALID);
        }
        Ok(())
    }
}

impl ObservedUsage {
    #[cfg(unix)]
    fn from_wire(row: &crate::provider_wire::UsageRow) -> Self {
        Self {
            instance_id: row.instance_id.clone(),
            project_id: row.project_id,
            team_id: row.team_id,
            timestamp: row.timestamp.clone(),
            event_type: row.event_type.clone(),
            usage_type: row.usage_type.clone(),
            billing_start: row.billing_start.clone(),
            billing_end: row.billing_end.clone(),
            billing_key: row.billing_key.clone(),
            billing_hour: row.billing_hour.clone(),
            billing_day: row.billing_day.clone(),
            cost_canonical_decimal: row.cost.canonical_identity().to_owned(),
        }
    }

    fn validate(&self) -> Result<(), LifecycleError> {
        if [
            &self.instance_id,
            &self.billing_key,
            &self.event_type,
            &self.usage_type,
        ]
        .into_iter()
        .any(|value| !nonempty(value))
        {
            return Err(INVALID);
        }
        let amount = ExactUsd::parse_json_number(&self.cost_canonical_decimal)?;
        if amount.canonical_identity() != self.cost_canonical_decimal {
            return Err(INVALID);
        }
        amount.ceil_microusd()?;
        Ok(())
    }
}

impl ObservationRecord {
    #[cfg(unix)]
    pub(crate) fn from_read(
        observation: &crate::observation::ReadObservation,
        recorded_at: u64,
    ) -> Result<Self, LifecycleError> {
        use crate::provider_http::CvmDetail;
        let source_generation = observation.reference().generation();
        let inventory: BTreeMap<_, _> = observation
            .inventory()
            .items()
            .iter()
            .map(|cvm| (cvm.id.as_str(), cvm))
            .collect();
        let record = Self {
            source_generation,
            committed_generation: source_generation.checked_add(1).ok_or(INVALID)?,
            usage_start_unix_seconds: observation.original_binding().original_window().0,
            usage_cutoff_unix_seconds: observation.usage_cutoff_unix_seconds(),
            finished_at_unix_seconds: observation.finished_at_unix_seconds(),
            recorded_at_unix_seconds: recorded_at,
            known_cost_floor_microusd: observation.known_cost_floor_microusd(),
            inventory_total: observation.inventory().total(),
            inventory_pages: observation.inventory().pages(),
            untracked_inventory_ids: observation.untracked_inventory_ids().to_vec(),
            tracked: observation
                .tracked()
                .iter()
                .map(|read| ObservedTarget {
                    target: read.target().clone(),
                    inventory: inventory
                        .get(read.target().cvm_id.as_str())
                        .map(|cvm| ObservedCvm::from_wire(cvm)),
                    detail: match read.detail() {
                        CvmDetail::Present(cvm) => {
                            ObservedDetail::Present(ObservedCvm::from_wire(cvm))
                        }
                        CvmDetail::NotFound => ObservedDetail::NotFound,
                    },
                })
                .collect(),
            usage_by_app: observation
                .unjoined_usage_by_app()
                .iter()
                .map(|(app, scan)| {
                    (
                        app.clone(),
                        scan.rows().iter().map(ObservedUsage::from_wire).collect(),
                    )
                })
                .collect(),
        };
        record.validate(observation.original_binding().workspace_id())?;
        Ok(record)
    }

    /// Validate the historical statement, without granting it live authority.
    /// Exact current-target coverage is additionally checked at append time;
    /// earlier records remain valid after the ledger tracks another resource.
    pub(crate) fn validate(&self, workspace: &str) -> Result<(), LifecycleError> {
        if !nonempty(workspace)
            || self.source_generation.checked_add(1) != Some(self.committed_generation)
            || self.usage_start_unix_seconds > self.usage_cutoff_unix_seconds
            || self.usage_cutoff_unix_seconds > self.finished_at_unix_seconds
            || self.finished_at_unix_seconds > self.recorded_at_unix_seconds
            || (self.inventory_pages == 0 && self.inventory_total != 0)
        {
            return Err(INVALID);
        }
        let mut targets = BTreeSet::new();
        let mut instances = BTreeSet::new();
        let mut apps = BTreeSet::new();
        let mut inventory_ids = BTreeSet::new();
        for observed in &self.tracked {
            let target = &observed.target;
            if !nonempty(&target.cvm_id)
                || !nonempty(&target.app_id)
                || !nonempty(&target.instance_id)
                || target.compute_and_disk_microusd_per_hour == 0
                || target.created_at_unix_seconds < self.usage_start_unix_seconds
                || target.created_at_unix_seconds > self.usage_cutoff_unix_seconds
                || !targets.insert(target.cvm_id.as_str())
                || !instances.insert(target.instance_id.as_str())
            {
                return Err(INVALID);
            }
            apps.insert(target.app_id.as_str());
            if let Some(cvm) = &observed.inventory {
                cvm.validate(target, workspace)?;
                inventory_ids.insert(cvm.id.as_str());
            }
            if let ObservedDetail::Present(cvm) = &observed.detail {
                cvm.validate(target, workspace)?;
            }
        }
        for id in &self.untracked_inventory_ids {
            if !nonempty(id) || targets.contains(id.as_str()) || !inventory_ids.insert(id.as_str())
            {
                return Err(INVALID);
            }
        }
        if inventory_ids.len() as u128 != u128::from(self.inventory_total)
            || apps != self.usage_by_app.keys().map(String::as_str).collect()
        {
            return Err(INVALID);
        }
        for rows in self.usage_by_app.values() {
            let mut keys = BTreeSet::new();
            for row in rows {
                row.validate()?;
                if !keys.insert(&row.billing_key) {
                    return Err(INVALID);
                }
            }
        }
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::{
        MAX_LIFETIME_SECONDS,
        controller::{ExperimentBinding, ExperimentLedger},
    };

    fn ledger() -> ExperimentLedger {
        let binding = ExperimentBinding::new(
            "experiment".into(),
            "workspace".into(),
            1000,
            1000 + MAX_LIFETIME_SECONDS,
        )
        .unwrap();
        let mut ledger = ExperimentLedger::new(binding, 0).unwrap();
        ledger.begin_attempt("attempt".into(), 1000).unwrap();
        add_target(&mut ledger, "one", 1000);
        ledger
    }

    fn add_target(ledger: &mut ExperimentLedger, id: &str, created: u64) {
        ledger
            .track_cvm(
                "workspace",
                "attempt",
                TrackedCvm {
                    cvm_id: id.into(),
                    app_id: format!("app-{id}"),
                    instance_id: format!("instance-{id}"),
                    created_at_unix_seconds: created,
                    compute_and_disk_microusd_per_hour: 3600,
                },
            )
            .unwrap();
    }

    fn row(key: &str, cost: &str) -> ObservedUsage {
        ObservedUsage::from_wire(&crate::provider_wire::UsageRow {
            instance_id: "unjoined-usage-instance".into(),
            project_id: 1,
            team_id: 2,
            timestamp: "provider timestamp".into(),
            event_type: "cvm".into(),
            usage_type: "compute".into(),
            billing_start: "provider start".into(),
            billing_end: "provider end".into(),
            billing_key: key.into(),
            billing_hour: "provider hour".into(),
            billing_day: "provider day".into(),
            cost: ExactUsd::parse_json_number(cost).unwrap(),
        })
    }

    fn record(
        ledger: &ExperimentLedger,
        generation: u64,
        cutoff: u64,
        rows: Vec<ObservedUsage>,
    ) -> ObservationRecord {
        let tracked: Vec<_> = ledger
            .tracked_cvms()
            .map(|target| {
                let cvm = ObservedCvm {
                    id: target.cvm_id.clone(),
                    status: "stopped".into(),
                    app_id: Some(target.app_id.clone()),
                    instance_id: Some(target.instance_id.clone()),
                    vm_uuid: Some(format!("uuid-{}", target.cvm_id)),
                    workspace_id: Some("workspace".into()),
                    created_at: None,
                    deleted_at: None,
                };
                ObservedTarget {
                    target: target.clone(),
                    inventory: Some(cvm.clone()),
                    detail: ObservedDetail::Present(cvm),
                }
            })
            .collect();
        let mut usage_by_app: BTreeMap<_, _> = tracked
            .iter()
            .map(|item| (item.target.app_id.clone(), Vec::new()))
            .collect();
        usage_by_app.insert("app-one".into(), rows);
        ObservationRecord {
            source_generation: generation,
            committed_generation: generation + 1,
            usage_start_unix_seconds: 1000,
            usage_cutoff_unix_seconds: cutoff,
            finished_at_unix_seconds: cutoff,
            recorded_at_unix_seconds: cutoff,
            known_cost_floor_microusd: ledger.planning_cost_at(cutoff).unwrap(),
            inventory_total: tracked.len() as u64,
            inventory_pages: 1,
            untracked_inventory_ids: Vec::new(),
            tracked,
            usage_by_app,
        }
    }

    #[test]
    fn late_rows_and_omissions_preserve_history_without_charging_unjoined_usage() {
        let mut ledger = ledger();
        let first = record(&ledger, 0, 1001, vec![row("a", "0.0000001")]);
        ledger.append_observation(first).unwrap();
        ledger
            .append_observation(record(&ledger, 1, 1002, vec![]))
            .unwrap();
        let third = record(
            &ledger,
            2,
            1003,
            vec![row("a", "0.00000010"), row("late", "40.84416")],
        );
        ledger.append_observation(third).unwrap();
        assert_eq!(ledger.observations().len(), 3);
        assert_eq!(
            ledger.observations()[0].usage_by_app["app-one"][0].cost_canonical_decimal,
            "1e-7"
        );
        assert!(ledger.observations()[1].usage_by_app["app-one"].is_empty());
        assert_eq!(ledger.conservative_cost_floor_microusd(), 3);
        assert!(ledger.deletion_intents().is_empty());
        let json = serde_json::to_value(&ledger).unwrap();
        assert_eq!(json["usage"], serde_json::json!({}));
        assert!(
            ExperimentLedger::from_json(&serde_json::to_vec(&ledger).unwrap(), ledger.binding())
                .is_ok()
        );
    }

    #[test]
    fn conflicting_returned_rows_fail_even_after_omission_and_leave_ledger_unchanged() {
        let mut ledger = ledger();
        ledger
            .append_observation(record(&ledger, 0, 1001, vec![row("a", "0.0000001")]))
            .unwrap();
        ledger
            .append_observation(record(&ledger, 1, 1002, vec![]))
            .unwrap();
        let before = serde_json::to_vec(&ledger).unwrap();
        for changed in [
            "cost",
            "instance",
            "category",
            "timestamp",
            "project",
            "event",
        ] {
            let mut usage = row("a", "1e-7");
            match changed {
                "cost" => usage.cost_canonical_decimal = "2e-7".into(),
                "instance" => usage.instance_id = "changed".into(),
                "category" => usage.usage_type = "storage".into(),
                "timestamp" => usage.timestamp = "changed".into(),
                "project" => usage.project_id += 1,
                _ => usage.event_type = "changed".into(),
            }
            assert!(
                ledger
                    .append_observation(record(&ledger, 2, 1003, vec![usage]))
                    .is_err(),
                "{changed}"
            );
            assert_eq!(serde_json::to_vec(&ledger).unwrap(), before);
        }
    }

    #[test]
    fn older_target_subsets_survive_additions_but_new_records_cover_every_target() {
        let mut ledger = ledger();
        ledger
            .append_observation(record(&ledger, 0, 1001, vec![]))
            .unwrap();
        let prior = ledger.clone();
        add_target(&mut ledger, "two", 1002);
        ledger.validate_successor(&prior).unwrap();
        assert!(
            ExperimentLedger::from_json(&serde_json::to_vec(&ledger).unwrap(), ledger.binding())
                .is_ok()
        );
        let mut missing = record(&ledger, 2, 1003, vec![]);
        missing
            .tracked
            .retain(|observed| observed.target.cvm_id == "one");
        missing.usage_by_app.remove("app-two");
        missing.inventory_total = 1;
        assert!(ledger.append_observation(missing).is_err());
        let mut valid = record(&ledger, 2, 1003, vec![]);
        valid.recorded_at_unix_seconds = 1004;
        ledger.append_observation(valid).unwrap();
        assert_eq!(ledger.observations()[0].tracked.len(), 1);
        assert_eq!(ledger.observations()[1].tracked.len(), 2);
        assert_eq!(ledger.conservative_cost_floor_microusd(), 6);

        let mut changed = serde_json::to_value(&ledger).unwrap();
        changed["observations"][0]["tracked"][0]["inventory"]["status"] =
            "different historical statement".into();
        let changed =
            ExperimentLedger::from_json(&serde_json::to_vec(&changed).unwrap(), ledger.binding())
                .unwrap();
        assert!(changed.validate_successor(&ledger).is_err());
    }

    #[test]
    fn malformed_observation_identity_time_amount_and_shape_are_rejected() {
        let mut ledger = ledger();
        let valid = record(&ledger, 0, 1001, vec![row("a", "1e-7")]);
        for field in [
            "generation",
            "start",
            "finish",
            "recorded",
            "floor",
            "total",
            "pages",
            "duplicate-target",
            "untracked-overlap",
            "workspace",
            "app",
            "instance",
            "canonical-cost",
            "duplicate-key",
            "usage-app",
        ] {
            let mut bad = valid.clone();
            match field {
                "generation" => bad.committed_generation += 1,
                "start" => bad.usage_start_unix_seconds += 1,
                "finish" => bad.finished_at_unix_seconds -= 1,
                "recorded" => bad.recorded_at_unix_seconds -= 1,
                "floor" => bad.known_cost_floor_microusd += 1,
                "total" => bad.inventory_total += 1,
                "pages" => bad.inventory_pages = 0,
                "duplicate-target" => bad.tracked.push(bad.tracked[0].clone()),
                "untracked-overlap" => bad.untracked_inventory_ids.push("one".into()),
                "workspace" => {
                    bad.tracked[0].inventory.as_mut().unwrap().workspace_id = Some("other".into())
                }
                "app" => bad.tracked[0].inventory.as_mut().unwrap().app_id = Some("other".into()),
                "instance" => {
                    bad.tracked[0].inventory.as_mut().unwrap().instance_id = Some("other".into())
                }
                "canonical-cost" => {
                    bad.usage_by_app.get_mut("app-one").unwrap()[0].cost_canonical_decimal =
                        "0.0000001".into()
                }
                "duplicate-key" => bad
                    .usage_by_app
                    .get_mut("app-one")
                    .unwrap()
                    .push(row("a", "1e-7")),
                _ => {
                    bad.usage_by_app.insert("unknown-app".into(), vec![]);
                }
            }
            assert!(ledger.append_observation(bad).is_err(), "{field}");
            assert!(ledger.observations().is_empty());
        }
        let mut unknown = serde_json::to_value(&valid).unwrap();
        unknown["cleanup_complete"] = true.into();
        assert!(serde_json::from_value::<ObservationRecord>(unknown).is_err());
        let duplicate_app = serde_json::to_string(&valid)
            .unwrap()
            .replace("\"usage_by_app\":{", "\"usage_by_app\":{\"app-one\":[],");
        assert!(serde_json::from_str::<ObservationRecord>(&duplicate_app).is_err());
        ledger.append_observation(valid).unwrap();
        let mut old = record(&ledger, 1, 1001, vec![row("a", "1e-7")]);
        old.usage_cutoff_unix_seconds = 1000;
        assert!(ledger.append_observation(old).is_err());
    }
}
