//! Unauthenticated projections of the pinned Phala `2026-06-23` response shapes.
//!
//! These pure decoders make no requests and establish neither request scope nor
//! inventory completeness. In particular, the two CVM instance identifiers and
//! the usage identifier remain distinct; no conversion to a ledger usage record
//! is provided. Unknown fields are consumed without retaining them, including
//! account details, credits, deployment configuration, and provider URLs.

use crate::{LifecycleError, amount::ExactUsd};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, MapAccess, Visitor},
};
use serde_json::value::RawValue;
use std::{fmt, marker::PhantomData};

/// The future HTTP caller must pin this version; a JSON body cannot prove which
/// request headers or authenticated workspace produced it.
pub const PHALA_API_VERSION: &str = "2026-06-23";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentWorkspace {
    pub workspace_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cvm {
    /// Exact returned string, without SDK alias rewriting or path interpretation.
    pub id: String,
    pub status: String,
    pub app_id: Option<String>,
    /// The CVM object's instance identifier, not a usage-record join key.
    pub instance_id: Option<String>,
    pub vm_uuid: Option<String>,
    /// None means missing or null, not evidence of the request's workspace.
    pub workspace_id: Option<String>,
    /// Uninterpreted provider timestamps; neither proves disk deletion.
    pub created_at: Option<String>,
    pub deleted_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryPage {
    pub items: Vec<Cvm>,
    pub total: u64,
    pub page: u64,
    pub page_size: u64,
    pub pages: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageRow {
    /// The usage API describes this as a CVM UUID. Its relation to either CVM
    /// identifier remains unproven, even when their field names are the same.
    pub instance_id: String,
    pub project_id: UsageScopeId,
    pub team_id: UsageScopeId,
    pub timestamp: String,
    pub event_type: String,
    pub usage_type: String,
    pub billing_start: String,
    pub billing_end: String,
    pub billing_key: String,
    pub billing_hour: String,
    pub billing_day: String,
    pub cost: ExactUsd,
}

/// The reviewed schema uses JSON numbers, but the live versioned endpoint
/// returned strings. Preserve either wire type in observations:
/// neither representation is an authenticated CVM/usage join key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum UsageScopeId {
    Number(i64),
    Text(String),
}

impl UsageScopeId {
    pub(crate) fn valid(&self) -> bool {
        match self {
            Self::Number(_) => true,
            Self::Text(value) => !value.trim().is_empty(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsagePage {
    pub usage: Vec<UsageRow>,
    /// Number of rows returned on this page, not all available rows.
    pub total: u64,
    /// Provider summary, kept separate from row charges and never added to them.
    pub total_cost: ExactUsd,
}

const INVALID: LifecycleError = LifecycleError("invalid Phala lifecycle response");

// Serde's derived struct visitor also accepts a positional sequence. Restrict
// each projected object to JSON maps, while retaining derive's rejection of
// duplicate recognized keys (including escaped spellings and nullable fields).
struct Object<T>(T);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Object<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjectVisitor<T>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>> Visitor<'de> for ObjectVisitor<T> {
            type Value = Object<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an object")
            }

            fn visit_map<M: MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
                T::deserialize(de::value::MapAccessDeserializer::new(map)).map(Object)
            }
        }
        deserializer.deserialize_map(ObjectVisitor(PhantomData))
    }
}

#[derive(Deserialize)]
struct WorkspaceWire {
    id: String,
}

#[derive(Deserialize)]
struct CurrentWorkspaceWire {
    workspace: Object<WorkspaceWire>,
}

#[derive(Deserialize)]
struct CvmWorkspaceWire {
    object_type: String,
    id: String,
}

#[derive(Deserialize)]
struct CvmWire {
    id: String,
    status: String,
    app_id: Option<String>,
    instance_id: Option<String>,
    vm_uuid: Option<String>,
    workspace: Option<Object<CvmWorkspaceWire>>,
    created_at: Option<String>,
    deleted_at: Option<String>,
}

#[derive(Deserialize)]
struct InventoryPageWire {
    items: Vec<Object<CvmWire>>,
    total: u64,
    page: u64,
    page_size: u64,
    pages: u64,
}

#[derive(Deserialize)]
struct UsageRowWire {
    instance_id: String,
    project_id: UsageScopeId,
    team_id: UsageScopeId,
    timestamp: String,
    event_type: String,
    usage_type: String,
    billing_start: String,
    billing_end: String,
    billing_key: String,
    billing_hour: String,
    billing_day: String,
    cost: Box<RawValue>,
}

#[derive(Deserialize)]
struct UsagePageWire {
    usage: Vec<Object<UsageRowWire>>,
    total: u64,
    total_cost: Box<RawValue>,
}

fn decode<'a, T: Deserialize<'a>>(bytes: &'a [u8], body_bound: usize) -> Result<T, LifecycleError> {
    if body_bound == 0 || bytes.len() > body_bound {
        return Err(LifecycleError("Phala response body bound exceeded or zero"));
    }
    // Decode directly from the original bytes. A generic Value map would erase
    // duplicate keys, and a number conversion would lose exact billing tokens.
    serde_json::from_slice::<Object<T>>(bytes)
        .map(|object| object.0)
        .map_err(|_| INVALID)
}

fn required_text(value: &str) -> Result<(), LifecycleError> {
    if value.trim().is_empty() {
        Err(INVALID)
    } else {
        Ok(())
    }
}

fn optional_identity(value: &Option<String>) -> Result<(), LifecycleError> {
    if let Some(value) = value {
        required_text(value)?;
    }
    Ok(())
}

fn charge(value: &RawValue) -> Result<ExactUsd, LifecycleError> {
    let amount = ExactUsd::parse_json_number(value.get()).map_err(|_| INVALID)?;
    // A syntactically valid decimal can exceed the ledger's accounting unit.
    // Reject that unsupported charge instead of returning a usable cost page.
    amount.ceil_microusd().map_err(|_| INVALID)?;
    Ok(amount)
}

impl CvmWire {
    fn into_projection(self) -> Result<Cvm, LifecycleError> {
        required_text(&self.id)?;
        required_text(&self.status)?;
        optional_identity(&self.app_id)?;
        optional_identity(&self.instance_id)?;
        optional_identity(&self.vm_uuid)?;
        let workspace_id = match self.workspace {
            Some(Object(workspace)) => {
                if workspace.object_type != "workspace" {
                    return Err(INVALID);
                }
                required_text(&workspace.id)?;
                Some(workspace.id)
            }
            None => None,
        };
        Ok(Cvm {
            id: self.id,
            status: self.status,
            app_id: self.app_id,
            instance_id: self.instance_id,
            vm_uuid: self.vm_uuid,
            workspace_id,
            created_at: self.created_at,
            deleted_at: self.deleted_at,
        })
    }
}

/// Read only the workspace identifier from the versioned `/auth/me` envelope.
/// The caller supplies a positive byte limit; there is no provider-derived
/// maximum response size or implicit production default.
pub fn parse_current_workspace(
    bytes: &[u8],
    body_bound: usize,
) -> Result<CurrentWorkspace, LifecycleError> {
    let wire: CurrentWorkspaceWire = decode(bytes, body_bound)?;
    required_text(&wire.workspace.0.id)?;
    Ok(CurrentWorkspace {
        workspace_id: wire.workspace.0.id,
    })
}

/// Decode one page, without asserting that it belongs to an authenticated
/// workspace or that any multi-page inventory scan completed.
pub fn parse_inventory_page(
    bytes: &[u8],
    body_bound: usize,
) -> Result<InventoryPage, LifecycleError> {
    let wire: InventoryPageWire = decode(bytes, body_bound)?;
    // These bounds are from the pinned OpenAPI query contract, not project
    // resource defaults. Cross-page consistency belongs to the future caller.
    if wire.page == 0
        || !(1..=100).contains(&wire.page_size)
        || u64::try_from(wire.items.len()).map_err(|_| INVALID)? > wire.page_size
    {
        return Err(INVALID);
    }
    Ok(InventoryPage {
        items: wire
            .items
            .into_iter()
            .map(|item| item.0.into_projection())
            .collect::<Result<_, _>>()?,
        total: wire.total,
        page: wire.page,
        page_size: wire.page_size,
        pages: wire.pages,
    })
}

/// Decode a present CVM body. HTTP status handling and committed-target identity
/// comparison are separate requirements; this does not interpret HTTP 404.
pub fn parse_cvm_detail(bytes: &[u8], body_bound: usize) -> Result<Cvm, LifecycleError> {
    decode::<CvmWire>(bytes, body_bound)?.into_projection()
}

/// Decode exactly the returned usage rows, without attaching an app identity or
/// treating a short/empty page as a billing-finality or disk-deletion receipt.
pub fn parse_usage_page(bytes: &[u8], body_bound: usize) -> Result<UsagePage, LifecycleError> {
    let wire: UsagePageWire = decode(bytes, body_bound)?;
    if wire.total != u64::try_from(wire.usage.len()).map_err(|_| INVALID)? {
        return Err(INVALID);
    }
    let total_cost = charge(&wire.total_cost)?;
    let usage = wire
        .usage
        .into_iter()
        .map(|Object(row)| {
            for value in [
                &row.instance_id,
                &row.billing_key,
                &row.event_type,
                &row.usage_type,
            ] {
                required_text(value)?;
            }
            if !row.project_id.valid() || !row.team_id.valid() {
                return Err(INVALID);
            }
            let cost = charge(&row.cost)?;
            Ok(UsageRow {
                instance_id: row.instance_id,
                project_id: row.project_id,
                team_id: row.team_id,
                timestamp: row.timestamp,
                event_type: row.event_type,
                usage_type: row.usage_type,
                billing_start: row.billing_start,
                billing_end: row.billing_end,
                billing_key: row.billing_key,
                billing_hour: row.billing_hour,
                billing_day: row.billing_day,
                cost,
            })
        })
        .collect::<Result<_, LifecycleError>>()?;
    Ok(UsagePage {
        usage,
        total: wire.total,
        total_cost,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUTH: &str =
        include_str!("../../../tests/fixtures/phala-lifecycle/current-workspace.json");
    const INVENTORY: &str = include_str!("../../../tests/fixtures/phala-lifecycle/inventory.json");
    const DETAIL: &str = include_str!("../../../tests/fixtures/phala-lifecycle/cvm-detail.json");
    const USAGE: &str = include_str!("../../../tests/fixtures/phala-lifecycle/usage.json");

    fn inventory(value: &str) -> Result<InventoryPage, LifecycleError> {
        parse_inventory_page(value.as_bytes(), value.len())
    }
    fn detail(value: &str) -> Result<Cvm, LifecycleError> {
        parse_cvm_detail(value.as_bytes(), value.len())
    }
    fn usage(value: &str) -> Result<UsagePage, LifecycleError> {
        parse_usage_page(value.as_bytes(), value.len())
    }

    #[test]
    fn projects_current_workspace_without_account_or_credit_data() {
        let parsed = parse_current_workspace(AUTH.as_bytes(), AUTH.len()).unwrap();
        assert_eq!(parsed.workspace_id, "wks_synthetic_only");
        assert!(!format!("{parsed:?}").contains("account-data-must-not-be-retained"));
        assert!(parse_current_workspace(br#"{"team_id":"legacy"}"#, AUTH.len()).is_err());
    }

    #[test]
    fn keeps_identifiers_distinct_and_missing_workspace_unknown() {
        let page = inventory(INVENTORY).unwrap();
        assert_eq!(
            (page.total, page.page, page.page_size, page.pages),
            (2, 1, 30, 1)
        );
        let first = &page.items[0];
        assert_eq!(
            first.instance_id.as_deref(),
            Some("1111111111111111111111111111111111111111")
        );
        assert_eq!(
            first.vm_uuid.as_deref(),
            Some("00000000-0000-4000-8000-000000000001")
        );
        assert_ne!(first.instance_id, first.vm_uuid);
        assert!(page.items[1].workspace_id.is_none());
        assert!(page.items[1].app_id.is_none());
        let row = &usage(USAGE).unwrap().usage[0];
        assert_eq!(row.instance_id, first.vm_uuid.as_deref().unwrap());
        assert_ne!(Some(row.instance_id.as_str()), first.instance_id.as_deref());
    }

    #[test]
    fn preserves_exact_amounts_and_separates_page_summary() {
        let parsed = usage(USAGE).unwrap();
        assert_eq!(parsed.usage[0].cost.ceil_microusd().unwrap(), 123457);
        assert_eq!(parsed.usage[1].cost.ceil_microusd().unwrap(), 1);
        assert_eq!(parsed.total_cost.ceil_microusd().unwrap(), 123457);
        let equivalent = usage(&USAGE.replace("0.1234561", "1.234561e-1")).unwrap();
        assert_eq!(
            parsed.usage[0].cost.canonical_identity(),
            equivalent.usage[0].cost.canonical_identity()
        );
        let distinct = usage(&USAGE.replace("2e-7", "3e-7")).unwrap();
        assert_ne!(
            parsed.usage[1].cost.canonical_identity(),
            distinct.usage[1].cost.canonical_identity()
        );
        assert_eq!(
            parsed.usage[1].cost.ceil_microusd(),
            distinct.usage[1].cost.ceil_microusd()
        );
    }

    #[test]
    fn accepts_current_string_scope_ids_without_conflating_historical_numbers() {
        let live_shape = USAGE
            .replace("\"project_id\": 11", "\"project_id\": \"project-current\"")
            .replace("\"team_id\": 22", "\"team_id\": \"team-current\"");
        let parsed = usage(&live_shape).unwrap();
        assert_eq!(
            parsed.usage[0].project_id,
            UsageScopeId::Text("project-current".into())
        );
        assert_eq!(
            parsed.usage[0].team_id,
            UsageScopeId::Text("team-current".into())
        );
        assert_eq!(
            usage(USAGE).unwrap().usage[0].project_id,
            UsageScopeId::Number(11)
        );
        assert!(usage(&live_shape.replace("\"project-current\"", "\" \"")).is_err());
        assert!(usage(&live_shape.replace("\"team-current\"", "[]")).is_err());
        assert!(usage(&live_shape.replace("\"team-current\"", "true")).is_err());
    }

    #[test]
    fn rejects_duplicate_critical_fields_before_normalization() {
        for (from, to) in [
            ("\"total\": 2", "\"total\": 2, \"total\": 2"),
            ("\"page\": 1", "\"page\": 1, \"pa\\u0067e\": 1"),
            (
                "\"workspace\": null",
                "\"workspace\": null, \"workspace\": null",
            ),
            ("\"app_id\": null", "\"app_id\": null, \"app_id\": null"),
            (
                "\"status\": \"running\"",
                "\"status\": \"running\", \"status\": \"stopped\"",
            ),
            (
                "\"id\": \"wks_synthetic_only\"",
                "\"id\": \"wks_synthetic_only\", \"id\": \"different\"",
            ),
        ] {
            assert!(INVENTORY.contains(from));
            assert!(inventory(&INVENTORY.replace(from, to)).is_err(), "{from}");
        }
        for (from, to) in [
            ("\"cost\": 0.1234561", "\"cost\": 0.1234561, \"cost\": 0"),
            (
                "\"total_cost\": 0.1234563",
                "\"total_cost\": 0.1234563, \"total_cost\": 0",
            ),
            (
                "\"billing_key\": \"synthetic-compute-1\"",
                "\"billing_key\": \"synthetic-compute-1\", \"billing_key\": \"other\"",
            ),
        ] {
            assert!(USAGE.contains(from));
            assert!(usage(&USAGE.replace(from, to)).is_err(), "{from}");
        }
        let duplicate = AUTH.replace(
            "\"id\": \"wks_synthetic_only\"",
            "\"id\": \"wks_synthetic_only\", \"id\": \"other\"",
        );
        assert!(parse_current_workspace(duplicate.as_bytes(), duplicate.len()).is_err());
    }

    #[test]
    fn enforces_caller_body_bound_and_whole_json_input() {
        assert!(parse_current_workspace(AUTH.as_bytes(), AUTH.len()).is_ok());
        assert!(parse_current_workspace(AUTH.as_bytes(), AUTH.len() - 1).is_err());
        assert!(parse_current_workspace(AUTH.as_bytes(), 0).is_err());
        assert!(parse_inventory_page(INVENTORY.as_bytes(), INVENTORY.len() - 1).is_err());
        assert!(parse_cvm_detail(DETAIL.as_bytes(), DETAIL.len() - 1).is_err());
        assert!(parse_usage_page(USAGE.as_bytes(), USAGE.len() - 1).is_err());
        assert!(detail(&format!("{DETAIL}{{}}")).is_err());
        assert!(parse_cvm_detail(b"\xff", 1).is_err());
    }

    #[test]
    fn rejects_positional_arrays_at_every_projected_object_boundary() {
        assert!(detail(r#"["id","running",null,null,null,null,null,null]"#).is_err());
        assert!(parse_current_workspace(br#"{"workspace":["id"]}"#, AUTH.len()).is_err());
        let object = "{\"object_type\": \"workspace\", \"id\": \"wks_synthetic_only\", \"name\": \"Synthetic fixture workspace\"}";
        assert!(DETAIL.contains(object));
        assert!(detail(&DETAIL.replace(object, "[\"workspace\",\"wks_synthetic_only\"]")).is_err());
        assert!(inventory(r#"{"items":[["id","running",null,null,null,null,null,null]],"total":1,"page":1,"page_size":30,"pages":1}"#).is_err());
        assert!(usage(r#"{"usage":[[]],"total":1,"total_cost":0}"#).is_err());
    }

    #[test]
    fn rejects_wrong_critical_types_and_legacy_numeric_ids() {
        for (from, to) in [
            ("\"id\": \"synthetic-cvm-1\"", "\"id\": 1"),
            ("\"status\": \"running\"", "\"status\": null"),
            (
                "\"instance_id\": \"1111111111111111111111111111111111111111\"",
                "\"instance_id\": []",
            ),
            (
                "\"object_type\": \"workspace\"",
                "\"object_type\": \"user\"",
            ),
        ] {
            assert!(DETAIL.contains(from));
            assert!(detail(&DETAIL.replace(from, to)).is_err());
        }
        for replacement in ["-1", "1.5", "\"1\"", "18446744073709551616"] {
            assert!(
                inventory(&INVENTORY.replace("\"total\": 2", &format!("\"total\": {replacement}")))
                    .is_err()
            );
        }
    }

    #[test]
    fn rejects_invalid_amounts_without_echoing_provider_contents() {
        for amount in [
            "\"private-provider-marker\"",
            "-1",
            "null",
            "{}",
            "true",
            "1e999",
            "01",
            "NaN",
        ] {
            let changed = USAGE.replace("0.1234561", amount);
            let error = usage(&changed).unwrap_err();
            assert_eq!(error, INVALID);
            assert!(!error.to_string().contains(amount));
        }
        assert!(usage(&USAGE.replace("0.1234563", "-1")).is_err());
    }

    #[test]
    fn usage_total_is_returned_count_and_short_page_has_no_completion_claim() {
        assert!(usage(&USAGE.replace("\"total\": 2", "\"total\": 3")).is_err());
        let empty = usage(r#"{"usage":[],"total":0,"total_cost":0}"#).unwrap();
        assert!(empty.usage.is_empty());
        assert_eq!(usage(USAGE).unwrap().total, 2);
    }

    #[test]
    fn ignores_unknown_fields_without_adding_evidence_or_aliasing_ids() {
        let parsed = detail(DETAIL).unwrap();
        assert_eq!(parsed.id, "synthetic-cvm-1");
        assert_eq!(parsed.deleted_at.as_deref(), Some("2026-01-01T02:00:00Z"));
        assert_eq!(parsed.status, "running");
        assert!(!format!("{parsed:?}").contains("provider-config-must-not-be-retained"));
        let alias_like = DETAIL.replace("synthetic-cvm-1", "name/../unchanged?raw#id");
        assert_eq!(detail(&alias_like).unwrap().id, "name/../unchanged?raw#id");
        // Parsing is not URL construction, authorization, or adoption of a target.
    }
}
