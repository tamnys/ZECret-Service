//! Offline shape inspection of operator-supplied IAM snapshots. This module
//! never authenticates a project, appraises effective IAM, or admits deletion.
//!
//! Google IAM v2 deny policy: https://docs.cloud.google.com/iam/docs/reference/rest/v2/policies
//! Google IAM v1 allow policy: https://docs.cloud.google.com/iam/docs/reference/rest/v1/Policy
//! Google custom role: https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.roles
//! `request.time` is an allow-condition attribute, not a deny condition:
//! https://docs.cloud.google.com/iam/docs/conditions-attribute-reference
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

const ALL: &str = "principalSet://goog/public:all";
const CREATE_V1: [&str; 6] = [
    "compute.networks.create",
    "compute.subnetworks.create",
    "compute.firewalls.create",
    "compute.images.create",
    "compute.disks.create",
    "compute.instances.create",
];
const CREATE_V2: [&str; 6] = [
    "compute.googleapis.com/networks.create",
    "compute.googleapis.com/subnetworks.create",
    "compute.googleapis.com/firewalls.create",
    "compute.googleapis.com/images.create",
    "compute.googleapis.com/disks.create",
    "compute.googleapis.com/instances.create",
];
const RENAME_V2: [&str; 1] = ["compute.googleapis.com/instances.setName"];

/// These are captured JSON responses, not independently authenticated cloud
/// evidence. The project number is an operator assertion until checked with
/// Resource Manager against the package's project ID.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub schema_version: u8,
    pub project_number: String,
    pub controller_member: String,
    pub cutoff_unix_seconds: u64,
    pub deny_policy: Value,
    pub project_allow_policy: Value,
    pub creator_role: Value,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub diagnostic: &'static str,
    pub policy_shape_matches_candidate: bool,
    pub deployment_approved: bool,
    pub private_mode_approved: bool,
    pub network_used: bool,
    pub failures: Vec<&'static str>,
    pub unresolved: &'static [&'static str],
}

const UNRESOLVED: &[&str] = &[
    "snapshot origin and project ID-to-number mapping are not authenticated",
    "inherited or alternate grants, role changes, service-agent behavior, and independent policy custody are not appraised",
    "IAM propagation and effective time-bound permissions have not been observed",
    "pre-cutoff and in-flight creation operations have not been independently reconciled",
    "teardown before the cutoff is unsafe under this candidate policy",
    "selected-project name-replacement and deletion rehearsal has not run",
];

fn nonempty<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key)?.as_str().filter(|s| !s.is_empty())
}

fn list<'a>(value: &'a Value, key: &str, optional: bool) -> Option<Vec<&'a str>> {
    match value.get(key) {
        None if optional => Some(Vec::new()),
        Some(Value::Array(items)) => items.iter().map(Value::as_str).collect(),
        _ => None,
    }
}

fn exact_set(actual: Option<Vec<&str>>, expected: &[&str]) -> bool {
    let Some(actual) = actual else { return false };
    actual.len() == expected.len()
        && actual.iter().copied().collect::<BTreeSet<_>>()
            == expected.iter().copied().collect::<BTreeSet<_>>()
}

fn controller_principal(member: &str) -> Option<String> {
    let (kind, email) = member.split_once(':')?;
    let (local, domain) = email.split_once('@')?;
    if local.is_empty()
        || domain.is_empty()
        || domain.contains('@')
        || email
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control() || b == b'/')
    {
        return None;
    }
    match kind {
        "user" => Some(format!("principal://goog/subject/{email}")),
        "serviceAccount" => Some(format!(
            "principal://iam.googleapis.com/projects/-/serviceAccounts/{email}"
        )),
        _ => None,
    }
}

fn rule_matches(rule: &Value, permissions: &[&str], exceptions: &[&str]) -> bool {
    let Some(wrapper) = rule.as_object() else {
        return false;
    };
    if wrapper
        .keys()
        .any(|key| key != "description" && key != "denyRule")
    {
        return false;
    }
    let Some(deny) = rule.get("denyRule").and_then(Value::as_object) else {
        return false;
    };
    if deny.keys().any(|key| {
        !matches!(
            key.as_str(),
            "deniedPrincipals"
                | "exceptionPrincipals"
                | "deniedPermissions"
                | "exceptionPermissions"
                | "denialCondition"
        )
    }) || deny.contains_key("denialCondition")
    {
        return false;
    }
    let body = &rule["denyRule"];
    exact_set(list(body, "deniedPrincipals", false), &[ALL])
        && exact_set(list(body, "exceptionPrincipals", true), exceptions)
        && exact_set(list(body, "deniedPermissions", false), permissions)
        && exact_set(list(body, "exceptionPermissions", true), &[])
}

fn deny_matches(snapshot: &Snapshot, controller: &str) -> bool {
    let policy = &snapshot.deny_policy;
    let prefix = format!(
        "policies/cloudresourcemanager.googleapis.com%2Fprojects%2F{}/denypolicies/",
        snapshot.project_number
    );
    let Some(policy_id) = nonempty(policy, "name").and_then(|n| n.strip_prefix(&prefix)) else {
        return false;
    };
    if policy_id.is_empty()
        || policy_id.contains('/')
        || nonempty(policy, "uid").is_none()
        || nonempty(policy, "etag").is_none()
        || nonempty(policy, "kind") != Some("DenyPolicy")
        || policy
            .get("deleteTime")
            .is_some_and(|value| value.as_str() != Some(""))
    {
        return false;
    }
    let Some(rules) = policy.get("rules").and_then(Value::as_array) else {
        return false;
    };
    rules.len() == 2
        && rules
            .iter()
            .any(|rule| rule_matches(rule, &CREATE_V2, &[controller]))
        && rules.iter().any(|rule| rule_matches(rule, &RENAME_V2, &[]))
}

fn role_matches(project_id: &str, role: &Value) -> bool {
    let prefix = format!("projects/{project_id}/roles/");
    let Some(role_id) = nonempty(role, "name").and_then(|n| n.strip_prefix(&prefix)) else {
        return false;
    };
    !role_id.is_empty()
        && !role_id.contains('/')
        && nonempty(role, "etag").is_some()
        && role
            .get("deleted")
            .is_none_or(|value| value.as_bool() == Some(false))
        && role.get("stage").and_then(Value::as_str) != Some("DISABLED")
        && exact_set(list(role, "includedPermissions", false), &CREATE_V1)
}

fn allow_matches(allow: &Value, role: &Value, member: &str, expression: &str) -> bool {
    if allow.get("version").and_then(Value::as_u64) != Some(3) || nonempty(allow, "etag").is_none()
    {
        return false;
    }
    let Some(role_name) = nonempty(role, "name") else {
        return false;
    };
    let Some(bindings) = allow.get("bindings").and_then(Value::as_array) else {
        return false;
    };
    let grants = bindings
        .iter()
        .filter(|binding| binding.get("role").and_then(Value::as_str) == Some(role_name))
        .collect::<Vec<_>>();
    if grants.len() != 1 {
        return false;
    }
    let binding = grants[0];
    binding.as_object().is_some_and(|b| {
        b.keys()
            .all(|k| matches!(k.as_str(), "role" | "members" | "condition"))
    }) && exact_set(list(binding, "members", false), &[member])
        && binding
            .pointer("/condition/expression")
            .and_then(Value::as_str)
            == Some(expression)
}

/// A matching result establishes only that submitted documents fit this one
/// candidate policy shape. It cannot make a name-only DELETE incarnation-safe.
pub fn inspect(project_id: &str, start: u64, deadline: u64, snapshot: &Snapshot) -> Report {
    let mut failures = Vec::new();
    if snapshot.schema_version != 1 {
        failures.push("unsupported IAM diagnostic snapshot version");
    }
    if snapshot.project_number.is_empty()
        || snapshot.project_number.starts_with('0')
        || !snapshot.project_number.bytes().all(|b| b.is_ascii_digit())
    {
        failures.push("project number assertion is not canonical decimal");
    }
    let controller = controller_principal(&snapshot.controller_member);
    if controller.is_none() {
        failures.push("controller must be one canonical user or service account member");
    }
    let expression = snapshot
        .cutoff_unix_seconds
        .try_into()
        .ok()
        .and_then(|seconds| DateTime::<Utc>::from_timestamp(seconds, 0))
        .map(|time| {
            format!(
                "request.time < timestamp('{}')",
                time.to_rfc3339_opts(SecondsFormat::Secs, true)
            )
        });
    if snapshot.cutoff_unix_seconds <= start
        || snapshot.cutoff_unix_seconds >= deadline
        || expression.is_none()
    {
        failures.push("creation cutoff must fall strictly inside the original evaluation window");
    }
    if !controller
        .as_deref()
        .is_some_and(|principal| deny_matches(snapshot, principal))
    {
        failures.push(
            "captured deny policy does not match the exact project creation and rename rules",
        );
    }
    if !role_matches(project_id, &snapshot.creator_role) {
        failures.push("captured project custom role is not the exact six-permission creator role");
    }
    if !expression.as_deref().is_some_and(|expected| {
        allow_matches(
            &snapshot.project_allow_policy,
            &snapshot.creator_role,
            &snapshot.controller_member,
            expected,
        )
    }) {
        failures.push("captured version-3 project allow policy lacks the one canonical time-bound creator grant");
    }
    Report {
        diagnostic: "offline_iam_snapshot_shape_only",
        policy_shape_matches_candidate: failures.is_empty(),
        deployment_approved: false,
        private_mode_approved: false,
        network_used: false,
        failures,
        unresolved: UNRESOLVED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const START: u64 = 1_735_689_600; // 2025-01-01T00:00:00Z
    const CUTOFF: u64 = 1_735_693_200; // one hour later
    const DEADLINE: u64 = 1_735_776_000; // one day later

    fn candidate() -> Snapshot {
        let member = "serviceAccount:controller@example.iam.gserviceaccount.com";
        let principal = "principal://iam.googleapis.com/projects/-/serviceAccounts/controller@example.iam.gserviceaccount.com";
        Snapshot {
            schema_version: 1,
            project_number: "123456789012".into(),
            controller_member: member.into(),
            cutoff_unix_seconds: CUTOFF,
            deny_policy: json!({
                "name":"policies/cloudresourcemanager.googleapis.com%2Fprojects%2F123456789012/denypolicies/zrpc-name-freeze",
                "uid":"policy-uid", "etag":"policy-etag", "kind":"DenyPolicy",
                "rules":[
                    {"denyRule":{"deniedPrincipals":[ALL],"exceptionPrincipals":[principal],"deniedPermissions":CREATE_V2}},
                    {"denyRule":{"deniedPrincipals":[ALL],"deniedPermissions":RENAME_V2}}
                ]
            }),
            project_allow_policy: json!({"version":3,"etag":"allow-etag","bindings":[{
                "role":"projects/test-project/roles/zrpcCreator",
                "members":[member],
                "condition":{"title":"creation window","expression":"request.time < timestamp('2025-01-01T01:00:00Z')"}
            }]}),
            creator_role: json!({
                "name":"projects/test-project/roles/zrpcCreator", "etag":"role-etag",
                "deleted":false, "stage":"GA", "includedPermissions":CREATE_V1
            }),
        }
    }

    fn check(snapshot: &Snapshot) -> Report {
        inspect("test-project", START, DEADLINE, snapshot)
    }

    #[test]
    fn canonical_captured_shape_is_diagnostic_only() {
        let report = check(&candidate());
        assert!(
            report.policy_shape_matches_candidate,
            "{:?}",
            report.failures
        );
        assert!(!report.deployment_approved);
        assert!(!report.private_mode_approved);
        assert!(!report.network_used);
        assert!(!report.unresolved.is_empty());
    }

    #[test]
    fn wrong_project_and_cutoff_never_match() {
        let mut input = candidate();
        input.project_number = "999".into();
        assert!(!check(&input).policy_shape_matches_candidate);
        input = candidate();
        input.cutoff_unix_seconds = DEADLINE;
        assert!(!check(&input).policy_shape_matches_candidate);
        input = candidate();
        input.cutoff_unix_seconds = START;
        assert!(!check(&input).policy_shape_matches_candidate);
        input = candidate();
        input.controller_member = "group:operators@example.com".into();
        assert!(!check(&input).policy_shape_matches_candidate);
    }

    #[test]
    fn deny_exceptions_conditions_and_missing_permissions_fail() {
        let mut input = candidate();
        input.deny_policy["rules"][0]["denyRule"]["deniedPermissions"] = json!(&CREATE_V2[..5]);
        assert!(!check(&input).policy_shape_matches_candidate);
        input = candidate();
        input.deny_policy["rules"][0]["denyRule"]["exceptionPrincipals"] = json!([
            "principal://iam.googleapis.com/projects/-/serviceAccounts/controller@example.iam.gserviceaccount.com",
            "principalSet://cloudresourcemanager.googleapis.com/projects/123456789012/type/ServiceAgent"
        ]);
        assert!(!check(&input).policy_shape_matches_candidate);
        input = candidate();
        input.deny_policy["rules"][1]["denyRule"]["exceptionPrincipals"] =
            json!(["principal://goog/subject/admin@example.com"]);
        assert!(!check(&input).policy_shape_matches_candidate);
        input = candidate();
        input.deny_policy["rules"][0]["denyRule"]["denialCondition"] =
            json!({"expression":"resource.matchTag('123/env','test')"});
        assert!(!check(&input).policy_shape_matches_candidate);
        input = candidate();
        input.deny_policy["rules"][1]["denyRule"]["exceptionPermissions"] = json!(RENAME_V2);
        assert!(!check(&input).policy_shape_matches_candidate);
        input = candidate();
        input.deny_policy["deleteTime"] = json!("2025-01-01T00:00:00Z");
        assert!(!check(&input).policy_shape_matches_candidate);
        input.deny_policy["deleteTime"] = json!("");
        assert!(check(&input).policy_shape_matches_candidate);
    }

    #[test]
    fn allow_policy_and_role_cannot_broaden_the_creator_grant() {
        let mut input = candidate();
        input.project_allow_policy["version"] = json!(1);
        assert!(!check(&input).policy_shape_matches_candidate);
        input = candidate();
        input.project_allow_policy["bindings"][0]["condition"]["expression"] =
            json!("request.time < timestamp('2025-01-02T00:00:00Z')");
        assert!(!check(&input).policy_shape_matches_candidate);
        input = candidate();
        input.project_allow_policy["bindings"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "role":"projects/test-project/roles/zrpcCreator",
                "members":["serviceAccount:controller@example.iam.gserviceaccount.com"]
            }));
        assert!(!check(&input).policy_shape_matches_candidate);
        input = candidate();
        input.project_allow_policy["bindings"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "role":"projects/test-project/roles/zrpcCreator",
                "members":["allUsers"]
            }));
        assert!(!check(&input).policy_shape_matches_candidate);
        input = candidate();
        input.creator_role["includedPermissions"]
            .as_array_mut()
            .unwrap()
            .push(json!("compute.instances.setName"));
        assert!(!check(&input).policy_shape_matches_candidate);
        input = candidate();
        input.creator_role["deleted"] = json!(true);
        assert!(!check(&input).policy_shape_matches_candidate);
        input = candidate();
        input
            .creator_role
            .as_object_mut()
            .unwrap()
            .remove("deleted");
        assert!(check(&input).policy_shape_matches_candidate);
    }
}
