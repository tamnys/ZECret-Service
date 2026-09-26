//! One bounded operator/controller pass. Pending/uncertain results are retained.
use super::{
    Error, Result,
    package::{Package, ResourceKind, ResourcePlan},
    provider::{Mutation, Operation, Provider},
    store::{Intent, Store},
    uuid,
};
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Progress {
    Pending,
    DeployedForSyntheticEvaluation,
    ResourcesAbsentBillingUnreconciled,
}

fn identity(resource: &ResourcePlan, value: &Value) -> Result<String> {
    let field = if resource.kind == ResourceKind::StagingObject {
        "generation"
    } else {
        "id"
    };
    let value = value
        .get(field)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        .ok_or(Error(
            "provider resource lacks numeric incarnation identity",
        ))?;
    Ok(value.to_owned())
}
fn owned(resource: &ResourcePlan, value: &Value) -> Result<()> {
    if resource.kind == ResourceKind::StagingObject {
        if value.get("metadata") != Some(&resource.create_body) {
            return Err(Error("staging object ownership/artifact metadata mismatch"));
        }
        let name = resource
            .path
            .split("/o/")
            .nth(1)
            .ok_or(Error("invalid object plan"))?;
        if value.get("name").and_then(Value::as_str) != Some(name) {
            return Err(Error("staging object name mismatch"));
        }
    } else if value.get("description") != resource.create_body.get("description")
        || value.get("name") != resource.create_body.get("name")
    {
        return Err(Error("resource is not the experiment-owned incarnation"));
    }
    Ok(())
}
fn intent(at: u64) -> Result<Intent> {
    Ok(Intent {
        request_id: uuid()?,
        committed_at: at,
        operation: None,
        done: false,
        failed: false,
    })
}
fn accept_operation(
    store: &mut Store,
    index: usize,
    resource: &ResourcePlan,
    operation: Operation,
    deleting: bool,
) -> Result<()> {
    let mut next = store.journal().clone();
    let state = &mut next.resources[index];
    let intent = if deleting {
        state.delete.as_mut()
    } else {
        state.create.as_mut()
    }
    .ok_or(Error("operation has no durable intent"))?;
    let target1 = format!("https://www.googleapis.com/compute/v1/{}", resource.path);
    let target2 = format!(
        "https://compute.googleapis.com/compute/v1/{}",
        resource.path
    );
    if !super::package::name(&operation.name)
        || !["PENDING", "RUNNING", "DONE"].contains(&operation.status.as_str())
        || operation.target_link != target1 && operation.target_link != target2
        || operation.client_operation_id.as_deref() != Some(&intent.request_id)
        || intent
            .operation
            .as_ref()
            .is_some_and(|n| *n != operation.name)
    {
        return Err(Error(
            "operation identity/scope does not match durable intent",
        ));
    }
    intent.operation = Some(operation.name);
    intent.done = operation.status == "DONE";
    intent.failed = operation.error.is_some();
    if let Some(id) = operation.target_id {
        if id.is_empty()
            || !id.bytes().all(|b| b.is_ascii_digit())
            || state.identity.as_ref().is_some_and(|old| old != &id)
        {
            return Err(Error("operation resource incarnation mismatch"));
        }
        state.identity = Some(id);
    }
    store.commit(next)
}
async fn observe_resource<P: Provider>(
    store: &mut Store,
    provider: &mut P,
    package: &Package,
    index: usize,
    at: u64,
) -> Result<Option<Value>> {
    let resource = &package.resources[index];
    let value = provider.get(resource).await?;
    let mut next = store.journal().clone();
    let state = &mut next.resources[index];
    if let Some(value) = &value {
        owned(resource, value)?;
        if state.create.is_none() {
            return Err(Error(
                "resource already exists without this journal's creation intent",
            ));
        }
        let id = identity(resource, value)?;
        if state.identity.as_ref().is_some_and(|old| old != &id) {
            return Err(Error(
                "resource name now belongs to another incarnation; deletion refused",
            ));
        }
        state.identity = Some(id);
        state.observed_absent = false;
        if resource.kind == ResourceKind::StagingObject {
            if let Some(create) = state.create.as_mut() {
                create.done = true;
            }
        }
    } else {
        state.observed_absent = true;
    }
    state.last_observed_at = Some(at);
    store.commit(next)?;
    Ok(value)
}
async fn poll<P: Provider>(
    store: &mut Store,
    provider: &mut P,
    package: &Package,
    index: usize,
    deleting: bool,
) -> Result<()> {
    let state = &store.journal().resources[index];
    let intent = if deleting {
        &state.delete
    } else {
        &state.create
    };
    if let Some(intent) = intent {
        if !intent.done && package.resources[index].kind != ResourceKind::StagingObject {
            let operation = if let Some(name) = &intent.operation {
                Some(provider.operation(&package.resources[index], name).await?)
            } else {
                provider
                    .recover_operation(&package.resources[index], &intent.request_id)
                    .await?
            };
            if let Some(operation) = operation {
                accept_operation(store, index, &package.resources[index], operation, deleting)?;
            }
        }
    }
    Ok(())
}

/// Runs only after live external-control admission. Does not interpret an
/// arbitrary file or readiness Boolean as approval to create cloud resources.
pub async fn deploy_once<P: Provider>(
    store: &mut Store,
    provider: &mut P,
    at: u64,
) -> Result<Progress> {
    let package = store.package()?;
    package.validate(at)?;
    if at < store.journal().original_start || store.journal().teardown_started {
        return Err(Error(
            "deployment outside original window or teardown already started",
        ));
    }
    provider.preflight(&package).await?;
    for (index, resource) in package.resources.iter().enumerate() {
        poll(store, provider, &package, index, false).await?;
        if store.journal().resources[index]
            .create
            .as_ref()
            .is_some_and(|i| i.failed)
        {
            return Err(Error(
                "creation operation failed; teardown or operator investigation required",
            ));
        }
        let present = observe_resource(store, provider, &package, index, at)
            .await?
            .is_some();
        let state = store.journal().resources[index].clone();
        if present {
            if resource.kind == ResourceKind::StagingObject
                && state.create.as_ref().is_some_and(|i| !i.done)
            {
                let mut next = store.journal().clone();
                next.resources[index]
                    .create
                    .as_mut()
                    .ok_or(Error("missing staging intent"))?
                    .done = true;
                store.commit(next)?;
            } else if !state.create.as_ref().is_some_and(|i| i.done) {
                return Ok(Progress::Pending);
            }
            continue;
        }
        if let Some(create) = &state.create {
            if create.done {
                return Err(Error(
                    "created resource disappeared; same-experiment recreation forbidden",
                ));
            }
            if create.operation.is_some() {
                return Ok(Progress::Pending);
            }
        }
        if state.create.is_none() {
            let mut next = store.journal().clone();
            next.resources[index].create = Some(intent(at)?);
            store.commit(next)?;
        }
        let request_id = store.journal().resources[index]
            .create
            .as_ref()
            .ok_or(Error("missing committed create intent"))?
            .request_id
            .clone();
        // The fsync above is complete before this first mutation request.
        match provider.create(&package, resource, &request_id).await? {
            Mutation::Operation(operation) => {
                accept_operation(store, index, resource, operation, false)?
            }
            Mutation::Object(value) => {
                owned(resource, &value)?;
                let id = identity(resource, &value)?;
                let mut next = store.journal().clone();
                let s = &mut next.resources[index];
                s.identity = Some(id);
                s.create
                    .as_mut()
                    .ok_or(Error("missing creation intent"))?
                    .done = true;
                s.observed_absent = false;
                s.last_observed_at = Some(at);
                store.commit(next)?;
            }
            Mutation::Absent => return Err(Error("creation response cannot establish absence")),
        }
        return Ok(Progress::Pending);
    }
    Ok(Progress::DeployedForSyntheticEvaluation)
}

pub async fn observe<P: Provider>(store: &mut Store, provider: &mut P, at: u64) -> Result<()> {
    let package = store.package()?;
    for index in 0..package.resources.len() {
        if store.journal().resources[index].create.is_none() {
            continue;
        }
        poll(store, provider, &package, index, false).await?;
        poll(store, provider, &package, index, true).await?;
        observe_resource(store, provider, &package, index, at).await?;
    }
    Ok(())
}

pub async fn teardown_once<P: Provider>(
    store: &mut Store,
    provider: &mut P,
    at: u64,
) -> Result<Progress> {
    let package = store.package()?;
    if !store.journal().teardown_started {
        let mut next = store.journal().clone();
        next.teardown_started = true;
        store.commit(next)?;
    }
    for (index, resource) in package.resources.iter().enumerate().rev() {
        if store.journal().resources[index].create.is_none() {
            continue;
        }
        poll(store, provider, &package, index, false).await?;
        let creation = store.journal().resources[index]
            .create
            .as_ref()
            .ok_or(Error("missing creation intent"))?;
        if creation.operation.is_some() && !creation.done {
            return Ok(Progress::Pending);
        }
        poll(store, provider, &package, index, true).await?;
        let present = observe_resource(store, provider, &package, index, at)
            .await?
            .is_some();
        let state = store.journal().resources[index].clone();
        if !present {
            // A timed-out create with no operation could still complete later.
            // Do not infer cancellation or reset its original request id.
            if !state.create.as_ref().is_some_and(|i| i.done) {
                return Err(Error(
                    "creation outcome uncertain; absence alone cannot finish cleanup",
                ));
            }
            if state
                .delete
                .as_ref()
                .is_some_and(|i| i.operation.is_some() && !i.done)
            {
                return Ok(Progress::Pending);
            }
            continue;
        }
        if state.delete.as_ref().is_some_and(|i| i.failed) {
            return Err(Error("deletion operation failed; original intent retained"));
        }
        if state.delete.as_ref().is_some_and(|i| i.done) {
            return Err(Error(
                "resource remains after completed deletion; cleanup uncertain",
            ));
        }
        if state.delete.as_ref().is_some_and(|i| i.operation.is_some()) {
            return Ok(Progress::Pending);
        }
        if state.delete.is_none() {
            let mut next = store.journal().clone();
            next.resources[index].delete = Some(intent(at)?);
            store.commit(next)?;
        }
        let state = &store.journal().resources[index];
        let request_id = state
            .delete
            .as_ref()
            .ok_or(Error("missing deletion intent"))?
            .request_id
            .clone();
        let id = state
            .identity
            .as_ref()
            .ok_or(Error("deletion requires resource incarnation"))?
            .clone();
        match provider.delete(resource, &id, &request_id).await? {
            Mutation::Operation(operation) => {
                accept_operation(store, index, resource, operation, true)?
            }
            Mutation::Object(_) | Mutation::Absent => {
                let mut next = store.journal().clone();
                next.resources[index]
                    .delete
                    .as_mut()
                    .ok_or(Error("missing deletion intent"))?
                    .done = true;
                store.commit(next)?;
            }
        }
        return Ok(Progress::Pending);
    }
    Ok(Progress::ResourcesAbsentBillingUnreconciled)
}

#[cfg(test)]
mod tests;
