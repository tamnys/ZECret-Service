//! Explicit operator commands; never invoked by the RPC client or guest.
use serde::de::DeserializeOwned;
use serde_json::json;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use zrpc_lifecycle::gcp::{
    self, Error, Result, controller,
    iam_diagnostic::{self, Snapshot as IamFreezeSnapshot},
    package::{Artifact, DeploymentSpec, Package},
    provider::{GoogleClient, Runtime},
    store::Store,
    watchdog::{self, Controls, WatchdogBinding},
};

fn read<T: DeserializeOwned>(path: &Path) -> Result<T> {
    serde_json::from_slice(&gcp::read_regular(path)?)
        .map_err(|_| Error("invalid typed operator input"))
}
fn value(args: &BTreeMap<String, String>, name: &str) -> Result<String> {
    args.get(name)
        .cloned()
        .ok_or(Error("required operator argument missing; see --help"))
}
fn path(args: &BTreeMap<String, String>, name: &str) -> Result<PathBuf> {
    Ok(PathBuf::from(value(args, name)?))
}
fn print(value: &impl serde::Serialize) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(value).map_err(|_| Error("output encoding failed"))?
    );
    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
async fn run() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "--help".into());
    if command == "--help" || command == "help" {
        println!(
            "zrpc-gcp-lifecycle: explicit Google C3 TDX operator control plane\n\nLocal commands (no authentication/network):\n  prepare --spec SPEC.json --package PACKAGE.json --state ABSOLUTE_NEW_DIRECTORY\n  status --state DIRECTORY\n  recover --state DIRECTORY\n  export-watchdog --state DIRECTORY --controls CONTROLS.json --output NEW_DIRECTORY\n  record-billing-evidence --state DIRECTORY --evidence ARTIFACT.json\n  inspect-iam-freeze --state DIRECTORY --snapshot CAPTURED_IAM.json\n\nOperator cloud commands (OAuth/network; deploy can incur costs):\n  deploy --state DIRECTORY --runtime RUNTIME.json --controls CONTROLS.json --approve-package SHA256\n  observe --state DIRECTORY --runtime RUNTIME.json\n  teardown --state DIRECTORY --runtime RUNTIME.json\n  watchdog-once --state DIRECTORY --runtime RUNTIME.json --controls CONTROLS.json\n\nEach pass is bounded by explicit runtime inputs. Pending results require another\npass. Never replace the original journal. No package grants private acceptance.\nLocal commands make no cloud calls; billing evidence does not establish finality.\nIAM snapshot inspection never grants deployment approval."
        );
        return Ok(());
    }
    let allowed: &[&str] = match command.as_str() {
        "prepare" => &["--spec", "--package", "--state"],
        "status" | "recover" => &["--state"],
        "export-watchdog" => &["--state", "--controls", "--output"],
        "record-billing-evidence" => &["--state", "--evidence"],
        "inspect-iam-freeze" => &["--state", "--snapshot"],
        "deploy" => &["--state", "--runtime", "--controls", "--approve-package"],
        "observe" | "teardown" => &["--state", "--runtime"],
        "watchdog-once" => &["--state", "--runtime", "--controls"],
        _ => return Err(Error("unknown lifecycle command; see --help")),
    };
    let mut options = BTreeMap::new();
    while let Some(key) = args.next() {
        let val = args.next().ok_or(Error("option requires a value"))?;
        if !allowed.contains(&key.as_str()) || options.insert(key, val).is_some() {
            return Err(Error("unknown or duplicate operator option"));
        }
    }
    let state_path = path(&options, "--state")?;
    let at = gcp::now()?;
    if command == "prepare" {
        let spec: DeploymentSpec = read(&path(&options, "--spec")?)?;
        let package = Package::prepare(spec, at)?;
        let output = path(&options, "--package")?;
        package.write_new(&output)?;
        Store::initialize(&state_path, &package)?;
        return print(
            &json!({"package_sha256":package.sha256()?,"resource_count":package.resources.len(),"network_used":false,"private_accepted":false,"live_deployment_blockers":gcp::LIVE_DEPLOYMENT_BLOCKERS,"deployment_prerequisites":["explicit operator package approval","effective external Linux systemd controls","hash-bound deletion rehearsal and independent backstop","current quote and verified image artifacts","authenticated Google project access"]}),
        );
    }
    if command == "recover" {
        Store::recover(&state_path)?;
        return print(&json!({"local_recovery":"completed","network_used":false}));
    }
    let mut store = Store::open(&state_path)?;
    let package = store.package()?;
    if command == "status" {
        return print(store.journal());
    }
    if command == "inspect-iam-freeze" {
        let snapshot: IamFreezeSnapshot = read(&path(&options, "--snapshot")?)?;
        return print(&iam_diagnostic::inspect(
            &package.spec.project,
            package.spec.start_unix_seconds,
            package.spec.deadline_unix_seconds,
            &snapshot,
        ));
    }
    if command == "record-billing-evidence" {
        let evidence: Artifact = read(&path(&options, "--evidence")?)?;
        store.record_billing_evidence(&evidence)?;
        return print(
            &json!({"billing_evidence_sha256":evidence.sha256,"billing_reconciled":false,"network_used":false}),
        );
    }
    if command == "export-watchdog" {
        let controls_path = path(&options, "--controls")?;
        let controls_bytes = gcp::read_regular(&controls_path)?;
        let controls: Controls = serde_json::from_slice(&controls_bytes)
            .map_err(|_| Error("invalid typed operator input"))?;
        if controls.package_sha256 != package.sha256()? {
            return Err(Error("controls bind another package"));
        }
        if let Some(original) = &store.journal().watchdog {
            if original.controls_path != controls_path
                || original.controls_sha256 != gcp::digest(&controls_bytes)
            {
                return Err(Error(
                    "admitted watchdog controls cannot be re-exported differently",
                ));
            }
        }
        watchdog::export(
            &controls,
            &package,
            &controls_path,
            &path(&options, "--output")?,
        )?;
        return print(&json!({"units_exported":true,"units_installed":false,"network_used":false}));
    }
    if command == "watchdog-once" && store.journal().watchdog.is_none() {
        if store.journal().resources.iter().any(|r| r.create.is_some()) {
            return Err(Error("created resources lack original watchdog admission"));
        }
        // Enabled startup reconciliation can run before the separately
        // approved deploy command. There is nothing to clean up yet.
        return print(&json!({"cleanup":"not_admitted","network_used":false}));
    }
    let runtime_path = path(&options, "--runtime")?;
    let runtime_bytes = gcp::read_regular(&runtime_path)?;
    let runtime: Runtime = serde_json::from_slice(&runtime_bytes)
        .map_err(|_| Error("invalid typed operator input"))?;
    let mut due = false;
    if command == "deploy" {
        let controls_path = path(&options, "--controls")?;
        let controls_bytes = gcp::read_regular(&controls_path)?;
        let controls: Controls = serde_json::from_slice(&controls_bytes)
            .map_err(|_| Error("invalid typed operator input"))?;
        if controls.package_sha256 != package.sha256()?
            || controls.state_directory != state_path
            || controls.runtime_file.path != runtime_path
            || gcp::digest(&runtime_bytes) != controls.runtime_file.sha256
        {
            return Err(Error(
                "external controls do not bind this journal and runtime",
            ));
        }
        if value(&options, "--approve-package")? != package.sha256()? {
            return Err(Error("explicit approval must match frozen package SHA-256"));
        }
        gcp::ensure_live_creation_ready()?;
        package.validate(at)?;
        controls.verify_live(&package, &controls_path, at)?;
        store.admit_watchdog(WatchdogBinding::from_admitted(
            &controls,
            &controls_path,
            &controls_bytes,
            &package,
        )?)?;
    } else {
        // Every cloud command uses the original fsynced admission. Controls
        // changes never supply a later cleanup trigger after a restart.
        let original = store
            .journal()
            .watchdog
            .as_ref()
            .ok_or(Error("cloud command requires admitted watchdog controls"))?;
        if runtime_path != original.runtime_file.path
            || gcp::digest(&runtime_bytes) != original.runtime_file.sha256
        {
            return Err(Error("runtime differs from admitted watchdog binding"));
        }
        if command == "watchdog-once" {
            due = original.due(
                &path(&options, "--controls")?,
                at,
                store.journal().teardown_started,
            )?;
        }
    }
    // No OAuth/network operation occurs before all applicable admission above.
    let mut provider = GoogleClient::authenticate(&runtime, &package.spec.project).await?;
    match command.as_str() {
        "deploy" => print(&controller::deploy_once(&mut store, &mut provider, at).await?),
        "teardown" => print(&controller::teardown_once(&mut store, &mut provider, at).await?),
        "watchdog-once" if due => {
            print(&controller::teardown_once(&mut store, &mut provider, at).await?)
        }
        "observe" | "watchdog-once" => {
            controller::observe(&mut store, &mut provider, at).await?;
            print(store.journal())
        }
        _ => Err(Error("invalid operator command")),
    }
}
