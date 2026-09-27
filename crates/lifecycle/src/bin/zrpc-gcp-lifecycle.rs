//! Explicit operator commands; never invoked by the RPC client or guest.
use serde::de::DeserializeOwned;
use serde_json::json;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use zrpc_lifecycle::gcp::{
    self, Error, Result, controller,
    package::{DeploymentSpec, Package},
    provider::{GoogleClient, Runtime},
    store::Store,
    watchdog::{self, Controls},
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
            "zrpc-gcp-lifecycle: explicit Google C3 TDX operator control plane\n\nLocal commands (no authentication/network):\n  prepare --spec SPEC.json --package PACKAGE.json --state ABSOLUTE_NEW_DIRECTORY\n  status --state DIRECTORY\n  recover --state DIRECTORY\n  export-watchdog --state DIRECTORY --controls CONTROLS.json --output NEW_DIRECTORY\n\nOperator cloud commands (OAuth/network; deploy can incur costs):\n  deploy --state DIRECTORY --runtime RUNTIME.json --controls CONTROLS.json --approve-package SHA256\n  observe --state DIRECTORY --runtime RUNTIME.json\n  teardown --state DIRECTORY --runtime RUNTIME.json\n  watchdog-once --state DIRECTORY --runtime RUNTIME.json --controls CONTROLS.json\n\nEach pass is bounded by explicit runtime inputs. Pending results require another\npass. Never replace the original journal. No package grants private acceptance.\nNo cloud commands are run by prepare or export-watchdog."
        );
        return Ok(());
    }
    let allowed: &[&str] = match command.as_str() {
        "prepare" => &["--spec", "--package", "--state"],
        "status" | "recover" => &["--state"],
        "export-watchdog" => &["--state", "--controls", "--output"],
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
    if command == "export-watchdog" {
        let controls_path = path(&options, "--controls")?;
        let controls: Controls = read(&controls_path)?;
        if controls.package_sha256 != package.sha256()? {
            return Err(Error("controls bind another package"));
        }
        watchdog::export(
            &controls,
            &package,
            &controls_path,
            &path(&options, "--output")?,
        )?;
        return print(&json!({"units_exported":true,"units_installed":false,"network_used":false}));
    }
    let runtime_path = path(&options, "--runtime")?;
    let runtime: Runtime = read(&runtime_path)?;
    let mut due = false;
    if command == "deploy" || command == "watchdog-once" {
        let controls_path = path(&options, "--controls")?;
        let controls: Controls = read(&controls_path)?;
        if controls.package_sha256 != package.sha256()?
            || controls.state_directory != state_path
            || controls.runtime_file.path != runtime_path
            || gcp::digest(&gcp::read_regular(&runtime_path)?) != controls.runtime_file.sha256
        {
            return Err(Error(
                "external controls do not bind this journal and runtime",
            ));
        }
        watchdog::verify_controls_path(&controls_path, controls.controller_uid)?;
        if command == "deploy" {
            if value(&options, "--approve-package")? != package.sha256()? {
                return Err(Error("explicit approval must match frozen package SHA-256"));
            }
            gcp::ensure_live_creation_ready()?;
            package.validate(at)?;
            controls.verify_live(&package, &controls_path, at)?;
        } else {
            due = at >= controls.deletion_start(&package)? || store.journal().teardown_started;
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
