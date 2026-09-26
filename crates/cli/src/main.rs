use serde::de::DeserializeOwned;
use serde_json::json;
use std::{
    env, fs,
    io::{self, Read, Write},
    process::{Command, Stdio},
};
use zrpc_client::{PrivateClient, Scenario, SimulationClient};
use zrpc_lifecycle::{DeploymentManifest, PlanInput};

mod ledger;
mod provider_deletion;
mod provider_observation;
mod provider_schedule;
mod provider_settings;
mod provider_watchdog;

const USAGE: &str = "zrpc doctor\nzrpc inspect-quote --quote FILE --collateral FILE\nzrpc inspect-workload --quote FILE --collateral FILE --event-log FILE --app-compose FILE --policy FILE\nzrpc inspect-endpoint --endpoint-host HOST --endpoint-port PORT --socks IPV4:PORT --collateral FILE --app-compose FILE --policy FILE\nzrpc verify [--endpoint HOST] [--policy FILE]\nzrpc query [--stdin | --method METHOD] [--simulate] [--scenario SCENARIO]\nzrpc demo [--no-open]\nzrpc plan --input FILE\nzrpc watchdog --manifest FILE --now UNIX_SECONDS --accrued-microusd INTEGER\nzrpc teardown --simulate --manifest FILE\nzrpc lifecycle --help\nM0 plus public endpoint diagnostics, lifecycle observations and explicit tracked deletion; private mode and deployment are unavailable.";

fn print_json(value: impl serde::Serialize) -> Result<(), String> {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, &value).map_err(|_| "output unavailable")?;
    writeln!(stdout).map_err(|_| "output unavailable".to_owned())
}
fn read_json<T: DeserializeOwned>(path: &str) -> Result<T, String> {
    let bytes = fs::read(path).map_err(|_| "input file unavailable")?;
    serde_json::from_slice(&bytes).map_err(|_| "invalid input document".into())
}
fn take_flag(args: &mut Vec<String>, flag: &str) -> bool {
    if let Some(index) = args.iter().position(|v| v == flag) {
        args.remove(index);
        true
    } else {
        false
    }
}
fn take_value(args: &mut Vec<String>, flag: &str) -> Result<Option<String>, String> {
    if let Some(index) = args.iter().position(|v| v == flag) {
        args.remove(index);
        if index >= args.len() || args[index].starts_with("--") {
            return Err("missing option value".into());
        }
        Ok(Some(args.remove(index)))
    } else {
        Ok(None)
    }
}
fn required(args: &mut Vec<String>, flag: &str) -> Result<String, String> {
    take_value(args, flag)?.ok_or_else(|| format!("required option: {flag}"))
}
fn exhausted(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        Ok(())
    } else {
        Err("unknown or repeated argument".into())
    }
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        // Static/sanitized messages only; never echo query input or credentials.
        let _ = print_json(
            json!({"error":error,"private_accepted":false,"query_sent":false,"deployment_enabled":false}),
        );
        std::process::exit(1);
    }
}
async fn run() -> Result<(), String> {
    let mut args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        println!("{USAGE}");
        return Ok(());
    }
    let command = args.remove(0);
    match command.as_str(){
        "help"|"--help"=>{exhausted(&args)?;println!("{USAGE}");Ok(())},
        "doctor"=>{exhausted(&args)?;print_json(json!({"milestone":"M0","private_mode":"blocked","simulation_available":true,"public_endpoint_inspection_available":true,"tor":"not_checked; public inspection requires explicit loopback SOCKS","hardware_verifier":"offline_dcap_qvl_0.6.3_inspection_only","approved_release":null,"gates":{"A":"unresolved","B":"unresolved","C":"unresolved","D":"unresolved","E":"unresolved"},"deployment_enabled":false,"cloud_resources_created_by_this_binary":0}))},
        "inspect-endpoint"=>inspect_endpoint_command(args).await,
        "lifecycle"=>provider_observation::run(args).await,
        "inspect-quote"=>{
            let quote_path=required(&mut args,"--quote")?;
            let collateral_path=required(&mut args,"--collateral")?;
            exhausted(&args)?;
            let quote=fs::read(quote_path).map_err(|_|"quote file unavailable")?;
            let collateral=fs::read(collateral_path).map_err(|_|"collateral file unavailable")?;
            let report=zrpc_verifier::offline::inspect_quote(&quote,&collateral);
            let rejected=report.issue.is_some();
            print_json(report)?;
            if rejected { std::process::exit(1) }
            Ok(())
        },
        "inspect-workload"=>{
            let quote_path=required(&mut args,"--quote")?;
            let collateral_path=required(&mut args,"--collateral")?;
            let event_log_path=required(&mut args,"--event-log")?;
            let app_compose_path=required(&mut args,"--app-compose")?;
            let policy_path=required(&mut args,"--policy")?;
            exhausted(&args)?;
            let policy_bytes=fs::read(policy_path).map_err(|_|"workload policy file unavailable")?;
            let policy=zrpc_verifier::workload::WorkloadPolicy::from_json(&policy_bytes).map_err(|_|"workload policy rejected")?;
            let quote=fs::read(quote_path).map_err(|_|"quote file unavailable")?;
            let collateral=fs::read(collateral_path).map_err(|_|"collateral file unavailable")?;
            let event_log=fs::read(event_log_path).map_err(|_|"event log file unavailable")?;
            let app_compose=fs::read(app_compose_path).map_err(|_|"app-compose file unavailable")?;
            let report=zrpc_verifier::workload::inspect_workload(&quote,&collateral,&event_log,&app_compose,&policy);
            let rejected=report.quote.issue.is_some() || report.workload_issue.is_some();
            print_json(report)?;
            if rejected { std::process::exit(1) }
            Ok(())
        },
        "verify"=>{
            let _endpoint=take_value(&mut args,"--endpoint")?;
            let policy=take_value(&mut args,"--policy")?;
            exhausted(&args)?;
            if let Some(path)=policy {
                let bytes=fs::read(path).map_err(|_|"policy unavailable")?;
                zrpc_verifier::ReleasePolicy::from_json(&bytes).map_err(|_|"policy rejected")?;
            }
            print_json(PrivateClient::new().verify())?;
            std::process::exit(1)
        },
        "query"=>{
            let simulation=take_flag(&mut args,"--simulate");
            let stdin=take_flag(&mut args,"--stdin");
            let method=take_value(&mut args,"--method")?;
            let scenario=take_value(&mut args,"--scenario")?;
            exhausted(&args)?;
            if stdin && method.is_some(){return Err("choose stdin or method".into())}
            if !simulation {
                // Do not even read a customer body before authorization.
                print_json(PrivateClient::new().verify())?;
                std::process::exit(1);
            }
            let scenario=scenario.unwrap_or_else(||"fixture".into()).parse::<Scenario>().map_err(|_|"unknown simulation scenario")?;
            let bytes=if stdin {
                let mut bytes=Vec::new();
                io::stdin().take(16*1024+1).read_to_end(&mut bytes).map_err(|_|"stdin unavailable")?;
                bytes
            }else{serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"method":method.unwrap_or_else(||"getblockcount".into()),"params":[]})).map_err(|_|"request unavailable")?};
            let report=SimulationClient::query(&bytes,scenario);
            let failed=report.error.is_some();
            print_json(report)?;
            if failed{std::process::exit(1)}else{Ok(())}
        },
        "demo"=>{
            let no_open=take_flag(&mut args,"--no-open");exhausted(&args)?;
            let listener=tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST,0)).await.map_err(|_|"loopback bind failed")?;
            let address=listener.local_addr().map_err(|_|"loopback address unavailable")?;
            let session=zrpc_cli::LocalSession::new(address)?;
            let url=session.bootstrap_url()?;
            if no_open {
                // Deliberate terminal delivery only, never stdout/stderr/log files.
                let mut tty=fs::OpenOptions::new().write(true).open("/dev/tty").map_err(|_|"interactive terminal required for --no-open")?;
                writeln!(tty,"Open this one-time local simulation link privately:\n{url}").map_err(|_|"terminal unavailable")?;
            }else{
                #[cfg(target_os="macos")] let opener="open";
                #[cfg(not(target_os="macos"))] let opener="xdg-open";
                Command::new(opener).arg(&url).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map_err(|_|"browser opener unavailable; use demo --no-open in a terminal")?;
            }
            println!("SIMULATION ONLY — local dashboard on http://{address}. Press Ctrl-C to close.");
            axum::serve(listener,zrpc_cli::dashboard(session)).with_graceful_shutdown(async {let _=tokio::signal::ctrl_c().await;}).await.map_err(|_|"local server failed".into())
        },
        "plan"=>{
            let path=required(&mut args,"--input")?;exhausted(&args)?;
            let input:PlanInput=read_json(&path)?;
            print_json(zrpc_lifecycle::plan(&input).map_err(|e|e.to_string())?)
        },
        "watchdog"=>{
            let path=required(&mut args,"--manifest")?;
            let now=required(&mut args,"--now")?.parse().map_err(|_|"invalid time")?;
            let accrued=required(&mut args,"--accrued-microusd")?.parse().map_err(|_|"invalid amount")?;
            exhausted(&args)?;
            let manifest:DeploymentManifest=read_json(&path)?;
            print_json(zrpc_lifecycle::watchdog(&manifest,now,accrued).map_err(|e|e.to_string())?)
        },
        "teardown"=>{
            if !take_flag(&mut args,"--simulate"){return Err("teardown requires --simulate; explicit tracked deletion uses lifecycle delete-tracked".into())}
            let path=required(&mut args,"--manifest")?;exhausted(&args)?;
            let mut manifest:DeploymentManifest=read_json(&path)?;
            print_json(zrpc_lifecycle::simulated_teardown(&mut manifest).map_err(|e|e.to_string())?)
        },
        "deploy"=>Err("deployment is disabled in M0; Gates A–E, external deletion proof and explicit operator deployment action are required".into()),
        _=>Err("unknown command; run zrpc help".into())
    }
}

async fn inspect_endpoint_command(mut args: Vec<String>) -> Result<(), String> {
    let hostname = required(&mut args, "--endpoint-host")?;
    let port = required(&mut args, "--endpoint-port")?
        .parse::<u16>()
        .map_err(|_| "invalid endpoint port")?;
    let socks = required(&mut args, "--socks")?;
    let collateral_path = required(&mut args, "--collateral")?;
    let compose_path = required(&mut args, "--app-compose")?;
    let policy_path = required(&mut args, "--policy")?;
    exhausted(&args)?;
    // Validate local settings and parse policy before opening any network socket.
    let config = zrpc_client::inspection::PublicInspectionConfig::new(&hostname, port, &socks)
        .map_err(|error| error.to_string())?;
    let policy_bytes = fs::read(policy_path).map_err(|_| "workload policy file unavailable")?;
    let policy = zrpc_verifier::workload::WorkloadPolicy::from_json(&policy_bytes)
        .map_err(|_| "workload policy rejected")?;
    let collateral = fs::read(collateral_path).map_err(|_| "collateral file unavailable")?;
    let compose = fs::read(compose_path).map_err(|_| "app-compose file unavailable")?;
    let report = zrpc_client::inspection::inspect_endpoint(&config, &collateral, &compose, &policy)
        .await
        .map_err(|error| error.to_string())?;
    let passed = report.diagnostic_passed();
    print_json(json!({
        "mode":"public_endpoint_inspection",
        "transport":"configured_loopback_socks_with_hostname_forwarding",
        "tor_process_identity_verified":false,
        "approved_release":null,
        "private_accepted":false,
        "query_sent":false,
        "deployment_enabled":false,
        "inspection":report
    }))?;
    if !passed {
        std::process::exit(1);
    }
    Ok(())
}
