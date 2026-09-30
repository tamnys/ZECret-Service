use serde::de::DeserializeOwned;
use serde_json::json;
use std::{
    env, fs,
    io::{self, Read, Write},
    process::{Command, Stdio},
};
use zrpc_client::{PrivateClient, Scenario, SimulationClient};
use zrpc_lifecycle::{DeploymentManifest, PlanInput};
use zrpc_protocol::{
    Backend, ErrorCode, PREVIEW_TESTNET_ADDRESS, SafeError, TestnetTransparentAddress,
};

mod ledger;
mod payments;
mod provider_deletion;
mod provider_observation;
mod provider_schedule;
mod provider_settings;
mod provider_watchdog;

const USAGE: &str = "zrpc doctor
zrpc inspect-quote --quote FILE --collateral FILE
zrpc inspect-workload [--platform gcp-tdx|phala-dstack] --quote FILE --collateral FILE --event-log FILE --policy FILE
zrpc inspect-endpoint [--platform gcp-tdx|phala-dstack] --endpoint-host HOST_OR_IP --endpoint-port PORT --socks IPV4:PORT --collateral FILE --policy FILE
zrpc verify [--platform gcp-tdx|phala-dstack] --endpoint-host HOST_OR_IP --endpoint-port PORT --tor-executable ABSOLUTE_PATH --collateral FILE --release-policy FILE
zrpc query [--stdin | --method METHOD] [--ticket-store PRIVATE_DIR --issuer-public-der FILE --issuer-name NAME --crypto-helper FILE] [--platform gcp-tdx|phala-dstack] --endpoint-host HOST_OR_IP --endpoint-port PORT --tor-executable ABSOLUTE_PATH --collateral FILE --release-policy FILE
zrpc query [--stdin | --method METHOD] --simulate [--scenario SCENARIO]
zrpc payments --help
zrpc dashboard [--platform gcp-tdx|phala-dstack] --endpoint-host HOST_OR_IP --endpoint-port PORT --tor-executable ABSOLUTE_PATH --collateral FILE --release-policy FILE [--no-open]
zrpc preview --platform phala-dstack --endpoint-host HOST_OR_IP --endpoint-port PORT --tor-executable ABSOLUTE_PATH --collateral FILE [--address TESTNET_TRANSPARENT_ADDRESS]
zrpc dashboard --preview --platform phala-dstack --endpoint-host HOST_OR_IP --endpoint-port PORT --tor-executable ABSOLUTE_PATH --collateral FILE [--address TESTNET_TRANSPARENT_ADDRESS] [--no-open]
zrpc demo [--no-open]
zrpc plan --input FILE
zrpc watchdog --manifest FILE --now UNIX_SECONDS --accrued-microusd INTEGER
zrpc teardown --simulate --manifest FILE
zrpc lifecycle --help
GCP operator tooling: zrpc-gcp-lifecycle --help
The legacy default platform for inspect, verify, query, and dashboard is gcp-tdx. Phala public preview requires --platform phala-dstack; Phala private and workload-inspection commands additionally require --app-compose FILE.
Public inspection uses the configured local SOCKS. Once an approved release exists, private commands start a local Tor child with a private Unix SOCKS socket; no direct mode exists.
Live Phala testnet preview verifies a TDX quote, current collateral, fresh challenge, and retained managed-Tor TLS key, then reads public testnet status and one validated testnet transparent address balance. The public fixture address is the default. Workload identity is unverified and private mode remains unavailable.
The compiled approved-release catalog is empty; private queries remain blocked.";

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

fn private_query_body(stdin: bool, method: Option<String>) -> Result<Vec<u8>, SafeError> {
    if stdin {
        let mut bytes = Vec::new();
        io::stdin()
            .take((zrpc_protocol::MAX_REQUEST_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| SafeError::new(ErrorCode::InvalidRequest, "Private input unavailable."))?;
        Ok(bytes)
    } else {
        let method = method.ok_or_else(|| {
            SafeError::new(ErrorCode::InvalidRequest, "Private request unavailable.")
        })?;
        serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":[]}))
            .map_err(|_| SafeError::new(ErrorCode::InvalidRequest, "Private request unavailable."))
    }
}

fn ticket_query_error() -> SafeError {
    SafeError::new(
        ErrorCode::InvalidRequest,
        "Ticket authorization unavailable.",
    )
}

fn platform(args: &mut Vec<String>) -> Result<Backend, String> {
    match take_value(args, "--platform")?
        .as_deref()
        .unwrap_or("gcp-tdx")
    {
        "gcp-tdx" => Ok(Backend::GcpTdx),
        "phala-dstack" => Ok(Backend::PhalaDstack),
        _ => Err("platform must be gcp-tdx or phala-dstack".into()),
    }
}

fn compose_input(args: &mut Vec<String>, backend: Backend) -> Result<Vec<u8>, String> {
    let path = take_value(args, "--app-compose")?;
    match (backend, path) {
        (Backend::GcpTdx, None) => Ok(Vec::new()),
        (Backend::GcpTdx, Some(_)) => {
            Err("--app-compose is only valid with --platform phala-dstack".into())
        }
        (Backend::PhalaDstack, Some(path)) => {
            fs::read(path).map_err(|_| "app-compose unavailable".into())
        }
        (Backend::PhalaDstack, None) => Err("required option: --app-compose".into()),
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
        "doctor"=>{exhausted(&args)?;print_json(json!({"milestone":"M0","primary_platform":"phala-dstack","default_platform":"gcp-tdx","platforms":["gcp-tdx","phala-dstack"],"private_mode":"blocked","simulation_available":true,"public_endpoint_inspection_available":true,"public_preview_available":true,"public_preview_platform":"phala-dstack","tor":"not_checked; public inspection uses explicit SOCKS, Phala preview starts a selected local Tor executable, private mode blocked","hardware_verifier":"offline_dcap_qvl_0.6.3_inspection_and_phala_public_preview_only","approved_release":null,"gates":{"A":"unresolved","B":"unresolved","C":"unresolved","D":"unresolved","E":"unresolved"},"gcp_gates":{"reproducible_guest":"unproven","hardware_boot_chain":"unproven","administrative_isolation":"unproven","durable_storage_isolation":"unproven","tls_exporter_review":"unproven","external_cleanup":"unproven"},"deployment_enabled":false,"cloud_resources_created_by_this_binary":0}))},
        "inspect-endpoint"=>inspect_endpoint_command(args).await,
        "payments"=>payments::run(args),
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
            let backend=platform(&mut args)?;
            let quote_path=required(&mut args,"--quote")?;
            let collateral_path=required(&mut args,"--collateral")?;
            let event_log_path=required(&mut args,"--event-log")?;
            let app_compose=compose_input(&mut args,backend)?;
            let policy_path=required(&mut args,"--policy")?;
            exhausted(&args)?;
            let policy_bytes=fs::read(policy_path).map_err(|_|"workload policy file unavailable")?;
            let quote=fs::read(quote_path).map_err(|_|"quote file unavailable")?;
            let collateral=fs::read(collateral_path).map_err(|_|"collateral file unavailable")?;
            let event_log=fs::read(event_log_path).map_err(|_|"event log file unavailable")?;
            let rejected=match backend {
                Backend::PhalaDstack => {
                    let policy=zrpc_verifier::workload::WorkloadPolicy::from_json(&policy_bytes).map_err(|_|"workload policy rejected")?;
                    let report=zrpc_verifier::workload::inspect_workload(&quote,&collateral,&event_log,&app_compose,&policy);
                    let rejected=report.quote.issue.is_some() || report.workload_issue.is_some();
                    print_json(report)?; rejected
                },
                Backend::GcpTdx => {
                    let policy=zrpc_verifier::gcp::GcpWorkloadPolicy::from_json(&policy_bytes).map_err(|_|"GCP workload policy rejected")?;
                    let report=zrpc_verifier::gcp::inspect_gcp_workload(&quote,&collateral,&event_log,&policy);
                    let rejected=report.quote.issue.is_some() || report.workload_issue.is_some();
                    print_json(report)?; rejected
                }
            };
            if rejected { std::process::exit(1) }
            Ok(())
        },
        "verify"=>{
            if args.is_empty() {
                print_json(PrivateClient::new().verify())?;
                std::process::exit(1)
            }
            if args.first().is_some_and(|arg| arg == "--policy") {
                let path=required(&mut args,"--policy")?;
                exhausted(&args)?;
                let policy=zrpc_verifier::ReleasePolicy::from_json(
                    &fs::read(path).map_err(|_|"policy unavailable")?
                ).map_err(|_|"policy rejected")?;
                print_json(PrivateClient::with_policy(policy).map_err(|error|error.to_string())?.verify())?;
                std::process::exit(1)
            }
            let live=live_inputs(&mut args)?;
            exhausted(&args)?;
            let session=zrpc_client::inspection::connect_verified(&live.config,&live.collateral,&live.compose,&live.policy)
                .await.map_err(|error|error.to_string())?;
            drop(session);
            print_json(json!({"mode":"private_verified","simulation":false,"private_accepted":true,"query_sent":false}))
        },
        "query"=>{
            let simulation=take_flag(&mut args,"--simulate");
            let stdin=take_flag(&mut args,"--stdin");
            let method=take_value(&mut args,"--method")?;
            let scenario=take_value(&mut args,"--scenario")?;
            if stdin && method.is_some(){return Err("choose stdin or method".into())}
            if !simulation {
                if scenario.is_some(){return Err("scenario is simulation-only".into())}
                let ticket_config=payments::QueryTicketConfig::parse(&mut args)?;
                if args.is_empty() {
                    // Do not even read a customer body before authorization.
                    print_json(PrivateClient::new().verify())?;
                    std::process::exit(1);
                }
                let live=live_inputs(&mut args)?;
                exhausted(&args)?;
                if !stdin && method.is_none(){return Err("private query requires --stdin or --method".into())}
                let session=zrpc_client::inspection::connect_verified(&live.config,&live.collateral,&live.compose,&live.policy)
                    .await.map_err(|error|error.to_string())?;
                // The retained session checks the managed Tor lease before
                // this closure reads or constructs any private body.
                let (result,ticket_state)=if let Some(config)=ticket_config {
                    let (issuer,mut store)=config.open()?;
                    let result=session.query_from_body_authorized(
                        || async move {private_query_body(stdin,method)},
                        || {
                            let ticket=store.preview_available().map_err(|_|ticket_query_error())?
                                .ok_or_else(ticket_query_error)?;
                            let authorization=issuer.authorization_for(ticket.token.expose())
                                .map_err(|_|ticket_query_error())?;
                            let marker=ticket.marker;
                            let claim_store=&mut store;
                            Ok((authorization,marker,move || claim_store.claim_available(&ticket)
                                .map_err(|_|ticket_query_error())))
                        }
                    ).await;
                    match result {
                        Ok((value,marker))=>{
                            let state=if store.mark_spent(marker).is_ok(){"spent"}else{"uncertain"};
                            (Ok(value),Some(state))
                        },
                        Err(error)=>(Err(error),None)
                    }
                }else{
                    (session.query_from_body(move || private_query_body(stdin,method)).await,None)
                };
                match result {
                    Ok(result)=>{
                        let mut output=json!({"mode":"private","simulation":false,"private_accepted":true,"query_sent":true,"result":result});
                        if let Some(state)=ticket_state {output["ticket_state"]=json!(state)}
                        print_json(output)
                    },
                    Err(error) if matches!(error.code,ErrorCode::InvalidRequest|ErrorCode::RequestTooLarge|ErrorCode::MethodNotAllowed|ErrorCode::InvalidParameters)=>Err(error.to_string()),
                    Err(error) if error.code == ErrorCode::TorUnavailable=>{
                        print_json(json!({"mode":"private_blocked","simulation":false,"private_accepted":false,"query_sent":false,"error":error}))?;
                        std::process::exit(1)
                    },
                    Err(error)=>{
                        // The sender may have transmitted before a response failed.
                        print_json(json!({"mode":"private_error","simulation":false,"private_accepted":false,"query_sent":"unknown","error":error}))?;
                        std::process::exit(1)
                    }
                }?;
                return Ok(());
            }
            exhausted(&args)?;
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
        "preview"=>{
            let inputs=preview_inputs(&mut args)?;
            exhausted(&args)?;
            match zrpc_client::inspection::preview_testnet(
                &inputs.config,&inputs.collateral,&inputs.address).await {
                Ok(report)=>{
                    let complete=report.public_preview_passed && report.preview.is_some();
                    print_json(json!({"mode":"live_testnet_preview","simulation":false,
                        "platform":inputs.config.platform(),"private_accepted":false,
                        "query_sent":false,"privacy_verification":"unavailable",
                        "report":report,"error":null}))?;
                    if !complete {std::process::exit(1)}
                    Ok(())
                },
                Err(error)=>{
                    print_json(json!({"mode":"live_testnet_preview","simulation":false,
                        "platform":inputs.config.platform(),"private_accepted":false,
                        "query_sent":false,"public_query_sent":false,
                        "privacy_verification":"unavailable",
                        "report":null,"error":error}))?;
                    std::process::exit(1)
                },
            }
        },
        "demo"=>{
            let no_open=take_flag(&mut args,"--no-open");exhausted(&args)?;
            serve_dashboard(DashboardInputs::Simulation,no_open).await
        },
        "dashboard"=>{
            let no_open=take_flag(&mut args,"--no-open");
            if take_flag(&mut args,"--preview") {
                let inputs=preview_inputs(&mut args)?;
                exhausted(&args)?;
                serve_dashboard(DashboardInputs::Preview(inputs),no_open).await
            } else {
                let live=live_inputs(&mut args)?;
                exhausted(&args)?;
                serve_dashboard(DashboardInputs::Live(live),no_open).await
            }
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

struct LiveInputs {
    config: zrpc_client::inspection::PrivateEndpointConfig,
    collateral: Vec<u8>,
    compose: Vec<u8>,
    policy: zrpc_verifier::ReleasePolicy,
}

enum DashboardInputs {
    Simulation,
    Live(LiveInputs),
    Preview(PreviewInputs),
}

struct PreviewInputs {
    config: zrpc_client::inspection::PreviewEndpointConfig,
    collateral: Vec<u8>,
    address: TestnetTransparentAddress,
}

fn preview_inputs(args: &mut Vec<String>) -> Result<PreviewInputs, String> {
    if required(args, "--platform")? != "phala-dstack" {
        return Err("preview platform must be phala-dstack".into());
    }
    let host = required(args, "--endpoint-host")?;
    let port = required(args, "--endpoint-port")?
        .parse::<u16>()
        .map_err(|_| "invalid endpoint port")?;
    let tor_executable = required(args, "--tor-executable")?;
    let collateral_path = required(args, "--collateral")?;
    let address = TestnetTransparentAddress::parse(
        &take_value(args, "--address")?.unwrap_or_else(|| PREVIEW_TESTNET_ADDRESS.to_owned()),
    )
    .map_err(|_| "address must be a valid Zcash testnet transparent address")?;
    let config =
        zrpc_client::inspection::PreviewEndpointConfig::for_phala(&host, port, tor_executable)
            .map_err(|error| error.to_string())?;
    let collateral = fs::read(collateral_path).map_err(|_| "collateral file unavailable")?;
    Ok(PreviewInputs {
        config,
        collateral,
        address,
    })
}

fn live_inputs(args: &mut Vec<String>) -> Result<LiveInputs, String> {
    let backend = platform(args)?;
    let host = required(args, "--endpoint-host")?;
    let port = required(args, "--endpoint-port")?
        .parse::<u16>()
        .map_err(|_| "invalid endpoint port")?;
    let tor_executable = required(args, "--tor-executable")?;
    let collateral_path = required(args, "--collateral")?;
    let compose = compose_input(args, backend)?;
    let release_path = required(args, "--release-policy")?;
    let config = zrpc_client::inspection::PrivateEndpointConfig::for_platform(
        backend,
        &host,
        port,
        tor_executable,
    )
    .map_err(|error| error.to_string())?;
    let policy = zrpc_verifier::ReleasePolicy::from_json(
        &fs::read(release_path).map_err(|_| "release policy unavailable")?,
    )
    .map_err(|_| "release policy rejected")?;
    let collateral = fs::read(collateral_path).map_err(|_| "collateral unavailable")?;
    Ok(LiveInputs {
        config,
        collateral,
        compose,
        policy,
    })
}

async fn serve_dashboard(input: DashboardInputs, no_open: bool) -> Result<(), String> {
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|_| "loopback bind failed")?;
    let address = listener
        .local_addr()
        .map_err(|_| "loopback address unavailable")?;
    let (session, label) = match input {
        DashboardInputs::Live(live) => (
            zrpc_cli::LocalSession::new_live(
                address,
                zrpc_cli::LiveConfiguration::new(
                    live.config,
                    live.collateral,
                    live.compose,
                    live.policy,
                ),
            )?,
            "LIVE CLIENT — private mode requires reviewed release acceptance",
        ),
        DashboardInputs::Preview(inputs) => (
            zrpc_cli::LocalSession::new_preview(
                address,
                zrpc_cli::PreviewConfiguration::new(
                    inputs.config,
                    inputs.collateral,
                    inputs.address,
                ),
            )?,
            "Live testnet preview — privacy verification unavailable",
        ),
        DashboardInputs::Simulation => (zrpc_cli::LocalSession::new(address)?, "SIMULATION ONLY"),
    };
    let url = session.bootstrap_url()?;
    if no_open {
        // Deliberate terminal delivery only, never stdout/stderr/log files.
        let mut tty = fs::OpenOptions::new()
            .write(true)
            .open("/dev/tty")
            .map_err(|_| "interactive terminal required for --no-open")?;
        writeln!(
            tty,
            "Open this one-time local dashboard link privately:\n{url}"
        )
        .map_err(|_| "terminal unavailable")?;
    } else {
        #[cfg(target_os = "macos")]
        let opener = "open";
        #[cfg(not(target_os = "macos"))]
        let opener = "xdg-open";
        Command::new(opener)
            .arg(&url)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "browser opener unavailable; use --no-open in a terminal")?;
    }
    println!("{label} — local dashboard on http://{address}. Press Ctrl-C to close.");
    axum::serve(listener, zrpc_cli::dashboard(session))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .map_err(|_| "local server failed".into())
}

async fn inspect_endpoint_command(mut args: Vec<String>) -> Result<(), String> {
    let backend = platform(&mut args)?;
    let hostname = required(&mut args, "--endpoint-host")?;
    let port = required(&mut args, "--endpoint-port")?
        .parse::<u16>()
        .map_err(|_| "invalid endpoint port")?;
    let socks = required(&mut args, "--socks")?;
    let collateral_path = required(&mut args, "--collateral")?;
    let compose = compose_input(&mut args, backend)?;
    let policy_path = required(&mut args, "--policy")?;
    exhausted(&args)?;
    // Validate local settings and parse policy before opening any network socket.
    let config = zrpc_client::inspection::PublicInspectionConfig::for_platform(
        backend, &hostname, port, &socks,
    )
    .map_err(|error| error.to_string())?;
    let policy_bytes = fs::read(policy_path).map_err(|_| "workload policy file unavailable")?;
    let collateral = fs::read(collateral_path).map_err(|_| "collateral file unavailable")?;
    let report = match backend {
        Backend::PhalaDstack => {
            let policy = zrpc_verifier::workload::WorkloadPolicy::from_json(&policy_bytes)
                .map_err(|_| "workload policy rejected")?;
            zrpc_client::inspection::inspect_endpoint(&config, &collateral, &compose, &policy).await
        }
        Backend::GcpTdx => {
            let policy = zrpc_verifier::gcp::GcpWorkloadPolicy::from_json(&policy_bytes)
                .map_err(|_| "GCP workload policy rejected")?;
            zrpc_client::inspection::inspect_gcp_endpoint(&config, &collateral, &policy).await
        }
    }
    .map_err(|error| error.to_string())?;
    let passed = report.diagnostic_passed();
    print_json(json!({
        "mode":"public_endpoint_inspection",
        "platform":backend,
        "transport":"configured_loopback_socks; remote DNS for hostnames",
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
