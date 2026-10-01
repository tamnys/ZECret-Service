use std::{
    fs::File,
    io::Read,
    net::SocketAddrV4,
    path::{Path, PathBuf},
    time::Duration,
};

use serde_json::json;
use tokio::net::TcpListener;
use zrpc_payments::{
    Balance, ClientStore, FreeIssuer, IssuerPublic, IssuerStore, PendingPurchase, PrivateDirectory,
    PurchaseId, RedeemerStore, collect_purchase, collect_purchase_bytes, exchange_free_batch,
    export_pending_purchase, export_pending_purchase_bytes, load_private_key_file,
    mock_settle_purchase, prepare_purchase, prepare_purchase_bytes,
};
use zrpc_transport::{IsolationLabel, ManagedTor, valid_v3_onion_host};

use super::{exhausted, print_json, required, take_value};

const USAGE: &str = "zrpc payments prepare --ticket-store PRIVATE_DIR --issuer-public-der FILE --issuer-name NAME --crypto-helper FILE --credits N --request-file PRIVATE_FILE
zrpc payments prepare --resume PURCHASE_ID --ticket-store PRIVATE_DIR --issuer-public-der FILE --issuer-name NAME --crypto-helper FILE --request-file PRIVATE_FILE
zrpc payments get --credits N --ticket-store PRIVATE_DIR --issuer-public-der FILE --issuer-name NAME --crypto-helper FILE --issuer-onion V3_ONION_HOST --issuer-port PORT --tor-executable ABSOLUTE_PATH
zrpc payments get --resume PURCHASE_ID --ticket-store PRIVATE_DIR --issuer-public-der FILE --issuer-name NAME --crypto-helper FILE --issuer-onion V3_ONION_HOST --issuer-port PORT --tor-executable ABSOLUTE_PATH
zrpc payments pending --ticket-store PRIVATE_DIR
zrpc payments mock-settle --issuer-store PRIVATE_DIR --issuer-public-der FILE --issuer-private-der PRIVATE_FILE --issuer-name NAME --crypto-helper FILE --credits N --request-file PRIVATE_FILE --response-file PRIVATE_FILE
zrpc payments collect --ticket-store PRIVATE_DIR --issuer-public-der FILE --issuer-name NAME --crypto-helper FILE --purchase-id PURCHASE_ID --response-file PRIVATE_FILE
zrpc payments init-issuer --issuer-store NEW_PRIVATE_DIR
zrpc payments serve-free --bind 127.0.0.1:PORT --issuer-store PRIVATE_DIR --issuer-public-der FILE --issuer-private-der PRIVATE_FILE --issuer-name NAME --crypto-helper FILE --max-batch N --max-total N --io-timeout-seconds N
zrpc payments init-redeemer --spent-store NEW_PRIVATE_DIR
zrpc payments balance --ticket-store PRIVATE_DIR
All exchange files and state directories must be owner-private and outside the checkout. Free issuance transfers no ZEC. The free issuer listens only on loopback; an operator must publish a pinned v3 onion service separately. Redeeming tickets with zrpc query requires an approved private deployment.";

pub(super) async fn run(mut args: Vec<String>) -> Result<(), String> {
    if args.is_empty() || (args.len() == 1 && args[0] == "--help") {
        println!("{USAGE}");
        return Ok(());
    }
    match args.remove(0).as_str() {
        "prepare" => prepare(args),
        "get" => get(args).await,
        "pending" => pending_command(args),
        "mock-settle" => mock_settle(args),
        "collect" => collect(args),
        "init-issuer" => init_issuer(args),
        "serve-free" => serve_free(args).await,
        "init-redeemer" => init_redeemer(args),
        "balance" => {
            let counts = balance(args)?;
            print_json(json!({"available": counts.available, "uncertain": counts.uncertain}))
        }
        _ => Err("unknown payments command".into()),
    }
}

fn purchase_id_hex(id: PurchaseId) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_purchase_id(value: &str) -> Result<PurchaseId, String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid purchase ID".into());
    }
    let mut id = [0_u8; 32];
    for (index, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "invalid purchase ID")?;
    }
    Ok(id)
}

fn credits(args: &mut Vec<String>) -> Result<usize, String> {
    let value = required(args, "--credits")?;
    let count = value
        .parse::<usize>()
        .map_err(|_| "invalid credit quantity")?;
    if count == 0 {
        return Err("invalid credit quantity".into());
    }
    Ok(count)
}

fn public_issuer(args: &mut Vec<String>) -> Result<(IssuerPublic, PathBuf), String> {
    let path = required(args, "--issuer-public-der")?;
    let issuer_name = required(args, "--issuer-name")?;
    let helper = PathBuf::from(required(args, "--crypto-helper")?);
    let issuer = load_public_issuer(&path, &issuer_name, &helper)?;
    Ok((issuer, helper))
}

fn load_public_issuer(
    path: &str,
    issuer_name: &str,
    helper: &Path,
) -> Result<IssuerPublic, String> {
    let mut public_der = Vec::new();
    File::open(path)
        .and_then(|file| file.take(u16::MAX as u64 + 1).read_to_end(&mut public_der))
        .map_err(|_| "issuer public key unavailable")?;
    if public_der.is_empty() || public_der.len() > u16::MAX as usize {
        return Err("issuer public key unavailable".into());
    }
    IssuerPublic::from_public_der(helper, &public_der, issuer_name)
        .map_err(|_| "issuer configuration unavailable".into())
}

pub(super) struct QueryTicketConfig {
    store: String,
    public_der: String,
    issuer_name: String,
    helper: PathBuf,
}

impl QueryTicketConfig {
    pub(super) fn parse(args: &mut Vec<String>) -> Result<Option<Self>, String> {
        let Some(store) = take_value(args, "--ticket-store")? else {
            return Ok(None);
        };
        Ok(Some(Self {
            store,
            public_der: required(args, "--issuer-public-der")?,
            issuer_name: required(args, "--issuer-name")?,
            helper: PathBuf::from(required(args, "--crypto-helper")?),
        }))
    }

    pub(super) fn open(&self) -> Result<(IssuerPublic, ClientStore), String> {
        let issuer = load_public_issuer(&self.public_der, &self.issuer_name, &self.helper)?;
        let client = open_client(&self.store)?;
        Ok((issuer, client))
    }
}

fn open_client(path: &str) -> Result<ClientStore, String> {
    let directory =
        PrivateDirectory::open(Path::new(path)).map_err(|_| "ticket store unavailable")?;
    ClientStore::open(&directory).map_err(|_| "ticket store unavailable".into())
}

fn open_or_create_client(path: &str) -> Result<ClientStore, String> {
    let directory_path = Path::new(path);
    if directory_path.exists() {
        return open_client(path);
    }
    let directory =
        PrivateDirectory::create(directory_path).map_err(|_| "ticket store unavailable")?;
    ClientStore::create(&directory).map_err(|_| "ticket store unavailable".into())
}

fn open_or_create_issuer(path: &str) -> Result<IssuerStore, String> {
    let path = Path::new(path);
    if path.exists() {
        let directory = PrivateDirectory::open(path).map_err(|_| "issuer store unavailable")?;
        return IssuerStore::open(&directory).map_err(|_| "issuer store unavailable".into());
    }
    let directory = PrivateDirectory::create(path).map_err(|_| "issuer store unavailable")?;
    IssuerStore::create(&directory).map_err(|_| "issuer store unavailable".into())
}

async fn get(mut args: Vec<String>) -> Result<(), String> {
    let resume = take_value(&mut args, "--resume")?;
    let store_path = required(&mut args, "--ticket-store")?;
    let (issuer, helper) = public_issuer(&mut args)?;
    let onion = required(&mut args, "--issuer-onion")?;
    let port = required(&mut args, "--issuer-port")?
        .parse::<u16>()
        .map_err(|_| "invalid issuer port")?;
    let tor_executable = PathBuf::from(required(&mut args, "--tor-executable")?);
    let count = if resume.is_none() {
        Some(credits(&mut args)?)
    } else {
        None
    };
    exhausted(&args)?;
    if !valid_v3_onion_host(&onion) || port == 0 {
        return Err("invalid v3 issuer onion endpoint".into());
    }
    let tor = ManagedTor::launch(&tor_executable).map_err(|_| "Tor unavailable")?;
    let mut client = if resume.is_some() {
        open_client(&store_path)?
    } else {
        open_or_create_client(&store_path)?
    };
    let (purchase_id, request, quantity) = if let Some(resume) = resume {
        let id = parse_purchase_id(&resume)?;
        let quantity = client
            .pending_purchases()
            .map_err(|_| "ticket store unavailable")?
            .into_iter()
            .find(|purchase| purchase.purchase_id == id)
            .ok_or("pending ticket request unavailable")?
            .quantity;
        let quantity = usize::try_from(quantity).map_err(|_| "invalid credit quantity")?;
        let request = export_pending_purchase_bytes(&client, &issuer, id)
            .map_err(|_| "purchase recovery unavailable")?;
        (id, request, quantity)
    } else {
        let quantity = count.ok_or("invalid credit quantity")?;
        let (id, request) = prepare_purchase_bytes(&mut client, &issuer, &helper, quantity)
            .map_err(|_| "ticket preparation unavailable")?;
        (id, request, quantity)
    };
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_| "Tor isolation unavailable")?;
    let isolation = IsolationLabel::new(format!("{:032x}", u128::from_be_bytes(random)))
        .map_err(|_| "Tor isolation unavailable")?;
    let response = tokio::time::timeout(
        Duration::from_secs(zrpc_protocol::MAX_CONNECTION_LIFETIME_SECONDS),
        async {
            let channel = tor
                .connect_issuer_onion(&onion, port, isolation)
                .await
                .map_err(|_| "free issuer unavailable")?;
            exchange_free_batch(channel, &request, quantity)
                .await
                .map_err(|_| "free issuer unavailable")
        },
    )
    .await
    .map_err(|_| "free issuer unavailable")??;
    collect_purchase_bytes(
        &mut client,
        &issuer,
        &helper,
        purchase_id,
        response.expose(),
    )
    .map_err(|_| "ticket collection unavailable")?;
    let balance = client.balance().map_err(|_| "ticket store unavailable")?;
    print_json(json!({
        "purchase_id": purchase_id_hex(purchase_id),
        "issued": quantity,
        "available": balance.available,
        "uncertain": balance.uncertain,
        "settlement": "free"
    }))
}

fn init_issuer(mut args: Vec<String>) -> Result<(), String> {
    let path = PathBuf::from(required(&mut args, "--issuer-store")?);
    exhausted(&args)?;
    if path.exists() {
        return Err("issuer store already exists".into());
    }
    let directory = PrivateDirectory::create(&path).map_err(|_| "issuer store unavailable")?;
    IssuerStore::create(&directory).map_err(|_| "issuer store unavailable")?;
    print_json(json!({"issuer_store_initialized": true}))
}

async fn serve_free(mut args: Vec<String>) -> Result<(), String> {
    let bind = required(&mut args, "--bind")?
        .parse::<SocketAddrV4>()
        .map_err(|_| "invalid free issuer bind address")?;
    let store_path = required(&mut args, "--issuer-store")?;
    let (issuer, helper) = public_issuer(&mut args)?;
    let private_key = PathBuf::from(required(&mut args, "--issuer-private-der")?);
    let max_batch = required(&mut args, "--max-batch")?
        .parse::<usize>()
        .map_err(|_| "invalid maximum batch")?;
    let max_total = required(&mut args, "--max-total")?
        .parse::<usize>()
        .map_err(|_| "invalid total ticket budget")?;
    let io_timeout = required(&mut args, "--io-timeout-seconds")?
        .parse::<u64>()
        .map_err(|_| "invalid issuer timeout")?;
    exhausted(&args)?;
    if !bind.ip().is_loopback() || bind.port() == 0 {
        return Err("free issuer must bind to nonzero IPv4 loopback port".into());
    }
    if io_timeout == 0 || io_timeout > zrpc_protocol::MAX_CONNECTION_LIFETIME_SECONDS {
        return Err("issuer timeout exceeds connection lifetime".into());
    }
    let directory =
        PrivateDirectory::open(Path::new(&store_path)).map_err(|_| "issuer store unavailable")?;
    let store = IssuerStore::open(&directory).map_err(|_| "issuer store unavailable")?;
    let private_key =
        load_private_key_file(&private_key).map_err(|_| "issuer private key unavailable")?;
    let mut issuer_service =
        FreeIssuer::new(issuer, helper, private_key, store, max_batch, max_total)
            .map_err(|_| "invalid issuer ticket budget or batch size")?;
    let listener = TcpListener::bind(bind)
        .await
        .map_err(|_| "free issuer listener unavailable")?;
    print_json(
        json!({"free_issuer_listening": true, "bind": bind.to_string(), "max_batch": max_batch, "max_total": max_total}),
    )?;
    loop {
        let connection = tokio::select! {
            accepted = listener.accept() => accepted.map_err(|_| "free issuer listener unavailable")?,
            signal = tokio::signal::ctrl_c() => {
                signal.map_err(|_| "free issuer shutdown unavailable")?;
                return Ok(());
            }
        };
        // A failed client session neither returns a ticket nor kills the
        // issuer. The store keeps a completed batch for exact replay/recovery.
        let _ = tokio::time::timeout(
            Duration::from_secs(io_timeout),
            issuer_service.serve_connection(connection.0),
        )
        .await;
    }
}

fn prepare(mut args: Vec<String>) -> Result<(), String> {
    let resume = take_value(&mut args, "--resume")?;
    let ticket_store = required(&mut args, "--ticket-store")?;
    let (issuer, helper) = public_issuer(&mut args)?;
    let request_file = PathBuf::from(required(&mut args, "--request-file")?);
    let count = if resume.is_none() {
        Some(credits(&mut args)?)
    } else {
        None
    };
    exhausted(&args)?;
    let mut client = if resume.is_some() {
        open_client(&ticket_store)?
    } else {
        open_or_create_client(&ticket_store)?
    };
    let purchase_id = if let Some(resume) = resume {
        let id = parse_purchase_id(&resume)?;
        export_pending_purchase(&client, &issuer, id, &request_file)
            .map_err(|_| "purchase recovery unavailable")?;
        id
    } else {
        prepare_purchase(
            &mut client,
            &issuer,
            &helper,
            count.ok_or("invalid credit quantity")?,
            &request_file,
        )
        .map_err(|_| "purchase preparation unavailable")?
    };
    print_json(json!({"purchase_id": purchase_id_hex(purchase_id), "request_file_written": true}))
}

fn pending_command(mut args: Vec<String>) -> Result<(), String> {
    let path = required(&mut args, "--ticket-store")?;
    exhausted(&args)?;
    let client = open_client(&path)?;
    let purchases = client
        .pending_purchases()
        .map_err(|_| "ticket store unavailable")?;
    let purchases = purchases
        .into_iter()
        .map(
            |PendingPurchase {
                 purchase_id,
                 quantity,
             }| {
                json!({"purchase_id":purchase_id_hex(purchase_id), "credits":quantity})
            },
        )
        .collect::<Vec<_>>();
    print_json(json!({"pending": purchases}))
}

fn mock_settle(mut args: Vec<String>) -> Result<(), String> {
    let store_path = required(&mut args, "--issuer-store")?;
    let (issuer, helper) = public_issuer(&mut args)?;
    let private_key = PathBuf::from(required(&mut args, "--issuer-private-der")?);
    let count = credits(&mut args)?;
    let request_file = PathBuf::from(required(&mut args, "--request-file")?);
    let response_file = PathBuf::from(required(&mut args, "--response-file")?);
    exhausted(&args)?;
    let private_der =
        load_private_key_file(&private_key).map_err(|_| "issuer private key unavailable")?;
    let mut store = open_or_create_issuer(&store_path)?;
    let id = mock_settle_purchase(
        &mut store,
        &issuer,
        &helper,
        &private_der,
        count,
        &request_file,
        &response_file,
    )
    .map_err(|_| "simulated settlement unavailable")?;
    print_json(
        json!({"purchase_id":purchase_id_hex(id), "credits":count, "simulated_settlement":true, "response_file_written":true}),
    )
}

fn collect(mut args: Vec<String>) -> Result<(), String> {
    let path = required(&mut args, "--ticket-store")?;
    let (issuer, helper) = public_issuer(&mut args)?;
    let id = parse_purchase_id(&required(&mut args, "--purchase-id")?)?;
    let response_file = PathBuf::from(required(&mut args, "--response-file")?);
    exhausted(&args)?;
    let mut client = open_client(&path)?;
    collect_purchase(&mut client, &issuer, &helper, id, &response_file)
        .map_err(|_| "ticket collection unavailable")?;
    let balance = client.balance().map_err(|_| "ticket store unavailable")?;
    print_json(
        json!({"collected":true,"available":balance.available,"uncertain":balance.uncertain}),
    )
}

fn balance(mut args: Vec<String>) -> Result<Balance, String> {
    let path = required(&mut args, "--ticket-store")?;
    exhausted(&args)?;
    let directory = PrivateDirectory::open(Path::new(&path))
        .map_err(|_| "ticket store unavailable".to_owned())?;
    let client =
        ClientStore::open(&directory).map_err(|_| "ticket store unavailable".to_owned())?;
    client
        .balance()
        .map_err(|_| "ticket store unavailable".to_owned())
}

fn init_redeemer(mut args: Vec<String>) -> Result<(), String> {
    let path = PathBuf::from(required(&mut args, "--spent-store")?);
    exhausted(&args)?;
    if path.exists() {
        return Err("redeemer store already exists".into());
    }
    let directory = PrivateDirectory::create(&path).map_err(|_| "redeemer store unavailable")?;
    RedeemerStore::create(&directory).map_err(|_| "redeemer store unavailable")?;
    print_json(json!({"redeemer_store_initialized": true}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn balance_reads_only_existing_private_store() {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "zrpc-payments-cli-{}-{}",
            std::process::id(),
            u128::from_be_bytes(random)
        ));
        let directory = PrivateDirectory::create(&path).unwrap();
        let args = vec![
            "--ticket-store".to_owned(),
            path.to_string_lossy().into_owned(),
        ];
        assert_eq!(
            balance(args.clone()),
            Err("ticket store unavailable".to_owned())
        );
        ClientStore::create(&directory).unwrap();
        assert_eq!(
            balance(args).unwrap(),
            Balance {
                available: 0,
                uncertain: 0,
            }
        );
        assert_eq!(
            balance(vec!["--ticket-store".into(), "relative".into()]),
            Err("ticket store unavailable".to_owned())
        );
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn redeemer_initialization_never_recreates_a_missing_existing_database() {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "zrpc-redeemer-cli-{}-{}",
            std::process::id(),
            u128::from_be_bytes(random)
        ));
        let args = vec!["--spent-store".into(), path.to_string_lossy().into_owned()];
        init_redeemer(args.clone()).unwrap();
        let directory = PrivateDirectory::open(&path).unwrap();
        RedeemerStore::open(&directory).unwrap();
        assert_eq!(
            init_redeemer(args),
            Err("redeemer store already exists".into())
        );
        fs::remove_file(path.join("redeemer.sqlite3")).unwrap();
        assert!(RedeemerStore::open(&directory).is_err());
        assert_eq!(
            init_redeemer(vec![
                "--spent-store".into(),
                path.to_string_lossy().into_owned()
            ]),
            Err("redeemer store already exists".into())
        );
        fs::remove_dir_all(path).unwrap();
    }
}
