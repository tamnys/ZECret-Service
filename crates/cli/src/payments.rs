use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

use serde_json::json;
use zrpc_payments::{
    Balance, ClientStore, IssuerPublic, IssuerStore, PendingPurchase, PrivateDirectory, PurchaseId,
    collect_purchase, export_pending_purchase, load_private_key_file, mock_settle_purchase,
    prepare_purchase,
};

use super::{exhausted, print_json, required, take_value};

const USAGE: &str = "zrpc payments prepare --ticket-store PRIVATE_DIR --issuer-public-der FILE --issuer-name NAME --crypto-helper FILE --credits N --request-file PRIVATE_FILE
zrpc payments prepare --resume PURCHASE_ID --ticket-store PRIVATE_DIR --issuer-public-der FILE --issuer-name NAME --crypto-helper FILE --request-file PRIVATE_FILE
zrpc payments pending --ticket-store PRIVATE_DIR
zrpc payments mock-settle --issuer-store PRIVATE_DIR --issuer-public-der FILE --issuer-private-der PRIVATE_FILE --issuer-name NAME --crypto-helper FILE --credits N --request-file PRIVATE_FILE --response-file PRIVATE_FILE
zrpc payments collect --ticket-store PRIVATE_DIR --issuer-public-der FILE --issuer-name NAME --crypto-helper FILE --purchase-id PURCHASE_ID --response-file PRIVATE_FILE
zrpc payments balance --ticket-store PRIVATE_DIR
All exchange files and state directories must be owner-private and outside the checkout. Settlement is simulated; these commands do not transfer ZEC or enable paid RPC.";

pub(super) fn run(mut args: Vec<String>) -> Result<(), String> {
    if args.is_empty() || (args.len() == 1 && args[0] == "--help") {
        println!("{USAGE}");
        return Ok(());
    }
    match args.remove(0).as_str() {
        "prepare" => prepare(args),
        "pending" => pending_command(args),
        "mock-settle" => mock_settle(args),
        "collect" => collect(args),
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
    let mut public_der = Vec::new();
    File::open(path)
        .and_then(|file| file.take(u16::MAX as u64 + 1).read_to_end(&mut public_der))
        .map_err(|_| "issuer public key unavailable")?;
    if public_der.is_empty() || public_der.len() > u16::MAX as usize {
        return Err("issuer public key unavailable".into());
    }
    let issuer = IssuerPublic::from_public_der(&helper, &public_der, &issuer_name)
        .map_err(|_| "issuer configuration unavailable")?;
    Ok((issuer, helper))
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
}
