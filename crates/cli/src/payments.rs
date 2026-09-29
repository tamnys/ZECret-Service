use std::path::Path;

use serde_json::json;
use zrpc_payments::{Balance, ClientStore, PrivateDirectory};

use super::{exhausted, print_json, required};

const USAGE: &str = "zrpc payments balance --ticket-store ABSOLUTE_PRIVATE_DIR\nOnly local balance inspection is available; ticket issuance and paid RPC are not enabled.";

pub(super) fn run(mut args: Vec<String>) -> Result<(), String> {
    if args.is_empty() || (args.len() == 1 && args[0] == "--help") {
        println!("{USAGE}");
        return Ok(());
    }
    match args.remove(0).as_str() {
        "balance" => {
            let counts = balance(args)?;
            print_json(json!({"available": counts.available, "uncertain": counts.uncertain}))
        }
        _ => Err("unknown payments command".into()),
    }
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
