//! Reference integration with the maintained Zcash wallet scanner. `init`
//! imports a viewing key into a new local database; `scan` opens that database.
//! Neither operation sends keys, seeds, or decrypted wallet data to the bridge.

use rusqlite::{Connection, OpenFlags};
use std::{
    env,
    error::Error,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Read,
    net::SocketAddr,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::PathBuf,
};
use zcash_client_backend::{
    data_api::wallet::ConfirmationsPolicy,
    data_api::{AccountBirthday, AccountPurpose, WalletRead, WalletWrite},
    proto::service::BlockId,
    sync,
};
use zcash_client_sqlite::{WalletDb, util::SystemClock, wallet::init::init_wallet_db};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::consensus::Network;
use zeroize::Zeroize;
use zrpc_payments::PrivateDirectory;
use zrpc_wallet_sdk::bridge::LocalWalletAdapter;

mod cache;
mod enhance;
use cache::SqliteBlockCache;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args_os();
    args.next();
    match args.next().as_deref().and_then(|mode| mode.to_str()) {
        Some("init") => init(args).await,
        Some("scan") => scan(args).await,
        _ => Err("usage: zrpc-wallet-reference {init|scan} ...".into()),
    }
}

fn parse_bind(value: OsString) -> Result<SocketAddr, Box<dyn Error>> {
    let bind: SocketAddr = value.to_string_lossy().parse()?;
    if !bind.ip().is_loopback() || bind.port() == 0 {
        return Err("bridge must use a loopback address with a nonzero port".into());
    }
    Ok(bind)
}

fn read_viewing_key(path: PathBuf) -> Result<UnifiedFullViewingKey, Box<dyn Error>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err("viewing key file must be owner-private and regular".into());
    }
    let mut encoded = String::new();
    file.read_to_string(&mut encoded)?;
    let decoded = UnifiedFullViewingKey::decode(&Network::TestNetwork, encoded.trim());
    encoded.zeroize();
    decoded.map_err(|_| "invalid testnet unified full viewing key".into())
}

async fn init(mut args: env::ArgsOs) -> Result<(), Box<dyn Error>> {
    let usage = "usage: zrpc-wallet-reference init LOOPBACK_HOST:PORT CAPABILITY_DIR NEW_PRIVATE_DIR UFVK_FILE BIRTHDAY_HEIGHT";
    let bind = parse_bind(args.next().ok_or(usage)?)?;
    let capability_dir = PathBuf::from(args.next().ok_or(usage)?);
    let private_dir = PathBuf::from(args.next().ok_or(usage)?);
    let ufvk_file = PathBuf::from(args.next().ok_or(usage)?);
    let birthday_height: u32 = args.next().ok_or(usage)?.to_string_lossy().parse()?;
    if args.next().is_some() || birthday_height == 0 {
        return Err(usage.into());
    }

    let viewing_key = read_viewing_key(ufvk_file)?;
    let adapter = LocalWalletAdapter::connect(bind, &capability_dir).await?;
    let mut client = adapter.maintained_scanner_client();
    let prior_height = birthday_height - 1;
    let tree_state = client
        .get_tree_state(BlockId {
            height: u64::from(prior_height),
            hash: vec![],
        })
        .await?
        .into_inner();
    if tree_state.height != u64::from(prior_height) {
        return Err("birthday tree state height differs from the requested block".into());
    }
    let birthday = AccountBirthday::from_treestate(tree_state, None)?;

    PrivateDirectory::create(&private_dir)?;
    let wallet_path = private_dir.join("wallet.sqlite");
    let conn = Connection::open_with_flags(
        &wallet_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    fs::set_permissions(&wallet_path, fs::Permissions::from_mode(0o600))?;
    rusqlite::vtab::array::load_module(&conn)?;
    let mut wallet =
        WalletDb::from_connection(conn, Network::TestNetwork, SystemClock, rand_core::OsRng);
    init_wallet_db(&mut wallet, None)?;
    wallet.import_account_ufvk(
        "reference",
        &viewing_key,
        &birthday,
        AccountPurpose::ViewOnly,
        None,
    )?;
    println!(
        "local testnet wallet initialized at {}",
        wallet_path.display()
    );
    Ok(())
}

async fn scan(mut args: env::ArgsOs) -> Result<(), Box<dyn Error>> {
    let usage = "usage: zrpc-wallet-reference scan LOOPBACK_HOST:PORT CAPABILITY_DIR WALLET_DB CACHE_DB BATCH_SIZE";
    let bind = parse_bind(args.next().ok_or(usage)?)?;
    let capability_dir = PathBuf::from(args.next().ok_or(usage)?);
    let wallet_path = PathBuf::from(args.next().ok_or(usage)?);
    let cache_path = PathBuf::from(args.next().ok_or(usage)?);
    let batch_size: u32 = args.next().ok_or(usage)?.to_string_lossy().parse()?;
    if args.next().is_some() || batch_size == 0 {
        return Err(usage.into());
    }

    // Both SQLite files stay under an owner-private directory, separate from
    // the bridge process. Never create a wallet database by typo or follow a
    // symbolic link to an unrelated file.
    let wallet_parent = wallet_path.parent().ok_or("wallet path has no parent")?;
    PrivateDirectory::open(wallet_parent)?;
    PrivateDirectory::open(cache_path.parent().ok_or("cache path has no parent")?)?;
    let metadata = fs::symlink_metadata(&wallet_path)?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.nlink() != 1
        || wallet_path == cache_path
    {
        return Err("wallet database path must be an owner-private regular file".into());
    }
    let conn = Connection::open_with_flags(
        &wallet_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    rusqlite::vtab::array::load_module(&conn)?;

    // The wallet database is never mounted into or opened by the local bridge.
    // It must have been initialized with viewing keys by the wallet application.
    let mut wallet =
        WalletDb::from_connection(conn, Network::TestNetwork, SystemClock, rand_core::OsRng);
    if wallet.get_account_ids()?.is_empty() {
        return Err("wallet database has no locally imported viewing-key account".into());
    }
    let adapter = LocalWalletAdapter::connect(bind, &capability_dir).await?;
    let mut client = adapter.maintained_scanner_client();
    let cache = SqliteBlockCache::open(&cache_path)?;
    sync::run(
        &mut client,
        &Network::TestNetwork,
        &cache,
        &mut wallet,
        batch_size,
    )
    .await?;
    let enhanced = enhance::process_snapshot(&mut client, &mut wallet).await?;

    // Only local derived totals and heights are printed. `is_synced` is the
    // maintained wallet scanner's local progress, not a claim of global tip
    // freshness or provider-independent TEE isolation.
    if let Some(summary) = wallet.get_wallet_summary(ConfirmationsPolicy::default())? {
        println!(
            "wallet_scan_height={} wallet_tip_height={} compact_scan_complete={} accounts={} enhanced_transactions={} status_checks={} mined_transparent_checks={} unresolved_transparent_history={} remaining_transaction_requests={}",
            u32::from(summary.fully_scanned_height()),
            u32::from(summary.chain_tip_height()),
            summary.is_synced(),
            summary.account_balances().len(),
            enhanced.enhanced,
            enhanced.status_checks,
            enhanced.mined_transparent_checks,
            enhanced.unresolved_transparent_history,
            enhanced.remaining_requests,
        );
        for (account, balance) in summary.account_balances() {
            println!(
                "account={account:?} sapling_observed_zat={} orchard_observed_zat={} ironwood_observed_zat={} transparent_observed_zat_unreconciled={}",
                u64::from(balance.sapling_balance().total()),
                u64::from(balance.orchard_balance().total()),
                u64::from(balance.ironwood_balance().total()),
                u64::from(balance.unshielded_balance().total())
            );
        }
    } else {
        return Err("wallet scanner returned no summary".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn bridge_target_must_be_loopback() {
        assert!(parse_bind(OsString::from("127.0.0.1:9067")).is_ok());
        assert!(parse_bind(OsString::from("0.0.0.0:9067")).is_err());
        assert!(parse_bind(OsString::from("127.0.0.1:0")).is_err());
    }

    #[test]
    fn viewing_key_file_rejects_permissive_modes_and_symlinks() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("viewing-key");
        fs::write(&path, "synthetic-invalid-ufvk").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_viewing_key(path.clone()).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let error = read_viewing_key(path.clone()).unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid testnet unified full viewing key"
        );
        let link = directory.path().join("link");
        symlink(path, &link).unwrap();
        assert!(read_viewing_key(link).is_err());
    }
}
