//! Explicit operator-controlled inputs for the read-only provider client.
//! No environment credential lookup, OS trust discovery or provider connection.
use crate::{
    LifecycleError,
    provider_http::{ApiKey, ProviderClient},
};
use rustls::pki_types::CertificateDer;
use std::{
    fs::OpenOptions,
    io::Read,
    num::NonZeroUsize,
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    time::Duration,
};
use zeroize::Zeroizing;

const INVALID: LifecycleError = LifecycleError("provider input unavailable or unsafe");

/// All limits and paths are explicit operator policy; no production defaults.
/// Paths and their ancestors must be protected by the operator. Final-component
/// no-follow and descriptor checks are not protection against hostile parent
/// directory replacement or a hostile same-UID process.
pub struct ProviderFiles {
    pub workspace_id: String,
    pub api_key_file: PathBuf,
    /// Each file contains one DER trust anchor selected independently of Phala.
    pub trust_root_der_files: Vec<PathBuf>,
    pub max_input_file_bytes: NonZeroUsize,
    pub invocation_budget: Duration,
    pub max_response_bytes: NonZeroUsize,
}

fn read_input(
    path: &Path,
    bound: NonZeroUsize,
    secret: bool,
) -> Result<Zeroizing<Vec<u8>>, LifecycleError> {
    if !path.is_absolute()
        || path
            .as_os_str()
            .as_bytes()
            .split(|b| *b == b'/')
            .any(|part| part == b"." || part == b"..")
    {
        return Err(INVALID);
    }
    let capacity = bound.get().checked_add(1).ok_or(INVALID)?;
    let max_read = u64::try_from(capacity).map_err(|_| INVALID)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| INVALID)?;
    let metadata = file.metadata().map_err(|_| INVALID)?;
    // The only unsafe operation is libc's argument-free process identity read.
    let uid = unsafe { libc::geteuid() };
    let owner_ok = metadata.uid() == uid || (!secret && metadata.uid() == 0);
    let forbidden_modes = if secret { 0o077 } else { 0o022 };
    if !metadata.is_file()
        || !owner_ok
        || metadata.mode() & forbidden_modes != 0
        || metadata.len() > u64::try_from(bound.get()).map_err(|_| INVALID)?
    {
        return Err(INVALID);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(max_read)
        .read_to_end(&mut bytes)
        .map_err(|_| INVALID)?;
    if bytes.is_empty() || bytes.len() > bound.get() {
        return Err(INVALID);
    }
    Ok(bytes)
}

impl ProviderFiles {
    /// Validate and load files only. Authentication/network reads require the
    /// returned client's separate explicit `authenticate` operation.
    pub fn load(self) -> Result<ProviderClient, LifecycleError> {
        if self.invocation_budget.is_zero()
            || self.workspace_id.trim().is_empty()
            || self.trust_root_der_files.is_empty()
        {
            return Err(INVALID);
        }
        let mut roots = Vec::new();
        for path in self.trust_root_der_files {
            let mut bytes = read_input(&path, self.max_input_file_bytes, false)?;
            roots.push(CertificateDer::from(std::mem::take(&mut *bytes)));
        }
        let mut key = read_input(&self.api_key_file, self.max_input_file_bytes, true)?;
        // Do not silently trim whitespace/newlines or transform a credential.
        let api_key = ApiKey::new(std::mem::take(&mut *key)).map_err(|_| INVALID)?;
        ProviderClient::new(
            api_key,
            self.workspace_id,
            roots,
            self.invocation_budget,
            self.max_response_bytes,
        )
        .map_err(|_| INVALID)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        sync::atomic::{AtomicU64, Ordering},
    };
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let root =
                Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.codex-tmp/provider-input-tests");
            fs::create_dir_all(&root).unwrap();
            let path = fs::canonicalize(root).unwrap().join(format!(
                "{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    #[test]
    fn explicit_secret_file_rejects_alias_permissions_shape_and_size() {
        let dir = Temp::new();
        let path = dir.0.join("key");
        let marker = b"SYNTHETIC_API_KEY";
        fs::write(&path, marker).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let bound = NonZeroUsize::new(marker.len()).unwrap();
        assert_eq!(&*read_input(&path, bound, true).unwrap(), marker);
        assert!(read_input(&path, NonZeroUsize::new(marker.len() - 1).unwrap(), true).is_err());
        let alias = dir.0.join("alias");
        symlink(&path, &alias).unwrap();
        for invalid in [
            &alias,
            &dir.0,
            Path::new("relative"),
            &dir.0.join("../key"),
            &dir.0.join("./key"),
        ] {
            assert_eq!(read_input(invalid, bound, true).unwrap_err(), INVALID);
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_input(&path, bound, true).is_err());
        assert!(read_input(&path, bound, false).is_ok());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(read_input(&path, bound, false).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, []).unwrap();
        assert!(read_input(&path, bound, true).is_err());
    }
    #[test]
    fn fifo_is_rejected_without_waiting_for_a_writer() {
        let dir = Temp::new();
        let path = dir.0.join("fifo");
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // Synthetic FIFO exists only beneath this test's owned temporary path.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(read_input(&path, NonZeroUsize::new(1).unwrap(), true).is_err());
    }
    #[tokio::test]
    async fn load_validates_all_trust_inputs_and_credential_bytes_without_network() {
        let dir = Temp::new();
        let key_path = dir.0.join("key");
        let root_path = dir.0.join("root.der");
        let malformed = dir.0.join("malformed.der");
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let certificate = rcgen::CertificateParams::new(vec!["cloud-api.phala.com".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        fs::write(&root_path, certificate.der()).unwrap();
        fs::write(&malformed, b"SYNTHETIC_INVALID_DER").unwrap();
        fs::write(&key_path, b"SYNTHETIC_API_KEY").unwrap();
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&root_path, fs::Permissions::from_mode(0o644)).unwrap();
        fs::set_permissions(&malformed, fs::Permissions::from_mode(0o644)).unwrap();
        let config = || ProviderFiles {
            workspace_id: "wks_synthetic_only".into(),
            api_key_file: key_path.clone(),
            trust_root_der_files: vec![root_path.clone()],
            max_input_file_bytes: NonZeroUsize::new(certificate.der().len()).unwrap(),
            // Test-only budget; no network operation is invoked by load.
            invocation_budget: Duration::from_secs(1),
            max_response_bytes: NonZeroUsize::new(1).unwrap(),
        };
        assert!(config().load().is_ok());
        let mut invalid = config();
        invalid.trust_root_der_files.push(malformed);
        assert!(invalid.load().is_err());
        let mut invalid = config();
        invalid.trust_root_der_files.clear();
        assert!(invalid.load().is_err());
        let mut invalid = config();
        invalid.invocation_budget = Duration::ZERO;
        assert!(invalid.load().is_err());
        let mut invalid = config();
        invalid.workspace_id = "scope\r\nInjected: value".into();
        assert!(invalid.load().is_err());
        for key in [
            b"SYNTHETIC_API_KEY\n".as_slice(),
            b"SYNTHETIC_API_KEY\r\n",
            b"",
        ] {
            fs::write(&key_path, key).unwrap();
            assert!(matches!(config().load(), Err(INVALID)));
        }
    }
}
