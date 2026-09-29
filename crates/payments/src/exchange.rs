//! Canonical envelopes for the POC's private client/issuer file exchange.
//! These bytes contain blinded requests or blind signatures, never finalized
//! bearer tickets. Parsing does not validate RSA signatures or authorize RPC.

use sha2::{Digest, Sha256};
use std::{
    fmt, fs,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
};
use zeroize::Zeroizing;

use crate::{
    store::{PrivateDirectory, PurchaseId},
    wire::{RSA_SIGNATURE_LEN, TOKEN_REQUEST_LEN, TokenRequest, TokenResponse},
};

const MAGIC: &[u8; 8] = b"ZRPCPAY1";
const REQUEST_KIND: u8 = 1;
const RESPONSE_KIND: u8 = 2;
const REQUEST_HEADER_LEN: usize = 8 + 1 + 32 + 32 + 8;
const RESPONSE_HEADER_LEN: usize = REQUEST_HEADER_LEN + 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExchangeError {
    Format,
    Quantity,
    Purchase,
    IssuerKey,
    RequestCommitment,
    PrivateFile,
}

impl fmt::Display for ExchangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid private payment exchange")
    }
}

pub(crate) struct RequestBatch {
    purchase_id: PurchaseId,
    issuer_key_id: [u8; 32],
    requests: Vec<TokenRequest>,
}

impl RequestBatch {
    pub(crate) fn new(
        purchase_id: PurchaseId,
        issuer_key_id: [u8; 32],
        requests: Vec<TokenRequest>,
    ) -> Result<Self, ExchangeError> {
        checked_count(requests.len())?;
        if requests
            .iter()
            .any(|request| TokenRequest::parse(request.as_bytes(), issuer_key_id).is_err())
        {
            return Err(ExchangeError::IssuerKey);
        }
        Ok(Self {
            purchase_id,
            issuer_key_id,
            requests,
        })
    }

    pub(crate) fn decode(
        bytes: &[u8],
        expected_issuer_key_id: [u8; 32],
    ) -> Result<Self, ExchangeError> {
        let (purchase_id, count) = parse_header(
            bytes,
            REQUEST_KIND,
            expected_issuer_key_id,
            REQUEST_HEADER_LEN,
            TOKEN_REQUEST_LEN,
        )?;
        let mut requests = Vec::new();
        requests
            .try_reserve_exact(count)
            .map_err(|_| ExchangeError::Quantity)?;
        for item in bytes[REQUEST_HEADER_LEN..].chunks_exact(TOKEN_REQUEST_LEN) {
            requests.push(
                TokenRequest::parse(item, expected_issuer_key_id)
                    .map_err(|_| ExchangeError::Format)?,
            );
        }
        Ok(Self {
            purchase_id,
            issuer_key_id: expected_issuer_key_id,
            requests,
        })
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, ExchangeError> {
        let size = encoded_len(REQUEST_HEADER_LEN, self.requests.len(), TOKEN_REQUEST_LEN)?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(size)
            .map_err(|_| ExchangeError::Quantity)?;
        output.extend_from_slice(MAGIC);
        output.push(REQUEST_KIND);
        output.extend_from_slice(&self.purchase_id);
        output.extend_from_slice(&self.issuer_key_id);
        output.extend_from_slice(&checked_count(self.requests.len())?.to_be_bytes());
        for request in &self.requests {
            output.extend_from_slice(request.as_bytes());
        }
        Ok(output)
    }

    pub(crate) fn commitment(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(MAGIC);
        digest.update([REQUEST_KIND]);
        digest.update(self.purchase_id);
        digest.update(self.issuer_key_id);
        digest.update((self.requests.len() as u64).to_be_bytes());
        for request in &self.requests {
            digest.update(request.as_bytes());
        }
        digest.finalize().into()
    }

    pub(crate) fn write_new(&self, path: &Path) -> Result<(), ExchangeError> {
        let encoded = Zeroizing::new(self.encode()?);
        write_new_private(path, &encoded)
    }

    pub(crate) fn read_private(
        path: &Path,
        expected_issuer_key_id: [u8; 32],
        expected_quantity: usize,
    ) -> Result<Self, ExchangeError> {
        let length = encoded_len(REQUEST_HEADER_LEN, expected_quantity, TOKEN_REQUEST_LEN)?;
        let encoded = read_exact_private(path, length)?;
        Self::decode(&encoded, expected_issuer_key_id)
    }

    pub(crate) fn purchase_id(&self) -> PurchaseId {
        self.purchase_id
    }

    pub(crate) fn requests(&self) -> &[TokenRequest] {
        &self.requests
    }
}

impl fmt::Debug for RequestBatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RequestBatch([redacted])")
    }
}

pub(crate) struct ResponseBatch {
    purchase_id: PurchaseId,
    issuer_key_id: [u8; 32],
    request_commitment: [u8; 32],
    responses: Vec<TokenResponse>,
}

impl ResponseBatch {
    pub(crate) fn new(
        purchase_id: PurchaseId,
        issuer_key_id: [u8; 32],
        request_commitment: [u8; 32],
        responses: Vec<TokenResponse>,
    ) -> Result<Self, ExchangeError> {
        checked_count(responses.len())?;
        Ok(Self {
            purchase_id,
            issuer_key_id,
            request_commitment,
            responses,
        })
    }

    pub(crate) fn decode(
        bytes: &[u8],
        expected_purchase_id: PurchaseId,
        expected_issuer_key_id: [u8; 32],
        expected_request_commitment: [u8; 32],
    ) -> Result<Self, ExchangeError> {
        let (purchase_id, count) = parse_header(
            bytes,
            RESPONSE_KIND,
            expected_issuer_key_id,
            RESPONSE_HEADER_LEN,
            RSA_SIGNATURE_LEN,
        )?;
        if purchase_id != expected_purchase_id {
            return Err(ExchangeError::Purchase);
        }
        let request_commitment: [u8; 32] = bytes[73..105]
            .try_into()
            .map_err(|_| ExchangeError::Format)?;
        if request_commitment != expected_request_commitment {
            return Err(ExchangeError::RequestCommitment);
        }
        let mut responses = Vec::new();
        responses
            .try_reserve_exact(count)
            .map_err(|_| ExchangeError::Quantity)?;
        for item in bytes[RESPONSE_HEADER_LEN..].chunks_exact(RSA_SIGNATURE_LEN) {
            responses.push(TokenResponse::parse(item).map_err(|_| ExchangeError::Format)?);
        }
        Self::new(
            purchase_id,
            expected_issuer_key_id,
            request_commitment,
            responses,
        )
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, ExchangeError> {
        let size = encoded_len(RESPONSE_HEADER_LEN, self.responses.len(), RSA_SIGNATURE_LEN)?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(size)
            .map_err(|_| ExchangeError::Quantity)?;
        output.extend_from_slice(MAGIC);
        output.push(RESPONSE_KIND);
        output.extend_from_slice(&self.purchase_id);
        output.extend_from_slice(&self.issuer_key_id);
        output.extend_from_slice(&self.request_commitment);
        output.extend_from_slice(&checked_count(self.responses.len())?.to_be_bytes());
        for response in &self.responses {
            output.extend_from_slice(response.as_bytes());
        }
        Ok(output)
    }

    pub(crate) fn responses(&self) -> &[TokenResponse] {
        &self.responses
    }

    pub(crate) fn write_new(&self, path: &Path) -> Result<(), ExchangeError> {
        let encoded = Zeroizing::new(self.encode()?);
        write_new_private(path, &encoded)
    }

    pub(crate) fn read_private(
        path: &Path,
        expected_purchase_id: PurchaseId,
        expected_issuer_key_id: [u8; 32],
        expected_request_commitment: [u8; 32],
        expected_quantity: usize,
    ) -> Result<Self, ExchangeError> {
        let length = encoded_len(RESPONSE_HEADER_LEN, expected_quantity, RSA_SIGNATURE_LEN)?;
        let encoded = read_exact_private(path, length)?;
        Self::decode(
            &encoded,
            expected_purchase_id,
            expected_issuer_key_id,
            expected_request_commitment,
        )
    }
}

impl fmt::Debug for ResponseBatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ResponseBatch([redacted])")
    }
}

fn checked_count(count: usize) -> Result<u64, ExchangeError> {
    let count = u64::try_from(count).map_err(|_| ExchangeError::Quantity)?;
    if count == 0 || count > i64::MAX as u64 {
        return Err(ExchangeError::Quantity);
    }
    Ok(count)
}

fn encoded_len(header: usize, count: usize, item: usize) -> Result<usize, ExchangeError> {
    checked_count(count)?;
    count
        .checked_mul(item)
        .and_then(|body| header.checked_add(body))
        .ok_or(ExchangeError::Quantity)
}

fn parse_header(
    bytes: &[u8],
    kind: u8,
    expected_issuer_key_id: [u8; 32],
    header_len: usize,
    item_len: usize,
) -> Result<(PurchaseId, usize), ExchangeError> {
    if bytes.len() < header_len || &bytes[..8] != MAGIC || bytes[8] != kind {
        return Err(ExchangeError::Format);
    }
    let purchase_id = bytes[9..41].try_into().map_err(|_| ExchangeError::Format)?;
    if bytes[41..73] != expected_issuer_key_id {
        return Err(ExchangeError::IssuerKey);
    }
    let count_offset = header_len - 8;
    let count = u64::from_be_bytes(
        bytes[count_offset..header_len]
            .try_into()
            .map_err(|_| ExchangeError::Format)?,
    );
    let count = usize::try_from(count).map_err(|_| ExchangeError::Quantity)?;
    if encoded_len(header_len, count, item_len)? != bytes.len() {
        return Err(ExchangeError::Format);
    }
    Ok((purchase_id, count))
}

fn private_file_path(path: &Path) -> Result<(PathBuf, PathBuf), ExchangeError> {
    if !path.is_absolute() || !matches!(path.components().next_back(), Some(Component::Normal(_))) {
        return Err(ExchangeError::PrivateFile);
    }
    let parent = path.parent().ok_or(ExchangeError::PrivateFile)?;
    PrivateDirectory::open(parent).map_err(|_| ExchangeError::PrivateFile)?;
    let parent = fs::canonicalize(parent).map_err(|_| ExchangeError::PrivateFile)?;
    let file_name = path.file_name().ok_or(ExchangeError::PrivateFile)?;
    let destination = parent.join(file_name);
    Ok((parent, destination))
}

struct TemporaryFile {
    path: PathBuf,
    owned: bool,
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        if self.owned {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn write_new_private(path: &Path, bytes: &[u8]) -> Result<(), ExchangeError> {
    let (parent, destination) = private_file_path(path)?;
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).map_err(|_| ExchangeError::PrivateFile)?;
    let nonce = u128::from_be_bytes(random);
    let temporary_path = parent.join(format!(".zrpc-exchange-{nonce:032x}"));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary_path)
        .map_err(|_| ExchangeError::PrivateFile)?;
    let mut temporary = TemporaryFile {
        path: temporary_path,
        owned: true,
    };
    file.write_all(bytes)
        .map_err(|_| ExchangeError::PrivateFile)?;
    file.sync_all().map_err(|_| ExchangeError::PrivateFile)?;
    // Linking in the same directory publishes the complete file atomically and
    // fails if the caller-selected destination already exists. A process exit
    // before this point leaves only an owner-private temporary file.
    fs::hard_link(&temporary.path, &destination).map_err(|_| ExchangeError::PrivateFile)?;
    fs::remove_file(&temporary.path).map_err(|_| ExchangeError::PrivateFile)?;
    temporary.owned = false;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| ExchangeError::PrivateFile)
}

fn read_exact_private(
    path: &Path,
    expected_length: usize,
) -> Result<Zeroizing<Vec<u8>>, ExchangeError> {
    let (_, path) = private_file_path(path)?;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| ExchangeError::PrivateFile)?;
    let metadata = file.metadata().map_err(|_| ExchangeError::PrivateFile)?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
        || metadata.len()
            != u64::try_from(expected_length).map_err(|_| ExchangeError::PrivateFile)?
    {
        return Err(ExchangeError::PrivateFile);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(expected_length)
        .map_err(|_| ExchangeError::PrivateFile)?;
    bytes.resize(expected_length, 0);
    file.read_exact(&mut bytes)
        .map_err(|_| ExchangeError::PrivateFile)?;
    let mut extra = [0u8; 1];
    if file
        .read(&mut extra)
        .map_err(|_| ExchangeError::PrivateFile)?
        != 0
    {
        return Err(ExchangeError::PrivateFile);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let mut random = [0u8; 16];
            getrandom::fill(&mut random).unwrap();
            let path = std::env::temp_dir().join(format!(
                "zrpc-payment-exchange-{}-{}",
                std::process::id(),
                u128::from_be_bytes(random)
            ));
            PrivateDirectory::create(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn canonical_batches_bind_purchase_key_requests_and_responses() {
        let id = [1; 32];
        let key = [2; 32];
        let request = RequestBatch::new(
            id,
            key,
            vec![TokenRequest::new(key, [3; RSA_SIGNATURE_LEN])],
        )
        .unwrap();
        let encoded = request.encode().unwrap();
        let encoded_digest: [u8; 32] = Sha256::digest(&encoded).into();
        assert_eq!(request.commitment(), encoded_digest);
        let decoded = RequestBatch::decode(&encoded, key).unwrap();
        assert_eq!(decoded.purchase_id(), id);
        assert_eq!(
            decoded.requests()[0].as_bytes(),
            request.requests()[0].as_bytes()
        );
        assert_eq!(format!("{decoded:?}"), "RequestBatch([redacted])");

        let response = ResponseBatch::new(
            id,
            key,
            request.commitment(),
            vec![TokenResponse::new([4; RSA_SIGNATURE_LEN])],
        )
        .unwrap();
        let encoded_response = response.encode().unwrap();
        let collected =
            ResponseBatch::decode(&encoded_response, id, key, request.commitment()).unwrap();
        assert_eq!(
            collected.responses()[0].as_bytes(),
            response.responses()[0].as_bytes()
        );
        assert_eq!(format!("{collected:?}"), "ResponseBatch([redacted])");
        assert_eq!(
            ResponseBatch::decode(&encoded_response, [9; 32], key, request.commitment()).err(),
            Some(ExchangeError::Purchase)
        );
        assert_eq!(
            ResponseBatch::decode(&encoded_response, id, key, [9; 32]).err(),
            Some(ExchangeError::RequestCommitment)
        );
        assert_eq!(
            ResponseBatch::decode(&encoded_response, id, [9; 32], request.commitment()).err(),
            Some(ExchangeError::IssuerKey)
        );
    }

    #[test]
    fn malformed_or_altered_exchange_is_rejected_without_reading_a_batch() {
        let key = [7; 32];
        let batch = RequestBatch::new(
            [8; 32],
            key,
            vec![TokenRequest::new(key, [9; RSA_SIGNATURE_LEN])],
        )
        .unwrap();
        let encoded = batch.encode().unwrap();
        for bad in [
            encoded[..80].to_vec(),
            encoded[..encoded.len() - 1].to_vec(),
            [encoded.as_slice(), &[0]].concat(),
        ] {
            assert!(RequestBatch::decode(&bad, key).is_err());
        }
        let mut wrong_kind = encoded.clone();
        wrong_kind[8] = RESPONSE_KIND;
        assert_eq!(
            RequestBatch::decode(&wrong_kind, key).err(),
            Some(ExchangeError::Format)
        );
        let mut empty = encoded.clone();
        empty[73..81].fill(0);
        assert_eq!(
            RequestBatch::decode(&empty, key).err(),
            Some(ExchangeError::Quantity)
        );
        let mut altered = encoded.clone();
        let last = altered.len() - 1;
        altered[last] ^= 1;
        let changed = RequestBatch::decode(&altered, key).unwrap();
        assert_ne!(changed.commitment(), batch.commitment());
        assert_eq!(
            RequestBatch::decode(&encoded, [0; 32]).err(),
            Some(ExchangeError::IssuerKey)
        );
        assert_eq!(
            RequestBatch::new(
                [0; 32],
                [0; 32],
                vec![TokenRequest::new(key, [1; RSA_SIGNATURE_LEN])]
            )
            .err(),
            Some(ExchangeError::IssuerKey)
        );
        assert_eq!(
            RequestBatch::new([0; 32], key, vec![]).err(),
            Some(ExchangeError::Quantity)
        );
    }

    #[test]
    fn private_exchange_files_are_owner_only_exact_and_never_overwritten() {
        let fixture = Fixture::new();
        let id = [1; 32];
        let key = [2; 32];
        let request = RequestBatch::new(
            id,
            key,
            vec![TokenRequest::new(key, [3; RSA_SIGNATURE_LEN])],
        )
        .unwrap();
        let request_file = fixture.0.join("blinded-requests.bin");
        request.write_new(&request_file).unwrap();
        assert_eq!(fs::read(&request_file).unwrap(), request.encode().unwrap());
        assert_eq!(
            fs::metadata(&request_file).unwrap().permissions().mode() & 0o077,
            0
        );
        assert_eq!(
            RequestBatch::read_private(&request_file, key, 1)
                .unwrap()
                .commitment(),
            request.commitment()
        );
        assert_eq!(
            RequestBatch::read_private(&request_file, key, 2).err(),
            Some(ExchangeError::PrivateFile)
        );
        assert_eq!(
            request.write_new(&request_file),
            Err(ExchangeError::PrivateFile)
        );
        assert_eq!(fs::read(&request_file).unwrap(), request.encode().unwrap());
        assert_eq!(
            request.write_new(Path::new("relative.bin")),
            Err(ExchangeError::PrivateFile)
        );

        let alias = fixture.0.join("alias.bin");
        symlink(&request_file, &alias).unwrap();
        assert_eq!(
            RequestBatch::read_private(&alias, key, 1).err(),
            Some(ExchangeError::PrivateFile)
        );
        fs::remove_file(&alias).unwrap();
        fs::hard_link(&request_file, &alias).unwrap();
        assert_eq!(
            RequestBatch::read_private(&request_file, key, 1).err(),
            Some(ExchangeError::PrivateFile)
        );
        fs::remove_file(&alias).unwrap();

        let response = ResponseBatch::new(
            id,
            key,
            request.commitment(),
            vec![TokenResponse::new([4; RSA_SIGNATURE_LEN])],
        )
        .unwrap();
        let response_file = fixture.0.join("blind-signatures.bin");
        response.write_new(&response_file).unwrap();
        assert_eq!(
            ResponseBatch::read_private(&response_file, id, key, request.commitment(), 1)
                .unwrap()
                .responses()[0]
                .as_bytes(),
            response.responses()[0].as_bytes()
        );

        fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            ResponseBatch::read_private(&response_file, id, key, request.commitment(), 1).err(),
            Some(ExchangeError::PrivateFile)
        );
        fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o700)).unwrap();
    }
}
