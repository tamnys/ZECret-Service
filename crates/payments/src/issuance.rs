//! Client-side preparation for the private blinded-ticket exchange.

use std::{
    fmt, fs,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path},
};
use zeroize::Zeroizing;

use crate::{
    challenge::CommonChallenge,
    crypto::{CryptoFrame, invoke_cli},
    exchange::{RequestBatch, ResponseBatch},
    store::{
        ClientStore, IssuerStore, PendingTicket, PrivateDirectory, PurchaseId, SecretBytes,
        StoreError,
    },
    wire::{
        RSA_SIGNATURE_LEN, TOKEN_INPUT_LEN, TokenInput, TokenRequest, TokenResponse,
        UnverifiedToken, key_id_for_spki,
    },
};

const BLINDING_STATE_LEN: usize = TOKEN_INPUT_LEN + RSA_SIGNATURE_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IssuanceError;

impl fmt::Display for IssuanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("payment issuance unavailable")
    }
}

impl std::error::Error for IssuanceError {}

/// The same issuer key and challenge must be configured for every purchaser
/// and redeemer in this testnet POC. Neither value varies by purchase.
pub struct IssuerPublic {
    pub(crate) spki: Vec<u8>,
    pub(crate) key_id: [u8; 32],
    pub(crate) challenge: CommonChallenge,
}

impl IssuerPublic {
    /// Convert a supported operator-generated public key to the shared
    /// canonical SPKI through the pinned local helper.
    pub fn from_public_der(
        helper: &Path,
        public_der: &[u8],
        issuer_name: &str,
    ) -> Result<Self, IssuanceError> {
        let frame = CryptoFrame::canonicalize_spki(public_der).map_err(|_| IssuanceError)?;
        let canonical = invoke_cli(helper, &frame).map_err(|_| IssuanceError)?;
        Self::new(canonical.expose().to_vec(), issuer_name)
    }

    pub(crate) fn new(spki: Vec<u8>, issuer_name: &str) -> Result<Self, IssuanceError> {
        if spki.is_empty() || u16::try_from(spki.len()).is_err() {
            return Err(IssuanceError);
        }
        let challenge = CommonChallenge::new(issuer_name).map_err(|_| IssuanceError)?;
        Ok(Self {
            key_id: key_id_for_spki(&spki),
            spki,
            challenge,
        })
    }

    pub fn key_id(&self) -> [u8; 32] {
        self.key_id
    }

    /// Build a redacted standard header only for a token bound to this shared
    /// challenge and issuer. This validates local framing before the ticket is
    /// claimed for a request.
    pub fn authorization_for(&self, token: &[u8]) -> Result<SecretBytes, IssuanceError> {
        let value =
            crate::http::format_authorization(token, self.challenge.as_bytes(), self.key_id)
                .map_err(|_| IssuanceError)?;
        Ok(SecretBytes::new(value.as_bytes().to_vec()))
    }
}

impl fmt::Debug for IssuerPublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IssuerPublic([redacted])")
    }
}

/// Read an operator key only from an explicitly selected owner-private file
/// outside a Git checkout. The helper's frame format bounds its DER length.
pub fn load_private_key_file(path: &Path) -> Result<SecretBytes, IssuanceError> {
    if !path.is_absolute() || !matches!(path.components().next_back(), Some(Component::Normal(_))) {
        return Err(IssuanceError);
    }
    PrivateDirectory::open(path.parent().ok_or(IssuanceError)?).map_err(|_| IssuanceError)?;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| IssuanceError)?;
    let metadata = file.metadata().map_err(|_| IssuanceError)?;
    let length = usize::try_from(metadata.len()).map_err(|_| IssuanceError)?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
        || length == 0
        || length > u16::MAX as usize
    {
        return Err(IssuanceError);
    }
    let mut bytes = Zeroizing::new(vec![0_u8; length]);
    file.read_exact(&mut bytes).map_err(|_| IssuanceError)?;
    if file.read(&mut [0_u8; 1]).map_err(|_| IssuanceError)? != 0 {
        return Err(IssuanceError);
    }
    Ok(SecretBytes::new(std::mem::take(&mut *bytes)))
}

/// Save every blinding secret in the client store before publishing a request
/// batch. If writing the batch fails, `pending_purchases` and
/// `export_pending_purchase` recover it without generating new tickets.
pub fn prepare_purchase(
    client: &mut ClientStore,
    issuer: &IssuerPublic,
    helper: &Path,
    quantity: usize,
    request_file: &Path,
) -> Result<PurchaseId, IssuanceError> {
    let (purchase_id, _) = prepare_purchase_bytes(client, issuer, helper, quantity)?;
    export_pending_purchase(client, issuer, purchase_id, request_file)?;
    Ok(purchase_id)
}

/// Prepare an issuance batch in the private client store and return only its
/// blinded wire requests. A failed exchange can resume with the same purchase
/// identifier; it never needs to generate replacement blinding state.
pub fn prepare_purchase_bytes(
    client: &mut ClientStore,
    issuer: &IssuerPublic,
    helper: &Path,
    quantity: usize,
) -> Result<(PurchaseId, SecretBytes), IssuanceError> {
    if quantity == 0 {
        return Err(IssuanceError);
    }
    let mut purchase_id = [0_u8; 32];
    getrandom::fill(&mut purchase_id).map_err(|_| IssuanceError)?;
    let mut pending = Vec::new();
    pending
        .try_reserve_exact(quantity)
        .map_err(|_| IssuanceError)?;
    for _ in 0..quantity {
        let mut nonce = [0_u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| IssuanceError)?;
        let input = TokenInput::new(nonce, issuer.challenge.as_bytes(), issuer.key_id);
        let blind =
            CryptoFrame::blind(&issuer.spki, input.as_bytes()).map_err(|_| IssuanceError)?;
        let result = invoke_cli(helper, &blind).map_err(|_| IssuanceError)?;
        let blinded_message: [u8; RSA_SIGNATURE_LEN] = result.expose()[..RSA_SIGNATURE_LEN]
            .try_into()
            .map_err(|_| IssuanceError)?;
        let request = TokenRequest::new(issuer.key_id, blinded_message);
        let mut state = Vec::with_capacity(BLINDING_STATE_LEN);
        state.extend_from_slice(input.as_bytes());
        state.extend_from_slice(&result.expose()[RSA_SIGNATURE_LEN..]);
        pending.push(PendingTicket {
            blinded_request: request.as_bytes().to_vec(),
            blinding_state: SecretBytes::new(state),
        });
    }
    client
        .store_prepared(purchase_id, &pending)
        .map_err(|_| IssuanceError)?;
    let bytes = export_pending_purchase_bytes(client, issuer, purchase_id)?;
    Ok((purchase_id, bytes))
}

/// Recreate the exact blinded request batch from a durable pending purchase.
/// This never calls the helper or creates another ticket.
pub fn export_pending_purchase(
    client: &ClientStore,
    issuer: &IssuerPublic,
    purchase_id: PurchaseId,
    request_file: &Path,
) -> Result<(), IssuanceError> {
    let (batch, _) = pending_batch(client, issuer, purchase_id)?;
    batch.write_new(request_file).map_err(|_| IssuanceError)
}

pub fn export_pending_purchase_bytes(
    client: &ClientStore,
    issuer: &IssuerPublic,
    purchase_id: PurchaseId,
) -> Result<SecretBytes, IssuanceError> {
    let (batch, _) = pending_batch(client, issuer, purchase_id)?;
    Ok(SecretBytes::new(batch.encode().map_err(|_| IssuanceError)?))
}

fn pending_batch(
    client: &ClientStore,
    issuer: &IssuerPublic,
    purchase_id: PurchaseId,
) -> Result<(RequestBatch, Vec<PendingTicket>), IssuanceError> {
    let purchase = client
        .pending_purchases()
        .map_err(|_| IssuanceError)?
        .into_iter()
        .find(|purchase| purchase.purchase_id == purchase_id)
        .ok_or(IssuanceError)?;
    let pending = client.pending(purchase_id).map_err(|_| IssuanceError)?;
    if pending.len() as u64 != purchase.quantity {
        return Err(IssuanceError);
    }
    let mut requests = Vec::new();
    requests
        .try_reserve_exact(pending.len())
        .map_err(|_| IssuanceError)?;
    for ticket in &pending {
        let state = ticket.blinding_state.expose();
        if state.len() != BLINDING_STATE_LEN {
            return Err(IssuanceError);
        }
        let nonce: [u8; 32] = state[2..34].try_into().map_err(|_| IssuanceError)?;
        let expected = TokenInput::new(nonce, issuer.challenge.as_bytes(), issuer.key_id);
        if state[..TOKEN_INPUT_LEN] != expected.as_bytes()[..] {
            return Err(IssuanceError);
        }
        requests.push(
            TokenRequest::parse(&ticket.blinded_request, issuer.key_id)
                .map_err(|_| IssuanceError)?,
        );
    }
    let batch =
        RequestBatch::new(purchase_id, issuer.key_id, requests).map_err(|_| IssuanceError)?;
    Ok((batch, pending))
}

/// Simulate operator-confirmed settlement of exactly `authorized_quantity`
/// credits. Authorization and the signatures are durable before the response
/// file is published; repeating the same batch returns identical signatures.
pub fn mock_settle_purchase(
    store: &mut IssuerStore,
    issuer: &IssuerPublic,
    helper: &Path,
    issuer_private_der: &SecretBytes,
    authorized_quantity: usize,
    request_file: &Path,
    response_file: &Path,
) -> Result<PurchaseId, IssuanceError> {
    let request = RequestBatch::read_private(request_file, issuer.key_id, authorized_quantity)
        .map_err(|_| IssuanceError)?;
    let purchase_id = request.purchase_id();
    issue_batch(
        store,
        issuer,
        helper,
        issuer_private_der,
        authorized_quantity,
        request,
        None,
    )?
    .write_new(response_file)
    .map_err(|_| IssuanceError)?;
    Ok(purchase_id)
}

/// Sign an operator-authorized free batch. The caller must enforce its own
/// issuance policy before calling this function; possession of a blinded
/// request does not itself authorize any credits.
pub fn issue_batch_bytes(
    store: &mut IssuerStore,
    issuer: &IssuerPublic,
    helper: &Path,
    issuer_private_der: &SecretBytes,
    authorized_quantity: usize,
    max_total: Option<usize>,
    request_bytes: &[u8],
) -> Result<SecretBytes, IssuanceError> {
    let request = RequestBatch::decode(request_bytes, issuer.key_id).map_err(|_| IssuanceError)?;
    let response = issue_batch(
        store,
        issuer,
        helper,
        issuer_private_der,
        authorized_quantity,
        request,
        max_total,
    )?;
    Ok(SecretBytes::new(
        response.encode().map_err(|_| IssuanceError)?,
    ))
}

fn issue_batch(
    store: &mut IssuerStore,
    issuer: &IssuerPublic,
    helper: &Path,
    issuer_private_der: &SecretBytes,
    authorized_quantity: usize,
    request: RequestBatch,
    max_total: Option<usize>,
) -> Result<ResponseBatch, IssuanceError> {
    if request.requests().len() != authorized_quantity {
        return Err(IssuanceError);
    }
    let purchase_id = request.purchase_id();
    if let Some(limit) = max_total {
        store
            .authorize_free(
                purchase_id,
                authorized_quantity,
                request.commitment(),
                limit,
            )
            .map_err(|_| IssuanceError)?;
    } else {
        store
            .authorize(purchase_id, authorized_quantity, request.commitment())
            .map_err(|_| IssuanceError)?;
    }
    let signatures = store
        .issue_once(purchase_id, request.commitment(), || {
            request
                .requests()
                .iter()
                .map(|token| {
                    let frame = CryptoFrame::sign(
                        &issuer.spki,
                        issuer_private_der.expose(),
                        token.blinded_msg(),
                    )
                    .map_err(|_| StoreError::StorageUnavailable)?;
                    let signature =
                        invoke_cli(helper, &frame).map_err(|_| StoreError::StorageUnavailable)?;
                    Ok(signature.expose().to_vec())
                })
                .collect()
        })
        .map_err(|_| IssuanceError)?;
    let responses = signatures
        .iter()
        .map(|signature| TokenResponse::parse(signature).map_err(|_| IssuanceError))
        .collect::<Result<Vec<_>, _>>()?;
    ResponseBatch::new(purchase_id, issuer.key_id, request.commitment(), responses)
        .map_err(|_| IssuanceError)
}

/// Finalize every authorized blind signature and verify the resulting tokens
/// before atomically making any of them available to the client.
pub fn collect_purchase(
    client: &mut ClientStore,
    issuer: &IssuerPublic,
    helper: &Path,
    purchase_id: PurchaseId,
    response_file: &Path,
) -> Result<(), IssuanceError> {
    let (request, pending) = pending_batch(client, issuer, purchase_id)?;
    let response = ResponseBatch::read_private(
        response_file,
        purchase_id,
        issuer.key_id,
        request.commitment(),
        pending.len(),
    )
    .map_err(|_| IssuanceError)?;
    collect_batch(
        client,
        issuer,
        helper,
        purchase_id,
        request,
        pending,
        response,
    )
}

pub fn collect_purchase_bytes(
    client: &mut ClientStore,
    issuer: &IssuerPublic,
    helper: &Path,
    purchase_id: PurchaseId,
    response_bytes: &[u8],
) -> Result<(), IssuanceError> {
    let (request, pending) = pending_batch(client, issuer, purchase_id)?;
    let response = ResponseBatch::decode(
        response_bytes,
        purchase_id,
        issuer.key_id,
        request.commitment(),
    )
    .map_err(|_| IssuanceError)?;
    if response.responses().len() != pending.len() {
        return Err(IssuanceError);
    }
    collect_batch(
        client,
        issuer,
        helper,
        purchase_id,
        request,
        pending,
        response,
    )
}

fn collect_batch(
    client: &mut ClientStore,
    issuer: &IssuerPublic,
    helper: &Path,
    purchase_id: PurchaseId,
    request: RequestBatch,
    pending: Vec<PendingTicket>,
    response: ResponseBatch,
) -> Result<(), IssuanceError> {
    let mut tokens = Vec::new();
    tokens
        .try_reserve_exact(pending.len())
        .map_err(|_| IssuanceError)?;
    for ((ticket, blinded), signature) in pending
        .iter()
        .zip(request.requests())
        .zip(response.responses())
    {
        let state = ticket.blinding_state.expose();
        let input = &state[..TOKEN_INPUT_LEN];
        let secret = &state[TOKEN_INPUT_LEN..];
        let frame = CryptoFrame::finalize(
            &issuer.spki,
            input,
            blinded.blinded_msg(),
            secret,
            signature.as_bytes(),
        )
        .map_err(|_| IssuanceError)?;
        let authenticator = invoke_cli(helper, &frame).map_err(|_| IssuanceError)?;
        let mut token = Vec::with_capacity(TOKEN_INPUT_LEN + RSA_SIGNATURE_LEN);
        token.extend_from_slice(input);
        token.extend_from_slice(authenticator.expose());
        let token = SecretBytes::new(token);
        let unverified =
            UnverifiedToken::parse(token.expose(), issuer.challenge.as_bytes(), issuer.key_id)
                .map_err(|_| IssuanceError)?;
        let frame = CryptoFrame::verify(
            &issuer.spki,
            unverified.signed_input(),
            unverified.authenticator(),
        )
        .map_err(|_| IssuanceError)?;
        invoke_cli(helper, &frame).map_err(|_| IssuanceError)?;
        tokens.push(token);
    }
    client
        .collect_verified(purchase_id, &tokens)
        .map_err(|_| IssuanceError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::PrivateDirectory;
    use std::{
        fs,
        path::PathBuf,
        process::{Command, Stdio},
    };

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let mut random = [0_u8; 16];
            getrandom::fill(&mut random).unwrap();
            let path = std::env::temp_dir().join(format!(
                "zrpc-payment-issuance-{}-{}",
                std::process::id(),
                u128::from_be_bytes(random)
            ));
            PrivateDirectory::create(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    #[ignore = "requires the separately locked helper binary built in the managed container"]
    fn interrupted_prepare_recovers_the_same_blinded_requests() {
        let helper = PathBuf::from(
            std::env::var_os("ZRPC_PAYMENT_CRYPTO_HELPER")
                .expect("set ZRPC_PAYMENT_CRYPTO_HELPER to the helper executable"),
        );
        let fixture =
            include_str!("../../../tools/payment-crypto/tests/rfc9578_public_vector.json");
        let prefix = "\"pkI\": \"";
        let start = fixture.find(prefix).unwrap() + prefix.len();
        let spki: Vec<u8> = fixture[start..]
            .split('"')
            .next()
            .unwrap()
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        let issuer = IssuerPublic::new(spki, "issuer.example").unwrap();
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).unwrap();
        let root = std::env::temp_dir().join(format!(
            "zrpc-payment-prepare-{}-{}",
            std::process::id(),
            u128::from_be_bytes(random)
        ));
        PrivateDirectory::create(&root).unwrap();
        let client_dir = PrivateDirectory::create(&root.join("client")).unwrap();
        PrivateDirectory::create(&root.join("exchange")).unwrap();
        let mut client = ClientStore::create(&client_dir).unwrap();
        let missing_parent = root.join("missing").join("requests.bin");
        assert!(prepare_purchase(&mut client, &issuer, &helper, 2, &missing_parent).is_err());
        let pending = client.pending_purchases().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].quantity, 2);
        let id = pending[0].purchase_id;
        drop(client);

        let client = ClientStore::open(&client_dir).unwrap();
        let first = root.join("exchange").join("requests-a.bin");
        export_pending_purchase(&client, &issuer, id, &first).unwrap();
        let batch = RequestBatch::read_private(&first, issuer.key_id(), 2).unwrap();
        assert_eq!(batch.purchase_id(), id);
        assert_eq!(batch.requests().len(), 2);
        let second = root.join("exchange").join("requests-b.bin");
        export_pending_purchase(&client, &issuer, id, &second).unwrap();
        assert_eq!(fs::read(first).unwrap(), fs::read(second).unwrap());
        assert_eq!(client.pending_purchases().unwrap().len(), 1);
        drop(client);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[ignore = "requires OpenSSL and the separately locked helper in the managed container"]
    fn simulated_settlement_collects_once_across_restarts() {
        let helper = PathBuf::from(
            std::env::var_os("ZRPC_PAYMENT_CRYPTO_HELPER")
                .expect("set ZRPC_PAYMENT_CRYPTO_HELPER to the helper executable"),
        );
        let root = TestDirectory::new();
        let private_key = root.0.join("issuer-private.der");
        let public_key = root.0.join("issuer-public.der");
        let generated = Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-outform",
                "DER",
                "-out",
            ])
            .arg(&private_key)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(generated.success());
        let exported = Command::new("openssl")
            .args(["pkey", "-inform", "DER", "-in"])
            .arg(&private_key)
            .args(["-pubout", "-outform", "DER", "-out"])
            .arg(&public_key)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(exported.success());
        let issuer = IssuerPublic::from_public_der(
            &helper,
            &fs::read(public_key).unwrap(),
            "issuer.example",
        )
        .unwrap();
        let private_der = load_private_key_file(&private_key).unwrap();
        let client_dir = PrivateDirectory::create(&root.0.join("client")).unwrap();
        let issuer_dir = PrivateDirectory::create(&root.0.join("issuer")).unwrap();
        PrivateDirectory::create(&root.0.join("exchange")).unwrap();
        let request = root.0.join("exchange").join("request.bin");
        let response = root.0.join("exchange").join("response.bin");
        let mut client = ClientStore::create(&client_dir).unwrap();
        let id = prepare_purchase(&mut client, &issuer, &helper, 2, &request).unwrap();
        drop(client);

        let mut operator = IssuerStore::create(&issuer_dir).unwrap();
        assert_eq!(
            mock_settle_purchase(
                &mut operator,
                &issuer,
                &helper,
                &private_der,
                2,
                &request,
                &response,
            )
            .unwrap(),
            id
        );
        drop(operator);
        let mut operator = IssuerStore::open(&issuer_dir).unwrap();
        let repeated_response = root.0.join("exchange").join("response-again.bin");
        mock_settle_purchase(
            &mut operator,
            &issuer,
            &helper,
            &private_der,
            2,
            &request,
            &repeated_response,
        )
        .unwrap();
        assert_eq!(
            fs::read(&response).unwrap(),
            fs::read(repeated_response).unwrap()
        );
        assert!(
            mock_settle_purchase(
                &mut operator,
                &issuer,
                &helper,
                &private_der,
                3,
                &request,
                &root.0.join("exchange").join("wrong-quantity.bin"),
            )
            .is_err()
        );

        let mut altered_request = fs::read(&request).unwrap();
        *altered_request.last_mut().unwrap() ^= 1;
        let altered_request = RequestBatch::decode(&altered_request, issuer.key_id()).unwrap();
        let altered_request_file = root.0.join("exchange").join("altered-request.bin");
        altered_request.write_new(&altered_request_file).unwrap();
        assert!(
            mock_settle_purchase(
                &mut operator,
                &issuer,
                &helper,
                &private_der,
                2,
                &altered_request_file,
                &root.0.join("exchange").join("altered-response.bin"),
            )
            .is_err()
        );

        let mut client = ClientStore::open(&client_dir).unwrap();
        let original_request = RequestBatch::read_private(&request, issuer.key_id(), 2).unwrap();
        let mut altered_response = fs::read(&response).unwrap();
        *altered_response.last_mut().unwrap() ^= 1;
        let altered_response = ResponseBatch::decode(
            &altered_response,
            id,
            issuer.key_id(),
            original_request.commitment(),
        )
        .unwrap();
        let altered_response_file = root.0.join("exchange").join("invalid-response.bin");
        altered_response.write_new(&altered_response_file).unwrap();
        assert!(
            collect_purchase(&mut client, &issuer, &helper, id, &altered_response_file).is_err()
        );
        assert_eq!(client.balance().unwrap().available, 0);
        assert_eq!(client.pending_purchases().unwrap().len(), 1);
        drop(client);
        let mut client = ClientStore::open(&client_dir).unwrap();
        collect_purchase(&mut client, &issuer, &helper, id, &response).unwrap();
        assert_eq!(client.balance().unwrap().available, 2);
        assert!(client.pending_purchases().unwrap().is_empty());
        drop(client);
        let mut client = ClientStore::open(&client_dir).unwrap();
        assert_eq!(client.balance().unwrap().available, 2);
        assert!(collect_purchase(&mut client, &issuer, &helper, id, &response).is_err());
        assert_eq!(client.balance().unwrap().available, 2);
    }
}
