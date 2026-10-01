//! One blinded batch per connection. The transport is supplied by the caller:
//! the issuer binds to loopback, and remote clients use a pinned v3 onion name.
//! No finalized bearer ticket or private RPC request crosses this connection.

use std::{fmt, path::PathBuf};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    exchange::{RequestBatch, ResponseBatch},
    issuance::{IssuerPublic, issue_batch_bytes},
    store::{IssuerStore, SecretBytes},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreeIssuerError;

impl fmt::Display for FreeIssuerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("free ticket issuance unavailable")
    }
}

impl std::error::Error for FreeIssuerError {}

pub struct FreeIssuer {
    issuer: IssuerPublic,
    helper: PathBuf,
    private_key: SecretBytes,
    store: IssuerStore,
    max_batch: usize,
    max_total: usize,
}

impl FreeIssuer {
    /// The operator explicitly sets the maximum batch that this free issuer
    /// will sign. It must not be derived from untrusted client input.
    pub fn new(
        issuer: IssuerPublic,
        helper: PathBuf,
        private_key: SecretBytes,
        store: IssuerStore,
        max_batch: usize,
        max_total: usize,
    ) -> Result<Self, FreeIssuerError> {
        RequestBatch::encoded_len_for(max_batch).map_err(|_| FreeIssuerError)?;
        ResponseBatch::encoded_len_for(max_batch).map_err(|_| FreeIssuerError)?;
        if max_total == 0 || i64::try_from(max_total).is_err() {
            return Err(FreeIssuerError);
        }
        Ok(Self {
            issuer,
            helper,
            private_key,
            store,
            max_batch,
            max_total,
        })
    }

    /// Invalid input closes the connection without signing or returning
    /// caller-controlled bytes. Issuance is durable before the response is sent.
    pub async fn serve_connection<S>(&mut self, mut stream: S) -> Result<(), FreeIssuerError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let max_len = RequestBatch::encoded_len_for(self.max_batch).map_err(|_| FreeIssuerError)?;
        let min_len = RequestBatch::encoded_len_for(1).map_err(|_| FreeIssuerError)?;
        let request = read_frame(&mut stream, min_len, max_len).await?;
        let batch = RequestBatch::decode(request.expose(), self.issuer.key_id())
            .map_err(|_| FreeIssuerError)?;
        let quantity = batch.requests().len();
        if quantity > self.max_batch {
            return Err(FreeIssuerError);
        }
        let response = issue_batch_bytes(
            &mut self.store,
            &self.issuer,
            &self.helper,
            &self.private_key,
            quantity,
            self.max_total,
            request.expose(),
        )
        .map_err(|_| FreeIssuerError)?;
        write_frame(&mut stream, response.expose()).await?;
        stream.shutdown().await.map_err(|_| FreeIssuerError)
    }
}

/// Send only a blinded batch on an issuer-authenticated connection. Response
/// signatures still need purchase binding and cryptographic verification by
/// `collect_purchase_bytes` before becoming available tickets.
pub async fn exchange_free_batch<S>(
    mut stream: S,
    request: &SecretBytes,
    quantity: usize,
) -> Result<SecretBytes, FreeIssuerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let expected_request = RequestBatch::encoded_len_for(quantity).map_err(|_| FreeIssuerError)?;
    let expected_response =
        ResponseBatch::encoded_len_for(quantity).map_err(|_| FreeIssuerError)?;
    if request.expose().len() != expected_request {
        return Err(FreeIssuerError);
    }
    write_frame(&mut stream, request.expose()).await?;
    read_frame(&mut stream, expected_response, expected_response).await
}

async fn write_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    bytes: &[u8],
) -> Result<(), FreeIssuerError> {
    let length = u64::try_from(bytes.len()).map_err(|_| FreeIssuerError)?;
    stream
        .write_all(&length.to_be_bytes())
        .await
        .map_err(|_| FreeIssuerError)?;
    stream.write_all(bytes).await.map_err(|_| FreeIssuerError)?;
    stream.flush().await.map_err(|_| FreeIssuerError)
}

async fn read_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    min_len: usize,
    max_len: usize,
) -> Result<SecretBytes, FreeIssuerError> {
    let mut header = [0_u8; 8];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|_| FreeIssuerError)?;
    let length = usize::try_from(u64::from_be_bytes(header)).map_err(|_| FreeIssuerError)?;
    if length < min_len || length > max_len {
        return Err(FreeIssuerError);
    }
    let mut bytes = vec![0_u8; length];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|_| FreeIssuerError)?;
    Ok(SecretBytes::new(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Admission, ClientStore, PrivateDirectory, Redeemer, RedeemerStore, collect_purchase_bytes,
        export_pending_purchase_bytes, load_private_key_file, prepare_purchase_bytes,
    };
    use std::{
        fs,
        path::PathBuf,
        process::{Command, Stdio},
    };

    #[tokio::test]
    async fn rejects_oversized_frame_before_reading_its_body() {
        let (mut writer, mut reader) = tokio::io::duplex(128);
        let expected = ResponseBatch::encoded_len_for(1).unwrap();
        writer
            .write_all(&(u64::try_from(expected).unwrap() + 1).to_be_bytes())
            .await
            .unwrap();
        assert!(read_frame(&mut reader, expected, expected).await.is_err());
    }

    #[tokio::test]
    #[ignore = "requires OpenSSL and the separately locked helper in the managed container"]
    async fn one_hundred_free_tickets_are_signed_verified_and_replay_safe() {
        let helper = PathBuf::from(
            std::env::var_os("ZRPC_PAYMENT_CRYPTO_HELPER")
                .expect("set ZRPC_PAYMENT_CRYPTO_HELPER to the helper executable"),
        );
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).unwrap();
        let root = std::env::temp_dir().join(format!(
            "zrpc-free-issuer-{}-{}",
            std::process::id(),
            u128::from_be_bytes(random)
        ));
        PrivateDirectory::create(&root).unwrap();
        let client_dir = PrivateDirectory::create(&root.join("client")).unwrap();
        let issuer_dir = PrivateDirectory::create(&root.join("issuer")).unwrap();
        let private_path = root.join("issuer-private.der");
        let public_path = root.join("issuer-public.der");
        assert!(
            Command::new("openssl")
                .args([
                    "genpkey",
                    "-algorithm",
                    "RSA",
                    "-pkeyopt",
                    "rsa_keygen_bits:2048",
                    "-outform",
                    "DER",
                    "-out"
                ])
                .arg(&private_path)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("openssl")
                .args(["pkey", "-inform", "DER", "-in"])
                .arg(&private_path)
                .args(["-pubout", "-outform", "DER", "-out"])
                .arg(&public_path)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success()
        );
        let public_der = fs::read(public_path).unwrap();
        let client_issuer =
            IssuerPublic::from_public_der(&helper, &public_der, "issuer.example").unwrap();
        let server_issuer =
            IssuerPublic::from_public_der(&helper, &public_der, "issuer.example").unwrap();
        let mut client = ClientStore::create(&client_dir).unwrap();
        let (purchase_id, request) =
            prepare_purchase_bytes(&mut client, &client_issuer, &helper, 100).unwrap();
        assert_eq!(
            export_pending_purchase_bytes(&client, &client_issuer, purchase_id)
                .unwrap()
                .expose(),
            request.expose()
        );
        let store = IssuerStore::create(&issuer_dir).unwrap();
        let private_key = load_private_key_file(&private_path).unwrap();
        let mut issuer =
            FreeIssuer::new(server_issuer, helper.clone(), private_key, store, 100, 100).unwrap();
        let (client_socket, server_socket) = tokio::io::duplex(65_536);
        let (served, response) = tokio::join!(
            issuer.serve_connection(server_socket),
            exchange_free_batch(client_socket, &request, 100)
        );
        served.unwrap();
        let response = response.unwrap();
        drop(client);
        let mut client = ClientStore::open(&client_dir).unwrap();
        collect_purchase_bytes(
            &mut client,
            &client_issuer,
            &helper,
            purchase_id,
            response.expose(),
        )
        .unwrap();
        assert_eq!(client.balance().unwrap().available, 100);
        let selected = client.preview_available().unwrap().unwrap();
        let authorization = client_issuer
            .authorization_for(selected.token.expose())
            .unwrap();
        let redeemer_dir = PrivateDirectory::create(&root.join("redeemer")).unwrap();
        let redeemer_issuer =
            IssuerPublic::from_public_der(&helper, &public_der, "issuer.example").unwrap();
        let redeemer = Redeemer::new(
            redeemer_issuer,
            helper.clone(),
            RedeemerStore::create(&redeemer_dir).unwrap(),
        );
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(300);
        assert_eq!(
            redeemer
                .redeem(authorization.expose(), deadline)
                .await
                .unwrap(),
            Admission::Accepted
        );
        assert_eq!(
            redeemer
                .redeem(authorization.expose(), deadline)
                .await
                .unwrap(),
            Admission::Replay
        );
        assert!(
            collect_purchase_bytes(
                &mut client,
                &client_issuer,
                &helper,
                purchase_id,
                response.expose()
            )
            .is_err()
        );

        let (client_socket, server_socket) = tokio::io::duplex(65_536);
        let (served, replay) = tokio::join!(
            issuer.serve_connection(server_socket),
            exchange_free_batch(client_socket, &request, 100)
        );
        served.unwrap();
        assert_eq!(replay.unwrap().expose(), response.expose());
        let (_, fresh_request) =
            prepare_purchase_bytes(&mut client, &client_issuer, &helper, 1).unwrap();
        let (client_socket, server_socket) = tokio::io::duplex(65_536);
        let (served, fresh_response) = tokio::join!(
            issuer.serve_connection(server_socket),
            exchange_free_batch(client_socket, &fresh_request, 1)
        );
        assert!(served.is_err());
        assert!(fresh_response.is_err());
        drop(client);
        drop(issuer);
        fs::remove_dir_all(root).unwrap();
    }
}
