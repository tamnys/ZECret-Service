//! Genuine local TLS tests using public upstream keys, not attestation fixtures.

use super::*;
use crate::{IsolationLabel, RemoteEndpoint, TorConfig};
use rustls::{
    ServerConfig, SignatureAlgorithm,
    pki_types::{PrivateKeyDer, pem::PemObject},
    sign::{CertifiedKey, Signer, SigningKey, SingleCertAndKey},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::{TlsAcceptor, server::TlsStream as ServerStream};

mod attestation_tests;

// Candidate encoding in ADR 0002, used only in tests until attestation protocol
// review. These are exporter inputs, not a fabricated expected TLS output.
const EXPORTER_LABEL: &[u8] = b"EXPORTER-zrpc-attestation-v1";
const VECTOR_NONCE: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

#[derive(Debug)]
struct CorruptKey(Arc<dyn SigningKey>);
#[derive(Debug)]
struct CorruptSigner(Box<dyn Signer>);

impl SigningKey for CorruptKey {
    fn choose_scheme(&self, schemes: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        self.0
            .choose_scheme(schemes)
            .map(|signer| Box::new(CorruptSigner(signer)) as Box<dyn Signer>)
    }
    fn algorithm(&self) -> SignatureAlgorithm {
        self.0.algorithm()
    }
}

impl Signer for CorruptSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let mut signature = self.0.sign(message)?;
        // Change the actual CertificateVerify signature, not merely a test flag.
        *signature.last_mut().unwrap() ^= 1;
        Ok(signature)
    }
    fn scheme(&self) -> SignatureScheme {
        self.0.scheme()
    }
}

fn server_config(corrupt_signature: bool, alpn: Option<&[u8]>) -> Arc<ServerConfig> {
    // Public Rustls test credentials, pinned and documented by fixture manifest.
    let certificate =
        CertificateDer::from(include_bytes!("../../../../tests/fixtures/tls/end.der").to_vec());
    let key =
        PrivateKeyDer::from_pem_slice(include_bytes!("../../../../tests/fixtures/tls/end.key"))
            .unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let key = provider.key_provider.load_private_key(key).unwrap();
    let key: Arc<dyn SigningKey> = if corrupt_signature {
        Arc::new(CorruptKey(key))
    } else {
        key
    };
    let resolver = SingleCertAndKey::from(CertifiedKey::new(vec![certificate], key));
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    config.alpn_protocols = alpn.into_iter().map(<[u8]>::to_vec).collect();
    Arc::new(config)
}

async fn accept_socks(mut socket: TcpStream) -> TcpStream {
    let mut greeting = [0; 4];
    socket.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 2, 0, 2]);
    socket.write_all(&[5, 2]).await.unwrap();
    assert_eq!(socket.read_u8().await.unwrap(), 1);
    let username_len = socket.read_u8().await.unwrap();
    let mut username = vec![0; username_len as usize];
    socket.read_exact(&mut username).await.unwrap();
    assert_eq!(username, b"<torS0X>0");
    let password_len = socket.read_u8().await.unwrap();
    let mut password = vec![0; password_len as usize];
    socket.read_exact(&mut password).await.unwrap();
    assert_eq!(password, b"public-fixture-isolation");
    socket.write_all(&[1, 0]).await.unwrap();
    let mut request = [0; 4];
    socket.read_exact(&mut request).await.unwrap();
    assert_eq!(request, [5, 1, 0, 3]);
    let hostname_len = socket.read_u8().await.unwrap();
    let mut hostname = vec![0; hostname_len as usize];
    socket.read_exact(&mut hostname).await.unwrap();
    assert_eq!(hostname, b"unresolved-fixture.invalid");
    assert_eq!(socket.read_u16().await.unwrap(), 443);
    socket
        .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
        .await
        .unwrap();
    socket
}

async fn connect_pair(
    config: Arc<ServerConfig>,
) -> (
    Result<PublicBootstrapTls, SafeError>,
    std::io::Result<ServerStream<TcpStream>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tor = TorConfig::new(match listener.local_addr().unwrap() {
        std::net::SocketAddr::V4(address) => address,
        _ => unreachable!(),
    })
    .unwrap();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        TlsAcceptor::from(config)
            .accept(accept_socks(socket).await)
            .await
    });
    let endpoint = RemoteEndpoint::new("unresolved-fixture.invalid", 443).unwrap();
    let channel = tor
        .connect_bootstrap(
            &endpoint,
            IsolationLabel::new("public-fixture-isolation").unwrap(),
        )
        .await
        .unwrap();
    let client = channel.start_tls().await;
    (client, server.await.unwrap())
}

async fn assert_no_application_bytes(mut server: ServerStream<TcpStream>) {
    let mut bytes = Vec::new();
    let result = server.read_to_end(&mut bytes).await;
    assert!(bytes.is_empty());
    // Dropping the client does not perform TLS close_notify. The local peer may
    // observe EOF or a TCP reset (e.g. unread post-handshake session tickets).
    // Neither terminal outcome changes the separate no-plaintext assertion.
    assert!(
        result.is_ok()
            || matches!(&result, Err(error) if matches!(error.kind(),
                std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset)),
        "unexpected TLS close outcome: {result:?}"
    );
}

#[tokio::test]
async fn tls13_signature_possession_and_challenge_remain_public_only() {
    let (client, server) = connect_pair(server_config(false, Some(ALPN))).await;
    let client = client.unwrap();
    let server = server.unwrap();
    let connection = client.stream.get_ref().1;
    assert_eq!(
        connection.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    assert_eq!(connection.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(
        server.get_ref().1.server_name(),
        Some("unresolved-fixture.invalid")
    );
    assert!(!client.private_rpc_allowed());
    let pending = client.prepare_challenge().unwrap();
    assert_eq!(pending.nonce().unwrap().len(), 32);
    assert!(!pending.private_rpc_allowed());
    assert!(!format!("{pending:?}").contains("public-fixture-isolation"));
    drop(pending);
    assert_no_application_bytes(server).await;
}

#[tokio::test]
async fn altered_certificate_verify_signature_is_rejected() {
    let (client, server) = connect_pair(server_config(true, Some(ALPN))).await;
    assert_eq!(client.unwrap_err().code, ErrorCode::PrivateModeUnavailable);
    assert!(server.is_err());
}

#[tokio::test]
async fn missing_or_wrong_alpn_never_yields_a_bootstrap_session() {
    for alpn in [None, Some(b"h2".as_slice())] {
        let (client, server) = connect_pair(server_config(false, alpn)).await;
        assert!(client.is_err());
        if let Ok(server) = server {
            assert_no_application_bytes(server).await;
        }
    }
}

#[tokio::test]
async fn one_connection_lifetime_cannot_be_extended_by_a_challenge() {
    let (client, server) = connect_pair(server_config(false, Some(ALPN))).await;
    let mut client = client.unwrap();
    client.established = Instant::now() - MAX_CONNECTION_LIFETIME;
    assert_eq!(
        client.prepare_challenge().unwrap_err().code,
        ErrorCode::StaleNonce
    );
    assert_no_application_bytes(server.unwrap()).await;

    let (client, server) = connect_pair(server_config(false, Some(ALPN))).await;
    let mut pending = client.unwrap().prepare_challenge().unwrap();
    pending.tls.established = Instant::now() - MAX_CONNECTION_LIFETIME;
    assert_eq!(pending.nonce().unwrap_err().code, ErrorCode::StaleNonce);
    drop(pending);
    assert_no_application_bytes(server.unwrap()).await;
}

#[tokio::test]
async fn disconnected_bootstrap_cannot_start_tls() {
    assert!(UnverifiedChannel::new().start_tls().await.is_err());
}

#[test]
fn key_logging_and_early_data_are_disabled_by_configuration() {
    let config = bootstrap_config().unwrap();
    assert!(!config.enable_early_data);
    assert!(!config.enable_secret_extraction);
    assert!(!config.key_log.will_log("CLIENT_TRAFFIC_SECRET_0"));
}

#[test]
fn proposed_exporter_encoding_vector_has_exact_bytes() {
    let label_hex: String = EXPORTER_LABEL
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let nonce_hex: String = VECTOR_NONCE
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        label_hex,
        "4558504f525445522d7a7270632d6174746573746174696f6e2d7631"
    );
    assert_eq!(
        nonce_hex,
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    );
}

#[tokio::test]
async fn proposed_exporter_agrees_only_for_same_session_label_and_context() {
    let config = server_config(false, Some(ALPN));
    let mut previous = None;
    // The server offers resumption tickets; each client must still do a full
    // handshake. Reusing its config makes this a reconnect isolation check.
    for _ in 0..2 {
        let (client, server) = connect_pair(config.clone()).await;
        let client = client.unwrap();
        let server = server.unwrap();
        assert_eq!(
            client.stream.get_ref().1.handshake_kind(),
            Some(HandshakeKind::Full)
        );
        let client_export = client
            .stream
            .get_ref()
            .1
            .export_keying_material([0; 64], EXPORTER_LABEL, Some(&VECTOR_NONCE))
            .unwrap();
        let server_export = server
            .get_ref()
            .1
            .export_keying_material([0; 64], EXPORTER_LABEL, Some(&VECTOR_NONCE))
            .unwrap();
        assert_eq!(client_export, server_export);
        let mut other_nonce = VECTOR_NONCE;
        other_nonce[0] ^= 1;
        let other_export = server
            .get_ref()
            .1
            .export_keying_material([0; 64], EXPORTER_LABEL, Some(&other_nonce))
            .unwrap();
        assert_ne!(client_export, other_export);
        let other_label = server
            .get_ref()
            .1
            .export_keying_material([0; 64], b"EXPORTER-other", Some(&VECTOR_NONCE))
            .unwrap();
        assert_ne!(client_export, other_label);
        if let Some(previous) = previous {
            assert_ne!(client_export, previous);
        }
        previous = Some(client_export);
        drop(client);
        assert_no_application_bytes(server).await;
    }
}
