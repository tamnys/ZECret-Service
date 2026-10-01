//! SOCKS/TLS bootstrap and a connection-owned verified RPC path.
//! The compiled reviewed-release catalog is currently empty, so no genuine
//! private session can be constructed in this client release.
//! Public diagnostics use only the configured numeric loopback SOCKS socket;
//! private sessions require a managed child and private Unix socket. A
//! successful SOCKS handshake does not prove Tor's identity or attest its peer.
#![forbid(unsafe_code)]

use std::{
    fmt, io,
    net::{IpAddr, SocketAddrV4},
    pin::Pin,
    task::{Context, Poll},
};
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use tokio_socks::{Error as SocksError, tcp::Socks5Stream};
use zrpc_protocol::{ErrorCode, Request, SafeError};
use zrpc_verifier::VerifiedChannel;

#[cfg(unix)]
mod managed_tor;
mod tls;
#[cfg(unix)]
pub use managed_tor::ManagedTor;
pub use tls::{
    EndpointInspection, EndpointInspectionIssue, PendingChallenge, PhalaTrustedRpcSession,
    PreviewRpcSession, PublicBootstrapTls, PublicTestnetPreview, UnverifiedGcpEvidence,
    UnverifiedPublicEvidence, VerifiedRpcSession,
};

/// A configuration value is not evidence that Tor is connected or functional.
#[derive(Debug, Clone, Copy)]
pub struct TorConfig {
    socks: SocketAddrV4,
}

impl TorConfig {
    pub fn new(socks: SocketAddrV4) -> Result<Self, SafeError> {
        if !socks.ip().is_loopback() || socks.port() == 0 {
            return Err(SafeError::new(
                ErrorCode::TorUnavailable,
                "A nonzero loopback Tor SOCKS endpoint is required.",
            ));
        }
        Ok(Self { socks })
    }

    pub fn socks_endpoint(&self) -> SocketAddrV4 {
        self.socks
    }

    /// Negotiate SOCKS CONNECT only; no TLS or application bytes are sent.
    ///
    /// The caller must supply a unique secret isolation label for each native
    /// session. This diagnostic API does not generate or authenticate labels,
    /// verify the locally installed Tor process, or authorize private queries.
    /// Cancellation drops the in-progress socket; there is no retry or fallback.
    pub async fn connect_bootstrap(
        &self,
        endpoint: &RemoteEndpoint,
        isolation: IsolationLabel,
    ) -> Result<UnverifiedChannel, SafeError> {
        let socket = TcpStream::connect(self.socks).await.map_err(|_| {
            SafeError::new(
                ErrorCode::TorUnavailable,
                "Configured loopback SOCKS endpoint is unavailable.",
            )
        })?;
        negotiate_socks(
            ProxySocket::Tcp(socket),
            endpoint,
            isolation,
            TransportOrigin::DiagnosticTcp,
        )
        .await
    }
}

/// The diagnostic TCP path can obtain public evidence but never promote it to
/// a private session. The managed child is retained from SOCKS through RPC.
#[derive(Clone, Default)]
pub(crate) enum TransportOrigin {
    #[default]
    DiagnosticTcp,
    #[cfg(unix)]
    Managed(ManagedTor),
}

impl TransportOrigin {
    pub(crate) fn ensure_usable(&self) -> Result<(), SafeError> {
        match self {
            Self::DiagnosticTcp => Ok(()),
            #[cfg(unix)]
            Self::Managed(tor) => tor.ensure_live(),
        }
    }

    pub(crate) fn require_managed(&self) -> Result<(), SafeError> {
        match self {
            Self::DiagnosticTcp => Err(SafeError::new(
                ErrorCode::TorUnavailable,
                "A managed local Tor process is required for private RPC.",
            )),
            #[cfg(unix)]
            Self::Managed(tor) => tor.ensure_live(),
        }
    }
}

/// Both socket types use the maintained SOCKS library's connected-socket API.
/// The enum keeps the TLS/attestation stack a single concrete owned type.
pub(crate) enum ProxySocket {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(UnixStream),
}

impl AsyncRead for ProxySocket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Tcp(socket) => Pin::new(socket).poll_read(cx, buf),
            #[cfg(unix)]
            Self::Unix(socket) => Pin::new(socket).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ProxySocket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            Self::Tcp(socket) => Pin::new(socket).poll_write(cx, buf),
            #[cfg(unix)]
            Self::Unix(socket) => Pin::new(socket).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Tcp(socket) => Pin::new(socket).poll_flush(cx),
            #[cfg(unix)]
            Self::Unix(socket) => Pin::new(socket).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Tcp(socket) => Pin::new(socket).poll_shutdown(cx),
            #[cfg(unix)]
            Self::Unix(socket) => Pin::new(socket).poll_shutdown(cx),
        }
    }
}

pub(crate) async fn negotiate_socks(
    socket: ProxySocket,
    endpoint: &RemoteEndpoint,
    isolation: IsolationLabel,
    origin: TransportOrigin,
) -> Result<UnverifiedChannel, SafeError> {
    // Use the maintained implementation's already-connected-socket API:
    // neither the endpoint nor a proxy hostname enters a local resolver.
    // The guard requires password negotiation because tokio-socks also
    // offers no-auth, which would omit the Tor isolation parameter.
    let socket = Socks5Stream::connect_with_password_and_socket(
        RequirePassword::new(socket),
        (endpoint.hostname.as_str(), endpoint.port),
        "<torS0X>0",
        &isolation.0,
    )
    .await
    .map_err(socks_failure)?;
    Ok(UnverifiedChannel {
        socket: Some(socket),
        origin,
        server_name: Some(endpoint.hostname.clone()),
        authority: Some(match endpoint.hostname.parse::<IpAddr>() {
            Ok(IpAddr::V6(ip)) => format!("[{ip}]:{}", endpoint.port),
            _ => format!("{}:{}", endpoint.hostname, endpoint.port),
        }),
    })
}

fn socks_failure(error: SocksError) -> SafeError {
    // Never serialize the library error: an I/O error could contain a peer
    // address, and the isolation label is a credential for the Tor stream.
    let message = match error {
        SocksError::NoAcceptableAuthMethods
        | SocksError::UnknownAuthMethod
        | SocksError::PasswordAuthFailure(_)
        | SocksError::AuthorizationRequired
        | SocksError::IdentdAuthFailure
        | SocksError::InvalidUserIdAuthFailure
        | SocksError::InvalidAuthValues(_) => {
            "SOCKS did not accept required password authentication."
        }
        SocksError::Io(ref cause) if cause.kind() == io::ErrorKind::InvalidData => {
            "SOCKS authentication or protocol response was invalid."
        }
        SocksError::GeneralSocksServerFailure
        | SocksError::NetworkUnreachable
        | SocksError::HostUnreachable
        | SocksError::ConnectionRefused
        | SocksError::TtlExpired => "SOCKS reported an endpoint connection failure.",
        SocksError::ConnectionNotAllowedByRuleset
        | SocksError::CommandNotSupported
        | SocksError::AddressTypeNotSupported => "SOCKS rejected the endpoint connection.",
        _ => "SOCKS negotiation failed or was interrupted.",
    };
    SafeError::new(ErrorCode::TorUnavailable, message)
}

/// A DNS hostname or numeric IP and port, always sent through SOCKS.
#[derive(Clone)]
pub struct RemoteEndpoint {
    hostname: String,
    port: u16,
}

impl RemoteEndpoint {
    pub fn new(hostname: impl Into<String>, port: u16) -> Result<Self, SafeError> {
        let hostname = hostname.into();
        let labels = hostname.strip_suffix('.').unwrap_or(&hostname);
        // SOCKS5 encodes its domain length in one octet (RFC1928); DNS labels
        // have at most 63 octets (RFC1035). These are protocol bounds.
        let numeric = hostname.parse::<IpAddr>().is_ok();
        let valid = port != 0
            && (numeric
                || (
                    // Reject numeric-looking names with a trailing dot: do not silently
                    // turn a mistyped IP into a DNS lookup.
                    labels.parse::<IpAddr>().is_err()
                        && !hostname.is_empty()
                        && hostname.len() <= u8::MAX as usize
                        && hostname.is_ascii()
                        && labels.split('.').all(|label| {
                            !label.is_empty()
                                && label.len() <= 63
                                && label.as_bytes()[0].is_ascii_alphanumeric()
                                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                                && label
                                    .bytes()
                                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                        })
                ));
        if !valid {
            return Err(SafeError::new(
                ErrorCode::InvalidParameters,
                "A DNS hostname or numeric IP and nonzero port are required; URLs are not accepted.",
            ));
        }
        Ok(Self { hostname, port })
    }
}

impl fmt::Debug for RemoteEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RemoteEndpoint([redacted])")
    }
}

/// Caller-supplied secret Tor stream-isolation label, consumed by a connection.
///
/// Its caller is responsible for per-session uniqueness and secret generation;
/// this type proves only the RFC1929 username/password byte-length constraint.
pub struct IsolationLabel(String);

impl IsolationLabel {
    pub fn new(label: impl Into<String>) -> Result<Self, SafeError> {
        let label = label.into();
        if label.is_empty() || label.len() > u8::MAX as usize {
            return Err(SafeError::new(
                ErrorCode::InvalidParameters,
                "A nonempty SOCKS isolation label fitting RFC1929 is required.",
            ));
        }
        Ok(Self(label))
    }
}

impl fmt::Debug for IsolationLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IsolationLabel([redacted])")
    }
}

/// Policy guard around the maintained SOCKS implementation, not a handshake
/// implementation. The first proxy message must select username/password.
struct RequirePassword<S> {
    socket: S,
    checked: usize,
    failed: bool,
}

impl<S> RequirePassword<S> {
    fn new(socket: S) -> Self {
        Self {
            socket,
            checked: 0,
            failed: false,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for RequirePassword<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.failed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SOCKS password negotiation required",
            )));
        }
        let before = buf.filled().len();
        match Pin::new(&mut self.socket).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                for byte in &buf.filled()[before..] {
                    if self.checked < 2 {
                        let expected = [0x05, 0x02][self.checked];
                        if *byte != expected {
                            self.failed = true;
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "SOCKS password negotiation required",
                            )));
                        }
                        self.checked += 1;
                    }
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RequirePassword<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.socket).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_shutdown(cx)
    }
}

/// No RPC API is exposed on an unverified bootstrap channel.
///
/// ```compile_fail
/// let bootstrap = zrpc_transport::UnverifiedChannel::new();
/// bootstrap.send_rpc(b"private parameters");
/// ```
///
/// Raw writing authority is also unavailable, even after SOCKS negotiation:
/// ```compile_fail
/// use tokio::io::AsyncWriteExt;
/// async fn cannot_write(mut bootstrap: zrpc_transport::UnverifiedChannel) {
///     bootstrap.write_all(b"private parameters").await.unwrap();
/// }
/// ```
/// ```compile_fail
/// let bootstrap = zrpc_transport::UnverifiedChannel::new();
/// let socket = bootstrap.into_inner();
/// ```
#[derive(Default)]
pub struct UnverifiedChannel {
    socket: Option<Socks5Stream<RequirePassword<ProxySocket>>>,
    origin: TransportOrigin,
    server_name: Option<String>,
    authority: Option<String>,
}

impl UnverifiedChannel {
    pub fn new() -> Self {
        Self::default()
    }

    /// SOCKS negotiation only; not evidence of Tor, TLS, or attestation.
    pub fn socks_connected(&self) -> bool {
        self.socket.is_some()
    }
}

impl fmt::Debug for UnverifiedChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnverifiedChannel")
            .field("socks_connected", &self.socks_connected())
            .field("private_rpc_allowed", &false)
            .finish()
    }
}

/// RPC transport requires a genuine verified session. It cannot be created in M0.
pub struct RpcChannel {
    _verified: VerifiedChannel,
}

impl RpcChannel {
    pub fn from_verified(verified: VerifiedChannel) -> Self {
        Self {
            _verified: verified,
        }
    }

    /// No wire serializer or socket is implemented until the reviewed TLS path exists.
    pub fn query(self, _request: &Request) -> Result<(), SafeError> {
        Err(SafeError::new(
            ErrorCode::PrivateModeUnavailable,
            "The genuine private transport is unavailable in M0.",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        task::JoinHandle,
    };

    #[test]
    fn tor_configuration_is_loopback_only_and_cannot_claim_connectivity() {
        assert!(TorConfig::new("127.0.0.1:9050".parse().unwrap()).is_ok());
        for endpoint in ["0.0.0.0:9050", "192.0.2.1:9050", "127.0.0.1:0"] {
            assert!(TorConfig::new(endpoint.parse().unwrap()).is_err());
        }
    }

    #[test]
    fn endpoint_and_isolation_types_reject_invalid_values_and_redact_debug() {
        for host in [
            "",
            "127.0.0.1.",
            "[::1]",
            "https://rpc.example",
            "rpc.example/path",
            "user@rpc.example",
            "bad host",
            "-bad.example",
        ] {
            assert!(RemoteEndpoint::new(host, 443).is_err());
        }
        assert!(RemoteEndpoint::new("rpc.example", 0).is_err());
        assert!(RemoteEndpoint::new("a".repeat(64), 443).is_err());
        assert!(IsolationLabel::new("").is_err());
        assert!(IsolationLabel::new("s".repeat(256)).is_err());
        assert!(IsolationLabel::new("s".repeat(255)).is_ok());
        assert!(
            !format!("{:?}", IsolationLabel::new("fixture-secret").unwrap())
                .contains("fixture-secret")
        );
        assert!(
            !format!("{:?}", RemoteEndpoint::new("rpc.example", 443).unwrap())
                .contains("rpc.example")
        );
        assert!(!UnverifiedChannel::new().socks_connected());
    }

    #[derive(Clone)]
    struct ProxyReply {
        method: Vec<u8>,
        auth: Vec<u8>,
        connect: Vec<u8>,
    }

    impl ProxyReply {
        fn success() -> Self {
            Self {
                method: vec![5, 2],
                auth: vec![1, 0],
                connect: vec![5, 0, 0, 1, 127, 0, 0, 1, 0, 0],
            }
        }
    }

    #[derive(Debug, Default)]
    struct Observed {
        username: Vec<u8>,
        password: Vec<u8>,
        hostname: Vec<u8>,
        port: u16,
        remaining: Vec<u8>,
    }

    async fn observe_connection(mut socket: TcpStream, reply: ProxyReply) -> Observed {
        let mut observed = Observed::default();
        let mut greeting = [0; 4];
        socket.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 2, 0, 2]);
        socket.write_all(&reply.method).await.unwrap();
        if reply.method != [5, 2] {
            socket.shutdown().await.unwrap();
            socket.read_to_end(&mut observed.remaining).await.unwrap();
            return observed;
        }
        assert_eq!(socket.read_u8().await.unwrap(), 1);
        let username_len = socket.read_u8().await.unwrap();
        observed.username.resize(username_len as usize, 0);
        socket.read_exact(&mut observed.username).await.unwrap();
        let password_len = socket.read_u8().await.unwrap();
        observed.password.resize(password_len as usize, 0);
        socket.read_exact(&mut observed.password).await.unwrap();
        socket.write_all(&reply.auth).await.unwrap();
        if reply.auth != [1, 0] {
            socket.shutdown().await.unwrap();
            socket.read_to_end(&mut observed.remaining).await.unwrap();
            return observed;
        }
        let mut header = [0; 4];
        socket.read_exact(&mut header).await.unwrap();
        assert_eq!(&header[..3], &[5, 1, 0]);
        let hostname_len = match header[3] {
            3 => socket.read_u8().await.unwrap() as usize,
            1 => 4,
            4 => 16,
            _ => panic!("unexpected SOCKS address type"),
        };
        observed.hostname.resize(hostname_len, 0);
        socket.read_exact(&mut observed.hostname).await.unwrap();
        observed.port = socket.read_u16().await.unwrap();
        socket.write_all(&reply.connect).await.unwrap();
        socket.shutdown().await.unwrap();
        socket.read_to_end(&mut observed.remaining).await.unwrap();
        observed
    }

    async fn fake_proxy(replies: Vec<ProxyReply>) -> (TorConfig, JoinHandle<Vec<Observed>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let config = TorConfig::new(match listener.local_addr().unwrap() {
            std::net::SocketAddr::V4(addr) => addr,
            _ => unreachable!(),
        })
        .unwrap();
        let task = tokio::spawn(async move {
            let mut observations = Vec::new();
            for reply in replies {
                let (socket, _) = listener.accept().await.unwrap();
                observations.push(observe_connection(socket, reply).await);
            }
            observations
        });
        (config, task)
    }

    #[tokio::test]
    async fn hostname_and_tor_isolation_are_forwarded_without_application_data() {
        let (config, proxy) = fake_proxy(vec![ProxyReply::success()]).await;
        let endpoint = RemoteEndpoint::new("unresolved-fixture.invalid", 443).unwrap();
        let channel = config
            .connect_bootstrap(
                &endpoint,
                IsolationLabel::new("fixture-session-secret").unwrap(),
            )
            .await
            .unwrap();
        assert!(channel.socks_connected());
        drop(channel);
        let seen = proxy.await.unwrap().pop().unwrap();
        assert_eq!(seen.username, b"<torS0X>0");
        assert_eq!(seen.password, b"fixture-session-secret");
        assert_eq!(seen.hostname, b"unresolved-fixture.invalid");
        assert_eq!(seen.port, 443);
        assert!(seen.remaining.is_empty());
    }

    #[tokio::test]
    async fn numeric_endpoints_use_socks_address_fields_without_direct_dialing() {
        for (host, expected) in [
            ("192.0.2.1", vec![192, 0, 2, 1]),
            (
                "2001:db8::1",
                "2001:db8::1"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets()
                    .to_vec(),
            ),
        ] {
            let (config, proxy) = fake_proxy(vec![ProxyReply::success()]).await;
            let endpoint = RemoteEndpoint::new(host, 443).unwrap();
            let channel = config
                .connect_bootstrap(&endpoint, IsolationLabel::new("numeric-fixture").unwrap())
                .await
                .unwrap();
            drop(channel);
            let seen = proxy.await.unwrap().pop().unwrap();
            assert_eq!(seen.hostname, expected);
            assert_eq!(seen.port, 443);
            assert!(seen.remaining.is_empty());
        }
    }

    #[tokio::test]
    async fn auth_downgrade_bad_version_and_truncation_fail_before_connect() {
        for method in [vec![5, 0], vec![4, 2], vec![5, 255], vec![5]] {
            let mut reply = ProxyReply::success();
            reply.method = method.clone();
            let (config, proxy) = fake_proxy(vec![reply]).await;
            let endpoint = RemoteEndpoint::new("unresolved-fixture.invalid", 443).unwrap();
            let error = config
                .connect_bootstrap(&endpoint, IsolationLabel::new("fixture-secret").unwrap())
                .await
                .unwrap_err();
            assert_eq!(error.code, ErrorCode::TorUnavailable);
            assert!(!format!("{error:?}").contains("fixture-secret"));
            if method == [5, 0] {
                assert_eq!(
                    error.message,
                    "SOCKS authentication or protocol response was invalid."
                );
            }
            let seen = proxy.await.unwrap().pop().unwrap();
            assert!(seen.username.is_empty());
            assert!(seen.hostname.is_empty());
            assert!(seen.remaining.is_empty());
        }
    }

    #[tokio::test]
    async fn rejected_or_malformed_auth_fails_before_connect() {
        for auth in [vec![1, 1], vec![2, 0], vec![1]] {
            let mut reply = ProxyReply::success();
            reply.auth = auth.clone();
            let (config, proxy) = fake_proxy(vec![reply]).await;
            let endpoint = RemoteEndpoint::new("unresolved-fixture.invalid", 443).unwrap();
            let error = config
                .connect_bootstrap(&endpoint, IsolationLabel::new("fixture-secret").unwrap())
                .await
                .unwrap_err();
            assert_eq!(error.code, ErrorCode::TorUnavailable);
            if auth == [1, 1] {
                assert_eq!(
                    error.message,
                    "SOCKS did not accept required password authentication."
                );
            }
            let seen = proxy.await.unwrap().pop().unwrap();
            assert!(seen.hostname.is_empty());
            assert!(seen.remaining.is_empty());
        }
    }

    #[tokio::test]
    async fn connect_rejection_malformed_and_truncated_replies_do_not_fall_back() {
        let trap = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        trap.set_nonblocking(true).unwrap();
        let endpoint = RemoteEndpoint::new("localhost", trap.local_addr().unwrap().port()).unwrap();
        for connect in [
            vec![5, 5, 0, 1],
            vec![4, 0, 0, 1],
            vec![5, 0, 1, 1],
            vec![5, 0, 0, 255],
            vec![5, 0],
        ] {
            let mut reply = ProxyReply::success();
            reply.connect = connect.clone();
            let (config, proxy) = fake_proxy(vec![reply]).await;
            let error = config
                .connect_bootstrap(&endpoint, IsolationLabel::new("fixture-secret").unwrap())
                .await
                .unwrap_err();
            assert_eq!(error.code, ErrorCode::TorUnavailable);
            if connect == [5, 5, 0, 1] {
                assert_eq!(
                    error.message,
                    "SOCKS reported an endpoint connection failure."
                );
            }
            assert!(proxy.await.unwrap().pop().unwrap().remaining.is_empty());
            assert_eq!(trap.accept().unwrap_err().kind(), io::ErrorKind::WouldBlock);
        }
    }

    #[tokio::test]
    async fn missing_tor_never_connects_to_direct_destination() {
        let trap = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        trap.set_nonblocking(true).unwrap();
        let unavailable = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let config = TorConfig::new(match unavailable.local_addr().unwrap() {
            std::net::SocketAddr::V4(addr) => addr,
            _ => unreachable!(),
        })
        .unwrap();
        drop(unavailable);
        let endpoint = RemoteEndpoint::new("localhost", trap.local_addr().unwrap().port()).unwrap();
        assert!(
            config
                .connect_bootstrap(&endpoint, IsolationLabel::new("fixture-secret").unwrap())
                .await
                .is_err()
        );
        assert_eq!(trap.accept().unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }

    #[tokio::test]
    async fn method_guard_handles_fragmented_reply_and_latches_failure() {
        for method in [2, 0] {
            // Capacity one forces the two-byte method reply across reads.
            let (client, mut peer) = tokio::io::duplex(1);
            let task = tokio::spawn(async move {
                peer.write_all(&[5, method]).await.unwrap();
            });
            let mut guarded = RequirePassword::new(client);
            let mut response = [0; 2];
            let result = guarded.read_exact(&mut response).await;
            if method == 2 {
                assert!(result.is_ok());
                assert_eq!(response, [5, 2]);
            } else {
                assert!(result.is_err());
                assert!(guarded.read_u8().await.is_err());
            }
            task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn reconnect_negotiates_again_and_never_inherits_acceptance() {
        let mut rejected = ProxyReply::success();
        rejected.method = vec![5, 0];
        let (config, proxy) = fake_proxy(vec![ProxyReply::success(), rejected]).await;
        let endpoint = RemoteEndpoint::new("unresolved-fixture.invalid", 443).unwrap();
        let first = config
            .connect_bootstrap(
                &endpoint,
                IsolationLabel::new("fixture-first-session").unwrap(),
            )
            .await
            .unwrap();
        drop(first);
        assert!(
            config
                .connect_bootstrap(
                    &endpoint,
                    IsolationLabel::new("fixture-second-session").unwrap()
                )
                .await
                .is_err()
        );
        let observations = proxy.await.unwrap();
        assert_eq!(observations.len(), 2);
        assert_eq!(observations[0].password, b"fixture-first-session");
        assert!(observations[1].password.is_empty());
        assert!(observations.iter().all(|seen| seen.remaining.is_empty()));
    }
}
