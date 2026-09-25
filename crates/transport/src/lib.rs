//! M0 transport types perform no network I/O. There is no direct fallback.
#![forbid(unsafe_code)]

use std::net::SocketAddrV4;
use zrpc_protocol::{ErrorCode, Request, SafeError};
use zrpc_verifier::VerifiedChannel;

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
}

/// No RPC API is exposed on an unverified bootstrap channel.
///
/// ```compile_fail
/// let bootstrap = zrpc_transport::UnverifiedChannel::new();
/// bootstrap.send_rpc(b"private parameters");
/// ```
#[derive(Debug, Default)]
pub struct UnverifiedChannel;

impl UnverifiedChannel {
    pub fn new() -> Self {
        Self
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

    #[test]
    fn tor_configuration_is_loopback_only_and_cannot_claim_connectivity() {
        assert!(TorConfig::new("127.0.0.1:9050".parse().unwrap()).is_ok());
        for endpoint in ["0.0.0.0:9050", "192.0.2.1:9050", "127.0.0.1:0"] {
            assert!(TorConfig::new(endpoint.parse().unwrap()).is_err());
        }
    }
}
