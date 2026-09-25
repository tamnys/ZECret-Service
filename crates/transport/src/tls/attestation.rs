//! One nonce-only public request on the challenge's original TLS connection.

use super::{MAX_CONNECTION_LIFETIME, PendingChallenge, unavailable};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, StatusCode, Version, client::conn::http1, header};
use hyper_util::rt::TokioIo;
use std::{fmt, time::Instant};
use zrpc_protocol::{
    ATTESTATION_EXPORTER_LABEL, ErrorCode, MAX_ATTESTATION_REQUEST_BYTES,
    MAX_ATTESTATION_RESPONSE_BYTES, PublicAttestationRequest, PublicAttestationResponse, SafeError,
    parse_attestation_response,
};

mod inspection;
pub use inspection::{EndpointInspection, EndpointInspectionIssue};

fn invalid_response() -> SafeError {
    SafeError::new(
        ErrorCode::InvalidBackendResponse,
        "Public attestation response is malformed; evidence remains unverified.",
    )
}

fn too_large() -> SafeError {
    SafeError::new(
        ErrorCode::ResponseTooLarge,
        "Public attestation response exceeds the release-policy limit.",
    )
}

fn expired() -> SafeError {
    SafeError::new(
        ErrorCode::StaleNonce,
        "TLS bootstrap lifetime expired; establish a new connection.",
    )
}

struct OwnedHttpSession {
    // Retain ownership but never expose this application-writing capability.
    sender: http1::SendRequest<Full<Bytes>>,
    driver: tokio::task::JoinHandle<()>,
}

impl Drop for OwnedHttpSession {
    fn drop(&mut self) {
        // Also applies on cancellation, parse failure and connection expiry.
        self.driver.abort();
    }
}

impl PendingChallenge {
    /// Send the sole public request allowed by this type: POST /attestation with
    /// this session's 32-byte nonce. No caller payload, selector or key is accepted.
    /// The nonce is consumed once, and the response is explicitly unverified.
    pub async fn request_attestation(self) -> Result<UnverifiedPublicEvidence, SafeError> {
        self.tls.ensure_live()?;
        let deadline = self
            .tls
            .established
            .checked_add(MAX_CONNECTION_LIFETIME)
            .ok_or_else(expired)?;
        // This is the original connection's existing five-minute lifetime, not
        // a fresh timeout or an extension starting at request time.
        tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), self.exchange())
            .await
            .map_err(|_| expired())?
    }

    async fn exchange(self) -> Result<UnverifiedPublicEvidence, SafeError> {
        let nonce = self.nonce;
        let established = self.tls.established;
        let deadline = established
            .checked_add(MAX_CONNECTION_LIFETIME)
            .ok_or_else(expired)?;
        // Capture from this original completed TLS session before handing it to
        // Hyper. Keeping these private inputs is not quote acceptance: a future
        // verifier must authenticate REPORTDATA before comparing it to them.
        let expected_report_data = self
            .tls
            .stream
            .get_ref()
            .1
            .export_keying_material([0; 64], ATTESTATION_EXPORTER_LABEL, Some(&nonce))
            .map_err(|_| unavailable())?;
        let body =
            serde_json::to_vec(&PublicAttestationRequest { nonce }).map_err(|_| unavailable())?;
        if body.len() > MAX_ATTESTATION_REQUEST_BYTES {
            return Err(SafeError::new(
                ErrorCode::RequestTooLarge,
                "Public attestation request exceeds the release-policy limit.",
            ));
        }
        let request = Request::post("/attestation")
            .header(header::HOST, self.tls.authority)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json")
            .header(header::ACCEPT_ENCODING, "identity")
            .body(Full::new(Bytes::from(body)))
            .map_err(|_| unavailable())?;
        // Hyper receives the owned TLS stream. This API neither opens a socket
        // nor resolves a host, follows a redirect, retries, or consults proxies.
        let (sender, connection) = http1::handshake(TokioIo::new(self.tls.stream))
            .await
            .map_err(|_| unavailable())?;
        let mut session = OwnedHttpSession {
            sender,
            driver: tokio::spawn(async move {
                let _ = connection.await;
            }),
        };
        let response = session
            .sender
            .send_request(request)
            .await
            .map_err(|_| unavailable())?;
        if response.status() != StatusCode::OK || response.version() != Version::HTTP_11 {
            return Err(invalid_response());
        }
        let headers = response.headers();
        if headers.contains_key(header::CONTENT_ENCODING)
            || headers.get_all(header::CONTENT_TYPE).iter().count() != 1
            || headers
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                != Some("application/json")
            || headers.get_all(header::CONNECTION).iter().any(|value| {
                value.to_str().map_or(true, |value| {
                    value
                        .split(',')
                        .any(|token| token.trim().eq_ignore_ascii_case("close"))
                })
            })
        {
            return Err(invalid_response());
        }
        if headers
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|length| length > MAX_ATTESTATION_RESPONSE_BYTES as u64)
        {
            return Err(too_large());
        }
        let body = Limited::new(response.into_body(), MAX_ATTESTATION_RESPONSE_BYTES)
            .collect()
            .await
            .map_err(|error| {
                if error.is::<http_body_util::LengthLimitError>() {
                    too_large()
                } else {
                    unavailable()
                }
            })?
            .to_bytes();
        let evidence = parse_attestation_response(&body)?;
        if evidence.nonce != nonce {
            return Err(SafeError::new(
                ErrorCode::InvalidNonce,
                "Public attestation response does not match this challenge.",
            ));
        }
        if Instant::now()
            .checked_duration_since(established)
            .is_none_or(|age| age >= MAX_CONNECTION_LIFETIME)
        {
            return Err(expired());
        }
        if session.sender.is_closed() || session.driver.is_finished() {
            return Err(unavailable());
        }
        Ok(UnverifiedPublicEvidence {
            evidence,
            _session: session,
            expected_report_data,
            established,
            deadline,
            nonce,
        })
    }
}

/// Raw peer-supplied quote material received over the challenge's TLS session.
/// Nonce equality establishes correlation only: no hardware, workload, quote
/// freshness, report-data binding or approval policy has been authenticated.
/// The retained socket is opaque; this type has no private-query capability.
///
/// ```compile_fail
/// fn cannot_authorize(evidence: zrpc_transport::UnverifiedPublicEvidence) {
///     let _: zrpc_verifier::VerifiedChannel = evidence.into();
/// }
/// ```
/// ```compile_fail
/// use tokio::io::AsyncWriteExt;
/// async fn cannot_write(mut evidence: zrpc_transport::UnverifiedPublicEvidence) {
///     evidence.write_all(b"private query").await.unwrap();
/// }
/// ```
/// ```compile_fail
/// async fn cannot_supply_query(challenge: zrpc_transport::PendingChallenge) {
///     challenge.request_attestation(b"private query").await.unwrap();
/// }
/// ```
pub struct UnverifiedPublicEvidence {
    evidence: PublicAttestationResponse,
    _session: OwnedHttpSession,
    // Retained for the future authenticated verifier boundary, never exported
    // through the raw evidence accessor or treated as acceptance in this API.
    expected_report_data: [u8; 64],
    established: Instant,
    deadline: Instant,
    nonce: [u8; 32],
}

impl UnverifiedPublicEvidence {
    pub fn raw_unverified(&self) -> &PublicAttestationResponse {
        &self.evidence
    }
    pub fn private_rpc_allowed(&self) -> bool {
        false
    }

    #[cfg(test)]
    pub(super) fn assert_retained_binding_for_test(
        &self,
        expected: [u8; 64],
        nonce: [u8; 32],
        established: Instant,
    ) {
        assert_eq!(self.expected_report_data, expected);
        assert_eq!(self.nonce, nonce);
        assert_eq!(self.established, established);
        assert_eq!(self.deadline, established + MAX_CONNECTION_LIFETIME);
    }
}

impl fmt::Debug for UnverifiedPublicEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnverifiedPublicEvidence")
            .field("evidence_authenticated", &false)
            .field("private_rpc_allowed", &false)
            .finish()
    }
}
