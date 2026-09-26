//! Public bootstrap framing grants no quote or session authority.
use crate::{ErrorCode, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, SafeError};
use serde::{Deserialize, Serialize};
use std::fmt;

// Reuse the design §9 body limits for the public bootstrap release policy.
pub const MAX_ATTESTATION_REQUEST_BYTES: usize = MAX_REQUEST_BYTES;
pub const MAX_ATTESTATION_RESPONSE_BYTES: usize = MAX_RESPONSE_BYTES;
// Design §7 connection lifetime, including any public attestation exchange.
pub const MAX_CONNECTION_LIFETIME_SECONDS: u64 = 300;
// ADR 0002: RFC 8446 exporter label, raw 32-byte context, 64-byte output.
pub const ATTESTATION_EXPORTER_LABEL: &[u8] = b"EXPORTER-zrpc-attestation-v1";

/// Explicit evidence format selection. It is not a trust assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Backend {
    PhalaDstack,
    GcpTdx,
}

/// GCP v1 carries raw Intel evidence, never a provider verification Boolean.
/// The legacy Phala object remains a distinct, unchanged wire format.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpAttestationResponse {
    pub schema_version: u32,
    pub platform: Backend,
    pub nonce: [u8; 32],
    pub quote: String,
    pub ccel: String,
}

impl fmt::Debug for GcpAttestationResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GcpAttestationResponse([unverified public evidence])")
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicAttestationRequest {
    pub nonce: [u8; 32],
}

/// Untrusted wire fields. A matching echo or report_data string is not quote
/// authentication, freshness, policy approval, or a verified channel.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicAttestationResponse {
    pub nonce: [u8; 32],
    pub quote: String,
    pub event_log: String,
    pub report_data: String,
    pub vm_config: String,
}

impl fmt::Debug for PublicAttestationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PublicAttestationRequest([public challenge])")
    }
}

impl fmt::Debug for PublicAttestationResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PublicAttestationResponse([unverified public evidence])")
    }
}

fn parse<T: serde::de::DeserializeOwned>(bytes: &[u8], maximum: usize) -> Result<T, SafeError> {
    if bytes.len() > maximum {
        return Err(SafeError::new(
            ErrorCode::InvalidRequest,
            "Public attestation body exceeds its limit.",
        ));
    }
    if bytes.iter().copied().find(|b| !b.is_ascii_whitespace()) != Some(b'{') {
        return Err(SafeError::new(
            ErrorCode::InvalidRequest,
            "Expected one public attestation object.",
        ));
    }
    serde_json::from_slice(bytes).map_err(|_| {
        SafeError::new(
            ErrorCode::InvalidRequest,
            "Invalid public attestation object.",
        )
    })
}

pub fn parse_attestation_request(bytes: &[u8]) -> Result<PublicAttestationRequest, SafeError> {
    parse(bytes, MAX_ATTESTATION_REQUEST_BYTES)
}

pub fn parse_attestation_response(bytes: &[u8]) -> Result<PublicAttestationResponse, SafeError> {
    parse(bytes, MAX_ATTESTATION_RESPONSE_BYTES)
}

pub fn parse_gcp_attestation_response(bytes: &[u8]) -> Result<GcpAttestationResponse, SafeError> {
    let evidence: GcpAttestationResponse = parse(bytes, MAX_ATTESTATION_RESPONSE_BYTES)?;
    let hex_bytes = |value: &str| {
        !value.is_empty() && value.len() % 2 == 0 && value.bytes().all(|b| b.is_ascii_hexdigit())
    };
    if evidence.schema_version != 1
        || evidence.platform != Backend::GcpTdx
        || !hex_bytes(&evidence.quote)
        || !hex_bytes(&evidence.ccel)
    {
        return Err(SafeError::new(
            ErrorCode::InvalidRequest,
            "Invalid GCP TDX evidence envelope.",
        ));
    }
    Ok(evidence)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn gcp_and_phala_envelopes_are_not_interchangeable() {
        let valid = serde_json::to_vec(&GcpAttestationResponse {
            schema_version: 1,
            platform: Backend::GcpTdx,
            nonce: [0; 32],
            quote: "0001".into(),
            ccel: "0203".into(),
        })
        .unwrap();
        assert!(parse_gcp_attestation_response(&valid).is_ok());
        assert!(parse_attestation_response(&valid).is_err());
        for (field, value) in [
            ("schema_version", serde_json::json!(2)),
            ("platform", serde_json::json!("phala-dstack")),
            ("quote", serde_json::json!("0")),
            ("ccel", serde_json::json!("zz")),
            ("verified", serde_json::json!(true)),
        ] {
            let mut object: serde_json::Value = serde_json::from_slice(&valid).unwrap();
            object[field] = value;
            assert!(parse_gcp_attestation_response(&serde_json::to_vec(&object).unwrap()).is_err());
        }
        let duplicate =
            String::from_utf8(valid)
                .unwrap()
                .replacen('{', "{\"schema_version\":1,", 1);
        assert!(parse_gcp_attestation_response(duplicate.as_bytes()).is_err());
    }
    #[test]
    fn only_exact_nonce_request_and_required_evidence_fields_are_supported() {
        let nonce = serde_json::to_string(&[0u8; 32]).unwrap();
        assert!(parse_attestation_request(format!(r#"{{"nonce":{nonce}}}"#).as_bytes()).is_ok());
        for raw in [
            format!("[{nonce}]"),
            format!(r#"{{"nonce":{nonce},"nonce":{nonce}}}"#),
            format!(r#"{{"nonce":{nonce},"report_data":"caller-controlled"}}"#),
            r#"{"nonce":[0]}"#.to_owned(),
            r#"{"nonce":"hex"}"#.to_owned(),
        ] {
            assert!(parse_attestation_request(raw.as_bytes()).is_err());
        }
        let valid = serde_json::to_vec(&PublicAttestationResponse {
            nonce: [0; 32],
            quote: "unverified".into(),
            event_log: "[]".into(),
            report_data: "unverified".into(),
            vm_config: "{}".into(),
        })
        .unwrap();
        assert!(parse_attestation_response(&valid).is_ok());
        let mut invalid = serde_json::from_slice::<serde_json::Value>(&valid).unwrap();
        invalid["verified"] = true.into();
        assert!(parse_attestation_response(&serde_json::to_vec(&invalid).unwrap()).is_err());
        assert!(parse_attestation_response(format!(r#"{{"nonce":{nonce}}}"#).as_bytes()).is_err());
        assert!(parse_attestation_request(&vec![b' '; MAX_ATTESTATION_REQUEST_BYTES + 1]).is_err());
        assert!(
            parse_attestation_response(&vec![b' '; MAX_ATTESTATION_RESPONSE_BYTES + 1]).is_err()
        );
    }
}
