//! RFC 9578 Section 6 type-2 wire values. These types do not authenticate a
//! token or validate an issuer key. Keep them internal until the cryptographic
//! gate is met.

use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::Zeroize;

pub(crate) const TOKEN_TYPE: [u8; 2] = 2_u16.to_be_bytes();
pub(crate) const RSA_SIGNATURE_LEN: usize = 256;
pub(crate) const TOKEN_INPUT_LEN: usize = 2 + 32 + 32 + 32;
pub(crate) const TOKEN_REQUEST_LEN: usize = 2 + 1 + RSA_SIGNATURE_LEN;
pub(crate) const TOKEN_LEN: usize = TOKEN_INPUT_LEN + RSA_SIGNATURE_LEN;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum WireError {
    Length,
    Type,
    IssuerKey,
    Challenge,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Length => "invalid type-2 message length",
            Self::Type => "unsupported Privacy Pass token type",
            Self::IssuerKey => "unexpected issuer key identifier",
            Self::Challenge => "unexpected token challenge",
        })
    }
}

impl std::error::Error for WireError {}

// The caller must validate the SPKI and its RSASSA-PSS parameters before using
// this digest as an issuer identifier. This helper only performs RFC 9578's
// SHA-256 key-ID calculation.
pub(crate) fn key_id_for_spki(spki: &[u8]) -> [u8; 32] {
    Sha256::digest(spki).into()
}

pub(crate) struct TokenInput([u8; TOKEN_INPUT_LEN]);

impl TokenInput {
    pub(crate) fn new(nonce: [u8; 32], challenge: &[u8], key_id: [u8; 32]) -> Self {
        let mut bytes = [0; TOKEN_INPUT_LEN];
        bytes[..2].copy_from_slice(&TOKEN_TYPE);
        bytes[2..34].copy_from_slice(&nonce);
        bytes[34..66].copy_from_slice(&Sha256::digest(challenge));
        bytes[66..98].copy_from_slice(&key_id);
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; TOKEN_INPUT_LEN] {
        &self.0
    }
}

impl fmt::Debug for TokenInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TokenInput([redacted])")
    }
}

impl Drop for TokenInput {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub(crate) struct TokenRequest([u8; TOKEN_REQUEST_LEN]);

impl TokenRequest {
    pub(crate) fn new(key_id: [u8; 32], blinded_msg: [u8; RSA_SIGNATURE_LEN]) -> Self {
        let mut bytes = [0; TOKEN_REQUEST_LEN];
        bytes[..2].copy_from_slice(&TOKEN_TYPE);
        bytes[2] = key_id[31];
        bytes[3..].copy_from_slice(&blinded_msg);
        Self(bytes)
    }

    pub(crate) fn parse(bytes: &[u8], expected_key_id: [u8; 32]) -> Result<Self, WireError> {
        if bytes.len() != TOKEN_REQUEST_LEN {
            return Err(WireError::Length);
        }
        if bytes[..2] != TOKEN_TYPE {
            return Err(WireError::Type);
        }
        if bytes[2] != expected_key_id[31] {
            return Err(WireError::IssuerKey);
        }
        let mut request = [0; TOKEN_REQUEST_LEN];
        request.copy_from_slice(bytes);
        Ok(Self(request))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; TOKEN_REQUEST_LEN] {
        &self.0
    }

    pub(crate) fn blinded_msg(&self) -> &[u8] {
        &self.0[3..]
    }
}

impl fmt::Debug for TokenRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TokenRequest([redacted])")
    }
}

impl Drop for TokenRequest {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub(crate) struct TokenResponse([u8; RSA_SIGNATURE_LEN]);

impl TokenResponse {
    pub(crate) fn new(blind_signature: [u8; RSA_SIGNATURE_LEN]) -> Self {
        Self(blind_signature)
    }

    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, WireError> {
        let signature = bytes.try_into().map_err(|_| WireError::Length)?;
        Ok(Self(signature))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; RSA_SIGNATURE_LEN] {
        &self.0
    }
}

impl fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TokenResponse([redacted])")
    }
}

impl Drop for TokenResponse {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// This structure has passed only length, type, challenge, and key-ID checks.
/// Its signature remains unverified and must never authorize a request.
pub(crate) struct UnverifiedToken([u8; TOKEN_LEN]);

impl UnverifiedToken {
    pub(crate) fn parse(
        bytes: &[u8],
        expected_challenge: &[u8],
        expected_key_id: [u8; 32],
    ) -> Result<Self, WireError> {
        if bytes.len() != TOKEN_LEN {
            return Err(WireError::Length);
        }
        if bytes[..2] != TOKEN_TYPE {
            return Err(WireError::Type);
        }
        if bytes[34..66] != Sha256::digest(expected_challenge)[..] {
            return Err(WireError::Challenge);
        }
        if bytes[66..TOKEN_INPUT_LEN] != expected_key_id {
            return Err(WireError::IssuerKey);
        }
        let mut token = [0; TOKEN_LEN];
        token.copy_from_slice(bytes);
        Ok(Self(token))
    }

    pub(crate) fn signed_input(&self) -> &[u8] {
        &self.0[..TOKEN_INPUT_LEN]
    }

    pub(crate) fn authenticator(&self) -> &[u8] {
        &self.0[TOKEN_INPUT_LEN..]
    }

    pub(crate) fn marker(&self) -> [u8; 32] {
        Sha256::digest(&self.0).into()
    }
}

impl fmt::Debug for UnverifiedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UnverifiedToken([redacted])")
    }
}

impl Drop for UnverifiedToken {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Public values from RFC 9578 Appendix A.2, vector 1. Only the challenge,
    // nonce, key ID, and token prefix are needed to verify this wire format.
    const RFC_CHALLENGE: &str = "0002000e6973737565722e6578616d706c65208e7acc900e393381e8810b7c9e4a68b5163f1f880ab6688a6ffe780923609e88000e6f726967696e2e6578616d706c65";
    const RFC_NONCE: &str = "aa72019d1f951df197021ce63876fe8b0a02dc1c31a12b0a2dd1508d07827f05";
    const RFC_KEY_ID: &str = "ca572f8982a9ca248a3056186322d93ca147266121ddeb5632c07f1f71cd2708";
    const RFC_TOKEN_PREFIX: &str = "0002aa72019d1f951df197021ce63876fe8b0a02dc1c31a12b0a2dd1508d07827f055969f643b4cfda5196d4aa86aeb5368834f4f06de46950ed435b3b81bd036d44ca572f8982a9ca248a3056186322d93ca147266121ddeb5632c07f1f71cd2708";

    fn decode(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn decode_fixed<const N: usize>(hex: &str) -> [u8; N] {
        let decoded = decode(hex);
        decoded.try_into().expect("RFC vector length")
    }

    #[test]
    fn rfc9578_vector_one_token_input() {
        let challenge = decode(RFC_CHALLENGE);
        let key_id = decode_fixed::<32>(RFC_KEY_ID);
        let input = TokenInput::new(decode_fixed::<32>(RFC_NONCE), &challenge, key_id);
        assert_eq!(input.as_bytes().as_slice(), decode(RFC_TOKEN_PREFIX));
        assert_eq!(format!("{input:?}"), "TokenInput([redacted])");
    }

    #[test]
    fn request_response_and_unverified_token_reject_bad_fields() {
        let challenge = decode(RFC_CHALLENGE);
        let key_id = decode_fixed::<32>(RFC_KEY_ID);
        let request = TokenRequest::new(key_id, [0x42; RSA_SIGNATURE_LEN]);
        assert_eq!(request.as_bytes().len(), 259);
        assert_eq!(&request.as_bytes()[..3], &[0, 2, 8]);
        assert_eq!(request.blinded_msg(), &[0x42; RSA_SIGNATURE_LEN]);
        assert_eq!(
            TokenRequest::parse(request.as_bytes(), key_id)
                .unwrap()
                .as_bytes(),
            request.as_bytes()
        );
        assert!(matches!(
            TokenRequest::parse(&request.as_bytes()[..258], key_id),
            Err(WireError::Length)
        ));
        let mut wrong_type = *request.as_bytes();
        wrong_type[1] = 1;
        assert!(matches!(
            TokenRequest::parse(&wrong_type, key_id),
            Err(WireError::Type)
        ));
        let mut wrong_key = key_id;
        wrong_key[31] ^= 1;
        assert!(matches!(
            TokenRequest::parse(request.as_bytes(), wrong_key),
            Err(WireError::IssuerKey)
        ));

        let response = TokenResponse::new([0x24; RSA_SIGNATURE_LEN]);
        assert_eq!(
            TokenResponse::parse(response.as_bytes())
                .unwrap()
                .as_bytes(),
            response.as_bytes()
        );
        assert!(matches!(
            TokenResponse::parse(&response.as_bytes()[..255]),
            Err(WireError::Length)
        ));

        let mut token = [0; TOKEN_LEN];
        token[..TOKEN_INPUT_LEN].copy_from_slice(&decode(RFC_TOKEN_PREFIX));
        token[TOKEN_INPUT_LEN..].fill(0x99); // Deliberately not a valid signature.
        let parsed = UnverifiedToken::parse(&token, &challenge, key_id).unwrap();
        assert_eq!(parsed.signed_input(), &token[..TOKEN_INPUT_LEN]);
        assert_eq!(parsed.authenticator().len(), RSA_SIGNATURE_LEN);
        assert_eq!(format!("{parsed:?}"), "UnverifiedToken([redacted])");
        assert!(matches!(
            UnverifiedToken::parse(&token[..353], &challenge, key_id),
            Err(WireError::Length)
        ));
        assert!(matches!(
            UnverifiedToken::parse(&token, b"other challenge", key_id),
            Err(WireError::Challenge)
        ));
        assert!(matches!(
            UnverifiedToken::parse(&token, &challenge, wrong_key),
            Err(WireError::IssuerKey)
        ));
        token[1] = 1;
        assert!(matches!(
            UnverifiedToken::parse(&token, &challenge, key_id),
            Err(WireError::Type)
        ));
    }
}
