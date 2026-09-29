//! A separately locked, local RFC 9578 type-2 signature verifier.
//!
//! The caller must validate the complete token type, challenge digest, key ID,
//! allowed RPC request, and spent state. This component verifies only the
//! RSASSA-PSS authenticator against a canonical issuer SPKI. It never contacts
//! an issuer or writes a token to disk.

use blind_rsa_signatures::{
    BlindMessage, BlindSignature, BlindingResult, DefaultRng, PublicKeySha384PSSDeterministic,
    Secret, SecretKeySha384PSSDeterministic, Signature,
};
use std::fmt;

pub const TOKEN_INPUT_LEN: usize = 98;
pub const AUTHENTICATOR_LEN: usize = 256;

pub struct PreparedBlind {
    pub blinded_message: [u8; AUTHENTICATOR_LEN],
    pub secret: [u8; AUTHENTICATOR_LEN],
}

impl fmt::Debug for PreparedBlind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreparedBlind([redacted])")
    }
}

fn canonical_public_key(issuer_spki: &[u8]) -> Option<PublicKeySha384PSSDeterministic> {
    let issuer = PublicKeySha384PSSDeterministic::from_spki(issuer_spki).ok()?;
    if issuer.to_spki().ok().as_deref() != Some(issuer_spki) {
        return None;
    }
    Some(issuer)
}

/// Normalize a supported RSA public key to the exact RFC 9578 issuer SPKI
/// before calculating its key identifier or sharing it with clients.
pub fn canonicalize_issuer_spki(public_der: &[u8]) -> Option<Vec<u8>> {
    let issuer = PublicKeySha384PSSDeterministic::from_spki(public_der)
        .or_else(|_| PublicKeySha384PSSDeterministic::from_der(public_der))
        .ok()?;
    issuer.to_spki().ok()
}

fn type_two_input(token_input: &[u8]) -> bool {
    token_input.len() == TOKEN_INPUT_LEN && token_input[..2] == [0, 2]
}

pub fn blind_token_input(issuer_spki: &[u8], token_input: &[u8]) -> Option<PreparedBlind> {
    if !type_two_input(token_input) {
        return None;
    }
    let issuer = canonical_public_key(issuer_spki)?;
    let result = issuer.blind(&mut DefaultRng, token_input).ok()?;
    Some(PreparedBlind {
        blinded_message: result.blind_message.0.try_into().ok()?,
        secret: result.secret.0.try_into().ok()?,
    })
}

pub fn sign_blinded(
    issuer_spki: &[u8],
    issuer_private_der: &[u8],
    blinded_message: &[u8],
) -> Option<[u8; AUTHENTICATOR_LEN]> {
    if blinded_message.len() != AUTHENTICATOR_LEN {
        return None;
    }
    canonical_public_key(issuer_spki)?;
    let issuer = SecretKeySha384PSSDeterministic::from_der(issuer_private_der).ok()?;
    if issuer.public_key().ok()?.to_spki().ok()? != issuer_spki {
        return None;
    }
    issuer.blind_sign(blinded_message).ok()?.0.try_into().ok()
}

pub fn finalize_blind_signature(
    issuer_spki: &[u8],
    token_input: &[u8],
    blinded_message: &[u8],
    secret: &[u8],
    blind_signature: &[u8],
) -> Option<[u8; AUTHENTICATOR_LEN]> {
    if !type_two_input(token_input)
        || blinded_message.len() != AUTHENTICATOR_LEN
        || secret.len() != AUTHENTICATOR_LEN
        || blind_signature.len() != AUTHENTICATOR_LEN
    {
        return None;
    }
    let issuer = canonical_public_key(issuer_spki)?;
    let result = BlindingResult {
        blind_message: BlindMessage(blinded_message.to_vec()),
        secret: Secret(secret.to_vec()),
        msg_randomizer: None,
    };
    issuer
        .finalize(
            &BlindSignature(blind_signature.to_vec()),
            &result,
            token_input,
        )
        .ok()?
        .0
        .try_into()
        .ok()
}

/// Verify the RFC 9578 SHA-384 / MGF1-SHA-384 / 48-byte-salt authenticator.
/// A false result has no distinguishing detail suitable for an RPC response.
pub fn verify_authenticator(issuer_spki: &[u8], token_input: &[u8], authenticator: &[u8]) -> bool {
    if !type_two_input(token_input) || authenticator.len() != AUTHENTICATOR_LEN {
        return false;
    }
    let Some(issuer) = canonical_public_key(issuer_spki) else {
        return false;
    };
    issuer
        .verify(&Signature(authenticator.to_vec()), None, token_input)
        .is_ok()
}
