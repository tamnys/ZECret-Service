//! RFC 9577 Section 2.2.2 `Authorization: PrivateToken` credentials.
//! Parsing checks framing and the common type-2 challenge/key configuration,
//! but deliberately returns an unverified token that cannot admit RPC.

use base64::{Engine, engine::general_purpose::URL_SAFE};
use std::fmt;
use zeroize::Zeroizing;

use crate::wire::{TOKEN_LEN, UnverifiedToken};

const SCHEME: &[u8] = b"PrivateToken";
const ENCODED_TOKEN_LEN: usize = TOKEN_LEN.div_ceil(3) * 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthorizationError;

impl fmt::Display for AuthorizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid PrivateToken authorization")
    }
}

pub(crate) struct AuthorizationValue(Zeroizing<String>);

impl AuthorizationValue {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for AuthorizationValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthorizationValue([redacted])")
    }
}

pub(crate) fn format_authorization(
    token: &[u8],
    expected_challenge: &[u8],
    expected_issuer_key_id: [u8; 32],
) -> Result<AuthorizationValue, AuthorizationError> {
    UnverifiedToken::parse(token, expected_challenge, expected_issuer_key_id)
        .map_err(|_| AuthorizationError)?;
    let mut value = Zeroizing::new(String::with_capacity(
        SCHEME.len() + b" token=\"\"".len() + ENCODED_TOKEN_LEN,
    ));
    value.push_str("PrivateToken token=\"");
    URL_SAFE.encode_string(token, &mut value);
    value.push('"');
    Ok(AuthorizationValue(value))
}

pub(crate) fn parse_authorization(
    header_value: &[u8],
    expected_challenge: &[u8],
    expected_issuer_key_id: [u8; 32],
) -> Result<UnverifiedToken, AuthorizationError> {
    let header = trim_ows(header_value);
    if header.len() <= SCHEME.len()
        || !header[..SCHEME.len()].eq_ignore_ascii_case(SCHEME)
        || !matches!(header[SCHEME.len()], b' ' | b'\t')
    {
        return Err(AuthorizationError);
    }
    let parameters = trim_ows(&header[SCHEME.len()..]);
    let mut encoded_token = None;
    for segment in split_parameters(parameters)? {
        let segment = trim_ows(segment);
        let equal = segment
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or(AuthorizationError)?;
        let name = trim_ows(&segment[..equal]);
        if name.is_empty() || !name.iter().copied().all(is_tchar) {
            return Err(AuthorizationError);
        }
        if name.eq_ignore_ascii_case(b"token") {
            if encoded_token.is_some() {
                return Err(AuthorizationError);
            }
            encoded_token = Some(parse_token_value(trim_ows(&segment[equal + 1..]))?);
        }
        // RFC 9577 requires unknown credential parameters to be ignored.
    }
    let encoded_token = encoded_token.ok_or(AuthorizationError)?;
    if encoded_token.len() != ENCODED_TOKEN_LEN {
        return Err(AuthorizationError);
    }
    let decoded = Zeroizing::new(
        URL_SAFE
            .decode(encoded_token.as_slice())
            .map_err(|_| AuthorizationError)?,
    );
    let canonical = Zeroizing::new(URL_SAFE.encode(decoded.as_slice()));
    if canonical.as_bytes() != encoded_token.as_slice() {
        return Err(AuthorizationError);
    }
    UnverifiedToken::parse(
        decoded.as_slice(),
        expected_challenge,
        expected_issuer_key_id,
    )
    .map_err(|_| AuthorizationError)
}

fn trim_ows(mut bytes: &[u8]) -> &[u8] {
    while bytes
        .first()
        .is_some_and(|byte| matches!(*byte, b' ' | b'\t'))
    {
        bytes = &bytes[1..];
    }
    while bytes
        .last()
        .is_some_and(|byte| matches!(*byte, b' ' | b'\t'))
    {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn split_parameters(input: &[u8]) -> Result<Vec<&[u8]>, AuthorizationError> {
    if input.is_empty() {
        return Err(AuthorizationError);
    }
    let mut parts = Vec::new();
    let mut begin = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (index, byte) in input.iter().copied().enumerate() {
        if (byte < 0x20 && byte != b'\t') || byte == 0x7f {
            return Err(AuthorizationError);
        }
        if escaped {
            escaped = false;
        } else if quoted && byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            quoted = !quoted;
        } else if byte == b',' && !quoted {
            if trim_ows(&input[begin..index]).is_empty() {
                return Err(AuthorizationError);
            }
            parts.push(&input[begin..index]);
            begin = index + 1;
        }
    }
    if quoted || escaped || trim_ows(&input[begin..]).is_empty() {
        return Err(AuthorizationError);
    }
    parts.push(&input[begin..]);
    Ok(parts)
}

fn parse_token_value(input: &[u8]) -> Result<Zeroizing<Vec<u8>>, AuthorizationError> {
    if input.first() == Some(&b'"') {
        let mut value = Zeroizing::new(Vec::new());
        let mut index = 1;
        while index < input.len() {
            let byte = input[index];
            if byte == b'"' {
                if trim_ows(&input[index + 1..]).is_empty() {
                    return Ok(value);
                }
                return Err(AuthorizationError);
            }
            let byte = if byte == b'\\' {
                index += 1;
                *input.get(index).ok_or(AuthorizationError)?
            } else {
                byte
            };
            if !matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'=') {
                return Err(AuthorizationError);
            }
            value.push(byte);
            index += 1;
        }
        Err(AuthorizationError)
    } else if input.iter().copied().all(is_tchar) {
        Ok(Zeroizing::new(input.to_vec()))
    } else {
        Err(AuthorizationError)
    }
}

fn is_tchar(byte: u8) -> bool {
    matches!(
        byte,
        b'!' | b'#'..=b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
            | b'0'..=b'9'
            | b'A'..=b'Z'
            | b'a'..=b'z'
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenge::CommonChallenge;
    use crate::wire::{RSA_SIGNATURE_LEN, TOKEN_INPUT_LEN, TokenInput};

    fn fixture() -> (Vec<u8>, Vec<u8>, [u8; 32]) {
        let challenge = CommonChallenge::new("issuer.example")
            .unwrap()
            .as_bytes()
            .to_vec();
        let key_id = [7; 32];
        let input = TokenInput::new([8; 32], &challenge, key_id);
        let mut token = vec![0; TOKEN_LEN];
        token[..TOKEN_INPUT_LEN].copy_from_slice(input.as_bytes());
        token[TOKEN_INPUT_LEN..].copy_from_slice(&[9; RSA_SIGNATURE_LEN]);
        (token, challenge, key_id)
    }

    #[test]
    fn rfc9577_private_token_header_round_trip_is_only_unverified() {
        let (token, challenge, key_id) = fixture();
        let value = format_authorization(&token, &challenge, key_id).unwrap();
        assert!(value.as_bytes().starts_with(b"PrivateToken token=\""));
        assert!(value.as_bytes().ends_with(b"\""));
        assert_eq!(format!("{value:?}"), "AuthorizationValue([redacted])");
        let parsed = parse_authorization(value.as_bytes(), &challenge, key_id).unwrap();
        assert_eq!(parsed.signed_input(), &token[..TOKEN_INPUT_LEN]);
        assert_eq!(parsed.authenticator(), &token[TOKEN_INPUT_LEN..]);

        let bare = format!(
            "privatetoken realm=\"a,b\", TOKEN={}, future=\"x\\\"y\"",
            URL_SAFE.encode(&token)
        );
        assert!(parse_authorization(bare.as_bytes(), &challenge, key_id).is_ok());
    }

    #[test]
    fn malformed_duplicate_wrong_challenge_and_wrong_key_are_rejected() {
        let (token, challenge, key_id) = fixture();
        let value = format_authorization(&token, &challenge, key_id).unwrap();
        let value = std::str::from_utf8(value.as_bytes()).unwrap();
        for invalid in [
            format!("{value}, token=abc"),
            format!("{value}, TOKEN=abc"),
            value.replace("PrivateToken", "Bearer"),
            value.replace("token=", "token"),
            format!("{value}\r\nX-Leak: 1"),
            format!("{value},"),
        ] {
            assert!(parse_authorization(invalid.as_bytes(), &challenge, key_id).is_err());
        }
        assert!(parse_authorization(value.as_bytes(), b"wrong challenge", key_id).is_err());
        assert!(parse_authorization(value.as_bytes(), &challenge, [0; 32]).is_err());
    }
}
