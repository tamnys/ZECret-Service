//! A shared RFC 9577 type-2 challenge for the testnet POC. The empty
//! redemption context and origin list keep the challenge independent of a
//! customer, request, connection, or purchase. Every accepting redeemer must
//! share double-spend state for this challenge.

use std::{fmt, net::Ipv6Addr};

use crate::wire::TOKEN_TYPE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChallengeError;

impl fmt::Display for ChallengeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid common token challenge issuer name")
    }
}

impl std::error::Error for ChallengeError {}

/// The POC accepts DNS hostnames (including IPv4 text) and bracketed IPv6,
/// with an optional numeric port. This is a deliberately narrow subset of the
/// URI authority server-name syntax allowed by RFC 9577 Section 2.1.1.1.
pub(crate) struct CommonChallenge(Vec<u8>);

impl CommonChallenge {
    pub(crate) fn new(issuer_name: &str) -> Result<Self, ChallengeError> {
        let name = issuer_name.as_bytes();
        let name_len = u16::try_from(name.len()).map_err(|_| ChallengeError)?;
        if name_len == 0 || !valid_server_name(issuer_name) {
            return Err(ChallengeError);
        }
        let mut bytes = Vec::with_capacity(2 + 2 + name.len() + 1 + 2);
        bytes.extend_from_slice(&TOKEN_TYPE);
        bytes.extend_from_slice(&name_len.to_be_bytes());
        bytes.extend_from_slice(name);
        bytes.push(0); // empty redemption_context
        bytes.extend_from_slice(&0_u16.to_be_bytes()); // empty origin_info
        Ok(Self(bytes))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

fn valid_server_name(name: &str) -> bool {
    if !name.is_ascii() || name.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return false;
    }
    let (host, port) = if name.starts_with('[') {
        let Some(end) = name.find(']') else {
            return false;
        };
        let host = &name[1..end];
        if host.parse::<Ipv6Addr>().is_err() {
            return false;
        }
        let rest = &name[end + 1..];
        if rest.is_empty() {
            (host, None)
        } else if let Some(port) = rest.strip_prefix(':') {
            (host, Some(port))
        } else {
            return false;
        }
    } else {
        let (host, port) = match name.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (name, None),
        };
        if host.is_empty()
            || host.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || !label.as_bytes()[0].is_ascii_alphanumeric()
                    || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                    || !label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
        {
            return false;
        }
        (host, port)
    };
    !host.is_empty()
        && port.is_none_or(|port| {
            !port.is_empty()
                && port.bytes().all(|byte| byte.is_ascii_digit())
                && port.parse::<u16>().is_ok()
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn rfc9577_common_challenge_matches_empty_context_vector() {
        let challenge = CommonChallenge::new("issuer.example").unwrap();
        assert_eq!(
            challenge.as_bytes(),
            b"\x00\x02\x00\x0eissuer.example\x00\x00\x00"
        );
        let digest: [u8; 32] = Sha256::digest(challenge.as_bytes()).into();
        assert_eq!(
            digest,
            [
                0xb7, 0x41, 0xec, 0x1b, 0x6f, 0xd0, 0x5f, 0x1e, 0x95, 0xf8, 0x98, 0x29, 0x06, 0xae,
                0xc1, 0x61, 0x28, 0x96, 0xd9, 0xca, 0x97, 0xd5, 0x3e, 0xef, 0x94, 0xad, 0x3c, 0x9f,
                0xe0, 0x23, 0xf7, 0xa4,
            ]
        );
        assert_eq!(
            CommonChallenge::new("issuer.example").unwrap().as_bytes(),
            challenge.as_bytes()
        );
    }

    #[test]
    fn accepts_host_and_optional_port_without_customer_context() {
        for name in [
            "issuer.example:8443",
            "localhost",
            "127.0.0.1",
            "[::1]:8443",
        ] {
            let challenge = CommonChallenge::new(name).unwrap();
            assert_eq!(&challenge.as_bytes()[..4], &[0, 2, 0, name.len() as u8]);
            assert_eq!(
                &challenge.as_bytes()[challenge.as_bytes().len() - 3..],
                &[0, 0, 0]
            );
        }
    }

    #[test]
    fn rejects_non_authority_or_ambiguous_names() {
        for name in [
            "",
            "issuer@example",
            "https://issuer.example",
            "issuer.example/path",
            "issuer.example?x=1",
            "issuer.example#x",
            "issuer example",
            "issüer.example",
            "issuer..example",
            "-issuer.example",
            "issuer-.example",
            "issuer.example:",
            "issuer.example:65536",
            "issuer.example:port",
            "issuer.example:+1",
            "issuer.example:443:9",
            "[::1",
            "[::1]suffix",
            "[not-ipv6]",
            "issuer.example\r\n",
        ] {
            assert!(CommonChallenge::new(name).is_err(), "accepted {name:?}");
        }
    }
}
