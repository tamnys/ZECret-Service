//! Bounded binary stdin interface for local public verification. No token,
//! issuer key, or request bytes are accepted in arguments or printed.

use std::io::{self, Read, Write};
use zrpc_payment_crypto::{
    AUTHENTICATOR_LEN, TOKEN_INPUT_LEN, blind_token_input, canonicalize_issuer_spki,
    finalize_blind_signature, sign_blinded, verify_authenticator,
};

const OP_VERIFY: u8 = 1;
const OP_BLIND: u8 = 2;
const OP_SIGN: u8 = 3;
const OP_FINALIZE: u8 = 4;
const OP_CANONICALIZE_SPKI: u8 = 5;
const MAGIC: &[u8; 8] = b"ZRPCPC01";

fn read_fixed<const N: usize>(input: &mut impl Read) -> io::Result<[u8; N]> {
    let mut bytes = [0_u8; N];
    input.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn read_bounded(input: &mut impl Read) -> io::Result<Vec<u8>> {
    let length = u16::from_be_bytes(read_fixed::<2>(input)?) as usize;
    if length == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "empty input"));
    }
    let mut bytes = vec![0_u8; length];
    input.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn eof(input: &mut impl Read) -> io::Result<bool> {
    Ok(input.read(&mut [0_u8; 1])? == 0)
}

fn run() -> io::Result<Option<Vec<u8>>> {
    let mut input = io::stdin().lock();
    let header = read_fixed::<9>(&mut input)?;
    if &header[..8] != MAGIC {
        return Ok(None);
    }
    let spki = read_bounded(&mut input)?;
    let result = match header[8] {
        OP_VERIFY => {
            let token_input = read_fixed::<TOKEN_INPUT_LEN>(&mut input)?;
            let authenticator = read_fixed::<AUTHENTICATOR_LEN>(&mut input)?;
            if eof(&mut input)? && verify_authenticator(&spki, &token_input, &authenticator) {
                Some(vec![1])
            } else {
                None
            }
        }
        OP_BLIND => {
            let token_input = read_fixed::<TOKEN_INPUT_LEN>(&mut input)?;
            if !eof(&mut input)? {
                return Ok(None);
            }
            blind_token_input(&spki, &token_input).map(|prepared| {
                let mut output = Vec::with_capacity(2 * AUTHENTICATOR_LEN);
                output.extend_from_slice(&prepared.blinded_message);
                output.extend_from_slice(&prepared.secret);
                output
            })
        }
        OP_SIGN => {
            let issuer_private_der = read_bounded(&mut input)?;
            let blinded_message = read_fixed::<AUTHENTICATOR_LEN>(&mut input)?;
            if !eof(&mut input)? {
                return Ok(None);
            }
            sign_blinded(&spki, &issuer_private_der, &blinded_message).map(Vec::from)
        }
        OP_FINALIZE => {
            let token_input = read_fixed::<TOKEN_INPUT_LEN>(&mut input)?;
            let blinded_message = read_fixed::<AUTHENTICATOR_LEN>(&mut input)?;
            let secret = read_fixed::<AUTHENTICATOR_LEN>(&mut input)?;
            let blind_signature = read_fixed::<AUTHENTICATOR_LEN>(&mut input)?;
            if !eof(&mut input)? {
                return Ok(None);
            }
            finalize_blind_signature(
                &spki,
                &token_input,
                &blinded_message,
                &secret,
                &blind_signature,
            )
            .map(Vec::from)
        }
        OP_CANONICALIZE_SPKI => {
            if !eof(&mut input)? {
                return Ok(None);
            }
            canonicalize_issuer_spki(&spki)
        }
        _ => None,
    };
    Ok(result)
}

fn main() {
    // A caller must treat every nonzero status as denial. No sensitive details
    // enter stdout or stderr, including on malformed or truncated input.
    let Ok(Some(output)) = run() else {
        std::process::exit(1)
    };
    if io::stdout().lock().write_all(&output).is_err() {
        std::process::exit(1)
    }
}
