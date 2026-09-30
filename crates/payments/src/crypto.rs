//! Private, bounded frames for the separately locked local cryptography helper.
//! Framing is not authorization: callers must validate the common challenge,
//! issuer key, allowed request, and spent state at their respective boundaries.

use std::{
    fmt, fs,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::Path,
    process::{Command, Stdio},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroize;

use crate::store::SecretBytes;
use crate::wire::{RSA_SIGNATURE_LEN, TOKEN_INPUT_LEN};

const MAGIC: &[u8; 8] = b"ZRPCPC01";
const VERIFY: u8 = 1;
const BLIND: u8 = 2;
const SIGN: u8 = 3;
const FINALIZE: u8 = 4;
const CANONICALIZE_SPKI: u8 = 5;
const CANONICAL_SPKI_LEN: usize = 342;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CryptoFrameError;

impl fmt::Display for CryptoFrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("payment cryptography unavailable")
    }
}

impl std::error::Error for CryptoFrameError {}

pub(crate) struct CryptoFrame {
    bytes: Vec<u8>,
    response_len: usize,
}

impl CryptoFrame {
    fn start(
        operation: u8,
        issuer_spki: &[u8],
        response_len: usize,
    ) -> Result<Self, CryptoFrameError> {
        let length = u16::try_from(issuer_spki.len()).map_err(|_| CryptoFrameError)?;
        if length == 0 {
            return Err(CryptoFrameError);
        }
        let mut bytes = Vec::with_capacity(11 + issuer_spki.len());
        bytes.extend_from_slice(MAGIC);
        bytes.push(operation);
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(issuer_spki);
        Ok(Self {
            bytes,
            response_len,
        })
    }

    pub(crate) fn verify(
        issuer_spki: &[u8],
        signed_input: &[u8],
        authenticator: &[u8],
    ) -> Result<Self, CryptoFrameError> {
        if signed_input.len() != TOKEN_INPUT_LEN || authenticator.len() != RSA_SIGNATURE_LEN {
            return Err(CryptoFrameError);
        }
        let mut frame = Self::start(VERIFY, issuer_spki, 1)?;
        frame.bytes.extend_from_slice(signed_input);
        frame.bytes.extend_from_slice(authenticator);
        Ok(frame)
    }

    pub(crate) fn canonicalize_spki(public_der: &[u8]) -> Result<Self, CryptoFrameError> {
        Self::start(CANONICALIZE_SPKI, public_der, CANONICAL_SPKI_LEN)
    }

    pub(crate) fn blind(issuer_spki: &[u8], signed_input: &[u8]) -> Result<Self, CryptoFrameError> {
        if signed_input.len() != TOKEN_INPUT_LEN {
            return Err(CryptoFrameError);
        }
        let mut frame = Self::start(BLIND, issuer_spki, 2 * RSA_SIGNATURE_LEN)?;
        frame.bytes.extend_from_slice(signed_input);
        Ok(frame)
    }

    pub(crate) fn sign(
        issuer_spki: &[u8],
        issuer_private_der: &[u8],
        blinded_message: &[u8],
    ) -> Result<Self, CryptoFrameError> {
        let private_len = u16::try_from(issuer_private_der.len()).map_err(|_| CryptoFrameError)?;
        if private_len == 0 || blinded_message.len() != RSA_SIGNATURE_LEN {
            return Err(CryptoFrameError);
        }
        let mut frame = Self::start(SIGN, issuer_spki, RSA_SIGNATURE_LEN)?;
        frame.bytes.extend_from_slice(&private_len.to_be_bytes());
        frame.bytes.extend_from_slice(issuer_private_der);
        frame.bytes.extend_from_slice(blinded_message);
        Ok(frame)
    }

    pub(crate) fn finalize(
        issuer_spki: &[u8],
        signed_input: &[u8],
        blinded_message: &[u8],
        blinding_secret: &[u8],
        blind_signature: &[u8],
    ) -> Result<Self, CryptoFrameError> {
        if signed_input.len() != TOKEN_INPUT_LEN
            || blinded_message.len() != RSA_SIGNATURE_LEN
            || blinding_secret.len() != RSA_SIGNATURE_LEN
            || blind_signature.len() != RSA_SIGNATURE_LEN
        {
            return Err(CryptoFrameError);
        }
        let mut frame = Self::start(FINALIZE, issuer_spki, RSA_SIGNATURE_LEN)?;
        frame.bytes.extend_from_slice(signed_input);
        frame.bytes.extend_from_slice(blinded_message);
        frame.bytes.extend_from_slice(blinding_secret);
        frame.bytes.extend_from_slice(blind_signature);
        Ok(frame)
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn expected_response_len(&self) -> usize {
        self.response_len
    }

    pub(crate) fn accept_response(
        &self,
        successful_exit: bool,
        bytes: Vec<u8>,
    ) -> Result<SecretBytes, CryptoFrameError> {
        if !successful_exit
            || bytes.len() != self.response_len
            || (self.bytes[8] == VERIFY && bytes != [1])
        {
            return Err(CryptoFrameError);
        }
        Ok(SecretBytes::new(bytes))
    }
}

/// Run one local helper operation for CLI-side issuance. A child that crashes,
/// prints extra bytes, or exits unsuccessfully cannot yield a usable response.
/// This blocking entrypoint is not suitable for the server's deadline-bound
/// request path; that path needs a cancellable child tied to its TLS deadline.
pub(crate) fn invoke_cli(
    helper: &Path,
    frame: &CryptoFrame,
) -> Result<SecretBytes, CryptoFrameError> {
    if !helper.is_absolute() {
        return Err(CryptoFrameError);
    }
    let metadata = fs::symlink_metadata(helper).map_err(|_| CryptoFrameError)?;
    let owner = rustix::process::geteuid().as_raw();
    if !metadata.is_file()
        || (metadata.uid() != owner && metadata.uid() != 0)
        || metadata.mode() & 0o022 != 0
    {
        return Err(CryptoFrameError);
    }
    let mut child = Command::new(helper)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| CryptoFrameError)?;
    let outcome = (|| {
        child
            .stdin
            .take()
            .ok_or(CryptoFrameError)?
            .write_all(frame.as_bytes())
            .map_err(|_| CryptoFrameError)?;
        let mut output = Vec::new();
        child
            .stdout
            .take()
            .ok_or(CryptoFrameError)?
            .take((frame.expected_response_len() + 1) as u64)
            .read_to_end(&mut output)
            .map_err(|_| CryptoFrameError)?;
        if output.len() != frame.expected_response_len() {
            return Err(CryptoFrameError);
        }
        let status = child.wait().map_err(|_| CryptoFrameError)?;
        frame.accept_response(status.success(), output)
    })();
    if outcome.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    outcome
}

/// Deadline-bound helper operation for an RPC connection. Dropping the future
/// kills the child, so an expired verification cannot later admit a ticket.
pub(crate) async fn invoke_rpc(
    helper: &Path,
    frame: &CryptoFrame,
) -> Result<SecretBytes, CryptoFrameError> {
    if !helper.is_absolute() {
        return Err(CryptoFrameError);
    }
    let metadata = fs::symlink_metadata(helper).map_err(|_| CryptoFrameError)?;
    let owner = rustix::process::geteuid().as_raw();
    if !metadata.is_file()
        || (metadata.uid() != owner && metadata.uid() != 0)
        || metadata.mode() & 0o022 != 0
    {
        return Err(CryptoFrameError);
    }
    let mut child = tokio::process::Command::new(helper)
        .env_clear()
        .current_dir("/")
        .kill_on_drop(true)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| CryptoFrameError)?;
    let outcome = async {
        child
            .stdin
            .take()
            .ok_or(CryptoFrameError)?
            .write_all(frame.as_bytes())
            .await
            .map_err(|_| CryptoFrameError)?;
        let mut output = Vec::new();
        child
            .stdout
            .take()
            .ok_or(CryptoFrameError)?
            .take((frame.expected_response_len() + 1) as u64)
            .read_to_end(&mut output)
            .await
            .map_err(|_| CryptoFrameError)?;
        if output.len() != frame.expected_response_len() {
            return Err(CryptoFrameError);
        }
        let status = child.wait().await.map_err(|_| CryptoFrameError)?;
        frame.accept_response(status.success(), output)
    }
    .await;
    if outcome.is_err() {
        let _ = child.kill().await;
    }
    outcome
}

impl fmt::Debug for CryptoFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CryptoFrame([redacted])")
    }
}

impl Drop for CryptoFrame {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn frames_match_the_helper_protocol_and_reject_bad_lengths() {
        let spki = [3_u8; 342];
        let input = [4_u8; TOKEN_INPUT_LEN];
        let rsa = [5_u8; RSA_SIGNATURE_LEN];
        let verify = CryptoFrame::verify(&spki, &input, &rsa).unwrap();
        assert_eq!(&verify.as_bytes()[..11], b"ZRPCPC01\x01\x01\x56");
        assert_eq!(verify.as_bytes().len(), 11 + 342 + 98 + 256);
        assert_eq!(verify.expected_response_len(), 1);
        assert!(verify.accept_response(true, vec![1]).is_ok());
        assert!(verify.accept_response(true, Vec::new()).is_err());
        assert!(verify.accept_response(true, vec![0]).is_err());
        assert!(verify.accept_response(false, vec![1]).is_err());

        let blind = CryptoFrame::blind(&spki, &input).unwrap();
        assert_eq!(blind.as_bytes()[8], BLIND);
        assert_eq!(blind.expected_response_len(), 512);
        assert!(blind.accept_response(true, vec![0; 512]).is_ok());
        assert!(blind.accept_response(true, vec![0; 511]).is_err());

        let sign = CryptoFrame::sign(&spki, &[7; 1190], &rsa).unwrap();
        assert_eq!(sign.as_bytes()[8], SIGN);
        assert_eq!(&sign.as_bytes()[353..355], &1190_u16.to_be_bytes());
        assert_eq!(sign.expected_response_len(), 256);

        let finalize = CryptoFrame::finalize(&spki, &input, &rsa, &rsa, &rsa).unwrap();
        assert_eq!(finalize.as_bytes()[8], FINALIZE);
        assert_eq!(finalize.as_bytes().len(), 11 + 342 + 98 + 256 * 3);

        assert!(CryptoFrame::blind(&[], &input).is_err());
        let normalize = CryptoFrame::canonicalize_spki(&spki).unwrap();
        assert_eq!(normalize.as_bytes()[8], CANONICALIZE_SPKI);
        assert_eq!(normalize.expected_response_len(), CANONICAL_SPKI_LEN);
        assert!(CryptoFrame::blind(&spki, &input[..97]).is_err());
        assert!(CryptoFrame::sign(&spki, &[], &rsa).is_err());
        assert!(CryptoFrame::sign(&spki, &[7], &rsa[..255]).is_err());
        assert_eq!(format!("{sign:?}"), "CryptoFrame([redacted])");
        assert!(invoke_cli(Path::new("relative-helper"), &verify).is_err());
        // An unrelated successful executable cannot attest token validity.
        assert!(invoke_cli(Path::new("/usr/bin/true"), &verify).is_err());
    }

    #[test]
    #[ignore = "requires the separately locked helper binary built in the managed container"]
    fn rfc9578_vector_crosses_the_local_process_boundary() {
        let helper = PathBuf::from(
            std::env::var_os("ZRPC_PAYMENT_CRYPTO_HELPER")
                .expect("set ZRPC_PAYMENT_CRYPTO_HELPER to the separately built helper executable"),
        );
        let fixture =
            include_str!("../../../tools/payment-crypto/tests/rfc9578_public_vector.json");
        let decode = |name: &str| -> Vec<u8> {
            let prefix = format!("\"{name}\": \"");
            let start = fixture.find(&prefix).expect("RFC field present") + prefix.len();
            let value = fixture[start..]
                .split('"')
                .next()
                .expect("RFC field quoted");
            value
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| {
                    u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16)
                        .expect("RFC hexadecimal")
                })
                .collect()
        };
        let spki = decode("pkI");
        let token = decode("token");
        let verify =
            CryptoFrame::verify(&spki, &token[..TOKEN_INPUT_LEN], &token[TOKEN_INPUT_LEN..])
                .unwrap();
        assert_eq!(invoke_cli(&helper, &verify).unwrap().expose(), &[1]);
        let mut altered = token;
        altered[34] ^= 1;
        let verify = CryptoFrame::verify(
            &spki,
            &altered[..TOKEN_INPUT_LEN],
            &altered[TOKEN_INPUT_LEN..],
        )
        .unwrap();
        assert!(invoke_cli(&helper, &verify).is_err());
        let blind = CryptoFrame::blind(&spki, &altered[..TOKEN_INPUT_LEN]).unwrap();
        assert_eq!(invoke_cli(&helper, &blind).unwrap().expose().len(), 512);
    }
}
