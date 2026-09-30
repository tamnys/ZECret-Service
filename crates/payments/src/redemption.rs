//! Local signature verification and atomic admission for type-2 tickets.

use std::{fmt, path::PathBuf, sync::Mutex};
use tokio::time::Instant;

use crate::{
    crypto::{CryptoFrame, invoke_rpc},
    http::parse_authorization,
    issuance::IssuerPublic,
    store::{Admission, RedeemerStore},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedemptionError;

impl fmt::Display for RedemptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("payment redemption unavailable")
    }
}

impl std::error::Error for RedemptionError {}

/// A single shared issuer configuration and spent database for an accepting
/// testnet service. All instances that accept this challenge must share the
/// same durable spent state; disk rollback is outside the POC threat model.
pub struct Redeemer {
    issuer: IssuerPublic,
    helper: PathBuf,
    spent: Mutex<RedeemerStore>,
}

impl Redeemer {
    pub fn new(issuer: IssuerPublic, helper: PathBuf, spent: RedeemerStore) -> Self {
        Self {
            issuer,
            helper,
            spent: Mutex::new(spent),
        }
    }

    /// The caller must validate the allowed request before this call. Signature
    /// verification completes before the spent marker is committed; the caller
    /// may forward to the node only on `Accepted`. A node error still consumes
    /// the credit. Timeout or helper failure admits nothing.
    pub async fn redeem(
        &self,
        authorization: &[u8],
        deadline: Instant,
    ) -> Result<Admission, RedemptionError> {
        let token = parse_authorization(
            authorization,
            self.issuer.challenge.as_bytes(),
            self.issuer.key_id,
        )
        .map_err(|_| RedemptionError)?;
        let frame = CryptoFrame::verify(
            &self.issuer.spki,
            token.signed_input(),
            token.authenticator(),
        )
        .map_err(|_| RedemptionError)?;
        tokio::time::timeout_at(deadline, invoke_rpc(&self.helper, &frame))
            .await
            .map_err(|_| RedemptionError)?
            .map_err(|_| RedemptionError)?;
        if Instant::now() >= deadline {
            return Err(RedemptionError);
        }
        let mut spent = self.spent.lock().map_err(|_| RedemptionError)?;
        spent
            .admit_verified(self.issuer.key_id, token.marker())
            .map_err(|_| RedemptionError)
    }
}

impl fmt::Debug for Redeemer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Redeemer([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        http::format_authorization,
        issuance::{
            collect_purchase, load_private_key_file, mock_settle_purchase, prepare_purchase,
        },
        store::{ClientStore, IssuerStore, PrivateDirectory},
    };
    use std::{
        fs,
        process::{Command, Stdio},
        time::Duration,
    };

    #[tokio::test]
    #[ignore = "requires OpenSSL and the separately locked helper in the managed container"]
    async fn verifies_once_and_rejects_replay_after_restart() {
        let helper = PathBuf::from(
            std::env::var_os("ZRPC_PAYMENT_CRYPTO_HELPER")
                .expect("set ZRPC_PAYMENT_CRYPTO_HELPER to the helper executable"),
        );
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).unwrap();
        let root = std::env::temp_dir().join(format!(
            "zrpc-payment-redeem-{}-{}",
            std::process::id(),
            u128::from_be_bytes(random)
        ));
        PrivateDirectory::create(&root).unwrap();
        let private_key = root.join("private.der");
        let public_key = root.join("public.der");
        assert!(
            Command::new("openssl")
                .args([
                    "genpkey",
                    "-algorithm",
                    "RSA",
                    "-pkeyopt",
                    "rsa_keygen_bits:2048",
                    "-outform",
                    "DER",
                    "-out"
                ])
                .arg(&private_key)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("openssl")
                .args(["pkey", "-inform", "DER", "-in"])
                .arg(&private_key)
                .args(["-pubout", "-outform", "DER", "-out"])
                .arg(&public_key)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success()
        );
        let issuer = IssuerPublic::from_public_der(
            &helper,
            &fs::read(&public_key).unwrap(),
            "issuer.example",
        )
        .unwrap();
        let client_dir = PrivateDirectory::create(&root.join("client")).unwrap();
        let issuer_dir = PrivateDirectory::create(&root.join("issuer")).unwrap();
        let redeemer_dir = PrivateDirectory::create(&root.join("redeemer")).unwrap();
        PrivateDirectory::create(&root.join("exchange")).unwrap();
        let request = root.join("exchange/request.bin");
        let response = root.join("exchange/response.bin");
        let mut client = ClientStore::create(&client_dir).unwrap();
        let id = prepare_purchase(&mut client, &issuer, &helper, 1, &request).unwrap();
        let mut operator = IssuerStore::create(&issuer_dir).unwrap();
        mock_settle_purchase(
            &mut operator,
            &issuer,
            &helper,
            &load_private_key_file(&private_key).unwrap(),
            1,
            &request,
            &response,
        )
        .unwrap();
        collect_purchase(&mut client, &issuer, &helper, id, &response).unwrap();
        let ticket = client.take_available_if(|_| Ok(())).unwrap().unwrap();
        let authorization = format_authorization(
            ticket.token.expose(),
            issuer.challenge.as_bytes(),
            issuer.key_id,
        )
        .unwrap();
        let header = authorization.as_bytes().to_vec();
        let spent = RedeemerStore::create(&redeemer_dir).unwrap();
        let redeemer = Redeemer::new(issuer, helper.clone(), spent);
        // Matches the existing verified connection's 300-second lifetime.
        let deadline = Instant::now() + Duration::from_secs(300);
        let (first, second) = tokio::join!(
            redeemer.redeem(&header, deadline),
            redeemer.redeem(&header, deadline)
        );
        assert_eq!(
            [first.unwrap(), second.unwrap()]
                .iter()
                .filter(|admission| **admission == Admission::Accepted)
                .count(),
            1
        );
        drop(redeemer);
        let issuer = IssuerPublic::from_public_der(
            &helper,
            &fs::read(&public_key).unwrap(),
            "issuer.example",
        )
        .unwrap();
        let reopened = Redeemer::new(issuer, helper, RedeemerStore::open(&redeemer_dir).unwrap());
        assert_eq!(
            reopened.redeem(&header, deadline).await.unwrap(),
            Admission::Replay
        );
        let mut altered = ticket.token.expose().to_vec();
        *altered.last_mut().unwrap() ^= 1;
        let invalid = format_authorization(
            &altered,
            reopened.issuer.challenge.as_bytes(),
            reopened.issuer.key_id,
        )
        .unwrap();
        assert!(reopened.redeem(invalid.as_bytes(), deadline).await.is_err());
        drop(reopened);
        drop(client);
        drop(operator);
        fs::remove_dir_all(&root).unwrap();
    }
}
