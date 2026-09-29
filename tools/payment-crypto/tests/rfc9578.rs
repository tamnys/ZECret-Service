use blind_rsa_signatures::{
    DefaultRng, KeyPairSha384PSSDeterministic, PublicKeySha384PSSDeterministic, Signature,
};
use serde_json::Value;
use std::{
    io::Write,
    process::{Command, Output, Stdio},
};
use zrpc_payment_crypto::{
    AUTHENTICATOR_LEN, TOKEN_INPUT_LEN, blind_token_input, finalize_blind_signature, sign_blinded,
    verify_authenticator,
};

fn decode(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn field<'a>(fields: &'a Value, name: &str) -> &'a str {
    fields[name].as_str().unwrap()
}

fn helper_call(operation: u8, spki: &[u8], payload: &[u8], tail: &[u8]) -> Output {
    let mut process = Command::new(env!("CARGO_BIN_EXE_zrpc-payment-crypto"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut input = process.stdin.take().unwrap();
        input.write_all(b"ZRPCPC01").unwrap();
        input.write_all(&[operation]).unwrap();
        input
            .write_all(&u16::try_from(spki.len()).unwrap().to_be_bytes())
            .unwrap();
        input.write_all(spki).unwrap();
        input.write_all(payload).unwrap();
        input.write_all(tail).unwrap();
    }
    process.wait_with_output().unwrap()
}

#[test]
fn rfc9578_public_token_vector_one_verifies() {
    let vector: Value =
        serde_json::from_slice(include_bytes!("rfc9578_public_vector.json")).unwrap();
    let fields = &vector["fields"];
    let spki = decode(field(fields, "pkI"));
    let token = decode(field(fields, "token"));
    let challenge = decode(field(fields, "token_challenge"));
    assert_eq!(spki.len(), 342);
    assert_eq!(token.len(), 354);
    assert_eq!(&token[..2], &[0, 2]);
    assert_eq!(challenge.len(), 67);

    let issuer = PublicKeySha384PSSDeterministic::from_spki(&spki).unwrap();
    assert_eq!(issuer.to_spki().unwrap(), spki);
    let signature = Signature(token[98..].to_vec());
    issuer.verify(&signature, None, &token[..98]).unwrap();
    assert_eq!(token[..TOKEN_INPUT_LEN].len(), TOKEN_INPUT_LEN);
    assert_eq!(token[TOKEN_INPUT_LEN..].len(), AUTHENTICATOR_LEN);
    assert!(verify_authenticator(
        &spki,
        &token[..TOKEN_INPUT_LEN],
        &token[TOKEN_INPUT_LEN..],
    ));
    let mut alternate_spki = spki.clone();
    alternate_spki.push(0);
    assert!(!verify_authenticator(
        &alternate_spki,
        &token[..TOKEN_INPUT_LEN],
        &token[TOKEN_INPUT_LEN..],
    ));
    let valid = helper_call(1, &spki, &token, &[]);
    assert!(valid.status.success());
    assert_eq!(valid.stdout, [1]);
    assert!(valid.stderr.is_empty());

    let mut changed_input = token[..98].to_vec();
    changed_input[34] ^= 1;
    assert!(issuer.verify(&signature, None, &changed_input).is_err());
    assert!(!verify_authenticator(&spki, &changed_input, &token[98..]));
    let mut changed_token = token.clone();
    changed_token[34] ^= 1;
    let invalid = helper_call(1, &spki, &changed_token, &[]);
    assert!(!invalid.status.success());
    assert!(invalid.stdout.is_empty() && invalid.stderr.is_empty());
    assert!(!helper_call(1, &spki, &token, &[0]).status.success());
    let mut changed_signature = token[98..].to_vec();
    changed_signature[0] ^= 1;
    assert!(
        issuer
            .verify(&Signature(changed_signature), None, &token[..98])
            .is_err()
    );
    assert!(!verify_authenticator(
        &spki,
        &token[..98],
        &[0_u8; AUTHENTICATOR_LEN]
    ));
    let other_key = KeyPairSha384PSSDeterministic::generate(&mut DefaultRng, 2048).unwrap();
    assert!(other_key.pk.verify(&signature, None, &token[..98]).is_err());
    assert!(!verify_authenticator(
        &other_key.pk.to_spki().unwrap(),
        &token[..98],
        &token[98..],
    ));
}

#[test]
fn blind_sign_finalize_round_trip_and_wrong_key_rejection() {
    let vector: Value =
        serde_json::from_slice(include_bytes!("rfc9578_public_vector.json")).unwrap();
    let input = decode(field(&vector["fields"], "token"));
    let input = &input[..TOKEN_INPUT_LEN];
    let issuer = KeyPairSha384PSSDeterministic::generate(&mut DefaultRng, 2048).unwrap();
    let other = KeyPairSha384PSSDeterministic::generate(&mut DefaultRng, 2048).unwrap();
    let spki = issuer.pk.to_spki().unwrap();
    let secret_der = issuer.sk.to_der().unwrap();
    let prepared = blind_token_input(&spki, input).unwrap();
    assert_eq!(format!("{prepared:?}"), "PreparedBlind([redacted])");
    assert!(blind_token_input(&spki, &input[..97]).is_none());
    let mut wrong_type = input.to_vec();
    wrong_type[1] = 1;
    assert!(blind_token_input(&spki, &wrong_type).is_none());
    let blind_signature = sign_blinded(&spki, &secret_der, &prepared.blinded_message).unwrap();
    assert!(
        sign_blinded(
            &other.pk.to_spki().unwrap(),
            &secret_der,
            &prepared.blinded_message
        )
        .is_none()
    );
    let signature = finalize_blind_signature(
        &spki,
        input,
        &prepared.blinded_message,
        &prepared.secret,
        &blind_signature,
    )
    .unwrap();
    assert!(verify_authenticator(&spki, input, &signature));
    let mut wrong_input = input.to_vec();
    wrong_input[34] ^= 1;
    assert!(
        finalize_blind_signature(
            &spki,
            &wrong_input,
            &prepared.blinded_message,
            &prepared.secret,
            &blind_signature,
        )
        .is_none()
    );
    assert!(!verify_authenticator(
        &other.pk.to_spki().unwrap(),
        input,
        &signature
    ));

    let blinded = helper_call(2, &spki, input, &[]);
    assert!(blinded.status.success());
    assert_eq!(blinded.stdout.len(), 2 * AUTHENTICATOR_LEN);
    assert!(blinded.stderr.is_empty());
    let mut sign_payload = Vec::new();
    sign_payload.extend_from_slice(&u16::try_from(secret_der.len()).unwrap().to_be_bytes());
    sign_payload.extend_from_slice(&secret_der);
    sign_payload.extend_from_slice(&blinded.stdout[..AUTHENTICATOR_LEN]);
    let signed = helper_call(3, &spki, &sign_payload, &[]);
    assert!(signed.status.success());
    assert_eq!(signed.stdout.len(), AUTHENTICATOR_LEN);
    assert!(signed.stderr.is_empty());
    let mut finalize_payload = Vec::new();
    finalize_payload.extend_from_slice(input);
    finalize_payload.extend_from_slice(&blinded.stdout);
    finalize_payload.extend_from_slice(&signed.stdout);
    let finalized = helper_call(4, &spki, &finalize_payload, &[]);
    assert!(finalized.status.success());
    assert_eq!(finalized.stdout.len(), AUTHENTICATOR_LEN);
    assert!(finalized.stderr.is_empty());
    let mut token = input.to_vec();
    token.extend_from_slice(&finalized.stdout);
    let redeemed = helper_call(1, &spki, &token, &[]);
    assert!(redeemed.status.success());
    assert_eq!(redeemed.stdout, [1]);
    assert!(redeemed.stderr.is_empty());
    let mut wrong_signature = finalize_payload;
    *wrong_signature.last_mut().unwrap() ^= 1;
    let failed = helper_call(4, &spki, &wrong_signature, &[]);
    assert!(!failed.status.success());
    assert!(failed.stdout.is_empty() && failed.stderr.is_empty());
}
