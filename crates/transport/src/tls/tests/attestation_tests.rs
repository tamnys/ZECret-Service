//! Public HTTP fixtures over genuine local TLS; every quote value is synthetic.

use super::*;
use zrpc_protocol::{
    MAX_ATTESTATION_RESPONSE_BYTES, PublicAttestationRequest, PublicAttestationResponse,
    parse_attestation_request,
};

pub(in crate::tls) async fn read_public_request(
    server: &mut ServerStream<TcpStream>,
) -> PublicAttestationRequest {
    // This fixture observes only the fixed request produced by our typed API.
    // HTTP parsing in production belongs to Hyper, not this observation helper.
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        headers.push(server.read_u8().await.unwrap());
    }
    let text = std::str::from_utf8(&headers).unwrap();
    let mut lines = text.split("\r\n");
    assert_eq!(lines.next(), Some("POST /attestation HTTP/1.1"));
    let mut content_length = None;
    let mut host = None;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').unwrap();
        match name.to_ascii_lowercase().as_str() {
            "host" => host = Some(value.trim()),
            "content-length" => content_length = Some(value.trim().parse::<usize>().unwrap()),
            "content-type" | "accept" => assert_eq!(value.trim(), "application/json"),
            "accept-encoding" => assert_eq!(value.trim(), "identity"),
            other => panic!("unexpected public request header: {other}"),
        }
    }
    assert_eq!(host, Some("unresolved-fixture.invalid:443"));
    let mut body = vec![0; content_length.unwrap()];
    server.read_exact(&mut body).await.unwrap();
    let request = parse_attestation_request(&body).unwrap();
    let object = serde_json::from_slice::<serde_json::Value>(&body).unwrap();
    assert_eq!(object.as_object().unwrap().len(), 1);
    assert!(object.get("nonce").unwrap().is_array());
    request
}

pub(in crate::tls) fn synthetic_body(nonce: [u8; 32]) -> Vec<u8> {
    serde_json::to_vec(&PublicAttestationResponse {
        nonce,
        quote: "00".into(),
        event_log: "[]".into(),
        report_data: "00".repeat(64),
        vm_config: "{}".into(),
    })
    .unwrap()
}

pub(in crate::tls) fn response(status: &str, extra_headers: &str, body: &[u8]) -> Vec<u8> {
    let mut wire = format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{extra_headers}\r\n", body.len()).into_bytes();
    wire.extend_from_slice(body);
    wire
}

async fn exchange_fixture(
    make_response: impl FnOnce([u8; 32]) -> Vec<u8> + Send + 'static,
) -> (
    Result<crate::UnverifiedPublicEvidence, SafeError>,
    tokio::task::JoinHandle<()>,
) {
    let (client, server) = connect_pair(server_config(false, Some(ALPN))).await;
    let pending = client.unwrap().prepare_challenge().unwrap();
    let nonce = *pending.nonce().unwrap();
    let mut server = server.unwrap();
    let peer = tokio::spawn(async move {
        let request = read_public_request(&mut server).await;
        assert_eq!(request.nonce, nonce);
        let wire = make_response(request.nonce);
        // An oversized-response rejection can close while the fixture is writing.
        let _ = server.write_all(&wire).await;
        let _ = server.flush().await;
        assert_no_application_bytes(server).await;
    });
    (pending.request_attestation().await, peer)
}

#[tokio::test]
async fn receives_only_unverified_public_evidence_on_original_tls_session() {
    let (result, peer) =
        exchange_fixture(|nonce| response("200 OK", "", &synthetic_body(nonce))).await;
    let evidence = result.unwrap();
    assert_eq!(evidence.raw_unverified().quote, "00");
    assert!(!evidence.private_rpc_allowed());
    assert!(!format!("{evidence:?}").contains("report_data"));
    // Retained connection stays owned until evidence is dropped, and exposes no
    // operation that could transmit additional application bytes.
    drop(evidence);
    peer.await.unwrap();
}

#[tokio::test]
async fn retains_original_session_binding_inputs_without_accepting_fixture_evidence() {
    let (client, server) = connect_pair(server_config(false, Some(ALPN))).await;
    let client = client.unwrap();
    let established = client.established;
    let pending = client.prepare_challenge().unwrap();
    let nonce = *pending.nonce().unwrap();
    let mut server = server.unwrap();
    let expected = server
        .get_ref()
        .1
        .export_keying_material(
            [0; 64],
            zrpc_protocol::ATTESTATION_EXPORTER_LABEL,
            Some(&nonce),
        )
        .unwrap();
    let peer = tokio::spawn(async move {
        assert_eq!(read_public_request(&mut server).await.nonce, nonce);
        // This remains fake quote material even though the local TLS exporter
        // is real. Matching an unauthenticated report_data string grants nothing.
        let mut body: serde_json::Value = serde_json::from_slice(&synthetic_body(nonce)).unwrap();
        body["report_data"] = expected
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
            .into();
        server
            .write_all(&response("200 OK", "", &serde_json::to_vec(&body).unwrap()))
            .await
            .unwrap();
        server.flush().await.unwrap();
        assert_no_application_bytes(server).await;
    });
    let evidence = pending.request_attestation().await.unwrap();
    evidence.assert_retained_binding_for_test(expected, nonce, established);
    assert!(!evidence.private_rpc_allowed());
    drop(evidence);
    peer.await.unwrap();
}

#[tokio::test]
async fn echoed_nonce_mismatch_is_rejected_without_freshness_claim() {
    let (result, peer) = exchange_fixture(|mut nonce| {
        nonce[0] ^= 1;
        response("200 OK", "", &synthetic_body(nonce))
    })
    .await;
    assert_eq!(result.unwrap_err().code, ErrorCode::InvalidNonce);
    peer.await.unwrap();
}

#[tokio::test]
async fn malformed_duplicate_unknown_and_missing_response_fields_are_rejected() {
    for variant in 0..4 {
        let (result, peer) = exchange_fixture(move |nonce| {
            let mut body = synthetic_body(nonce);
            match variant {
                0 => body = b"not-json".to_vec(),
                1 => body
                    .splice(1..1, b"\"quote\":\"01\",".iter().copied())
                    .for_each(drop),
                2 => body
                    .splice(1..1, b"\"verified\":true,".iter().copied())
                    .for_each(drop),
                3 => {
                    let mut object: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    object.as_object_mut().unwrap().remove("vm_config");
                    body = serde_json::to_vec(&object).unwrap();
                }
                _ => unreachable!(),
            }
            response("200 OK", "", &body)
        })
        .await;
        assert!(result.is_err());
        peer.await.unwrap();
    }
}

#[tokio::test]
async fn redirect_compression_duplicate_type_and_connection_close_are_rejected() {
    for (status, headers) in [
        (
            "307 Temporary Redirect",
            "Location: https://direct.invalid/attestation\r\n",
        ),
        ("200 OK", "Content-Encoding: gzip\r\n"),
        ("200 OK", "Content-Encoding: identity\r\n"),
        ("200 OK", "Content-Type: application/json\r\n"),
        ("200 OK", "Connection: close\r\n"),
    ] {
        let (result, peer) =
            exchange_fixture(move |nonce| response(status, headers, &synthetic_body(nonce))).await;
        assert!(result.is_err());
        peer.await.unwrap();
    }
}

#[tokio::test]
async fn declared_and_streamed_oversized_responses_are_rejected() {
    let (result, peer) = exchange_fixture(|_| {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            MAX_ATTESTATION_RESPONSE_BYTES + 1,
        )
        .into_bytes()
    })
    .await;
    assert_eq!(result.unwrap_err().code, ErrorCode::ResponseTooLarge);
    peer.await.unwrap();

    let (result, peer) = exchange_fixture(|_| {
        let mut wire = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        let length = MAX_ATTESTATION_RESPONSE_BYTES + 1;
        wire.extend_from_slice(format!("{length:x}\r\n").as_bytes());
        wire.resize(wire.len() + length, b' ');
        wire.extend_from_slice(b"\r\n0\r\n\r\n");
        wire
    }).await;
    assert_eq!(result.unwrap_err().code, ErrorCode::ResponseTooLarge);
    peer.await.unwrap();
}

#[tokio::test]
async fn truncated_or_closed_session_never_returns_evidence() {
    for send_prefix in [false, true] {
        let (client, server) = connect_pair(server_config(false, Some(ALPN))).await;
        let pending = client.unwrap().prepare_challenge().unwrap();
        let mut server = server.unwrap();
        let peer = tokio::spawn(async move {
            let _ = read_public_request(&mut server).await;
            if send_prefix {
                server.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 10\r\n\r\n{").await.unwrap();
                server.flush().await.unwrap();
            }
            server.shutdown().await.unwrap();
        });
        assert!(pending.request_attestation().await.is_err());
        peer.await.unwrap();
    }
}

#[tokio::test]
async fn expired_challenge_sends_no_public_request() {
    let (client, server) = connect_pair(server_config(false, Some(ALPN))).await;
    let mut pending = client.unwrap().prepare_challenge().unwrap();
    pending.tls.established = Instant::now() - MAX_CONNECTION_LIFETIME;
    assert_eq!(
        pending.request_attestation().await.unwrap_err().code,
        ErrorCode::StaleNonce
    );
    assert_no_application_bytes(server.unwrap()).await;
}
