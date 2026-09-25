use super::*;
use crate::tls::{
    ALPN,
    tests::{
        assert_no_application_bytes,
        attestation_tests::{read_public_request, response, synthetic_body},
        connect_pair, server_config,
    },
};
use tokio::io::AsyncWriteExt;
use zrpc_verifier::{
    offline::InspectionStatus,
    workload::{KeyProviderPolicy, StorageFs},
};

fn synthetic_policy() -> WorkloadPolicy {
    // Explicit fabricated comparison input only. No release expectation or
    // authentic quote/workload tuple is supplied by this local TLS fixture.
    WorkloadPolicy {
        schema_version: 1,
        mrtd: [0; 48],
        rtmr0: [0; 48],
        rtmr1: [0; 48],
        rtmr2: [0; 48],
        os_image_hash: [0; 32],
        compose_hash: [0; 32],
        mr_kms: [0; 32],
        app_id: [0; 20],
        instance_id: [0; 20],
        storage_fs: StorageFs::Ext4,
        key_provider: KeyProviderPolicy {
            name: "kms".into(),
            id: "POLICY_UNIT_ONLY".into(),
        },
    }
}

async fn received_fixture() -> (
    UnverifiedPublicEvidence,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let (client, server) = connect_pair(server_config(false, Some(ALPN))).await;
    let pending = client.unwrap().prepare_challenge().unwrap();
    let mut server = server.unwrap();
    let (close, should_close) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let nonce = read_public_request(&mut server).await.nonce;
        server
            .write_all(&response("200 OK", "", &synthetic_body(nonce)))
            .await
            .unwrap();
        server.flush().await.unwrap();
        if should_close.await.is_ok() {
            server.shutdown().await.unwrap();
        } else {
            assert_no_application_bytes(server).await;
        }
    });
    (pending.request_attestation().await.unwrap(), close, peer)
}

fn assert_no_private_approval(report: &EndpointInspection) {
    assert!(!report.private_accepted && !report.query_sent);
    assert!(report.network_used);
    assert!(!report.diagnostic_passed());
    assert_eq!(
        report.release_policy_provenance,
        InspectionStatus::NotChecked
    );
    assert_eq!(
        report.approved_workload_ownership,
        InspectionStatus::NotChecked
    );
    assert_eq!(report.freshness, InspectionStatus::NotChecked);
    assert_eq!(report.live_key_binding, InspectionStatus::NotChecked);
}

#[tokio::test]
async fn synthetic_peer_report_data_never_authenticates_or_leaks_into_diagnostic() {
    let (evidence, close, peer) = received_fixture().await;
    let report = evidence.inspect(b"{}", b"{}", &synthetic_policy());
    let inspected = report.evidence.as_ref().unwrap();
    assert_eq!(
        inspected.workload.quote.hardware_authenticity,
        InspectionStatus::Rejected
    );
    assert_eq!(
        inspected.authenticated_report_data_match,
        InspectionStatus::NotChecked
    );
    assert_eq!(report.local_session_lifetime, InspectionStatus::Verified);
    assert_eq!(report.local_clock, InspectionStatus::Verified);
    assert_no_private_approval(&report);
    let json = serde_json::to_string(&report).unwrap();
    assert!(!json.contains("POLICY_UNIT_ONLY") && !json.contains("unresolved-fixture.invalid"));
    drop(close);
    peer.await.unwrap();
}

#[tokio::test]
async fn expired_retained_session_rejects_before_quote_inspection() {
    let (mut evidence, close, peer) = received_fixture().await;
    evidence.established = Instant::now() - MAX_CONNECTION_LIFETIME;
    evidence.deadline = evidence.established + MAX_CONNECTION_LIFETIME;
    let report = evidence.inspect(b"{}", b"{}", &synthetic_policy());
    assert_eq!(
        report.issue,
        Some(EndpointInspectionIssue::ConnectionExpired)
    );
    assert_eq!(report.local_session_lifetime, InspectionStatus::Rejected);
    assert!(report.evidence.is_none());
    assert_no_private_approval(&report);
    drop(close);
    peer.await.unwrap();
}

#[tokio::test]
async fn closed_original_session_rejects_before_quote_inspection() {
    let (mut evidence, close, peer) = received_fixture().await;
    close.send(()).unwrap();
    peer.await.unwrap();
    // Wait for this owned HTTP driver to observe the genuine TLS peer closure.
    (&mut evidence._session.driver).await.unwrap();
    let report = evidence.inspect(b"{}", b"{}", &synthetic_policy());
    assert_eq!(
        report.issue,
        Some(EndpointInspectionIssue::ConnectionClosed)
    );
    assert_eq!(report.session_observed_open, InspectionStatus::Rejected);
    assert!(report.evidence.is_none());
    assert_no_private_approval(&report);
}
