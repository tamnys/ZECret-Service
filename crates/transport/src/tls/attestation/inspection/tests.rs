use super::*;
use crate::tls::{
    ALPN,
    tests::{
        assert_no_application_bytes,
        attestation_tests::{read_public_request, response, synthetic_body},
        connect_pair, server_config,
    },
};
#[cfg(unix)]
use crate::{ManagedTor, TransportOrigin};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use zrpc_verifier::{
    ReleasePolicy,
    offline::InspectionStatus,
    workload::{KeyProviderPolicy, StorageFs},
};

#[tokio::test]
async fn synthetic_evidence_and_local_policy_cannot_send_a_private_body() {
    let (evidence, close, peer) = received_fixture().await;
    let error = evidence
        .authorize(b"{}", b"{}", &ReleasePolicy::default())
        .err()
        .expect("empty reviewed catalog must reject");
    assert_eq!(error.code, zrpc_protocol::ErrorCode::TorUnavailable);
    drop(close);
    peer.await.unwrap();

    let (evidence, close, peer) = received_fixture().await;
    let mut policy = ReleasePolicy::default();
    policy.private_mode_enabled = true;
    policy.approved_release_ids.push("SYNTHETIC".into());
    assert!(evidence.authorize(b"{}", b"{}", &policy).is_err());
    drop(close);
    peer.await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn phala_synthetic_session_expiry_prevents_body_read_and_transmission() {
    let (mut evidence, close, peer) = received_fixture().await;
    let (tor, _listener) = ManagedTor::synthetic_live().unwrap();
    evidence._session.origin = TransportOrigin::Managed(tor);
    // Unit-only construction bypasses the empty release catalog to exercise
    // the retained connection guard; it authenticates no synthetic quote.
    let session = VerifiedRpcSession::from_authenticated_inspection(
        evidence._session,
        evidence.deadline,
        evidence.authority,
        PrivateDeadline {
            monotonic: Instant::now() + Duration::from_millis(200),
            collateral_expiration_unix_seconds: u64::MAX,
        },
    )
    .unwrap();
    drop(close);
    tokio::time::sleep(Duration::from_millis(250)).await;
    let mut body_read = false;
    let error = session
        .query_from_body(|| {
            body_read = true;
            Ok(b"SYNTHETIC_PRIVATE_CANARY".to_vec())
        })
        .await
        .unwrap_err();
    assert_eq!(error.code, zrpc_protocol::ErrorCode::ExpiredCollateral);
    assert!(!body_read);
    peer.await.unwrap();
}

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

#[cfg(unix)]
#[tokio::test]
async fn public_preview_rejects_synthetic_quote_before_any_rpc() {
    let (mut evidence, close, peer) = received_fixture().await;
    let (tor, _listener) = ManagedTor::synthetic_live().unwrap();
    evidence._session.origin = TransportOrigin::Managed(tor);
    let (report, session) = evidence.inspect_for_public_preview(b"{}").unwrap();
    assert!(session.is_none());
    assert!(!report.public_preview_passed());
    assert_eq!(report.freshness, InspectionStatus::NotChecked);
    assert_eq!(report.live_key_binding, InspectionStatus::NotChecked);
    assert_eq!(
        report
            .hardware_evidence
            .unwrap()
            .quote
            .hardware_authenticity,
        InspectionStatus::Rejected
    );
    assert!(!report.private_accepted && !report.query_sent);
    drop(close);
    peer.await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn preview_launch_diagnostic_rejects_synthetic_quote_without_workload_or_rpc() {
    let (mut evidence, close, peer) = received_fixture().await;
    let (tor, _listener) = ManagedTor::synthetic_live().unwrap();
    evidence._session.origin = TransportOrigin::Managed(tor);
    let (report, workload) = evidence
        .inspect_public_preview_launch(b"{}", b"{}", &synthetic_policy())
        .unwrap();
    assert!(!report.public_preview_passed());
    assert!(workload.is_none());
    assert!(!report.private_accepted && !report.query_sent);
    drop(close);
    peer.await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn public_preview_rejects_challenge_mismatch_before_quote_and_rpc() {
    let (mut evidence, close, peer) = received_fixture().await;
    let (tor, _listener) = ManagedTor::synthetic_live().unwrap();
    evidence._session.origin = TransportOrigin::Managed(tor);
    evidence.nonce[0] ^= 1;
    let (report, session) = evidence.inspect_for_public_preview(b"{}").unwrap();
    assert!(session.is_none());
    assert_eq!(
        report.issue,
        Some(EndpointInspectionIssue::ChallengeMismatch)
    );
    assert_eq!(report.freshness, InspectionStatus::Rejected);
    assert!(report.hardware_evidence.is_none());
    assert!(!report.public_preview_passed());
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
