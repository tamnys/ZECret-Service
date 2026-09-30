//! GCP evidence can authorize only the connection that produced its exporter.
use super::{
    EndpointInspection, EndpointInspectionIssue, PrivateDeadline, UnverifiedGcpEvidence,
    VerifiedRpcSession,
};
use crate::tls::MAX_CONNECTION_LIFETIME;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use zrpc_protocol::{Backend, ErrorCode, GcpAttestationResponse, SafeError};
use zrpc_verifier::{
    ApprovedRelease, ReleasePolicy,
    gcp::{GcpWorkloadPolicy, inspect_gcp_workload_and_report_data},
    offline::InspectionStatus,
};

impl UnverifiedGcpEvidence {
    pub fn raw_unverified(&self) -> &GcpAttestationResponse {
        &self.evidence
    }
    pub fn private_rpc_allowed(&self) -> bool {
        false
    }

    /// Diagnostic policies can describe expected measurements but cannot grant
    /// release approval. Consuming this value also closes the original socket.
    pub fn inspect(self, collateral: &[u8], policy: &GcpWorkloadPolicy) -> EndpointInspection {
        self.inspect_against(collateral, policy)
    }

    pub fn authorize(
        self,
        collateral: &[u8],
        selection: &ReleasePolicy,
    ) -> Result<VerifiedRpcSession, SafeError> {
        self.connection.session.origin.require_managed()?;
        let releases = ApprovedRelease::selected(selection)?;
        if !releases
            .iter()
            .any(|release| release.backend() == Backend::GcpTdx)
        {
            return Err(SafeError::new(
                ErrorCode::UnknownRelease,
                "This client has no selected reviewed GCP release.",
            ));
        }
        let collateral_deadline = releases.iter().find_map(|release| {
            release.gcp_workload().and_then(|policy| {
                let report = self.inspect_against_with_release(collateral, policy, Some(release));
                (report.diagnostic_passed()
                    && report
                        .gcp_evidence
                        .as_ref()
                        .is_some_and(|evidence| evidence.private_acceptance_ready()))
                .then_some(report.private_collateral_deadline)
                .flatten()
            })
        });
        let Some(collateral_deadline) = collateral_deadline else {
            return Err(SafeError::new(
                ErrorCode::PrivateModeUnavailable,
                "Hardware, workload, provenance, freshness or live TLS key did not match a reviewed release.",
            ));
        };
        VerifiedRpcSession::from_authenticated_inspection(
            self.connection.session,
            self.connection.deadline,
            self.connection.authority,
            collateral_deadline,
        )
    }

    fn inspect_against(&self, collateral: &[u8], policy: &GcpWorkloadPolicy) -> EndpointInspection {
        self.inspect_against_with_release(collateral, policy, None)
    }

    fn inspect_against_with_release(
        &self,
        collateral: &[u8],
        policy: &GcpWorkloadPolicy,
        release: Option<&ApprovedRelease>,
    ) -> EndpointInspection {
        let mut report = EndpointInspection::new();
        report.platform = Backend::GcpTdx;
        self.check_session(&mut report);
        if report.issue.is_some() {
            return report;
        }
        let before = SystemTime::now();
        let Ok(before_unix) = before.duration_since(UNIX_EPOCH) else {
            report.local_clock = InspectionStatus::Rejected;
            report.issue = Some(EndpointInspectionIssue::ClockUnavailable);
            return report;
        };
        report.local_clock = InspectionStatus::Verified;
        if self.evidence.nonce != self.connection.nonce {
            report.issue = Some(EndpointInspectionIssue::ChallengeMismatch);
            return report;
        }
        let (Ok(quote), Ok(ccel)) = (
            hex::decode(&self.evidence.quote),
            hex::decode(&self.evidence.ccel),
        ) else {
            report.issue = Some(EndpointInspectionIssue::MalformedQuoteEncoding);
            return report;
        };
        report.gcp_evidence = Some(match release {
            Some(release) => {
                let Some(inspection) = release.inspect_gcp_evidence(
                    &quote,
                    collateral,
                    &ccel,
                    &self.connection.expected_report_data,
                ) else {
                    return report;
                };
                inspection
            }
            None => inspect_gcp_workload_and_report_data(
                &quote,
                collateral,
                &ccel,
                policy,
                &self.connection.expected_report_data,
            ),
        });
        self.check_session(&mut report);
        let after_instant = Instant::now();
        let after = SystemTime::now();
        let Ok(after_unix) = after.duration_since(UNIX_EPOCH) else {
            report.local_clock = InspectionStatus::Rejected;
            report.issue = Some(EndpointInspectionIssue::ClockUnavailable);
            return report;
        };
        let inspection = &report.gcp_evidence.as_ref().unwrap().workload.quote;
        match inspection.checked_at_unix_seconds {
            None => {
                report.local_clock = InspectionStatus::Rejected;
                report.issue = Some(EndpointInspectionIssue::ClockUnavailable);
            }
            Some(checked)
                if after < before
                    || checked < before_unix.as_secs()
                    || checked > after_unix.as_secs() =>
            {
                report.local_clock = InspectionStatus::Rejected;
                report.issue = Some(EndpointInspectionIssue::ClockChangedDuringInspection);
            }
            _ => {
                if let Some(expiration) = inspection.collateral_earliest_expiration_unix_seconds {
                    match PrivateDeadline::from_inspection_snapshot(
                        expiration,
                        after,
                        after_instant,
                    ) {
                        Some(deadline) => report.private_collateral_deadline = Some(deadline),
                        None => {
                            report.issue.get_or_insert(
                                EndpointInspectionIssue::CollateralExpiredDuringInspection,
                            );
                        }
                    }
                }
            }
        }
        report
    }

    fn check_session(&self, report: &mut EndpointInspection) {
        let now = Instant::now();
        if now >= self.connection.deadline
            || now
                .checked_duration_since(self.connection.established)
                .is_none_or(|age| age >= MAX_CONNECTION_LIFETIME)
        {
            report.local_session_lifetime = InspectionStatus::Rejected;
            report
                .issue
                .get_or_insert(EndpointInspectionIssue::ConnectionExpired);
        } else {
            report.local_session_lifetime = InspectionStatus::Verified;
        }
        if self.connection.session.sender.is_closed()
            || self.connection.session.driver.is_finished()
        {
            report.session_observed_open = InspectionStatus::Rejected;
            report
                .issue
                .get_or_insert(EndpointInspectionIssue::ConnectionClosed);
        } else {
            report.session_observed_open = InspectionStatus::Verified;
        }
    }
}

#[cfg(test)]
mod tests {
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn fixture(
        body: impl FnOnce([u8; 32]) -> Vec<u8> + Send + 'static,
    ) -> (
        Result<UnverifiedGcpEvidence, SafeError>,
        tokio::task::JoinHandle<()>,
    ) {
        let (client, server) = connect_pair(server_config(false, Some(ALPN))).await;
        let pending = client.unwrap().prepare_challenge().unwrap();
        let mut server = server.unwrap();
        let task = tokio::spawn(async move {
            let nonce = read_public_request(&mut server).await.nonce;
            server
                .write_all(&response("200 OK", "", &body(nonce)))
                .await
                .unwrap();
            server.flush().await.unwrap();
            assert_no_application_bytes(server).await;
        });
        (pending.request_gcp_attestation().await, task)
    }

    fn body(nonce: [u8; 32]) -> Vec<u8> {
        serde_json::to_vec(&GcpAttestationResponse {
            schema_version: 1,
            platform: Backend::GcpTdx,
            nonce,
            quote: "00".into(),
            ccel: "00".into(),
        })
        .unwrap()
    }

    #[tokio::test]
    async fn gcp_rejects_phala_and_replayed_nonce_without_private_bytes() {
        let (result, peer) = fixture(synthetic_body).await;
        assert!(result.is_err());
        peer.await.unwrap();
        let (result, peer) = fixture(|mut nonce| {
            nonce[0] ^= 1;
            body(nonce)
        })
        .await;
        assert_eq!(result.unwrap_err().code, ErrorCode::InvalidNonce);
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn gcp_fixture_cannot_authorize_retained_sender() {
        let (result, peer) = fixture(body).await;
        let evidence = result.unwrap();
        assert!(!evidence.private_rpc_allowed());
        assert_eq!(
            evidence
                .authorize(b"{}", &ReleasePolicy::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::TorUnavailable
        );
        peer.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn synthetic_gcp_retained_sender_uses_one_tls_stream_for_typed_rpc() {
        for (oversized_result, paid) in [(false, false), (true, false), (false, true), (true, true)]
        {
            let (client, server) = connect_pair(server_config(false, Some(ALPN))).await;
            let pending = client.unwrap().prepare_challenge().unwrap();
            let mut server = server.unwrap();
            let (test_promotion, mut wait_for_test_promotion) = tokio::sync::oneshot::channel();
            let (ready, server_ready) = tokio::sync::oneshot::channel();
            let peer = tokio::spawn(async move {
                let nonce = read_public_request(&mut server).await.nonce;
                server
                    .write_all(&response("200 OK", "", &body(nonce)))
                    .await
                    .unwrap();
                server.flush().await.unwrap();
                // The unverified evidence has no RPC sender. Do not let the
                // fixture start reading an RPC until the test-only constructor
                // has made a session; any earlier application byte is a bug.
                tokio::select! {
                    biased;
                    received = server.read_u8() => panic!("private byte before test promotion: {received:?}"),
                    promoted = &mut wait_for_test_promotion => promoted.unwrap(),
                }
                ready.send(()).unwrap();

                let mut headers = Vec::new();
                while !headers.ends_with(b"\r\n\r\n") {
                    headers.push(server.read_u8().await.unwrap());
                    assert!(headers.len() <= zrpc_protocol::MAX_REQUEST_BYTES);
                }
                let headers = std::str::from_utf8(&headers).unwrap();
                assert!(headers.starts_with("POST /rpc HTTP/1.1\r\n"));
                let authorization: Vec<_> = headers
                    .split("\r\n")
                    .filter(|line| line.to_ascii_lowercase().starts_with("authorization: "))
                    .collect();
                if paid {
                    assert_eq!(
                        authorization,
                        ["authorization: PrivateToken token=\"synthetic\""]
                    );
                } else {
                    assert!(authorization.is_empty());
                }
                let lengths: Vec<usize> = headers
                    .split("\r\n")
                    .filter_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .and_then(|value| value.parse().ok())
                    })
                    .collect();
                let [length] = lengths.as_slice() else {
                    panic!("one RPC content length required");
                };
                assert!(*length <= zrpc_protocol::MAX_REQUEST_BYTES);
                let mut private_body = vec![0; *length];
                server.read_exact(&mut private_body).await.unwrap();
                let request: serde_json::Value = serde_json::from_slice(&private_body).unwrap();
                assert_eq!(
                    request,
                    serde_json::json!({"jsonrpc":"2.0","id":"synthetic-id","method":"getblockcount","params":[]})
                );
                let response = if oversized_result {
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                        zrpc_protocol::MAX_RESPONSE_BYTES + 1
                    )
                    .into_bytes()
                } else {
                    response(
                        "200 OK",
                        "",
                        br#"{"jsonrpc":"2.0","id":"synthetic-id","result":42}"#,
                    )
                };
                server.write_all(&response).await.unwrap();
                server.flush().await.unwrap();
                assert_no_application_bytes(server).await;
            });

            let mut evidence = pending.request_gcp_attestation().await.unwrap();
            assert!(!evidence.private_rpc_allowed());
            let (tor, _listener) = ManagedTor::synthetic_live().unwrap();
            // The real GCP authorization path remains unreachable. This
            // test-only constructor exercises the retained sender with a fake
            // quote and fake Tor lease; it grants no release approval.
            evidence.connection.session.origin = TransportOrigin::Managed(tor);
            let session = VerifiedRpcSession::from_authenticated_inspection(
                evidence.connection.session,
                evidence.connection.deadline,
                evidence.connection.authority,
                PrivateDeadline {
                    monotonic: Instant::now() + MAX_CONNECTION_LIFETIME,
                    collateral_expiration_unix_seconds: u64::MAX,
                },
            )
            .unwrap();
            test_promotion.send(()).unwrap();
            server_ready.await.unwrap();
            let claimed = std::cell::Cell::new(false);
            let released = std::cell::Cell::new(false);
            let result = if paid {
                session
                    .query_from_body_authorized(
                        || async {
                            Ok(br#"{"jsonrpc":"2.0","id":"synthetic-id","method":"getblockcount","params":[]}"#.to_vec())
                        },
                        || {
                            Ok((b"PrivateToken token=\"synthetic\"".to_vec(), (), || {
                                claimed.set(true);
                                Ok(|| {
                                    released.set(true);
                                    Ok(())
                                })
                            }))
                        },
                    )
                    .await
                    .map(|(value, ())| value)
            } else {
                session
                    .query_from_body(|| {
                        Ok(br#"{"jsonrpc":"2.0","id":"synthetic-id","method":"getblockcount","params":[]}"#.to_vec())
                    })
                    .await
            };
            assert_eq!(claimed.get(), paid);
            assert!(!released.get());
            if oversized_result {
                assert_eq!(result.unwrap_err().code, ErrorCode::InvalidBackendResponse);
            } else {
                assert_eq!(result.unwrap(), serde_json::json!(42));
            }
            peer.await.unwrap();
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn gcp_synthetic_session_expiry_prevents_body_read_and_transmission() {
        let (result, peer) = fixture(body).await;
        let mut evidence = result.unwrap();
        let (tor, _listener) = ManagedTor::synthetic_live().unwrap();
        evidence.connection.session.origin = TransportOrigin::Managed(tor);
        // Unit-only construction bypasses the empty release catalog to test
        // the retained sender. No synthetic quote becomes accepted evidence.
        let session = VerifiedRpcSession::from_authenticated_inspection(
            evidence.connection.session,
            evidence.connection.deadline,
            evidence.connection.authority,
            PrivateDeadline {
                monotonic: Instant::now() + Duration::from_millis(200),
                collateral_expiration_unix_seconds: u64::MAX,
            },
        )
        .unwrap();
        tokio::time::sleep(Duration::from_millis(250)).await;
        let mut body_read = false;
        let error = session
            .query_from_body(|| {
                body_read = true;
                Ok(b"SYNTHETIC_PRIVATE_CANARY".to_vec())
            })
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::ExpiredCollateral);
        assert!(!body_read);
        peer.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn paid_query_rejects_invalid_body_before_ticket_selection() {
        let (result, peer) = fixture(body).await;
        let mut evidence = result.unwrap();
        let (tor, _listener) = ManagedTor::synthetic_live().unwrap();
        evidence.connection.session.origin = TransportOrigin::Managed(tor);
        let session = VerifiedRpcSession::from_authenticated_inspection(
            evidence.connection.session,
            evidence.connection.deadline,
            evidence.connection.authority,
            PrivateDeadline {
                monotonic: Instant::now() + MAX_CONNECTION_LIFETIME,
                collateral_expiration_unix_seconds: u64::MAX,
            },
        )
        .unwrap();
        let selected = std::cell::Cell::new(false);
        let error = session
            .query_from_body_authorized(
                || async {
                    Ok(
                        br#"{"jsonrpc":"2.0","id":1,"method":"sendrawtransaction","params":[]}"#
                            .to_vec(),
                    )
                },
                || {
                    selected.set(true);
                    Ok((b"PrivateToken token=\"synthetic\"".to_vec(), (), || {
                        Ok(|| Ok(()))
                    }))
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::MethodNotAllowed);
        assert!(!selected.get());
        peer.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn paid_query_rejects_dead_tor_or_expired_connection_before_ticket_selection() {
        for tor_unavailable in [true, false] {
            let (result, peer) = fixture(body).await;
            let mut evidence = result.unwrap();
            let (tor, _listener) = ManagedTor::synthetic_live().unwrap();
            evidence.connection.session.origin = TransportOrigin::Managed(tor.clone());
            let session = VerifiedRpcSession::from_authenticated_inspection(
                evidence.connection.session,
                evidence.connection.deadline,
                evidence.connection.authority,
                PrivateDeadline {
                    monotonic: Instant::now()
                        + if tor_unavailable {
                            MAX_CONNECTION_LIFETIME
                        } else {
                            Duration::from_millis(200)
                        },
                    collateral_expiration_unix_seconds: u64::MAX,
                },
            )
            .unwrap();
            if tor_unavailable {
                tor.terminate_synthetic_child();
            } else {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            let body_read = std::cell::Cell::new(false);
            let ticket_selected = std::cell::Cell::new(false);
            let error = session
                .query_from_body_authorized(
                    || {
                        body_read.set(true);
                        async {
                            Ok(
                                br#"{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}"#
                                    .to_vec(),
                            )
                        }
                    },
                    || {
                        ticket_selected.set(true);
                        Ok((b"PrivateToken token=\"synthetic\"".to_vec(), (), || {
                            Ok(|| Ok(()))
                        }))
                    },
                )
                .await
                .unwrap_err();
            assert_eq!(
                error.code,
                if tor_unavailable {
                    ErrorCode::TorUnavailable
                } else {
                    ErrorCode::ExpiredCollateral
                }
            );
            assert!(!body_read.get());
            assert!(!ticket_selected.get());
            // The fixture peer fails if it sees an RPC byte on this stream.
            peer.await.unwrap();
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn paid_query_claim_failure_prevents_ticket_and_body_transmission() {
        let (result, peer) = fixture(body).await;
        let mut evidence = result.unwrap();
        let (tor, _listener) = ManagedTor::synthetic_live().unwrap();
        evidence.connection.session.origin = TransportOrigin::Managed(tor);
        let session = VerifiedRpcSession::from_authenticated_inspection(
            evidence.connection.session,
            evidence.connection.deadline,
            evidence.connection.authority,
            PrivateDeadline {
                monotonic: Instant::now() + MAX_CONNECTION_LIFETIME,
                collateral_expiration_unix_seconds: u64::MAX,
            },
        )
        .unwrap();
        let claimed = std::cell::Cell::new(false);
        let error = session
            .query_from_body_authorized(
                || async {
                    Ok(
                        br#"{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}"#
                            .to_vec(),
                    )
                },
                || {
                    Ok((b"PrivateToken token=\"synthetic\"".to_vec(), (), || {
                        claimed.set(true);
                        Err::<fn() -> Result<(), SafeError>, _>(SafeError::new(
                            ErrorCode::InvalidRequest,
                            "Ticket authorization unavailable.",
                        ))
                    }))
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidRequest);
        assert!(claimed.get());
        peer.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn paid_query_does_not_transmit_if_managed_tor_dies_during_claim() {
        let (result, peer) = fixture(body).await;
        let mut evidence = result.unwrap();
        let (tor, _listener) = ManagedTor::synthetic_live().unwrap();
        evidence.connection.session.origin = TransportOrigin::Managed(tor.clone());
        let session = VerifiedRpcSession::from_authenticated_inspection(
            evidence.connection.session,
            evidence.connection.deadline,
            evidence.connection.authority,
            PrivateDeadline {
                monotonic: Instant::now() + MAX_CONNECTION_LIFETIME,
                collateral_expiration_unix_seconds: u64::MAX,
            },
        )
        .unwrap();
        let claimed = std::cell::Cell::new(false);
        let released = std::cell::Cell::new(false);
        let error = session
            .query_from_body_authorized(
                || async {
                    Ok(
                        br#"{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}"#
                            .to_vec(),
                    )
                },
                || {
                    Ok((b"PrivateToken token=\"synthetic\"".to_vec(), (), || {
                        claimed.set(true);
                        tor.terminate_synthetic_child();
                        Ok(|| {
                            released.set(true);
                            Ok(())
                        })
                    }))
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::TorUnavailable);
        assert!(claimed.get());
        assert!(released.get());
        // The fixture peer fails if it sees any RPC byte on this TLS stream.
        peer.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn paid_query_does_not_transmit_if_verified_deadline_expires_during_claim() {
        let (result, peer) = fixture(body).await;
        let mut evidence = result.unwrap();
        let (tor, _listener) = ManagedTor::synthetic_live().unwrap();
        evidence.connection.session.origin = TransportOrigin::Managed(tor);
        let session = VerifiedRpcSession::from_authenticated_inspection(
            evidence.connection.session,
            evidence.connection.deadline,
            evidence.connection.authority,
            PrivateDeadline {
                monotonic: Instant::now() + Duration::from_millis(200),
                collateral_expiration_unix_seconds: u64::MAX,
            },
        )
        .unwrap();
        let claimed = std::cell::Cell::new(false);
        let released = std::cell::Cell::new(false);
        let error = session
            .query_from_body_authorized(
                || async {
                    Ok(
                        br#"{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}"#
                            .to_vec(),
                    )
                },
                || {
                    Ok((b"PrivateToken token=\"synthetic\"".to_vec(), (), || {
                        claimed.set(true);
                        std::thread::sleep(Duration::from_millis(250));
                        Ok(|| {
                            released.set(true);
                            Ok(())
                        })
                    }))
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::ExpiredCollateral);
        assert!(claimed.get());
        assert!(released.get());
        peer.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pending_private_body_stops_at_the_first_existing_deadline_without_rpc() {
        for session_expires_first in [true, false] {
            let (result, peer) = fixture(body).await;
            let mut evidence = result.unwrap();
            let (tor, _listener) = ManagedTor::synthetic_live().unwrap();
            evidence.connection.session.origin = TransportOrigin::Managed(tor);
            let short_deadline = Instant::now() + Duration::from_millis(200);
            if session_expires_first {
                evidence.connection.deadline = short_deadline;
            }
            let session = VerifiedRpcSession::from_authenticated_inspection(
                evidence.connection.session,
                evidence.connection.deadline,
                evidence.connection.authority,
                PrivateDeadline {
                    monotonic: if session_expires_first {
                        Instant::now() + MAX_CONNECTION_LIFETIME
                    } else {
                        short_deadline
                    },
                    collateral_expiration_unix_seconds: u64::MAX,
                },
            )
            .unwrap();
            let body_polled = std::cell::Cell::new(false);
            let result = tokio::time::timeout(
                Duration::from_secs(2),
                session.query_from_body_async(|| async {
                    body_polled.set(true);
                    std::future::pending::<Result<Vec<u8>, SafeError>>().await
                }),
            )
            .await
            .expect("pending body must stop at the private-session deadline");
            assert!(body_polled.get());
            assert_eq!(
                result.unwrap_err().code,
                if session_expires_first {
                    ErrorCode::StaleNonce
                } else {
                    ErrorCode::ExpiredCollateral
                }
            );
            // The fixture peer reads to EOF and fails if any /rpc byte arrived.
            peer.await.unwrap();
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn synthetic_child_death_closes_private_session_before_body_read() {
        let (result, peer) = fixture(body).await;
        let mut evidence = result.unwrap();
        let (tor, _listener) = ManagedTor::synthetic_live().unwrap();
        evidence.connection.session.origin = TransportOrigin::Managed(tor.clone());
        let session = VerifiedRpcSession::from_authenticated_inspection(
            evidence.connection.session,
            evidence.connection.deadline,
            evidence.connection.authority,
            PrivateDeadline {
                monotonic: Instant::now() + MAX_CONNECTION_LIFETIME,
                collateral_expiration_unix_seconds: u64::MAX,
            },
        )
        .unwrap();
        tor.terminate_synthetic_child();
        let error = session
            .query_from_body(|| panic!("body read after synthetic child death"))
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::TorUnavailable);
        peer.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn synthetic_socket_replacement_closes_private_session_before_body_read() {
        let (result, peer) = fixture(body).await;
        let mut evidence = result.unwrap();
        let (tor, original_listener) = ManagedTor::synthetic_live().unwrap();
        evidence.connection.session.origin = TransportOrigin::Managed(tor.clone());
        let session = VerifiedRpcSession::from_authenticated_inspection(
            evidence.connection.session,
            evidence.connection.deadline,
            evidence.connection.authority,
            PrivateDeadline {
                monotonic: Instant::now() + MAX_CONNECTION_LIFETIME,
                collateral_expiration_unix_seconds: u64::MAX,
            },
        )
        .unwrap();
        std::fs::remove_file(tor.synthetic_socket_path()).unwrap();
        let replacement = tokio::net::UnixListener::bind(tor.synthetic_socket_path()).unwrap();
        let callback_called = std::cell::Cell::new(false);
        let error = session
            .query_from_body_async(|| {
                callback_called.set(true);
                async { Ok(Vec::new()) }
            })
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::TorUnavailable);
        assert!(!callback_called.get());
        drop(replacement);
        drop(original_listener);
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn gcp_diagnostic_checks_connection_lifetime_before_evidence() {
        let (result, peer) = fixture(body).await;
        let mut evidence = result.unwrap();
        evidence.connection.established = Instant::now() - MAX_CONNECTION_LIFETIME;
        evidence.connection.deadline = evidence.connection.established + MAX_CONNECTION_LIFETIME;
        let policy = GcpWorkloadPolicy::from_json(include_bytes!(
            "../../../../../tests/fixtures/gcp/policy.synthetic.json"
        ))
        .unwrap();
        let report = evidence.inspect(b"{}", &policy);
        assert_eq!(
            report.issue,
            Some(EndpointInspectionIssue::ConnectionExpired)
        );
        assert!(report.gcp_evidence.is_none());
        assert!(!report.diagnostic_passed() && !report.private_accepted && !report.query_sent);
        peer.await.unwrap();
    }
}
