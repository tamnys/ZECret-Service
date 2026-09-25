//! Offline Intel quote inspection, deliberately separate from private authority.
//! Only this module calls the maintained QVL. It has no fetch client or network API.
use dcap_qvl::{
    Policy, QuoteClaims, QuoteCollateralV3, QuotePolicy,
    configs::RingConfig,
    quote::{Quote, Report},
    verify::QuoteVerifier,
};
use parity_scale_codec::{DecodeAll, Encode};
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InspectionStatus {
    NotChecked,
    Verified,
    Rejected,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InspectionIssue {
    ClockUnavailable,
    MalformedQuote,
    MalformedCollateral,
    CryptographicOrValidityCheckFailed,
    UnsupportedTee,
    AdvisoryNotApproved,
    StrictSecurityPolicyRejected,
}

/// This is a diagnostic report, not a capability. It cannot create VerifiedChannel.
/// Platform identifiers, raw report_data, paths and upstream error strings are omitted.
#[derive(Debug, Serialize)]
pub struct OfflineInspection {
    pub operation: &'static str,
    pub verifier: &'static str,
    pub time_source: &'static str,
    pub checked_at_unix_seconds: Option<u64>,
    pub hardware_authenticity: InspectionStatus,
    pub security_policy: InspectionStatus,
    pub policy: &'static str,
    pub tee: Option<&'static str>,
    pub tcb_status: Option<String>,
    pub advisory_ids: Vec<String>,
    pub collateral_earliest_expiration_unix_seconds: Option<u64>,
    pub workload_policy: InspectionStatus,
    pub freshness: InspectionStatus,
    pub live_key_binding: InspectionStatus,
    pub private_accepted: bool,
    pub query_sent: bool,
    pub network_used: bool,
    pub issue: Option<InspectionIssue>,
}

impl OfflineInspection {
    fn new(now: Option<u64>, time_source: &'static str) -> Self {
        Self {
            operation: "offline_quote_inspection",
            verifier: "dcap-qvl=0.6.3/ring/intel-production-root",
            time_source,
            checked_at_unix_seconds: now,
            hardware_authenticity: InspectionStatus::NotChecked,
            security_policy: InspectionStatus::NotChecked,
            policy: "dcap-qvl strict; TDX only; no unapproved advisories; no grace or override",
            tee: None,
            tcb_status: None,
            advisory_ids: Vec::new(),
            collateral_earliest_expiration_unix_seconds: None,
            workload_policy: InspectionStatus::NotChecked,
            freshness: InspectionStatus::NotChecked,
            live_key_binding: InspectionStatus::NotChecked,
            private_accepted: false,
            query_sent: false,
            network_used: false,
            issue: None,
        }
    }
}

/// Verify supplied evidence at the customer's current wall clock. There is no
/// historical-time, custom-root or permissive-policy production entrypoint.
/// Collateral is untrusted signed input; no PCCS or other HTTP call is available.
pub fn inspect_quote(quote: &[u8], collateral_json: &[u8]) -> OfflineInspection {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(now) => inspect_at(quote, collateral_json, now.as_secs(), "system_clock"),
        Err(_) => {
            let mut report = OfflineInspection::new(None, "system_clock");
            report.issue = Some(InspectionIssue::ClockUnavailable);
            report
        }
    }
}

fn inspect_at(
    quote: &[u8],
    collateral_json: &[u8],
    now: u64,
    time_source: &'static str,
) -> OfflineInspection {
    let mut result = OfflineInspection::new(Some(now), time_source);
    // Upstream parse() permits trailing bytes. Use its complete decoder and
    // encoder to reject ignored bytes inside length envelopes too. Never use
    // parsed (unauthenticated) report fields as acceptance evidence.
    let mut input = quote;
    let canonical =
        Quote::decode_all(&mut input).is_ok_and(|parsed| parsed.encode().as_slice() == quote);
    if !canonical {
        result.hardware_authenticity = InspectionStatus::Rejected;
        result.issue = Some(InspectionIssue::MalformedQuote);
        return result;
    }
    // Serde structs can accept positional arrays: require the documented JSON
    // object representation before handing collateral to the maintained parser.
    if collateral_json
        .iter()
        .copied()
        .find(|b| !b.is_ascii_whitespace())
        != Some(b'{')
    {
        result.issue = Some(InspectionIssue::MalformedCollateral);
        return result;
    }
    let collateral: QuoteCollateralV3 = match serde_json::from_slice(collateral_json) {
        Ok(collateral) => collateral,
        Err(_) => {
            result.issue = Some(InspectionIssue::MalformedCollateral);
            return result;
        }
    };
    // claims_only separates authentic signed facts from acceptance policy. It
    // still checks Intel trust, signatures, validity, CRLs and non-debug attrs.
    let claims = match QuoteVerifier::new_prod()
        .with_config::<RingConfig>()
        .verify_with_policy(quote, collateral, now, &QuotePolicy::claims_only(now))
    {
        Ok(claims) => claims,
        Err(_) => {
            result.hardware_authenticity = InspectionStatus::Rejected;
            result.issue = Some(InspectionIssue::CryptographicOrValidityCheckFailed);
            return result;
        }
    };
    result.hardware_authenticity = InspectionStatus::Verified;
    result.tee = Some(
        if matches!(claims.report, Report::TD10(_) | Report::TD15(_)) {
            "tdx"
        } else {
            "sgx"
        },
    );
    result.tcb_status = Some(claims.tcb.status.to_string());
    result.advisory_ids = claims.tcb.advisory_ids.clone();
    result.collateral_earliest_expiration_unix_seconds = Some(claims.earliest_expiration_date);
    match appraise(&claims, now) {
        Ok(()) => result.security_policy = InspectionStatus::Verified,
        Err(issue) => {
            result.security_policy = InspectionStatus::Rejected;
            result.issue = Some(issue);
        }
    }
    result
}

fn appraise(claims: &QuoteClaims, now: u64) -> Result<(), InspectionIssue> {
    // 0x81 is Intel's TDX quote TEE discriminator, checked alongside the decoded body.
    if claims.tee_type != 0x81 || !matches!(claims.report, Report::TD10(_) | Report::TD15(_)) {
        return Err(InspectionIssue::UnsupportedTee);
    }
    // No advisory exception has been approved by this project's release policy.
    if !claims.tcb.advisory_ids.is_empty()
        || !claims.platform.tcb_level.advisory_ids.is_empty()
        || !claims.qe.tcb_level.advisory_ids.is_empty()
    {
        return Err(InspectionIssue::AdvisoryNotApproved);
    }
    QuotePolicy::strict(now)
        .validate(claims)
        .map_err(|_| InspectionIssue::StrictSecurityPolicyRejected)
}

#[cfg(test)]
mod tests {
    use super::*;
    const QUOTE: &[u8] = include_bytes!("../../../tests/fixtures/dcap/tdx_quote.exact.bin");
    const COLLATERAL: &[u8] =
        include_bytes!("../../../tests/fixtures/dcap/tdx_quote_collateral.json");
    // Exact upstream fixture PCK CRL nextUpdate minus one second; fixture-only
    // historical reference time, never a production clock override.
    const FIXTURE_TIME: u64 = 1_752_919_234;
    fn historical(quote: &[u8], collateral: &[u8]) -> OfflineInspection {
        inspect_at(
            quote,
            collateral,
            FIXTURE_TIME,
            "historical_upstream_fixture_test",
        )
    }
    fn assert_no_private_authority(report: &OfflineInspection) {
        assert!(!report.private_accepted && !report.query_sent && !report.network_used);
        assert_eq!(report.workload_policy, InspectionStatus::NotChecked);
        assert_eq!(report.freshness, InspectionStatus::NotChecked);
        assert_eq!(report.live_key_binding, InspectionStatus::NotChecked);
    }
    #[test]
    fn fixture_derivation_uses_maintained_decoder_and_rejects_padding() {
        use parity_scale_codec::Decode;
        let upstream = include_bytes!("../../../tests/fixtures/dcap/tdx_quote.bin");
        let mut remaining = upstream.as_slice();
        let decoded = Quote::decode(&mut remaining).unwrap();
        assert!(remaining.iter().all(|byte| *byte == 0));
        assert_eq!(&upstream[..upstream.len() - remaining.len()], QUOTE);
        assert_eq!(decoded.encode(), QUOTE);
        assert_eq!(
            historical(upstream, COLLATERAL).issue,
            Some(InspectionIssue::MalformedQuote)
        );
    }
    #[test]
    fn authentic_historical_tdx_quote_is_cryptographically_verified_only() {
        let result = historical(QUOTE, COLLATERAL);
        assert_eq!(result.hardware_authenticity, InspectionStatus::Verified);
        assert_eq!(result.tee, Some("tdx"));
        assert_eq!(result.tcb_status.as_deref(), Some("UpToDate"));
        assert_no_private_authority(&result);
        assert!(!serde_json::to_string(&result).unwrap().contains("ppid"));
    }
    #[test]
    fn expired_and_not_yet_valid_collateral_fail() {
        for time in [0, 1_752_919_236] {
            let result = inspect_at(QUOTE, COLLATERAL, time, "historical_upstream_fixture_test");
            assert_eq!(result.hardware_authenticity, InspectionStatus::Rejected);
            assert_no_private_authority(&result);
        }
    }
    #[test]
    fn modified_quote_and_signed_collateral_fail() {
        let mut parsed = Quote::parse(QUOTE).unwrap();
        match &mut parsed.report {
            Report::TD10(report) => report.report_data[0] ^= 1,
            _ => panic!("upstream TDX 1.0 fixture changed"),
        }
        assert_eq!(
            historical(&parsed.encode(), COLLATERAL).hardware_authenticity,
            InspectionStatus::Rejected
        );
        let mut collateral: QuoteCollateralV3 = serde_json::from_slice(COLLATERAL).unwrap();
        collateral.tcb_info_signature[0] ^= 1;
        assert_eq!(
            historical(QUOTE, &serde_json::to_vec(&collateral).unwrap()).hardware_authenticity,
            InspectionStatus::Rejected
        );
    }
    #[test]
    fn appended_truncated_and_fake_evidence_fail() {
        let mut appended = QUOTE.to_vec();
        appended.push(0);
        for quote in [
            appended.as_slice(),
            &QUOTE[..QUOTE.len() - 1],
            br#"{"verified":true}"#,
        ] {
            assert_eq!(
                historical(quote, COLLATERAL).issue,
                Some(InspectionIssue::MalformedQuote)
            );
        }
        for collateral in [
            br#"{"verified":true}"#.as_slice(),
            b"[]",
            b"SYNTHETIC_SECRET_MARKER",
        ] {
            let result = historical(QUOTE, collateral);
            assert_eq!(result.issue, Some(InspectionIssue::MalformedCollateral));
            assert!(
                !serde_json::to_string(&result)
                    .unwrap()
                    .contains("SYNTHETIC_SECRET_MARKER")
            );
        }
    }
    #[test]
    fn unknown_tcb_advisory_sgx_and_platform_flags_are_rejected() {
        let collateral: QuoteCollateralV3 = serde_json::from_slice(COLLATERAL).unwrap();
        let claims = QuoteVerifier::new_prod()
            .with_config::<RingConfig>()
            .verify_with_policy(
                QUOTE,
                collateral,
                FIXTURE_TIME,
                &QuotePolicy::claims_only(FIXTURE_TIME),
            )
            .unwrap();
        // Policy-unit mutations are not re-signed evidence and cannot enter the
        // production evidence path. They exercise downstream rejection rules.
        let mut changed = claims.clone();
        changed.tee_type = 0;
        assert_eq!(
            appraise(&changed, FIXTURE_TIME),
            Err(InspectionIssue::UnsupportedTee)
        );
        let mut changed = claims.clone();
        changed
            .tcb
            .advisory_ids
            .push("UNAPPROVED-TEST-ADVISORY".into());
        assert_eq!(
            appraise(&changed, FIXTURE_TIME),
            Err(InspectionIssue::AdvisoryNotApproved)
        );
        let mut changed = claims.clone();
        changed.tcb.status = dcap_qvl::TcbStatus::OutOfDate;
        assert_eq!(
            appraise(&changed, FIXTURE_TIME),
            Err(InspectionIssue::StrictSecurityPolicyRejected)
        );
        let mut changed = claims;
        changed.platform.pck.cached_keys = dcap_qvl::PckCertFlag::True;
        assert_eq!(
            appraise(&changed, FIXTURE_TIME),
            Err(InspectionIssue::StrictSecurityPolicyRejected)
        );
    }
}
