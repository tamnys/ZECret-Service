//! Offline Intel quote inspection, deliberately separate from private authority.
//! Only this module calls the maintained QVL. It has no fetch client or network API.
use dcap_qvl::{
    Policy, QuoteClaims, QuoteCollateralV3, QuotePolicy,
    configs::RingConfig,
    quote::{Quote, Report},
    verify::QuoteVerifier,
};
use parity_scale_codec::{Decode, DecodeAll, Encode};
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
    /// Bytes after the canonical signed quote envelope. They are not evidence.
    pub untrusted_trailing_bytes: usize,
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

/// Strict hardware and live-key diagnostic only. It carries no workload
/// identity comparison or private-query authority.
#[derive(Debug, Serialize)]
pub struct BoundQuoteInspection {
    #[serde(flatten)]
    pub quote: OfflineInspection,
    pub authenticated_report_data_match: InspectionStatus,
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
            untrusted_trailing_bytes: 0,
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
    inspect_quote_with_claims(quote, collateral_json, |_| {})
}

/// Compare signed TDX REPORTDATA only after the production-root QVL and strict
/// current-time TDX security policy pass. The expected bytes must come from
/// the caller's private TLS exporter; this function cannot attest that origin.
pub fn inspect_quote_and_report_data(
    quote: &[u8],
    collateral_json: &[u8],
    expected_report_data: &[u8; 64],
) -> BoundQuoteInspection {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(now) => inspect_quote_and_report_data_at(
            quote,
            collateral_json,
            expected_report_data,
            now.as_secs(),
            "system_clock",
        ),
        Err(_) => BoundQuoteInspection {
            quote: inspect_quote(quote, collateral_json),
            authenticated_report_data_match: InspectionStatus::NotChecked,
        },
    }
}

/// Phala public-read preview only. Phala's attestation response may append an
/// untrusted trailer to the signed Intel quote. Verify exactly the canonical
/// quote envelope and ignore the trailer; never expose this path to private
/// authorization or approved-release matching.
pub fn inspect_phala_public_preview_quote_and_report_data(
    quote: &[u8],
    collateral_json: &[u8],
    expected_report_data: &[u8; 64],
) -> BoundQuoteInspection {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(now) => inspect_bound_at(
            quote,
            collateral_json,
            expected_report_data,
            now.as_secs(),
            "system_clock",
            Appraisal::PhalaPublicPreview,
        ),
        Err(_) => {
            let mut report = OfflineInspection::new(None, "system_clock");
            report.issue = Some(InspectionIssue::ClockUnavailable);
            BoundQuoteInspection {
                quote: report,
                authenticated_report_data_match: InspectionStatus::NotChecked,
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Appraisal {
    Strict,
    PhalaPublicPreview,
    PhalaTrusted,
}

fn inspect_quote_and_report_data_at(
    quote: &[u8],
    collateral_json: &[u8],
    expected_report_data: &[u8; 64],
    now: u64,
    time_source: &'static str,
) -> BoundQuoteInspection {
    inspect_bound_at(
        quote,
        collateral_json,
        expected_report_data,
        now,
        time_source,
        Appraisal::Strict,
    )
}

fn inspect_bound_at(
    quote: &[u8],
    collateral_json: &[u8],
    expected_report_data: &[u8; 64],
    now: u64,
    time_source: &'static str,
    appraisal: Appraisal,
) -> BoundQuoteInspection {
    let mut binding = InspectionStatus::NotChecked;
    let quote = inspect_at_with_appraisal(
        quote,
        collateral_json,
        now,
        time_source,
        appraisal,
        |claims| {
            binding = if claims
                .report
                .as_td10()
                .is_some_and(|td| td.report_data == *expected_report_data)
            {
                InspectionStatus::Verified
            } else {
                InspectionStatus::Rejected
            };
        },
    );
    BoundQuoteInspection {
        quote,
        authenticated_report_data_match: binding,
    }
}

// The callback receives an immutable borrow only after hardware and strict
// security checks pass. Authenticated claims never leave this crate.
pub(crate) fn inspect_quote_with_claims(
    quote: &[u8],
    collateral_json: &[u8],
    inspect: impl FnOnce(&QuoteClaims),
) -> OfflineInspection {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(now) => inspect_at_with_claims(
            quote,
            collateral_json,
            now.as_secs(),
            "system_clock",
            inspect,
        ),
        Err(_) => {
            let mut report = OfflineInspection::new(None, "system_clock");
            report.issue = Some(InspectionIssue::ClockUnavailable);
            report
        }
    }
}

/// The same authenticated claims callback under the deliberately limited Phala
/// public-preview appraisal. This is diagnostic only; callers cannot turn it
/// into strict TCB acceptance or a private-session capability.
pub(crate) fn inspect_phala_public_preview_quote_with_claims(
    quote: &[u8],
    collateral_json: &[u8],
    inspect: impl FnOnce(&QuoteClaims),
) -> OfflineInspection {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(now) => inspect_at_with_appraisal(
            quote,
            collateral_json,
            now.as_secs(),
            "system_clock",
            Appraisal::PhalaPublicPreview,
            inspect,
        ),
        Err(_) => {
            let mut report = OfflineInspection::new(None, "system_clock");
            report.issue = Some(InspectionIssue::ClockUnavailable);
            report
        }
    }
}

/// The Phala-managed release profile uses the reviewed stock-platform flag
/// allowances, while retaining production Intel roots, current collateral,
/// UpToDate TCB, no advisories and debug rejection.
pub(crate) fn inspect_phala_trusted_quote_with_claims(
    quote: &[u8],
    collateral_json: &[u8],
    inspect: impl FnOnce(&QuoteClaims),
) -> OfflineInspection {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(now) => inspect_at_with_appraisal(
            quote,
            collateral_json,
            now.as_secs(),
            "system_clock",
            Appraisal::PhalaTrusted,
            inspect,
        ),
        Err(_) => {
            let mut report = OfflineInspection::new(None, "system_clock");
            report.issue = Some(InspectionIssue::ClockUnavailable);
            report
        }
    }
}

#[cfg(test)]
fn inspect_at(
    quote: &[u8],
    collateral_json: &[u8],
    now: u64,
    time_source: &'static str,
) -> OfflineInspection {
    inspect_at_with_claims(quote, collateral_json, now, time_source, |_| {})
}

#[cfg(test)]
pub(crate) fn inspect_fixture_quote_with_claims(
    quote: &[u8],
    collateral_json: &[u8],
    now: u64,
    inspect: impl FnOnce(&QuoteClaims),
) -> OfflineInspection {
    inspect_at_with_claims(
        quote,
        collateral_json,
        now,
        "historical_upstream_fixture_test",
        inspect,
    )
}

fn inspect_at_with_claims(
    quote: &[u8],
    collateral_json: &[u8],
    now: u64,
    time_source: &'static str,
    inspect: impl FnOnce(&QuoteClaims),
) -> OfflineInspection {
    inspect_at_with_appraisal(
        quote,
        collateral_json,
        now,
        time_source,
        Appraisal::Strict,
        inspect,
    )
}

fn inspect_at_with_appraisal(
    quote: &[u8],
    collateral_json: &[u8],
    now: u64,
    time_source: &'static str,
    appraisal: Appraisal,
    inspect: impl FnOnce(&QuoteClaims),
) -> OfflineInspection {
    let mut result = OfflineInspection::new(Some(now), time_source);
    if matches!(appraisal, Appraisal::PhalaPublicPreview) {
        result.policy = "public preview only: Intel-root TDX, UpToDate TCB, no advisories; dynamic platform, cached keys, SMT and untrusted quote trailer allowed; no private authority";
    } else if matches!(appraisal, Appraisal::PhalaTrusted) {
        result.policy = "Phala-managed guest trust: Intel-root TDX, UpToDate TCB, no advisories; dynamic platform, cached platform keys and SMT allowed; quote trailer untrusted";
    }
    // Upstream parse() permits trailing bytes. Use its complete decoder and
    // encoder to reject ignored bytes inside length envelopes too. Never use
    // parsed (unauthenticated) report fields as acceptance evidence.
    let mut input = quote;
    let parsed = match appraisal {
        Appraisal::Strict => Quote::decode_all(&mut input),
        Appraisal::PhalaPublicPreview | Appraisal::PhalaTrusted => Quote::decode(&mut input),
    };
    let signed_length = quote.len() - input.len();
    if !parsed.is_ok_and(|parsed| parsed.encode().as_slice() == &quote[..signed_length]) {
        result.hardware_authenticity = InspectionStatus::Rejected;
        result.issue = Some(InspectionIssue::MalformedQuote);
        return result;
    }
    result.untrusted_trailing_bytes = input.len();
    let signed_quote = &quote[..signed_length];
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
        .verify_with_policy(
            signed_quote,
            collateral,
            now,
            &QuotePolicy::claims_only(now),
        ) {
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
    let appraisal_result = match appraisal {
        Appraisal::Strict => appraise(&claims, now),
        Appraisal::PhalaPublicPreview | Appraisal::PhalaTrusted => {
            appraise_phala_public_preview(&claims, now)
        }
    };
    match appraisal_result {
        Ok(()) => {
            result.security_policy = InspectionStatus::Verified;
            inspect(&claims);
        }
        Err(issue) => {
            result.security_policy = InspectionStatus::Rejected;
            result.issue = Some(issue);
        }
    }
    result
}

fn appraise(claims: &QuoteClaims, now: u64) -> Result<(), InspectionIssue> {
    appraise_with_policy(claims, QuotePolicy::strict(now))
}

fn appraise_phala_public_preview(claims: &QuoteClaims, now: u64) -> Result<(), InspectionIssue> {
    appraise_with_policy(
        claims,
        QuotePolicy::strict(now)
            .allow_dynamic_platform(true)
            .allow_cached_keys(true)
            .allow_smt(true),
    )
}

fn appraise_with_policy(claims: &QuoteClaims, policy: QuotePolicy) -> Result<(), InspectionIssue> {
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
    policy
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
    fn bound_quote_keeps_report_data_unchecked_when_strict_qvl_rejects() {
        let parsed = Quote::parse(QUOTE).unwrap();
        let expected = parsed.report.as_td10().unwrap().report_data;
        let rejected = inspect_quote_and_report_data_at(
            QUOTE,
            COLLATERAL,
            &expected,
            FIXTURE_TIME,
            "historical_upstream_fixture_test",
        );
        assert_eq!(
            rejected.quote.hardware_authenticity,
            InspectionStatus::Verified
        );
        assert_eq!(rejected.quote.security_policy, InspectionStatus::Rejected);
        assert_eq!(
            rejected.authenticated_report_data_match,
            InspectionStatus::NotChecked
        );
        assert_eq!(rejected.quote.workload_policy, InspectionStatus::NotChecked);
        assert!(!rejected.quote.private_accepted);

        let mut wrong = expected;
        wrong[0] ^= 1;
        let mismatch = inspect_quote_and_report_data_at(
            QUOTE,
            COLLATERAL,
            &wrong,
            FIXTURE_TIME,
            "historical_upstream_fixture_test",
        );
        assert_eq!(
            mismatch.authenticated_report_data_match,
            InspectionStatus::NotChecked
        );

        let expired = inspect_quote_and_report_data_at(
            QUOTE,
            COLLATERAL,
            &expected,
            FIXTURE_TIME + 2,
            "historical_upstream_fixture_test",
        );
        assert_eq!(
            expired.quote.hardware_authenticity,
            InspectionStatus::Rejected
        );
        assert_eq!(
            expired.authenticated_report_data_match,
            InspectionStatus::NotChecked
        );
    }
    #[test]
    fn phala_public_preview_verifies_only_the_canonical_quote_and_never_grants_private_authority() {
        let expected = Quote::parse(QUOTE)
            .unwrap()
            .report
            .as_td10()
            .unwrap()
            .report_data;
        let mut with_trailer = QUOTE.to_vec();
        with_trailer.extend_from_slice(b"untrusted provider trailer");
        let preview = inspect_bound_at(
            &with_trailer,
            COLLATERAL,
            &expected,
            FIXTURE_TIME,
            "historical_upstream_fixture_test",
            Appraisal::PhalaPublicPreview,
        );
        assert_eq!(
            preview.quote.hardware_authenticity,
            InspectionStatus::Verified
        );
        assert_eq!(preview.quote.security_policy, InspectionStatus::Verified);
        assert_eq!(
            preview.authenticated_report_data_match,
            InspectionStatus::Verified
        );
        assert_eq!(preview.quote.untrusted_trailing_bytes, 26);
        assert_no_private_authority(&preview.quote);
        assert_eq!(
            historical(&with_trailer, COLLATERAL).issue,
            Some(InspectionIssue::MalformedQuote)
        );

        let mut wrong = expected;
        wrong[0] ^= 1;
        let mismatch = inspect_bound_at(
            &with_trailer,
            COLLATERAL,
            &wrong,
            FIXTURE_TIME,
            "historical_upstream_fixture_test",
            Appraisal::PhalaPublicPreview,
        );
        assert_eq!(
            mismatch.authenticated_report_data_match,
            InspectionStatus::Rejected
        );

        let mut changed = with_trailer;
        changed[100] ^= 1;
        let invalid = inspect_bound_at(
            &changed,
            COLLATERAL,
            &expected,
            FIXTURE_TIME,
            "historical_upstream_fixture_test",
            Appraisal::PhalaPublicPreview,
        );
        assert_eq!(
            invalid.quote.hardware_authenticity,
            InspectionStatus::Rejected
        );
        assert_eq!(
            invalid.authenticated_report_data_match,
            InspectionStatus::NotChecked
        );
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
