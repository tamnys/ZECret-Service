use super::*;
use dcap_qvl::quote::{Quote, Report};
use parity_scale_codec::Encode;

const QUOTE: &[u8] = include_bytes!("../../../../tests/fixtures/dcap/tdx_quote.exact.bin");
const COLLATERAL: &[u8] =
    include_bytes!("../../../../tests/fixtures/dcap/tdx_quote_collateral.json");

fn u32le(out: &mut Vec<u8>, n: u32) {
    out.extend(n.to_le_bytes());
}
fn synthetic_log() -> Vec<u8> {
    let mut spec = b"Spec ID Event03\0".to_vec();
    u32le(&mut spec, 0);
    spec.extend([0, 2, 0, 2]);
    u32le(&mut spec, 1);
    spec.extend(0x000cu16.to_le_bytes());
    spec.extend(48u16.to_le_bytes());
    spec.push(0);
    let mut out = Vec::new();
    u32le(&mut out, 1);
    u32le(&mut out, 3);
    out.extend([0; 20]);
    u32le(&mut out, spec.len() as u32);
    out.extend(spec);
    for (index, kind, data) in [
        (1, 0x8000_0001, b"SYNTHETIC_BOOT_POLICY".as_slice()),
        (2, 0x8000_0003, b"SYNTHETIC_UKI_DESCRIPTOR".as_slice()),
        (3, 0x0000_000d, b"SYNTHETIC_KERNEL".as_slice()),
    ] {
        u32le(&mut out, index);
        u32le(&mut out, kind);
        u32le(&mut out, 1);
        out.extend(0x000cu16.to_le_bytes());
        out.extend(Sha384::hash(data));
        u32le(&mut out, data.len() as u32);
        out.extend(data);
    }
    out
}

// Fabricated report and artifact identities are restricted to this test module.
// They never become an embedded release or valid signed hardware evidence.
pub(crate) fn synthetic_policy() -> GcpWorkloadPolicy {
    let bytes = synthetic_log();
    let log = ccel::parse(&bytes).unwrap();
    let [rtmr0, rtmr1, rtmr2, rtmr3] = ccel::replay(&log.events);
    GcpWorkloadPolicy {
        schema_version: 1,
        mrtd: [1; 48],
        rtmr0,
        rtmr1,
        rtmr2,
        rtmr3,
        spec_id_sha256: Sha256::hash(log.spec_id),
        uki_event_index: 1,
        artifacts: GcpArtifactPolicy {
            firmware_endorsement_sha256: [1; 32],
            uki_sha256: [2; 32],
            uki_pe_coff_sha384: log.events[1].digest,
            rootfs_verity_sha256: [3; 32],
            kernel_command_line_sha256: [4; 32],
            boot_policy_sha256: [5; 32],
            wrapper_sha256: [6; 32],
            zebra_sha256: [7; 32],
            quote_broker_sha256: [8; 32],
            measurement_recipe_sha256: [9; 32],
        },
        expected_events: log
            .events
            .iter()
            .map(|e| GcpEventPolicy {
                mr_index: e.mr_index,
                event_type: e.event_type,
                digest_sha384: e.digest,
                event_data_sha256: Sha256::hash(e.data),
            })
            .collect(),
    }
}

fn synthetic_report(policy: &GcpWorkloadPolicy) -> TDReport10 {
    let quote = Quote::parse(QUOTE).unwrap();
    let mut td = quote.report.as_td10().unwrap().clone();
    td.mr_td = policy.mrtd;
    td.rt_mr0 = policy.rtmr0;
    td.rt_mr1 = policy.rtmr1;
    td.rt_mr2 = policy.rtmr2;
    td.rt_mr3 = policy.rtmr3;
    td
}

#[test]
fn maintained_google_fixture_replay_agrees_without_authentication_or_approval() {
    let bytes = include_bytes!("../../../../tests/fixtures/gcp/cos-113-intel-tdx.bin");
    assert_eq!(
        hex::encode(Sha256::hash(bytes)),
        "090dc18758380a5cc03014bf2fe354788a4f4222671e1e38f85b772d2fd344b5"
    );
    let registers = ccel::replay(&ccel::parse(bytes).unwrap().events);
    // Expected values transcribed from pinned Google's COS113TDX test vector.
    let expected = [
        "3fa2f61f395b7f5feefb4ec2df61297f109ad8abcd6410c1b7df60f21f37b19297fc35e544039c7e1edece752afd17f6",
        "f62dbc072bd5d3f3438b7b35c39a727f5aea2ffc2473f43723953f530daf62504f0a7944aa62c41a86e8a878c2b122c1",
        "4969684dc87381fc3b3134176c8d8806eaf0a901859f5f70cfae8d17714b46c10a8de219048c9fc09f11f381a6fbe7c1",
    ];
    for (actual, expected) in registers[..3].iter().zip(expected) {
        assert_eq!(hex::encode(actual), expected);
    }
    assert_eq!(registers[3], [0; 48]);
    assert!(
        crate::ApprovedRelease::selected(&crate::ReleasePolicy::default())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn strict_quote_failure_never_runs_gcp_policy_or_report_data_checks() {
    let p = synthetic_policy();
    let report = inspect_using(&synthetic_log(), &p, Some(&[0; 64]), |inspect| {
        offline::inspect_fixture_quote_with_claims(QUOTE, COLLATERAL, 1_752_919_234, inspect)
    });
    assert_eq!(
        report.workload.quote.hardware_authenticity,
        InspectionStatus::Verified
    );
    assert_eq!(
        report.workload.quote.security_policy,
        InspectionStatus::Rejected
    );
    assert_eq!(report.workload.ccel_integrity, InspectionStatus::NotChecked);
    assert_eq!(
        report.authenticated_report_data_match,
        InspectionStatus::NotChecked
    );
    assert!(!report.diagnostic_passed());
    assert!(
        !report.workload.quote.private_accepted
            && !report.workload.quote.query_sent
            && !report.workload.quote.network_used
    );
}

#[test]
fn diagnostic_measurement_success_without_provenance_cannot_be_private_ready() {
    let policy = synthetic_policy();
    let mut report = inspect_using(&synthetic_log(), &policy, Some(&[0; 64]), |inspect| {
        offline::inspect_fixture_quote_with_claims(QUOTE, COLLATERAL, 1_752_919_234, inspect)
    });
    // Fabricate an otherwise passing diagnostic report in this unit test. No
    // actual quote is modified or promoted to accepted private evidence.
    report.workload.quote.hardware_authenticity = InspectionStatus::Verified;
    report.workload.quote.security_policy = InspectionStatus::Verified;
    report.workload.quote.workload_policy = InspectionStatus::Verified;
    report.workload.quote.issue = None;
    report.workload.ccel_integrity = InspectionStatus::Verified;
    report.workload.firmware_measurement_reference_match = InspectionStatus::Verified;
    report.workload.boot_measurement_reference_match = InspectionStatus::Verified;
    report.authenticated_report_data_match = InspectionStatus::Verified;
    assert!(report.diagnostic_passed());
    assert!(!report.private_acceptance_ready());

    report.workload.firmware_endorsement_provenance = InspectionStatus::Verified;
    assert!(!report.private_acceptance_ready());
    report.workload.firmware_endorsement_provenance = InspectionStatus::NotChecked;
    report.workload.artifact_provenance = InspectionStatus::Verified;
    assert!(!report.private_acceptance_ready());
}

#[test]
fn fabricated_matching_measurements_never_authenticate_a_quote() {
    let p = synthetic_policy();
    let td = synthetic_report(&p);
    assert_eq!(
        check(&td, &synthetic_log(), &p, &mut Checks::default()),
        Ok(())
    );
    let mut quote = Quote::parse(QUOTE).unwrap();
    quote.report = Report::TD10(td);
    let result = inspect_gcp_workload_and_report_data(
        &quote.encode(),
        COLLATERAL,
        &synthetic_log(),
        &p,
        &[0; 64],
    );
    assert_eq!(
        result.workload.quote.hardware_authenticity,
        InspectionStatus::Rejected
    );
    assert_eq!(result.workload.ccel_integrity, InspectionStatus::NotChecked);
    assert!(!result.diagnostic_passed());
    assert!(!result.workload.quote.private_accepted);
}

#[test]
fn replay_alone_does_not_authorize_changed_event_descriptions_or_types() {
    let p = synthetic_policy();
    let td = synthetic_report(&p);
    let mut bytes = synthetic_log();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    assert_eq!(
        ccel::replay(&ccel::parse(&bytes).unwrap().events),
        [p.rtmr0, p.rtmr1, p.rtmr2, p.rtmr3]
    );
    assert_eq!(
        check(&td, &bytes, &p, &mut Checks::default()),
        Err(GcpWorkloadIssue::EventDescriptorMismatch)
    );
    let mut bytes = synthetic_log();
    // Header is 65 bytes; changing the first event's unmeasured type preserves replay.
    bytes[69..73].copy_from_slice(&5u32.to_le_bytes());
    assert_eq!(
        check(&td, &bytes, &p, &mut Checks::default()),
        Err(GcpWorkloadIssue::EventSequenceMismatch)
    );
}

#[test]
fn unextended_no_action_digests_must_be_zero_in_every_bank() {
    let mut bytes = synthetic_log();
    let original = ccel::replay(&ccel::parse(&bytes).unwrap().events);
    u32le(&mut bytes, 1);
    u32le(&mut bytes, ccel::EV_NO_ACTION);
    u32le(&mut bytes, 1);
    bytes.extend(0x000cu16.to_le_bytes());
    bytes.extend([0; 48]);
    u32le(&mut bytes, 8);
    bytes.extend(b"ADVISORY");
    assert_eq!(ccel::replay(&ccel::parse(&bytes).unwrap().events), original);

    // A nonzero digest in this event would otherwise be silently skipped by
    // replay, so it must not be treated as hardware-authenticated evidence.
    let digest_offset = bytes.len() - 8 - 4 - 48;
    bytes[digest_offset] = 1;
    assert!(matches!(
        ccel::parse(&bytes),
        Err(GcpWorkloadIssue::UnsupportedCcel)
    ));

    // The SHA-384 replay bank alone is insufficient: a second declared bank
    // must also obey the zero-digest rule for an unextended event.
    let source = synthetic_log();
    let parsed = ccel::parse(&source).unwrap();
    let mut spec = b"Spec ID Event03\0".to_vec();
    u32le(&mut spec, 0);
    spec.extend([0, 2, 0, 2]);
    u32le(&mut spec, 2);
    spec.extend(0x000bu16.to_le_bytes());
    spec.extend(32u16.to_le_bytes());
    spec.extend(0x000cu16.to_le_bytes());
    spec.extend(48u16.to_le_bytes());
    spec.push(0);
    let mut multibank = Vec::new();
    u32le(&mut multibank, 1);
    u32le(&mut multibank, ccel::EV_NO_ACTION);
    multibank.extend([0; 20]);
    u32le(&mut multibank, spec.len() as u32);
    multibank.extend(spec);
    for event in &parsed.events {
        u32le(&mut multibank, event.mr_index);
        u32le(&mut multibank, event.event_type);
        u32le(&mut multibank, 2);
        multibank.extend(0x000bu16.to_le_bytes());
        multibank.extend(Sha256::hash(event.data));
        multibank.extend(0x000cu16.to_le_bytes());
        multibank.extend(event.digest);
        u32le(&mut multibank, event.data.len() as u32);
        multibank.extend(event.data);
    }
    u32le(&mut multibank, 1);
    u32le(&mut multibank, ccel::EV_NO_ACTION);
    u32le(&mut multibank, 2);
    multibank.extend(0x000bu16.to_le_bytes());
    let sha256_offset = multibank.len();
    multibank.extend([0; 32]);
    multibank.extend(0x000cu16.to_le_bytes());
    multibank.extend([0; 48]);
    u32le(&mut multibank, 8);
    multibank.extend(b"ADVISORY");
    assert_eq!(
        ccel::replay(&ccel::parse(&multibank).unwrap().events),
        original
    );
    multibank[sha256_offset] = 1;
    assert!(matches!(
        ccel::parse(&multibank),
        Err(GcpWorkloadIssue::UnsupportedCcel)
    ));
}

#[test]
fn hash_of_measured_variable_content_cannot_be_replaced_by_a_descriptor_reference() {
    let mut p = synthetic_policy();
    let td = synthetic_report(&p);
    let mut bytes = synthetic_log();
    bytes[131] ^= 1; // First event data begins after its checked length field.
    let log = ccel::parse(&bytes).unwrap();
    p.expected_events[0].event_data_sha256 = Sha256::hash(log.events[0].data);
    assert_eq!(
        check(&td, &bytes, &p, &mut Checks::default()),
        Err(GcpWorkloadIssue::EventContentDigestMismatch)
    );
}

#[test]
fn truncated_lengths_unknown_banks_indices_and_hidden_suffixes_fail_closed() {
    let p = synthetic_policy();
    let td = synthetic_report(&p);
    let bytes = synthetic_log();
    for end in 0..bytes.len() {
        assert!(
            check(&td, &bytes[..end], &p, &mut Checks::default()).is_err(),
            "truncation {end}"
        );
    }
    for (offset, value) in [
        (28, u32::MAX),
        (56, u32::MAX),
        (65, 0),
        (65, 5),
        (73, u32::MAX),
        (127, u32::MAX),
    ] {
        let mut corrupt = bytes.clone();
        corrupt[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        assert!(ccel::parse(&corrupt).is_err(), "offset {offset}");
    }
    for (offset, value) in [(60, 0xffffu16), (62, 32), (77, 0x000b)] {
        let mut corrupt = bytes.clone();
        corrupt[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        assert!(ccel::parse(&corrupt).is_err(), "algorithm offset {offset}");
    }
    let mut hidden = bytes.clone();
    hidden.extend([0; 4]);
    hidden.push(1);
    assert!(ccel::parse(&hidden).is_err());
    for pad in [0, 255] {
        let mut padded = bytes.clone();
        padded.extend([pad; 32]);
        assert_eq!(check(&td, &padded, &p, &mut Checks::default()), Ok(()));
    }
}

#[test]
fn all_signed_registers_and_uki_measurement_are_required() {
    let p = synthetic_policy();
    let td = synthetic_report(&p);
    for index in 0..5 {
        let mut changed = td.clone();
        let register = match index {
            0 => &mut changed.mr_td,
            1 => &mut changed.rt_mr0,
            2 => &mut changed.rt_mr1,
            3 => &mut changed.rt_mr2,
            _ => &mut changed.rt_mr3,
        };
        register[0] ^= 1;
        assert!(check(&changed, &synthetic_log(), &p, &mut Checks::default()).is_err());
    }
    let mut changed = p.clone();
    changed.artifacts.uki_pe_coff_sha384[0] ^= 1;
    assert_eq!(changed.validate(), Err(GcpWorkloadIssue::InvalidPolicy));
    changed = p;
    changed.artifacts.rootfs_verity_sha256 = [0; 32];
    assert_eq!(changed.validate(), Err(GcpWorkloadIssue::InvalidPolicy));
}

#[test]
fn substituted_nonzero_artifact_hashes_never_verify_provenance() {
    let mut policy = synthetic_policy();
    let td = synthetic_report(&policy);
    let log = synthetic_log();
    // Only the UKI PE/COFF measurement is compared with a CCEL event. These
    // other commitments need independent artifact reconstruction at release.
    policy.artifacts.firmware_endorsement_sha256 = [0xa5; 32];
    policy.artifacts.uki_sha256 = [0xa5; 32];
    policy.artifacts.rootfs_verity_sha256 = [0xa5; 32];
    policy.artifacts.kernel_command_line_sha256 = [0xa5; 32];
    policy.artifacts.boot_policy_sha256 = [0xa5; 32];
    policy.artifacts.wrapper_sha256 = [0xa5; 32];
    policy.artifacts.zebra_sha256 = [0xa5; 32];
    policy.artifacts.quote_broker_sha256 = [0xa5; 32];
    policy.artifacts.measurement_recipe_sha256 = [0xa5; 32];

    let mut checks = Checks::default();
    assert_eq!(check(&td, &log, &policy, &mut checks), Ok(()));
    assert_eq!(checks.firmware_measurement, InspectionStatus::Verified);
    assert_eq!(checks.boot_measurements, InspectionStatus::Verified);

    let report = inspect_gcp_workload(QUOTE, COLLATERAL, &log, &policy);
    let output = serde_json::to_value(report).unwrap();
    assert_eq!(output["artifact_provenance"], "not_checked");
    assert_eq!(output["firmware_endorsement_provenance"], "not_checked");
    assert!(output.get("boot_artifact_policy").is_none());
    assert!(output.get("firmware_policy").is_none());
}

#[test]
fn policy_rejects_empty_boot_configuration_and_kernel_register_references() {
    let policy = synthetic_policy();
    for register in [0, 1, 2] {
        let mut changed = policy.clone();
        match register {
            0 => changed.rtmr0 = [0; 48],
            1 => changed.rtmr1 = [0; 48],
            _ => changed.rtmr2 = [0; 48],
        }
        assert_eq!(changed.validate(), Err(GcpWorkloadIssue::InvalidPolicy));
    }
    for register in [1, 3] {
        let mut changed = policy.clone();
        for event in &mut changed.expected_events {
            if event.mr_index == register {
                event.event_type = ccel::EV_NO_ACTION;
            }
        }
        assert_eq!(changed.validate(), Err(GcpWorkloadIssue::InvalidPolicy));
    }
    assert_eq!(policy.validate(), Ok(()));
}

#[test]
fn policies_reject_missing_duplicate_unknown_and_wrong_shape_fields() {
    let p = synthetic_policy();
    let raw = serde_json::to_vec(&p).unwrap();
    assert_eq!(GcpWorkloadPolicy::from_json(&raw), Ok(p));
    for (key, value) in [
        ("schema_version", serde_json::json!(2)),
        ("artifacts", serde_json::json!([])),
        ("verified", serde_json::json!(true)),
        ("expected_events", serde_json::json!([])),
        ("mrtd", serde_json::json!("00")),
    ] {
        let mut object: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        object[key] = value;
        assert!(GcpWorkloadPolicy::from_json(&serde_json::to_vec(&object).unwrap()).is_err());
    }
    let duplicate = String::from_utf8(raw)
        .unwrap()
        .replacen('{', "{\"schema_version\":1,", 1);
    assert!(GcpWorkloadPolicy::from_json(duplicate.as_bytes()).is_err());
    let report = inspect_gcp_workload(b"SYNTHETIC_NOT_A_QUOTE", b"{}", b"", &synthetic_policy());
    assert_eq!(
        report.quote.hardware_authenticity,
        InspectionStatus::Rejected
    );
    assert_eq!(report.ccel_integrity, InspectionStatus::NotChecked);
}

#[test]
fn independently_generated_synthetic_inputs_match_unit_examples_only() {
    let policy = include_bytes!("../../../../tests/fixtures/gcp/policy.synthetic.json");
    let log = include_bytes!("../../../../tests/fixtures/gcp/ccel.synthetic.bin");
    assert_eq!(GcpWorkloadPolicy::from_json(policy), Ok(synthetic_policy()));
    assert_eq!(log.as_slice(), synthetic_log());
}
