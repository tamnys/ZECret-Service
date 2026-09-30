//! Narrow GCE Persistent Disk identity importer for the measured guest udev rule.
//!
//! Google guest-configs ba80fe774c17e41c15d92f5c0b1901dd14d35212 reads
//! the NVMe Identify Namespace vendor extension at byte 384. This helper
//! recognizes the public-data disk by default. A separate, explicit paid
//! invocation recognizes only the spent-state disk. It does not use metadata,
//! a shell, a guest agent, or a network endpoint.

use serde::Deserialize;
use std::io::Read;
use std::process::{Command, Stdio};

const NAMESPACE_BYTES: usize = 4096; // NVMe Identify Namespace data structure.
const VENDOR_OFFSET: usize = 384; // Google guest-configs google_nvme_id.
const PUBLIC_DISK: &str = "zrpc-public-data";
const SPENT_DISK: &str = "zrpc-spent-data";

#[derive(Deserialize)]
struct VendorExtension {
    device_name: String,
}

fn namespace_path(path: &str) -> bool {
    let Some(suffix) = path.strip_prefix("/dev/nvme") else {
        return false;
    };
    let Some((controller, namespace)) = suffix.split_once('n') else {
        return false;
    };
    !controller.is_empty()
        && !namespace.is_empty()
        && controller.bytes().all(|byte| byte.is_ascii_digit())
        && namespace.bytes().all(|byte| byte.is_ascii_digit())
}

fn approved_name(namespace: &[u8], expected: &str) -> Result<(), ()> {
    if namespace.len() != NAMESPACE_BYTES {
        return Err(());
    }
    let vendor = &namespace[VENDOR_OFFSET..];
    let end = vendor
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(vendor.len());
    let parsed: VendorExtension = serde_json::from_slice(&vendor[..end]).map_err(|_| ())?;
    if parsed.device_name != expected {
        return Err(());
    }
    Ok(())
}

fn requested_disk(arguments: &[String]) -> Option<(&str, &'static str)> {
    match arguments {
        [path] if !path.starts_with("--") => Some((path, PUBLIC_DISK)),
        [flag, path] if flag == "--spent" => Some((path, SPENT_DISK)),
        _ => None,
    }
}

fn identify(path: &str) -> Result<Vec<u8>, ()> {
    if !namespace_path(path) {
        return Err(());
    }
    let mut child = Command::new("/usr/sbin/nvme")
        .args(["id-ns", "-b", path])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ())?;
    let mut bytes = Vec::with_capacity(NAMESPACE_BYTES);
    let mut stdout = child.stdout.take().ok_or(())?;
    let read = stdout
        .by_ref()
        .take((NAMESPACE_BYTES + 1) as u64)
        .read_to_end(&mut bytes);
    if read.is_err() || bytes.len() != NAMESPACE_BYTES {
        let _ = child.kill();
        let _ = child.wait();
        return Err(());
    }
    if !child.wait().map_err(|_| ())?.success() {
        return Err(());
    }
    Ok(bytes)
}

fn main() {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    let Some((path, expected)) = requested_disk(&arguments) else {
        std::process::exit(1);
    };
    if !identify(path).is_ok_and(|namespace| approved_name(&namespace, expected).is_ok()) {
        std::process::exit(1);
    }
    println!("{expected}");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn namespace(vendor: &[u8]) -> Vec<u8> {
        let mut result = vec![0; NAMESPACE_BYTES];
        result[VENDOR_OFFSET..VENDOR_OFFSET + vendor.len()].copy_from_slice(vendor);
        result
    }

    #[test]
    fn exact_public_disk_is_accepted() {
        assert!(
            approved_name(
                &namespace(br#"{"device_name":"zrpc-public-data"}"#),
                PUBLIC_DISK
            )
            .is_ok()
        );
        assert!(
            approved_name(
                &namespace(br#"{"device_name":"zrpc-public-data"}"#),
                SPENT_DISK
            )
            .is_err()
        );
        assert!(
            approved_name(
                &namespace(br#"{"device_name":"zrpc-spent-data"}"#),
                SPENT_DISK
            )
            .is_ok()
        );
        assert!(
            approved_name(
                &namespace(br#"{"device_name":"zrpc-spent-data"}"#),
                PUBLIC_DISK
            )
            .is_err()
        );
    }

    #[test]
    fn absent_wrong_or_duplicated_identity_is_rejected() {
        for vendor in [
            br#"{}"#.as_slice(),
            b"not-json",
            br#"{"device_name":"other"}"#,
            br#"{"device_name":"zrpc-public-data","device_name":"other"}"#,
        ] {
            assert!(approved_name(&namespace(vendor), PUBLIC_DISK).is_err());
        }
        assert!(
            approved_name(
                &namespace(br#"{"device_name":"zrpc-public-data"}"#)[..4095],
                PUBLIC_DISK
            )
            .is_err()
        );
    }

    #[test]
    fn bytes_after_vendor_json_terminator_are_not_treated_as_a_disk_name() {
        assert!(
            approved_name(
                &namespace(b"{\"device_name\":\"zrpc-public-data\"}\0future-vendor-bytes"),
                PUBLIC_DISK
            )
            .is_ok()
        );
        assert!(
            approved_name(
                &namespace(b"{\"device_name\":\"other\"}\0zrpc-public-data"),
                PUBLIC_DISK
            )
            .is_err()
        );
    }

    #[test]
    fn paid_disk_mode_is_explicit_and_cannot_select_an_arbitrary_device_name() {
        let public = vec!["/dev/nvme0n2".to_owned()];
        let paid = vec!["--spent".to_owned(), "/dev/nvme0n3".to_owned()];
        assert_eq!(requested_disk(&public), Some(("/dev/nvme0n2", PUBLIC_DISK)));
        assert_eq!(requested_disk(&paid), Some(("/dev/nvme0n3", SPENT_DISK)));
        assert_eq!(requested_disk(&[]), None);
        assert_eq!(requested_disk(&["--spent".to_owned()]), None);
        assert_eq!(
            requested_disk(&["--other".to_owned(), "/dev/nvme0n3".to_owned()]),
            None
        );
        assert_eq!(requested_disk(&[paid, public].concat()), None);
    }

    #[test]
    fn only_whole_nvme_namespace_nodes_are_allowed() {
        assert!(namespace_path("/dev/nvme12n3"));
        for path in [
            "/dev/nvme12n3p1",
            "/dev/nvme12",
            "/dev/sda",
            "/dev/nvme0n1/../sda",
        ] {
            assert!(!namespace_path(path));
        }
    }
}
