//! Narrow GCE Persistent Disk identity importer for the measured guest udev rule.
//!
//! Google guest-configs ba80fe774c17e41c15d92f5c0b1901dd14d35212 reads
//! the NVMe Identify Namespace vendor extension at byte 384. This helper
//! deliberately recognizes only the evaluation's public-data disk. It does
//! not use metadata, a shell, a guest agent, or a network endpoint.

use serde::Deserialize;
use std::io::Read;
use std::process::{Command, Stdio};

const NAMESPACE_BYTES: usize = 4096; // NVMe Identify Namespace data structure.
const VENDOR_OFFSET: usize = 384; // Google guest-configs google_nvme_id.
const PUBLIC_DISK: &str = "zrpc-public-data";

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

fn approved_name(namespace: &[u8]) -> Result<(), ()> {
    if namespace.len() != NAMESPACE_BYTES {
        return Err(());
    }
    let vendor = &namespace[VENDOR_OFFSET..];
    let end = vendor
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(vendor.len());
    let parsed: VendorExtension = serde_json::from_slice(&vendor[..end]).map_err(|_| ())?;
    if parsed.device_name != PUBLIC_DISK {
        return Err(());
    }
    Ok(())
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
    let mut arguments = std::env::args();
    let program = arguments.next();
    let path = arguments.next();
    let valid = program.is_some()
        && arguments.next().is_none()
        && path
            .and_then(|path| identify(&path).ok())
            .is_some_and(|namespace| approved_name(&namespace).is_ok());
    if !valid {
        std::process::exit(1);
    }
    println!("{PUBLIC_DISK}");
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
        assert!(approved_name(&namespace(br#"{"device_name":"zrpc-public-data"}"#)).is_ok());
    }

    #[test]
    fn absent_wrong_or_duplicated_identity_is_rejected() {
        for vendor in [
            br#"{}"#.as_slice(),
            b"not-json",
            br#"{"device_name":"other"}"#,
            br#"{"device_name":"zrpc-public-data","device_name":"other"}"#,
        ] {
            assert!(approved_name(&namespace(vendor)).is_err());
        }
        assert!(
            approved_name(&namespace(br#"{"device_name":"zrpc-public-data"}"#)[..4095]).is_err()
        );
    }

    #[test]
    fn bytes_after_vendor_json_terminator_are_not_treated_as_a_disk_name() {
        assert!(
            approved_name(&namespace(
                b"{\"device_name\":\"zrpc-public-data\"}\0future-vendor-bytes"
            ))
            .is_ok()
        );
        assert!(
            approved_name(&namespace(b"{\"device_name\":\"other\"}\0zrpc-public-data")).is_err()
        );
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
