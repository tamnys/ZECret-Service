//! Immutable pre-start policy. No fixture paths or mount overrides in the CLI.
use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

#[derive(Debug)]
struct Mount<'a> {
    path: &'a str,
    device: &'a str,
    kind: &'a str,
    options: HashSet<&'a str>,
}
fn mounts(text: &str) -> Result<Vec<Mount<'_>>, ()> {
    let mut paths = HashSet::new();
    let mut ids = HashSet::new();
    text.lines()
        .map(|line| {
            let fields: Vec<_> = line.split(' ').collect();
            let separator = fields.iter().position(|field| *field == "-").ok_or(())?;
            if separator < 6 || fields.len() != separator + 4 || fields.contains(&"") {
                return Err(());
            }
            let id = fields[0].parse::<u64>().map_err(|_| ())?;
            let path = fields[4];
            // Approved mount paths have no escapes, dot components or whitespace.
            if !path.starts_with('/')
                || path.contains('\\')
                || path.split('/').any(|p| p == "." || p == "..")
                || !paths.insert(path)
                || !ids.insert(id)
            {
                return Err(());
            }
            if fields[2].split(':').count() != 2
                || fields[2].split(':').any(|p| p.parse::<u32>().is_err())
            {
                return Err(());
            }
            Ok(Mount {
                path,
                device: fields[2],
                kind: fields[separator + 1],
                options: fields[5].split(',').collect(),
            })
        })
        .collect()
}
#[cfg(test)]
fn validate(mountinfo: &str, swaps: &str, core: &str, suid_dump: &str) -> Result<String, ()> {
    validate_namespace(mountinfo, swaps, core, suid_dump, None)
}
fn validate_namespace(
    mountinfo: &str,
    swaps: &str,
    core: &str,
    suid_dump: &str,
    service: Option<&str>,
) -> Result<String, ()> {
    if swaps.lines().collect::<Vec<_>>() != ["Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority"]
        || core.trim() != "/dev/null"
        || suid_dump.trim() != "0"
    {
        return Err(());
    }
    let mounts = mounts(mountinfo)?;
    let root = mounts.iter().find(|m| m.path == "/").ok_or(())?;
    if root.kind != "ext4" || !root.options.contains("ro") {
        return Err(());
    }
    for required in ["/run", "/tmp", "/var", "/var/lib/zebra"] {
        let m = mounts.iter().find(|m| m.path == required).ok_or(())?;
        if required == "/var/lib/zebra" {
            if matches!(service, Some("wrapper" | "broker" | "cookie"))
                && m.kind == "tmpfs"
                && m.options.contains("ro")
            {
                continue;
            }
            if m.kind != "ext4"
                || !["noexec", "nodev", "nosuid"]
                    .iter()
                    .all(|o| m.options.contains(o))
            {
                return Err(());
            }
            if service != Some("broker") && !m.options.contains("rw") {
                return Err(());
            }
        } else if m.kind != "tmpfs" || !["nodev", "nosuid"].iter().all(|o| m.options.contains(o)) {
            return Err(());
        }
        if service.is_none() && !m.options.contains("rw") {
            return Err(());
        }
        if service.is_some() && required != "/var/lib/zebra" && !m.options.contains("ro") {
            return Err(());
        }
    }
    for m in &mounts {
        // A read-only view of another tmpfs may still contain bytes written
        // by a different unit. Check the effective namespace rather than
        // trusting unit directives.
        if service.is_some()
            && ((m.kind == "tmpfs" && !m.options.contains("noexec"))
                || (m.options.contains("rw")
                    && !m.options.contains("noexec")
                    && !matches!(
                        m.kind,
                        "proc" | "sysfs" | "cgroup2" | "configfs" | "securityfs"
                    )))
        {
            return Err(());
        }
        if m.options.contains("rw") && m.path != "/var/lib/zebra" {
            let memory = m.kind == "tmpfs"
                && (m.path == "/run"
                    || m.path.starts_with("/run/")
                    || m.path == "/tmp"
                    || m.path.starts_with("/tmp/")
                    || m.path == "/var"
                    || m.path.starts_with("/var/")
                    || m.path == "/dev"
                    || m.path == "/dev/shm");
            let service_memory = match service {
                None => true,
                Some("broker") => Path::new(m.path).starts_with("/run/zrpc-gcp-quote"),
                Some("cookie") => Path::new(m.path).starts_with("/run/zrpc-wrapper"),
                Some("zebra") => Path::new(m.path).starts_with("/run/zrpc-node"),
                Some("wrapper") => false,
                _ => return Err(()),
            };
            let kernel = matches!(
                (m.path, m.kind),
                ("/dev", "devtmpfs")
                    | ("/dev/pts", "devpts")
                    | ("/proc", "proc")
                    | ("/sys", "sysfs")
                    | ("/sys/fs/cgroup", "cgroup2")
                    | ("/sys/kernel/config", "configfs")
                    | ("/sys/kernel/security", "securityfs")
            );
            if !(memory && service_memory) && !kernel {
                return Err(());
            }
        }
        // Even read-only additional filesystems may introduce executable or
        // configuration inputs. Approve only root, expected memory and kernel.
        if m.path != "/"
            && m.path != "/var/lib/zebra"
            && !(m.kind == "ext4"
                && m.device == root.device
                && m.options.contains("ro")
                && (m.path == "/usr"
                    || m.path.starts_with("/usr/")
                    || m.path == "/etc"
                    || m.path.starts_with("/etc/")))
            && !matches!(
                m.kind,
                "tmpfs"
                    | "devtmpfs"
                    | "devpts"
                    | "proc"
                    | "sysfs"
                    | "cgroup2"
                    | "configfs"
                    | "securityfs"
            )
        {
            return Err(());
        }
        if (m.path == "/usr"
            || m.path.starts_with("/usr/")
            || m.path == "/etc"
            || m.path.starts_with("/etc/"))
            && !(m.kind == "ext4" && m.device == root.device && m.options.contains("ro"))
        {
            return Err(());
        }
        if m.path.starts_with("/var/lib/zebra/") {
            return Err(());
        }
    }
    let required_write: &[&str] = match service {
        Some("broker") => &["/run/zrpc-gcp-quote"],
        Some("zebra") => &["/run/zrpc-node", "/var/lib/zebra"],
        Some("cookie") => &["/run/zrpc-wrapper"],
        Some("wrapper") | None => &[],
        _ => return Err(()),
    };
    for path in required_write {
        if *path != "/var/lib/zebra"
            && service.is_some()
            && !mounts
                .iter()
                .any(|m| m.path == *path && m.kind == "tmpfs" && m.options.contains("rw"))
        {
            return Err(());
        }
        let covering = mounts
            .iter()
            .filter(|m| Path::new(path).starts_with(m.path))
            .max_by_key(|m| m.path.len())
            .ok_or(())?;
        if !covering.options.contains("rw")
            || (covering.kind != "tmpfs" && *path != "/var/lib/zebra")
        {
            return Err(());
        }
    }
    Ok(root.device.to_owned())
}

fn account(passwd: &str, name: &str) -> Result<(u32, u32), ()> {
    let mut entries = passwd
        .lines()
        .filter(|line| line.split(':').next() == Some(name));
    let entry = entries.next().ok_or(())?;
    if entries.next().is_some() {
        return Err(());
    }
    let fields: Vec<_> = entry.split(':').collect();
    if fields.len() != 7 || fields[6] != "/usr/sbin/nologin" {
        return Err(());
    }
    let uid = fields[2].parse::<u32>().map_err(|_| ())?;
    let gid = fields[3].parse::<u32>().map_err(|_| ())?;
    if uid == 0 || gid == 0 {
        return Err(());
    }
    Ok((uid, gid))
}

fn status_value<'a>(status: &'a str, key: &str) -> Result<&'a str, ()> {
    let mut values = status.lines().filter_map(|line| line.strip_prefix(key));
    let value = values.next().ok_or(())?;
    if values.next().is_some() {
        return Err(());
    }
    Ok(value.trim())
}

fn four_ids(status: &str, key: &str, expected: u32) -> Result<(), ()> {
    let ids: Vec<_> = status_value(status, key)?
        .split_whitespace()
        .map(|part| part.parse::<u32>().map_err(|_| ()))
        .collect::<Result<_, _>>()?;
    if ids == [expected; 4] {
        Ok(())
    } else {
        Err(())
    }
}

fn validate_privileges(status: &str, passwd: &str, service: &str) -> Result<(), ()> {
    let (wrapper_uid, wrapper_gid) = account(passwd, "zrpc-wrapper")?;
    let (node_uid, node_gid) = account(passwd, "zrpc-node")?;
    if node_uid == wrapper_uid {
        return Err(());
    }
    let (uid, gid, allowed_caps) = match service {
        "broker" => (0, wrapper_gid, 0),
        // Linux UAPI capability.h: CAP_CHOWN=0, CAP_DAC_READ_SEARCH=2.
        "cookie" => (0, 0, (1 << 0) | (1 << 2)),
        "zebra" => (node_uid, node_gid, 0),
        "wrapper" => (wrapper_uid, wrapper_gid, 0),
        _ => return Err(()),
    };
    four_ids(status, "Uid:", uid)?;
    four_ids(status, "Gid:", gid)?;
    if status_value(status, "NoNewPrivs:")? != "1" {
        return Err(());
    }
    for key in ["CapEff:", "CapPrm:", "CapBnd:", "CapInh:", "CapAmb:"] {
        let caps = u64::from_str_radix(status_value(status, key)?, 16).map_err(|_| ())?;
        if caps & !allowed_caps != 0 {
            return Err(());
        }
    }
    Ok(())
}
fn run() -> Result<(), ()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [flag, service] = args.as_slice() else {
        return Err(());
    };
    if !["--mark-start", "--check"].contains(&flag.as_str())
        || !["broker", "cookie", "zebra", "wrapper"].contains(&service.as_str())
    {
        return Err(());
    }
    if flag == "--mark-start" && rustix::process::geteuid().as_raw() != 0 {
        return Err(());
    }
    let read = |path: &str| fs::read_to_string(path).map_err(|_| ());
    if flag == "--check" {
        validate_privileges(&read("/proc/self/status")?, &read("/etc/passwd")?, service)?;
    }
    let mountinfo = read("/proc/self/mountinfo")?;
    let device = validate_namespace(
        &mountinfo,
        &read("/proc/swaps")?,
        &read("/proc/sys/kernel/core_pattern")?,
        &read("/proc/sys/fs/suid_dumpable")?,
        if flag == "--check" {
            Some(service)
        } else {
            None
        },
    )?;
    let uuid = read(&format!("/sys/dev/block/{device}/dm/uuid"))?;
    if !uuid.trim_end().starts_with("CRYPT-VERITY-") {
        return Err(());
    }
    for path in [
        "/run",
        "/tmp",
        "/var",
        "/var/lib/zebra",
        "/usr/lib/zrpc",
        "/etc/zrpc",
    ] {
        if fs::canonicalize(path).map_err(|_| ())? != Path::new(path) {
            return Err(());
        }
    }
    // Markers prohibit a same-boot retry, but never replace the live checks.
    if flag == "--mark-start" {
        let parent = Path::new("/run/zrpc-starts");
        let metadata = fs::symlink_metadata(parent).map_err(|_| ())?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
            return Err(());
        }
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(parent.join(service))
            .map_err(|_| ())?;
    }
    if read("/proc/self/mountinfo")? != mountinfo {
        return Err(());
    }
    Ok(())
}
fn main() {
    if run().is_err() {
        eprintln!("GCP guest startup denied");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const MOUNTS: &str = "1 0 253:0 / / ro - ext4 /dev/mapper/root ro\n2 1 0:2 / /run rw,nosuid,nodev - tmpfs tmpfs rw\n3 1 0:3 / /tmp rw,nosuid,nodev - tmpfs tmpfs rw\n4 1 0:4 / /var rw,nosuid,nodev - tmpfs tmpfs rw\n5 4 259:1 / /var/lib/zebra rw,nosuid,nodev,noexec - ext4 /dev/nvme0n2 rw\n";
    const SWAPS: &str = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n";
    #[test]
    fn synthetic_mount_contract_rejects_persistence_and_runtime_overrides() {
        assert!(validate(MOUNTS, SWAPS, "/dev/null\n", "0\n").is_ok());
        for bad in [
            MOUNTS.replace("/ / ro", "/ / rw"),
            MOUNTS.replace(
                "/ /var rw,nosuid,nodev - tmpfs",
                "/ /var rw,nosuid,nodev - ext4",
            ),
            MOUNTS.replace("rw,nosuid,nodev,noexec", "rw,nosuid,nodev"),
            format!("{MOUNTS}6 5 259:2 / /var/lib/zebra/config ro - ext4 disk ro\n"),
            format!("{MOUNTS}6 1 259:2 / /etc ro - ext4 disk ro\n"),
            format!("{MOUNTS}6 1 0:8 / /run rw - tmpfs tmpfs rw\n"),
        ] {
            assert!(validate(&bad, SWAPS, "/dev/null", "0").is_err());
        }
        assert!(
            validate(
                MOUNTS,
                &format!("{SWAPS}/swap file 1 0 -1\n"),
                "/dev/null",
                "0"
            )
            .is_err()
        );
        assert!(validate(MOUNTS, SWAPS, "|/usr/bin/dumper", "0").is_err());
    }

    #[test]
    fn service_namespace_checks_allow_only_narrowed_runtime_access() {
        let narrowed = MOUNTS
            .replace("/ /run rw,nosuid,nodev", "/ /run rw,nosuid,nodev,noexec")
            .replace("/ /tmp rw,nosuid,nodev", "/ /tmp rw,nosuid,nodev,noexec")
            .replace("/ /var rw,nosuid,nodev", "/ /var rw,nosuid,nodev,noexec")
            .replace("/ /var rw,", "/ /var ro,")
            .replace("/ /tmp rw,", "/ /tmp ro,")
            .replace("/ /run rw,", "/ /run ro,");
        let node = format!(
            "{narrowed}6 2 0:2 /zrpc-node /run/zrpc-node rw,nosuid,nodev,noexec - tmpfs tmpfs rw\n"
        );
        assert!(validate_namespace(&node, SWAPS, "/dev/null", "0", Some("zebra")).is_ok());
        let node_with_devices =
            format!("{node}7 1 0:7 / /dev rw,nosuid,nodev,noexec - devtmpfs udev rw\n");
        assert!(
            validate_namespace(&node_with_devices, SWAPS, "/dev/null", "0", Some("zebra")).is_ok()
        );
        for executable in [
            node.replace("/ /run ro,nosuid,nodev,noexec", "/ /run ro,nosuid,nodev"),
            node.replace(
                "/run/zrpc-node rw,nosuid,nodev,noexec",
                "/run/zrpc-node rw,nosuid,nodev",
            ),
            node_with_devices.replace("/ /dev rw,nosuid,nodev,noexec", "/ /dev rw,nosuid,nodev"),
        ] {
            assert!(
                validate_namespace(&executable, SWAPS, "/dev/null", "0", Some("zebra")).is_err()
            );
        }
        assert!(validate_namespace(&narrowed, SWAPS, "/dev/null", "0", Some("zebra")).is_err());
        let wrong = node.replace("/ /run ro,", "/ /run rw,");
        assert!(validate_namespace(&wrong, SWAPS, "/dev/null", "0", Some("zebra")).is_err());
        let rogue =
            format!("{node}7 2 0:7 /rogue /run/rogue rw,nosuid,nodev,noexec - tmpfs tmpfs rw\n");
        assert!(validate_namespace(&rogue, SWAPS, "/dev/null", "0", Some("zebra")).is_err());
        let hidden = narrowed.replace(
            "5 4 259:1 / /var/lib/zebra rw,nosuid,nodev,noexec - ext4 /dev/nvme0n2 rw",
            "5 4 0:5 / /var/lib/zebra ro,nosuid,nodev,noexec - tmpfs inaccessible ro",
        );
        assert!(validate_namespace(&hidden, SWAPS, "/dev/null", "0", Some("wrapper")).is_ok());
        assert!(validate_namespace(&hidden, SWAPS, "/dev/null", "0", Some("zebra")).is_err());
        let broker = format!(
            "{hidden}6 2 0:2 /zrpc-gcp-quote /run/zrpc-gcp-quote rw,nosuid,nodev,noexec - tmpfs tmpfs rw\n"
        );
        assert!(validate_namespace(&broker, SWAPS, "/dev/null", "0", Some("broker")).is_ok());
        assert!(validate_namespace(&hidden, SWAPS, "/dev/null", "0", Some("broker")).is_err());
        let cookie = format!(
            "{hidden}6 2 0:2 /zrpc-wrapper /run/zrpc-wrapper rw,nosuid,nodev,noexec - tmpfs tmpfs rw\n"
        );
        assert!(validate_namespace(&cookie, SWAPS, "/dev/null", "0", Some("cookie")).is_ok());
        assert!(validate_namespace(&hidden, SWAPS, "/dev/null", "0", Some("cookie")).is_err());
        assert!(
            validate_namespace(
                &format!("{hidden}6 1 0:8 / /etc ro - tmpfs injected ro\n"),
                SWAPS,
                "/dev/null",
                "0",
                Some("wrapper")
            )
            .is_err()
        );
    }

    fn status(uid: u32, gid: u32, caps: u64, no_new_privs: u8) -> String {
        format!(
            "Uid:\t{uid}\t{uid}\t{uid}\t{uid}\nGid:\t{gid}\t{gid}\t{gid}\t{gid}\nCapInh:\t0000000000000000\nCapPrm:\t{caps:016x}\nCapEff:\t{caps:016x}\nCapBnd:\t{caps:016x}\nCapAmb:\t0000000000000000\nNoNewPrivs:\t{no_new_privs}\n"
        )
    }

    #[test]
    fn service_privileges_reject_root_override_and_capability_expansion() {
        let passwd = "zrpc-wrapper:x:612:613::/nonexistent:/usr/sbin/nologin\nzrpc-node:x:614:615::/nonexistent:/usr/sbin/nologin\n";
        assert!(validate_privileges(&status(612, 613, 0, 1), passwd, "wrapper").is_ok());
        assert!(validate_privileges(&status(614, 615, 0, 1), passwd, "zebra").is_ok());
        assert!(validate_privileges(&status(0, 613, 0, 1), passwd, "broker").is_ok());
        assert!(validate_privileges(&status(0, 0, 5, 1), passwd, "cookie").is_ok());
        for (service, bad) in [
            ("wrapper", status(0, 613, 0, 1)),
            ("zebra", status(614, 0, 0, 1)),
            ("broker", status(0, 613, 1, 1)),
            ("cookie", status(0, 0, 0x25, 1)),
            ("wrapper", status(612, 613, 0, 0)),
            (
                "wrapper",
                format!("{}Uid:\t612\t612\t612\t612\n", status(612, 613, 0, 1)),
            ),
        ] {
            assert!(
                validate_privileges(&bad, passwd, service).is_err(),
                "{service}"
            );
        }
        let duplicate = format!("{passwd}zrpc-wrapper:x:616:617::/nonexistent:/usr/sbin/nologin\n");
        assert!(validate_privileges(&status(612, 613, 0, 1), &duplicate, "wrapper").is_err());
    }
}
