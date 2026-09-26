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
            if service == Some("wrapper") && m.kind == "tmpfs" && m.options.contains("ro") {
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
    }
    for m in &mounts {
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
            if !memory && !kernel {
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
        Some("broker") => &["/run"],
        Some("zebra") => &["/run/zrpc-node", "/var/lib/zebra"],
        Some("wrapper") | None => &[],
        _ => return Err(()),
    };
    for path in required_write {
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
fn run() -> Result<(), ()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [flag, service] = args.as_slice() else {
        return Err(());
    };
    if !["--mark-start", "--check"].contains(&flag.as_str())
        || !["broker", "zebra", "wrapper"].contains(&service.as_str())
    {
        return Err(());
    }
    if flag == "--mark-start" && rustix::process::geteuid().as_raw() != 0 {
        return Err(());
    }
    let read = |path: &str| fs::read_to_string(path).map_err(|_| ());
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
            .replace("/ /var rw,", "/ /var ro,")
            .replace("/ /tmp rw,", "/ /tmp ro,");
        assert!(validate_namespace(&narrowed, SWAPS, "/dev/null", "0", Some("zebra")).is_ok());
        let wrong = narrowed.replace("/ /run rw,", "/ /run ro,");
        assert!(validate_namespace(&wrong, SWAPS, "/dev/null", "0", Some("zebra")).is_err());
        let hidden = narrowed.replace(
            "5 4 259:1 / /var/lib/zebra rw,nosuid,nodev,noexec - ext4 /dev/nvme0n2 rw",
            "5 4 0:5 / /var/lib/zebra ro,nosuid,nodev,noexec - tmpfs inaccessible ro",
        );
        assert!(validate_namespace(&hidden, SWAPS, "/dev/null", "0", Some("wrapper")).is_ok());
        assert!(validate_namespace(&hidden, SWAPS, "/dev/null", "0", Some("zebra")).is_err());
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
}
