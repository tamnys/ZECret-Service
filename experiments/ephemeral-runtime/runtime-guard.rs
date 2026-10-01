//! Candidate immutable-image pre-start check. No installation or image approval.
//! Linux proc formats: fs/proc_namespace.c::show_mountinfo and
//! mm/swapfile.c::swap_show, plus Documentation/filesystems/proc.rst.
//! Uses only std; compile/test with the managed, already-pinned Rust toolchain.

#[cfg(not(target_os = "linux"))]
compile_error!("the candidate runtime guard requires Linux procfs semantics");

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::ErrorKind;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const RUNTIME_ROOTS: [&str; 4] = [
    "/var/lib/docker",
    "/var/lib/containerd",
    "/var/lib/sysbox",
    "/dstack",
];
const PUBLIC_DATA_MOUNT: &str = "/var/volatile/dstack/persistent";
const PUBLIC_STATE_SOURCE: &str = "/var/volatile/dstack/persistent/zebra-public-testnet";
const PUBLIC_STATE_MOUNT: &str = "/var/lib/zebra-public";
const SHARED_RUNTIME: &str = "/run/zrpc-shared";

#[derive(Debug, PartialEq, Eq)]
enum Denial {
    ArgumentsUnsupported,
    ProcReadFailed,
    RuntimeRootUnavailable,
    RuntimeRootNotDirectory,
    OverlappingRuntimeRoots,
    MalformedMountInfo,
    DuplicateMountId,
    AmbiguousMountPoint,
    MountTopologyMismatch,
    MissingCoveringMount,
    NonMemoryRuntimeMount,
    NonMemoryDescendantMount,
    PublicStateMountUnsafe,
    SharedRuntimeUnsafe,
    MalformedSwaps,
    SwapPresent,
    CrashDumpPolicyUnsafe,
    ObservedStateChanged,
    StartMarkUnavailable,
    AlreadyStarted,
}

const START_SERVICES: [&str; 8] = [
    "docker", "containerd", "sysbox", "sysbox-mgr", "sysbox-fs",
    "app-compose", "dstack-guest-agent", "quote-proxy",
];

enum Mode {
    Probe,
    PreOverlay,
    MarkStart(&'static str),
}

fn mode() -> Result<Mode, Denial> {
    let args: Vec<OsString> = std::env::args_os().collect();
    match args.as_slice() {
        [_] => Ok(Mode::Probe),
        [_, flag] if flag == "--pre-overlay" => Ok(Mode::PreOverlay),
        [_, flag, service] if flag == "--mark-start" => START_SERVICES
            .iter()
            .copied()
            .find(|allowed| service == allowed)
            .map(Mode::MarkStart)
            .ok_or(Denial::ArgumentsUnsupported),
        _ => Err(Denial::ArgumentsUnsupported),
    }
}

#[derive(Debug)]
struct Mount {
    id: u64,
    parent: u64,
    device: Vec<u8>,
    root: PathBuf,
    point: PathBuf,
    options: Vec<u8>,
    filesystem: Vec<u8>,
}

fn decimal(input: &[u8]) -> Result<u64, Denial> {
    if input.is_empty() || !input.iter().all(u8::is_ascii_digit) {
        return Err(Denial::MalformedMountInfo);
    }
    input.iter().try_fold(0_u64, |value, digit| {
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(digit - b'0')))
            .ok_or(Denial::MalformedMountInfo)
    })
}

fn proc_path(input: &[u8]) -> Result<PathBuf, Denial> {
    let mut decoded = Vec::new();
    let mut cursor = 0;
    while cursor < input.len() {
        if input[cursor] == b'\\' {
            let escape = input
                .get(cursor..cursor + 4)
                .ok_or(Denial::MalformedMountInfo)?;
            decoded.push(match escape {
                b"\\040" => b' ',
                b"\\011" => b'\t',
                b"\\012" => b'\n',
                b"\\134" => b'\\',
                _ => return Err(Denial::MalformedMountInfo),
            });
            cursor += 4;
        } else {
            if input[cursor] == 0 || input[cursor].is_ascii_whitespace() {
                return Err(Denial::MalformedMountInfo);
            }
            decoded.push(input[cursor]);
            cursor += 1;
        }
    }
    if decoded.first() != Some(&b'/') {
        return Err(Denial::MalformedMountInfo);
    }
    if decoded != b"/"
        && decoded[1..]
            .split(|byte| *byte == b'/')
            .any(|part| part.is_empty() || part == b"." || part == b"..")
    {
        return Err(Denial::MalformedMountInfo);
    }
    Ok(PathBuf::from(OsString::from_vec(decoded)))
}

fn parse_mountinfo(input: &[u8]) -> Result<Vec<Mount>, Denial> {
    let body = input
        .strip_suffix(b"\n")
        .ok_or(Denial::MalformedMountInfo)?;
    if body.is_empty() {
        return Err(Denial::MalformedMountInfo);
    }
    let mut ids = HashSet::new();
    let mut mounts = Vec::new();
    for line in body.split(|byte| *byte == b'\n') {
        if line.iter().any(|byte| byte.is_ascii_control()) {
            return Err(Denial::MalformedMountInfo);
        }
        let fields: Vec<&[u8]> = line.split(|byte| *byte == b' ').collect();
        if fields.iter().any(|field| field.is_empty()) {
            return Err(Denial::MalformedMountInfo);
        }
        let separator = fields
            .iter()
            .position(|field| *field == b"-")
            .ok_or(Denial::MalformedMountInfo)?;
        if separator < 6 || fields.len() != separator + 4 {
            return Err(Denial::MalformedMountInfo);
        }
        let id = decimal(fields[0])?;
        let parent = decimal(fields[1])?;
        if !ids.insert(id) {
            return Err(Denial::DuplicateMountId);
        }
        let device: Vec<&[u8]> = fields[2].split(|byte| *byte == b':').collect();
        if device.len() != 2 {
            return Err(Denial::MalformedMountInfo);
        }
        decimal(device[0])?;
        decimal(device[1])?;
        let root = proc_path(fields[3])?;
        let point = proc_path(fields[4])?;
        // Unknown optional fields before '-' are deliberately ignored, as Linux
        // documents. Filesystem identity comes after '-', never from the source.
        mounts.push(Mount {
            id,
            parent,
            device: fields[2].to_vec(),
            root,
            point,
            options: fields[5].to_vec(),
            filesystem: fields[separator + 1].to_vec(),
        });
    }
    Ok(mounts)
}

fn no_swap(input: &[u8]) -> Result<(), Denial> {
    let body = input.strip_suffix(b"\n").ok_or(Denial::MalformedSwaps)?;
    let mut lines = body.split(|byte| *byte == b'\n');
    let header: Vec<&[u8]> = lines
        .next()
        .ok_or(Denial::MalformedSwaps)?
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|part| !part.is_empty())
        .collect();
    if header != [b"Filename".as_slice(), b"Type", b"Size", b"Used", b"Priority"] {
        return Err(Denial::MalformedSwaps);
    }
    // Every additional record is refused, including zero-use swap and zram.
    // There is no reason to interpret swap filenames or numeric fields.
    if lines.next().is_some() {
        return Err(Denial::SwapPresent);
    }
    Ok(())
}

fn no_core_dump(pattern: &[u8], uses_pid: &[u8], suid_dumpable: &[u8]) -> Result<(), Denial> {
    // Linux core(5): an empty pattern with core_uses_pid=0 writes no dump.
    // Refuse pipe handlers: RLIMIT_CORE does not constrain their input.
    if pattern != b"\n" || uses_pid != b"0\n" || suid_dumpable != b"0\n" {
        return Err(Denial::CrashDumpPolicyUnsafe);
    }
    Ok(())
}

fn live_core_policy() -> Result<[Vec<u8>; 3], Denial> {
    [
        "/proc/sys/kernel/core_pattern",
        "/proc/sys/kernel/core_uses_pid",
        "/proc/sys/fs/suid_dumpable",
    ]
    .map(|path| fs::read(path).map_err(|_| Denial::ProcReadFailed))
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?
    .try_into()
    .map_err(|_| Denial::ProcReadFailed)
}

fn memory_filesystem(mount: &Mount) -> bool {
    matches!(mount.filesystem.as_slice(), b"tmpfs" | b"ramfs")
}

fn has_option(mount: &Mount, option: &[u8]) -> bool {
    mount.options.split(|byte| *byte == b',').any(|part| part == option)
}

fn check_public_data_mount(mountinfo: &[u8]) -> Result<(), Denial> {
    let mounts = parse_mountinfo(mountinfo)?;
    let unique_at = |point: &str| -> Result<&Mount, Denial> {
        let mut found = mounts.iter().filter(|mount| mount.point == Path::new(point));
        let mount = found.next().ok_or(Denial::PublicStateMountUnsafe)?;
        if found.next().is_some() {
            return Err(Denial::AmbiguousMountPoint);
        }
        Ok(mount)
    };
    let data = unique_at(PUBLIC_DATA_MOUNT)?;
    let state = unique_at(PUBLIC_STATE_MOUNT)?;
    if data.filesystem != b"ext4"
        || data.root != Path::new("/")
        || state.filesystem != b"ext4"
        || state.root != Path::new("/zebra-public-testnet")
        || state.device != data.device
        || ![data, state].iter().all(|mount| {
            [b"rw".as_slice(), b"noexec", b"nodev", b"nosuid", b"nosymfollow"]
                .iter()
                .all(|option| has_option(mount, option))
        })
    {
        return Err(Denial::PublicStateMountUnsafe);
    }
    for endpoint in [data, state] {
        let chain: Vec<&Mount> = mounts.iter()
            .filter(|mount| endpoint.point.starts_with(&mount.point))
            .collect();
        let mut seen = HashSet::new();
        for mount in &chain {
            if !seen.insert(&mount.point) {
                return Err(Denial::AmbiguousMountPoint);
            }
            if mount.point != Path::new("/") {
                let parent = chain.iter()
                    .filter(|candidate| candidate.point != mount.point
                        && mount.point.starts_with(&candidate.point))
                    .max_by_key(|candidate| candidate.point.as_os_str().as_bytes().len())
                    .ok_or(Denial::MountTopologyMismatch)?;
                if mount.parent != parent.id {
                    return Err(Denial::MountTopologyMismatch);
                }
            }
        }
        if mounts.iter().any(|mount| mount.point != endpoint.point
            && mount.point.starts_with(&endpoint.point)) {
            return Err(Denial::MountTopologyMismatch);
        }
    }
    Ok(())
}

fn live_public_state() -> Result<(), Denial> {
    let mut identity = None;
    for path in [PUBLIC_STATE_SOURCE, PUBLIC_STATE_MOUNT] {
        let target = Path::new(path);
        let entry = fs::symlink_metadata(target).map_err(|_| Denial::PublicStateMountUnsafe)?;
        if !entry.is_dir() || entry.file_type().is_symlink()
            || fs::canonicalize(target).map_err(|_| Denial::PublicStateMountUnsafe)? != target
            || entry.uid() != 10001 || entry.gid() != 10001
            || entry.permissions().mode() & 0o7777 != 0o700
        {
            return Err(Denial::PublicStateMountUnsafe);
        }
        let current = (entry.dev(), entry.ino());
        if let Some(previous) = identity {
            if current != previous {
                return Err(Denial::PublicStateMountUnsafe);
            }
        }
        identity = Some(current);
    }
    Ok(())
}

fn check_shared_runtime(mountinfo: &[u8]) -> Result<(), Denial> {
    if parse_mountinfo(mountinfo)?.iter().any(|mount| {
        mount.point == Path::new(SHARED_RUNTIME)
            || mount.point.starts_with(Path::new(SHARED_RUNTIME))
    }) {
        return Err(Denial::SharedRuntimeUnsafe);
    }
    Ok(())
}

fn live_shared_runtime() -> Result<(), Denial> {
    let path = Path::new(SHARED_RUNTIME);
    let entry = fs::symlink_metadata(path).map_err(|_| Denial::SharedRuntimeUnsafe)?;
    if !entry.is_dir() || entry.file_type().is_symlink()
        || fs::canonicalize(path).map_err(|_| Denial::SharedRuntimeUnsafe)? != path
        || entry.uid() != 10001 || entry.gid() != 10001
        || entry.permissions().mode() & 0o7777 != 0o700
    {
        return Err(Denial::SharedRuntimeUnsafe);
    }
    Ok(())
}

fn check(mountinfo: &[u8], swaps: &[u8], roots: &[PathBuf]) -> Result<(), Denial> {
    no_swap(swaps)?;
    for (index, root) in roots.iter().enumerate() {
        if !root.is_absolute() {
            return Err(Denial::RuntimeRootUnavailable);
        }
        for other in &roots[index + 1..] {
            if root.starts_with(other) || other.starts_with(root) {
                return Err(Denial::OverlappingRuntimeRoots);
            }
        }
    }
    let mounts = parse_mountinfo(mountinfo)?;
    let relevant: Vec<&Mount> = mounts
        .iter()
        .filter(|mount| {
            roots
                .iter()
                .any(|root| root.starts_with(&mount.point) || mount.point.starts_with(root))
        })
        .collect();
    let mut points = HashMap::new();
    for mount in &relevant {
        if points.insert(&mount.point, mount.id).is_some() {
            return Err(Denial::AmbiguousMountPoint);
        }
    }

    // A lexical path alone can describe a hidden mount beneath a later ancestor
    // overmount. Require its parent ID to agree with the nearest path ancestor.
    // Stacked relevant mountpoints are refused rather than choosing a winner.
    for mount in &relevant {
        if mount.point == Path::new("/") {
            if mount.parent != mount.id && mounts.iter().any(|item| item.id == mount.parent) {
                return Err(Denial::MountTopologyMismatch);
            }
            continue; // A process-root mount may have an unlisted parent.
        }
        let parent = relevant
            .iter()
            .filter(|candidate| candidate.point != mount.point && mount.point.starts_with(&candidate.point))
            .max_by_key(|candidate| candidate.point.as_os_str().as_bytes().len())
            .ok_or(Denial::MountTopologyMismatch)?;
        if mount.parent != parent.id {
            return Err(Denial::MountTopologyMismatch);
        }
    }

    for root in roots {
        let covering = relevant
            .iter()
            .filter(|mount| root.starts_with(&mount.point))
            .max_by_key(|mount| mount.point.as_os_str().as_bytes().len())
            .ok_or(Denial::MissingCoveringMount)?;
        if !memory_filesystem(covering) {
            return Err(Denial::NonMemoryRuntimeMount);
        }
        for mount in &relevant {
            if mount.point != *root && mount.point.starts_with(root) && !memory_filesystem(mount) {
                return Err(Denial::NonMemoryDescendantMount);
            }
        }
    }
    Ok(())
}

fn live_paths(paths: &[&str]) -> Result<Vec<PathBuf>, Denial> {
    let mut roots = Vec::new();
    for path in paths {
        let root = fs::canonicalize(path).map_err(|_| Denial::RuntimeRootUnavailable)?;
        if !fs::metadata(&root)
            .map_err(|_| Denial::RuntimeRootUnavailable)?
            .is_dir()
        {
            return Err(Denial::RuntimeRootNotDirectory);
        }
        roots.push(root);
    }
    Ok(roots)
}

fn live_roots() -> Result<[PathBuf; 4], Denial> {
    live_paths(&RUNTIME_ROOTS)?
        .try_into()
        .map_err(|_| Denial::RuntimeRootUnavailable)
}

fn live_check() -> Result<(), Denial> {
    let mode = mode()?;
    let mounts = fs::read("/proc/self/mountinfo").map_err(|_| Denial::ProcReadFailed)?;
    let swaps = fs::read("/proc/swaps").map_err(|_| Denial::ProcReadFailed)?;
    let core = live_core_policy()?;
    no_core_dump(&core[0], &core[1], &core[2])?;
    if matches!(mode, Mode::PreOverlay) {
        // These are the stock image's memory-backed writable system roots.
        // Verify them before overlay setup and before reading KMS material.
        let early = live_paths(&["/var/volatile", "/run", "/tmp"])?;
        check(&mounts, &swaps, &early)?;
        if mounts != fs::read("/proc/self/mountinfo").map_err(|_| Denial::ProcReadFailed)?
            || swaps != fs::read("/proc/swaps").map_err(|_| Denial::ProcReadFailed)?
            || core != live_core_policy()?
            || early != live_paths(&["/var/volatile", "/run", "/tmp"])?
        {
            return Err(Denial::ObservedStateChanged);
        }
        return Ok(());
    }
    // Runtime roots alone do not cover sockets, temporary configuration and
    // other private process files placed beneath /run or /tmp.
    let scratch = live_paths(&["/run", "/tmp"])?;
    check(&mounts, &swaps, &scratch)?;
    let roots = live_roots()?;
    check(&mounts, &swaps, &roots)?;
    check_public_data_mount(&mounts)?;
    live_public_state()?;
    check_shared_runtime(&mounts)?;
    live_shared_runtime()?;
    if matches!(mode, Mode::MarkStart(_)) {
        // The denial marker is never a readiness proof. It may only live on
        // memory-backed /run, so same-boot retries cannot use persistent state.
        check(&mounts, &swaps, &[PathBuf::from("/run/zrpc-starts")])?;
    }

    // Reject observed changes during this invocation. This is not an atomic
    // mount/swap transaction and cannot prevent changes after the final read.
    if mounts != fs::read("/proc/self/mountinfo").map_err(|_| Denial::ProcReadFailed)?
        || swaps != fs::read("/proc/swaps").map_err(|_| Denial::ProcReadFailed)?
        || core != live_core_policy()?
        || scratch != live_paths(&["/run", "/tmp"])?
        || roots != live_roots()?
    {
        return Err(Denial::ObservedStateChanged);
    }
    live_public_state()?;
    live_shared_runtime()?;
    if let Mode::MarkStart(service) = mode {
        mark_start(Path::new("/run/zrpc-starts"), service, 0)?;
    }
    Ok(())
}

fn mark_start(directory: &Path, service: &str, required_uid: u32) -> Result<(), Denial> {
    if !START_SERVICES.contains(&service) {
        return Err(Denial::ArgumentsUnsupported);
    }
    match fs::create_dir(directory) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
        Err(_) => return Err(Denial::StartMarkUnavailable),
    }
    let metadata = fs::symlink_metadata(directory).map_err(|_| Denial::StartMarkUnavailable)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.uid() != required_uid {
        return Err(Denial::StartMarkUnavailable);
    }
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
        .map_err(|_| Denial::StartMarkUnavailable)?;
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join(service))
    {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => Err(Denial::AlreadyStarted),
        Err(_) => Err(Denial::StartMarkUnavailable),
    }
}

fn main() -> ExitCode {
    match live_check() {
        Ok(()) => {
            println!("{{\"candidate_runtime_storage_check\":\"passed\",\"private_accepted\":false}}");
            ExitCode::SUCCESS
        }
        Err(reason) => {
            eprintln!("candidate runtime storage check denied: {reason:?}; private_accepted=false");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MEMORY: &str = include_str!("fixtures/memory.mountinfo");
    const PERSISTENT: &str = include_str!("fixtures/persistent.mountinfo");
    const NO_SWAP: &[u8] = include_bytes!("fixtures/no-swaps.proc");
    const ACTIVE_SWAP: &[u8] = include_bytes!("fixtures/active-swaps.proc");

    fn roots() -> [PathBuf; 3] {
        ["docker", "containerd", "sysbox"].map(|name| Path::new("/var/volatile/lib").join(name))
    }

    fn check_text(text: &str) -> Result<(), Denial> {
        check(text.as_bytes(), NO_SWAP, &roots())
    }

    fn public_mounts() -> String {
        format!(
            "{MEMORY}\
40 10 253:0 / /var/volatile/dstack/persistent rw,nosuid,nodev,noexec,nosymfollow - ext4 /dev/dm-0 rw\n\
41 1 253:0 /zebra-public-testnet /var/lib/zebra-public rw,nosuid,nodev,noexec,nosymfollow - ext4 /dev/dm-0 rw\n"
        )
    }

    #[test]
    fn only_reviewed_public_directory_may_bind_persistent_data() {
        let mounted = public_mounts();
        assert_eq!(check_public_data_mount(mounted.as_bytes()), Ok(()));
        assert_eq!(check_public_data_mount(MEMORY.as_bytes()), Err(Denial::PublicStateMountUnsafe));
        for changed in [
            mounted.replace("/zebra-public-testnet /var/lib/zebra-public", "/ /var/lib/zebra-public"),
            mounted.replace("41 1 253:0", "41 1 253:1"),
            mounted.replace("41 1 253:0", "41 10 253:0"),
            mounted.replace("- ext4 /dev/dm-0", "- overlay overlay"),
            mounted.replace("rw,nosuid,nodev,noexec,nosymfollow", "rw,nosuid,nodev,noexec"),
            mounted.replace("rw,nosuid,nodev,noexec,nosymfollow", "ro,nosuid,nodev,noexec,nosymfollow"),
            format!("{mounted}42 41 0:42 / /var/lib/zebra-public/hidden rw - tmpfs tmpfs rw\n"),
            format!("{mounted}42 40 0:42 / /var/volatile/dstack/persistent/hidden rw - tmpfs tmpfs rw\n"),
            format!("{mounted}42 1 0:42 / /var/lib rw - tmpfs tmpfs rw\n"),
            format!("{mounted}42 10 0:42 / /var/volatile/dstack rw - tmpfs tmpfs rw\n"),
        ] {
            assert!(check_public_data_mount(changed.as_bytes()).is_err(), "{changed}");
        }
    }

    #[test]
    fn shared_runtime_is_an_unmounted_directory_beneath_run() {
        assert_eq!(check_shared_runtime(MEMORY.as_bytes()), Ok(()));
        for point in ["/run/zrpc-shared", "/run/zrpc-shared/cookie"] {
            let changed = format!("{MEMORY}42 1 0:42 / {point} rw - tmpfs tmpfs rw\n");
            assert_eq!(check_shared_runtime(changed.as_bytes()), Err(Denial::SharedRuntimeUnsafe));
        }
    }

    #[test]
    fn memory_roots_and_optional_fields_pass() {
        assert_eq!(check_text(MEMORY), Ok(()));
    }

    #[test]
    fn pre_overlay_storage_must_be_memory_backed_without_swap() {
        let volatile = [PathBuf::from("/var/volatile")];
        assert_eq!(check(MEMORY.as_bytes(), NO_SWAP, &volatile), Ok(()));
        assert_eq!(check(PERSISTENT.as_bytes(), NO_SWAP, &volatile), Err(Denial::NonMemoryDescendantMount));
        assert_eq!(check(MEMORY.as_bytes(), ACTIVE_SWAP, &volatile), Err(Denial::SwapPresent));
    }

    #[test]
    fn run_and_tmp_require_memory_mounts_without_persistent_children() {
        let early = ["/var/volatile", "/run", "/tmp"].map(PathBuf::from);
        let run = "3 1 0:3 / /run rw - tmpfs tmpfs rw\n";
        let tmp = "4 1 0:4 / /tmp rw - tmpfs tmpfs rw\n";
        let mounts = format!("{MEMORY}{run}{tmp}");
        assert_eq!(check(mounts.as_bytes(), NO_SWAP, &early), Ok(()));
        assert_eq!(check(MEMORY.as_bytes(), NO_SWAP, &early), Err(Denial::NonMemoryRuntimeMount));
        for (original, replacement) in [
            (run, "3 1 253:0 / /run rw - ext4 /dev/dm-1 rw\n"),
            (tmp, "4 1 253:0 / /tmp rw - ext4 /dev/dm-1 rw\n"),
        ] {
            assert_eq!(
                check(mounts.replace(original, replacement).as_bytes(), NO_SWAP, &early),
                Err(Denial::NonMemoryRuntimeMount)
            );
        }
        let nested = format!("{mounts}5 3 253:0 / /run/private rw - ext4 /dev/dm-1 rw\n");
        assert_eq!(check(nested.as_bytes(), NO_SWAP, &early), Err(Denial::NonMemoryDescendantMount));
    }

    #[test]
    fn start_mark_requires_memory_and_refuses_same_boot_retry() {
        let with_run = MEMORY.to_owned() + "3 1 0:3 / /run rw - tmpfs tmpfs rw\n";
        let marker = [PathBuf::from("/run/zrpc-starts")];
        assert_eq!(check(with_run.as_bytes(), NO_SWAP, &marker), Ok(()));
        assert_eq!(check(MEMORY.as_bytes(), NO_SWAP, &marker), Err(Denial::NonMemoryRuntimeMount));

        let unique = format!(
            "zrpc-guard-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let base = std::env::temp_dir().join(unique);
        fs::create_dir(&base).unwrap();
        let required_uid = fs::metadata(&base).unwrap().uid();
        let directory = base.join("starts");
        assert_eq!(mark_start(&directory, "docker", required_uid), Ok(()));
        assert_eq!(mark_start(&directory, "docker", required_uid), Err(Denial::AlreadyStarted));
        assert_eq!(mark_start(&directory, "containerd", required_uid), Ok(()));
        assert_eq!(mark_start(&directory, "unknown", required_uid), Err(Denial::ArgumentsUnsupported));
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn source_name_is_not_filesystem_identity() {
        assert_eq!(check_text(PERSISTENT), Err(Denial::NonMemoryRuntimeMount));
        assert_eq!(check_text(&MEMORY.replace("- tmpfs tmpfs", "- ext4 tmpfs")),
                   Err(Denial::NonMemoryRuntimeMount));
    }

    #[test]
    fn missing_memory_root_cannot_inherit_persistent_root() {
        let text = MEMORY.lines().filter(|line| !line.contains("/var/volatile"))
            .collect::<Vec<_>>().join("\n") + "\n";
        assert_eq!(check_text(&text), Err(Denial::NonMemoryRuntimeMount));
    }

    #[test]
    fn canonical_roots_may_inherit_one_memory_filesystem() {
        let text = MEMORY.lines().filter(|line| !line.contains("/var/volatile/lib/"))
            .collect::<Vec<_>>().join("\n") + "\n";
        assert_eq!(check_text(&text), Ok(()));
    }

    #[test]
    fn nested_persistent_mount_with_escaped_path_is_denied() {
        let text = format!("{MEMORY}30 20 253:0 /cache /var/volatile/lib/docker/cache\\040state rw - ext4 /dev/dm-1 rw\n");
        assert_eq!(check_text(&text), Err(Denial::NonMemoryDescendantMount));
    }

    #[test]
    fn overlays_are_denied_without_guessing_their_backing() {
        let text = format!("{MEMORY}30 20 0:30 / /var/volatile/lib/docker/overlay2/merged rw - overlay overlay rw,upperdir=/ram/upper,lowerdir=/ram/lower\n");
        assert_eq!(check_text(&text), Err(Denial::NonMemoryDescendantMount));
    }

    #[test]
    fn nested_memory_mount_passes_and_prefix_sibling_is_unrelated() {
        let text = format!("{MEMORY}30 20 0:30 / /var/volatile/lib/docker/cache rw - tmpfs none rw\n31 10 253:0 / /var/volatile/lib/docker-old rw - ext4 /dev/dm-1 rw\n");
        assert_eq!(check_text(&text), Ok(()));
    }

    #[test]
    fn stacked_memory_mount_is_ambiguous() {
        let text = format!("{MEMORY}30 20 0:30 / /var/volatile/lib/docker rw - tmpfs tmpfs rw\n");
        assert_eq!(check_text(&text), Err(Denial::AmbiguousMountPoint));
    }

    #[test]
    fn ancestor_overmount_cannot_hide_persistent_or_memory_children() {
        let text = format!("{MEMORY}30 10 253:0 / /var/volatile/lib rw - ext4 /dev/dm-1 rw\n");
        assert_eq!(check_text(&text), Err(Denial::MountTopologyMismatch));
    }

    #[test]
    fn duplicate_ids_and_wrong_parent_are_denied() {
        assert_eq!(check_text(&MEMORY.replace("21 10", "20 10")), Err(Denial::DuplicateMountId));
        assert_eq!(check_text(&MEMORY.replace("21 10", "21 1")), Err(Denial::MountTopologyMismatch));
    }

    #[test]
    fn aliased_or_nested_canonical_runtime_roots_are_denied() {
        let mut aliases = roots();
        aliases[1] = aliases[0].clone();
        assert_eq!(check(MEMORY.as_bytes(), NO_SWAP, &aliases), Err(Denial::OverlappingRuntimeRoots));
        aliases[1] = aliases[0].join("nested");
        assert_eq!(check(MEMORY.as_bytes(), NO_SWAP, &aliases), Err(Denial::OverlappingRuntimeRoots));
    }

    #[test]
    fn active_swap_is_denied_even_when_unused_or_memory_compressed() {
        assert_eq!(check(MEMORY.as_bytes(), ACTIVE_SWAP, &roots()), Err(Denial::SwapPresent));
        let zram = b"Filename\tType\tSize\tUsed\tPriority\n/dev/zram0 partition 1024 0 100\n";
        assert_eq!(check(MEMORY.as_bytes(), zram, &roots()), Err(Denial::SwapPresent));
    }

    #[test]
    fn any_core_dump_file_or_pipe_policy_is_denied() {
        assert_eq!(no_core_dump(b"\n", b"0\n", b"0\n"), Ok(()));
        for (pattern, uses_pid, suid_dumpable) in [
            (b"core\n".as_slice(), b"0\n".as_slice(), b"0\n".as_slice()),
            (b"|/usr/lib/systemd/systemd-coredump\n", b"0\n", b"0\n"),
            (b"/dev/null\n", b"0\n", b"0\n"),
            (b"\n", b"1\n", b"0\n"),
            (b"\n", b"0\n", b"2\n"),
            (b"", b"0\n", b"0\n"),
        ] {
            assert_eq!(no_core_dump(pattern, uses_pid, suid_dumpable),
                       Err(Denial::CrashDumpPolicyUnsafe));
        }
    }

    #[test]
    fn incomplete_and_malformed_proc_records_fail_closed() {
        for malformed in ["", "\n", "1 0 0:1 / / rw tmpfs none rw\n", "1 0 0:1 / / rw - tmpfs none\n"] {
            assert_eq!(check_text(malformed), Err(Denial::MalformedMountInfo));
        }
        assert_eq!(check_text(MEMORY.trim_end()), Err(Denial::MalformedMountInfo));
        assert_eq!(check_text(&MEMORY.replace("0:20", "bad:20")), Err(Denial::MalformedMountInfo));
        assert_eq!(check_text(&MEMORY.replace("20 10", "x 10")), Err(Denial::MalformedMountInfo));
        assert_eq!(check_text(&MEMORY.replace("20 10", "18446744073709551616 10")), Err(Denial::MalformedMountInfo));
        assert_eq!(no_swap(b""), Err(Denial::MalformedSwaps));
        assert_eq!(no_swap(b"Filename Type Size Used\n"), Err(Denial::MalformedSwaps));
        assert_eq!(no_swap(b"Filename Type Size Used Priority"), Err(Denial::MalformedSwaps));
    }

    #[test]
    fn pathname_escapes_are_decoded_once_and_invalid_escapes_are_denied() {
        assert_eq!(proc_path(br"/a\040b\011c\012d\134040").unwrap().as_os_str().as_bytes(),
                   b"/a b\tc\nd\\040");
        for bad in [br"/bad\000".as_slice(), br"/bad\999", br"/bad\04", b"relative", b"/a/../b", b"/a//b"] {
            assert_eq!(proc_path(bad), Err(Denial::MalformedMountInfo));
        }
    }
}
