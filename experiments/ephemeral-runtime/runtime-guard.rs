//! Candidate immutable-image pre-start check. No installation or image approval.
//! Linux proc formats: fs/proc_namespace.c::show_mountinfo and
//! mm/swapfile.c::swap_show, plus Documentation/filesystems/proc.rst.
//! Uses only std; compile/test with the managed, already-pinned Rust toolchain.

#[cfg(not(target_os = "linux"))]
compile_error!("the candidate runtime guard requires Linux procfs semantics");

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const RUNTIME_ROOTS: [&str; 3] = [
    "/var/lib/docker",
    "/var/lib/containerd",
    "/var/lib/sysbox",
];

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
    MalformedSwaps,
    SwapPresent,
    ObservedStateChanged,
}

#[derive(Debug)]
struct Mount {
    id: u64,
    parent: u64,
    point: PathBuf,
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
        proc_path(fields[3])?; // Validate the filesystem-relative mount root too.
        let point = proc_path(fields[4])?;
        // Unknown optional fields before '-' are deliberately ignored, as Linux
        // documents. Filesystem identity comes after '-', never from the source.
        mounts.push(Mount {
            id,
            parent,
            point,
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

fn memory_filesystem(mount: &Mount) -> bool {
    matches!(mount.filesystem.as_slice(), b"tmpfs" | b"ramfs")
}

fn check(mountinfo: &[u8], swaps: &[u8], roots: &[PathBuf; 3]) -> Result<(), Denial> {
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

fn live_roots() -> Result<[PathBuf; 3], Denial> {
    let mut roots = Vec::new();
    for path in RUNTIME_ROOTS {
        let root = fs::canonicalize(path).map_err(|_| Denial::RuntimeRootUnavailable)?;
        if !fs::metadata(&root)
            .map_err(|_| Denial::RuntimeRootUnavailable)?
            .is_dir()
        {
            return Err(Denial::RuntimeRootNotDirectory);
        }
        roots.push(root);
    }
    roots.try_into().map_err(|_| Denial::RuntimeRootUnavailable)
}

fn live_check() -> Result<(), Denial> {
    if std::env::args_os().len() != 1 {
        return Err(Denial::ArgumentsUnsupported);
    }
    let mounts = fs::read("/proc/self/mountinfo").map_err(|_| Denial::ProcReadFailed)?;
    let swaps = fs::read("/proc/swaps").map_err(|_| Denial::ProcReadFailed)?;
    let roots = live_roots()?;
    check(&mounts, &swaps, &roots)?;

    // Reject observed changes during this invocation. This is not an atomic
    // mount/swap transaction and cannot prevent changes after the final read.
    if mounts != fs::read("/proc/self/mountinfo").map_err(|_| Denial::ProcReadFailed)?
        || swaps != fs::read("/proc/swaps").map_err(|_| Denial::ProcReadFailed)?
        || roots != live_roots()?
    {
        return Err(Denial::ObservedStateChanged);
    }
    Ok(())
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

    #[test]
    fn memory_roots_and_optional_fields_pass() {
        assert_eq!(check_text(MEMORY), Ok(()));
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
