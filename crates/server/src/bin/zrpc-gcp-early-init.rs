//! Candidate first process for the GCP initrd. The final UKI and hardware boot
//! policy must independently exclude later initrds that could replace /init.

use std::{
    ffi::OsStr,
    fs::{self, File},
    io::Read,
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::Path,
    process::Command,
};

// mkosi 25.3 prepends its repart-derived roothash to KernelCommandLine.
// This checks the fixed flags and shape of that hash, not its identity. The
// signed UKI and reviewed release must bind the exact final .cmdline bytes.
const FIXED_CMDLINE: &str = "ro systemd.gpt_auto=0 rd.systemd.gpt_auto=0 rd.modules_load=dm-verity systemd.import_credentials=no systemd.unit=zrpc.target systemd.crash_shell=0 systemd.crash_action=poweroff systemd.dump_core=0 systemd.mask=debug-shell.service systemd.mask=ctrl-alt-del.target systemd.mask=systemd-hibernate.service systemd.mask=systemd-hybrid-sleep.service systemd.mask=systemd-suspend-then-hibernate.service pstore.backend=none panic=-1 oops=panic module.sig_enforce=1 lockdown=confidentiality";
const ROOT_HASH_PREFIX: &[u8] = b"roothash=";
const SHA256_HEX_BYTES: usize = 64;

fn check_cmdline(bytes: &[u8]) -> Result<(), &'static str> {
    let line = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let expected_len = ROOT_HASH_PREFIX.len() + SHA256_HEX_BYTES + 1 + FIXED_CMDLINE.len();
    if line.len() != expected_len || !line.starts_with(ROOT_HASH_PREFIX) {
        return Err("kernel command line differs");
    }
    let hash = &line[ROOT_HASH_PREFIX.len()..ROOT_HASH_PREFIX.len() + SHA256_HEX_BYTES];
    if !hash
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        || line[ROOT_HASH_PREFIX.len() + SHA256_HEX_BYTES] != b' '
        || &line[ROOT_HASH_PREFIX.len() + SHA256_HEX_BYTES + 1..] != FIXED_CMDLINE.as_bytes()
    {
        return Err("kernel command line differs");
    }
    Ok(())
}

fn check_stub_extra(root: &Path) -> Result<(), &'static str> {
    let extra = root.join(".extra");
    if !fs::symlink_metadata(&extra)
        .map_err(|_| "stub OS release missing")?
        .file_type()
        .is_dir()
    {
        return Err("stub extra directory redirected");
    }
    let mut os_release_seen = false;
    for item in fs::read_dir(extra).map_err(|_| "stub extra directory unreadable")? {
        let item = item.map_err(|_| "stub extra directory unreadable")?;
        if item.file_name() != OsStr::new("os-release") || os_release_seen {
            return Err("unreviewed stub companion input");
        }
        let metadata =
            fs::symlink_metadata(item.path()).map_err(|_| "stub OS release unreadable")?;
        if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o133 != 0 {
            return Err("stub OS release redirected or executable");
        }
        os_release_seen = true;
    }
    if !os_release_seen {
        return Err("stub OS release missing");
    }
    Ok(())
}

fn mount_proc() -> Result<(), &'static str> {
    let proc = fs::symlink_metadata("/proc").map_err(|_| "proc mount point absent")?;
    if !proc.file_type().is_dir() {
        return Err("proc mount point redirected");
    }
    // The kernel does not promise that procfs is mounted before initramfs PID1.
    // A pre-existing or failed mount is not accepted as trusted evidence.
    let result = unsafe {
        libc::mount(
            c"proc".as_ptr(),
            c"/proc".as_ptr(),
            c"proc".as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            std::ptr::null(),
        )
    };
    if result != 0 {
        return Err("proc mount failed");
    }
    Ok(())
}

fn check_boot() -> Result<(), &'static str> {
    if std::process::id() != 1 || unsafe { libc::geteuid() } != 0 {
        return Err("early guard is not root PID1");
    }
    check_stub_extra(Path::new("/"))?;
    mount_proc()?;
    let max_len = ROOT_HASH_PREFIX.len() + SHA256_HEX_BYTES + 1 + FIXED_CMDLINE.len() + 1;
    let mut cmdline = Vec::new();
    File::open("/proc/cmdline")
        .map_err(|_| "kernel command line unavailable")?
        .take((max_len + 1) as u64)
        .read_to_end(&mut cmdline)
        .map_err(|_| "kernel command line unreadable")?;
    check_cmdline(&cmdline)
}

fn clear_boot_environment(command: &mut Command) {
    // systemd 257 normally skips system credential import when the fixed
    // command line says no. An inherited credential-directory variable is a
    // separate import path, so pass no inherited environment to PID1.
    command.env_clear();
}

fn main() {
    if check_boot().is_ok() {
        let mut command = Command::new("/usr/lib/systemd/systemd");
        clear_boot_environment(&mut command);
        let error = command.exec();
        eprintln!("GCP early init refused systemd exec: {error}");
    } else {
        eprintln!("GCP early init rejected boot");
    }
    // No RPC listener has started. If poweroff fails, exiting PID1 leaves the
    // guest unavailable rather than continuing through an unreviewed path.
    unsafe { libc::reboot(libc::RB_POWER_OFF) };
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_flags_match_source_recipe() {
        let source = include_str!("../../../../deploy/gcp/guest/mkosi.conf");
        let lines: Vec<_> = source
            .lines()
            .filter_map(|line| line.strip_prefix("KernelCommandLine="))
            .collect();
        assert_eq!(lines, [FIXED_CMDLINE]);
    }

    #[test]
    fn command_line_rejects_addons_overrides_and_malformed_hashes() {
        let accepted = format!(
            "roothash={} {FIXED_CMDLINE}\n",
            "a".repeat(SHA256_HEX_BYTES)
        );
        assert!(check_cmdline(accepted.as_bytes()).is_ok());
        for rejected in [
            accepted.replace("a", "g"),
            accepted.replace("roothash=", "root=PARTUUID="),
            accepted.replace(" ro ", " init=/bin/sh ro "),
            format!("{accepted}init=/bin/sh"),
            format!("{accepted}\n"),
            accepted.replace("lockdown=confidentiality", "lockdown=none"),
            accepted.replace("pstore.backend=none ", ""),
            accepted.replace("pstore.backend=none", "pstore.backend=efi_pstore"),
            accepted.replace(
                "pstore.backend=none",
                "pstore.backend=none pstore.backend=efi_pstore",
            ),
            accepted.replace(
                "systemd.import_credentials=no",
                "systemd.import_credentials=yes",
            ),
            accepted.replace("systemd.import_credentials=no ", ""),
            accepted.replace(
                "systemd.import_credentials=no",
                "systemd.import_credentials=no systemd.import_credentials=yes",
            ),
        ] {
            assert!(check_cmdline(rejected.as_bytes()).is_err(), "{rejected:?}");
        }
    }

    #[test]
    fn systemd_exec_drops_inherited_credential_directories() {
        let mut command = Command::new("/usr/bin/env");
        command.env("CREDENTIALS_DIRECTORY", "/run/credentials/@initrd");
        command.env(
            "ENCRYPTED_CREDENTIALS_DIRECTORY",
            "/run/credentials/@initrd",
        );
        command.env("SYSTEMD_UNIT_PATH", "/unreviewed");
        clear_boot_environment(&mut command);
        let output = command.output().unwrap();
        assert!(output.status.success());
        assert!(output.stdout.is_empty());
    }

    #[test]
    fn stub_extra_rejects_companions_and_redirects() {
        let root = std::env::temp_dir().join(format!("zrpc-early-init-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        assert!(check_stub_extra(&root).is_err());
        let extra = root.join(".extra");
        fs::create_dir(&extra).unwrap();
        fs::write(extra.join("os-release"), b"ID=debian\n").unwrap();
        assert!(check_stub_extra(&root).is_ok());
        for name in [
            "credentials",
            "global_credentials",
            "sysext",
            "confext",
            "profile",
        ] {
            let path = extra.join(name);
            fs::create_dir(&path).unwrap();
            assert!(check_stub_extra(&root).is_err(), "{name}");
            fs::remove_dir(path).unwrap();
        }
        fs::remove_file(extra.join("os-release")).unwrap();
        std::os::unix::fs::symlink("/etc/os-release", extra.join("os-release")).unwrap();
        assert!(check_stub_extra(&root).is_err());
        fs::remove_file(extra.join("os-release")).unwrap();
        fs::remove_dir(&extra).unwrap();
        std::os::unix::fs::symlink("/etc", &extra).unwrap();
        assert!(check_stub_extra(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
