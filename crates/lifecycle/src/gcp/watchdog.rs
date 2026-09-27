//! External Linux/systemd controls. Export never installs or enables units.
//! Live admission reads effective units and current clock state locally.
use super::{
    Error, Result,
    package::{Artifact, Package},
    provider::Runtime,
    read_regular,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Controls {
    pub package_sha256: String,
    pub executable: Artifact,
    pub runtime_file: Artifact,
    pub state_directory: PathBuf,
    pub controller_machine_id: String,
    pub controller_uid: u32,
    /// Timings supplied from the rehearsal report, never invented defaults.
    pub poll_interval_seconds: u64,
    pub deletion_duration_seconds: u64,
    pub systemd_delay_seconds: u64,
    pub deletion_rehearsal: Artifact,
    pub independent_backstop: Artifact,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rehearsal {
    pub controller_machine_id: String,
    pub executable_sha256: String,
    pub runtime_sha256: String,
    pub completed_at: u64,
    pub measured_deletion_duration_seconds: u64,
    pub measured_systemd_delay_seconds: u64,
    pub evidence: Vec<Artifact>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backstop {
    pub package_sha256: String,
    pub check_by_unix_seconds: u64,
    pub operator_reference: String,
}
fn safe_path(path: &Path) -> Result<&str> {
    let s = path.to_str().ok_or(Error("invalid external-host path"))?;
    // Literal paths simplify exact systemd ExecStart comparison and avoid
    // specifier/environment/quote expansion. No shell invocation is generated.
    if !path.is_absolute()
        || s.bytes()
            .any(|b| !b.is_ascii_alphanumeric() && !b"/_- .".contains(&b))
        || s.contains(' ')
        || s.split('/').any(|s| s == ".." || s == ".")
    {
        return Err(Error(
            "external control paths must be absolute literal paths without spaces",
        ));
    }
    Ok(s)
}

/// The unit pins a controls *path*, not its contents. Reject a path that
/// another local UID could replace after deployment admission. The controller
/// UID itself remains part of the trusted external-host boundary.
pub fn verify_controls_path(path: &Path, controller_uid: u32) -> Result<()> {
    safe_path(path)?;
    let metadata =
        fs::symlink_metadata(path).map_err(|_| Error("external controls file unavailable"))?;
    if !metadata.is_file()
        || metadata.uid() != 0 && metadata.uid() != controller_uid
        || metadata.mode() & 0o022 != 0
    {
        return Err(Error("external controls file permits replacement"));
    }
    for parent in path.ancestors().skip(1) {
        let metadata = fs::symlink_metadata(parent)
            .map_err(|_| Error("external controls path unavailable"))?;
        let root_owned_sticky = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
        if !metadata.is_dir()
            || metadata.uid() != 0 && metadata.uid() != controller_uid
            || metadata.mode() & 0o022 != 0 && !root_owned_sticky
        {
            return Err(Error("external controls path permits replacement"));
        }
    }
    Ok(())
}
impl Controls {
    pub fn deletion_start(&self, package: &Package) -> Result<u64> {
        let runtime: Runtime = serde_json::from_slice(&read_regular(&self.runtime_file.path)?)
            .map_err(|_| Error("invalid runtime file"))?;
        // A timer cannot interrupt a running oneshot. Include its entire
        // admitted budget in the original deadline reserve.
        let lead = self
            .deletion_duration_seconds
            .checked_add(self.poll_interval_seconds)
            .and_then(|n| n.checked_add(self.systemd_delay_seconds))
            .and_then(|n| n.checked_add(runtime.invocation_budget_ms.div_ceil(1000)))
            .ok_or(Error("watchdog timing overflow"))?;
        package
            .spec
            .deadline_unix_seconds
            .checked_sub(lead)
            .filter(|t| *t > package.spec.start_unix_seconds)
            .ok_or(Error(
                "measured cleanup allowance does not fit original experiment window",
            ))
    }
    pub fn validate(&self, package: &Package, at: u64) -> Result<()> {
        if self.package_sha256 != package.sha256()?
            || self.controller_uid == 0
            || self.controller_uid == u32::MAX
            || self.poll_interval_seconds == 0
            || self.deletion_duration_seconds == 0
            || self.systemd_delay_seconds == 0
        {
            return Err(Error(
                "external controls lack matching package, non-root UID, or measured timing",
            ));
        }
        if self.controller_machine_id.len() != 32
            || !self
                .controller_machine_id
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
        {
            return Err(Error("external Linux machine identity required"));
        }
        for a in [
            &self.executable,
            &self.runtime_file,
            &self.deletion_rehearsal,
            &self.independent_backstop,
        ] {
            a.verify()?;
            safe_path(&a.path)?;
        }
        safe_path(&self.state_directory)?;
        let rehearsal: Rehearsal =
            serde_json::from_slice(&read_regular(&self.deletion_rehearsal.path)?)
                .map_err(|_| Error("invalid external deletion rehearsal"))?;
        if rehearsal.controller_machine_id != self.controller_machine_id
            || rehearsal.executable_sha256 != self.executable.sha256
            || rehearsal.runtime_sha256 != self.runtime_file.sha256
            || rehearsal.completed_at > at
            || rehearsal.measured_deletion_duration_seconds == 0
            || rehearsal.measured_deletion_duration_seconds > self.deletion_duration_seconds
            || rehearsal.measured_systemd_delay_seconds == 0
            || rehearsal.measured_systemd_delay_seconds > self.systemd_delay_seconds
            || rehearsal.evidence.is_empty()
        {
            return Err(Error(
                "cleanup rehearsal does not bind this controller and measured timing",
            ));
        }
        for evidence in rehearsal.evidence {
            evidence.verify()?;
        }
        let backstop: Backstop =
            serde_json::from_slice(&read_regular(&self.independent_backstop.path)?)
                .map_err(|_| Error("invalid independent backstop evidence"))?;
        if backstop.package_sha256 != self.package_sha256
            || backstop.check_by_unix_seconds > self.deletion_start(package)?
            || backstop.check_by_unix_seconds <= at
            || backstop.operator_reference.trim().is_empty()
        {
            return Err(Error(
                "independent backstop does not cover original deadline",
            ));
        }
        Ok(())
    }
    pub fn units(
        &self,
        package: &Package,
        controls_path: &Path,
    ) -> Result<BTreeMap<String, String>> {
        let stem = format!("zrpc-gcp-{}", package.spec.experiment);
        let command = format!(
            "{} watchdog-once --state {} --runtime {} --controls {}",
            safe_path(&self.executable.path)?,
            safe_path(&self.state_directory)?,
            safe_path(&self.runtime_file.path)?,
            safe_path(controls_path)?
        );
        let runtime: Runtime = serde_json::from_slice(&read_regular(&self.runtime_file.path)?)
            .map_err(|_| Error("invalid runtime file"))?;
        // RuntimeMaxSec also bounds invocations waiting on local process I/O.
        let service = format!(
            "[Unit]\nDescription=ZRPC external Google cleanup controller\nAfter=network-online.target\nWants=network-online.target\n[Service]\nType=oneshot\nUser={}\nExecStart={command}\nTimeoutStartSec={}ms\nKillMode=control-group\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nReadWritePaths={} {}\n[Install]\nWantedBy=multi-user.target\n",
            self.controller_uid,
            runtime.invocation_budget_ms,
            safe_path(&self.state_directory)?,
            safe_path(&runtime.gcloud_config_directory)?
        );
        let periodic = format!(
            "[Unit]\nDescription=ZRPC Google periodic cleanup check\n[Timer]\nOnBootSec={}s\nOnUnitActiveSec={}s\nAccuracySec=1us\nRandomizedDelaySec=0\nUnit={stem}.service\n[Install]\nWantedBy=timers.target\n",
            self.poll_interval_seconds, self.poll_interval_seconds
        );
        let when = chrono::DateTime::from_timestamp(
            i64::try_from(self.deletion_start(package)?)
                .map_err(|_| Error("deadline outside calendar range"))?,
            0,
        )
        .ok_or(Error("deadline outside calendar range"))?
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string();
        let deadline = format!(
            "[Unit]\nDescription=ZRPC Google absolute cleanup deadline\n[Timer]\nOnCalendar={when}\nPersistent=true\nAccuracySec=1us\nRandomizedDelaySec=0\nUnit={stem}.service\n[Install]\nWantedBy=timers.target\n"
        );
        Ok(BTreeMap::from([
            (format!("{stem}.service"), service),
            (format!("{stem}-periodic.timer"), periodic),
            (format!("{stem}-deadline.timer"), deadline),
        ]))
    }
    /// Must execute on the independently hosted Linux controller, before OAuth.
    /// Evidence files document an operator rehearsal/backstop; they are not
    /// hardware attestation or a guarantee that an external host cannot fail.
    pub fn verify_live(&self, package: &Package, controls_path: &Path, at: u64) -> Result<()> {
        if !cfg!(target_os = "linux") {
            return Err(Error(
                "deployment requires effective external Linux/systemd controls",
            ));
        }
        self.validate(package, at)?;
        verify_controls_path(controls_path, self.controller_uid)?;
        if at >= self.deletion_start(package)? {
            return Err(Error("deletion window reached; deploy is disabled"));
        }
        if unsafe { libc::geteuid() } != self.controller_uid {
            return Err(Error(
                "deployment must run as the configured external controller UID",
            ));
        }
        let machine = read_regular(Path::new("/etc/machine-id"))?;
        if std::str::from_utf8(&machine).map(str::trim).ok()
            != Some(self.controller_machine_id.as_str())
        {
            return Err(Error("wrong external controller host"));
        }
        let runtime: Runtime = serde_json::from_slice(&read_regular(&self.runtime_file.path)?)
            .map_err(|_| Error("invalid runtime file"))?;
        runtime.validate()?;
        let executable =
            std::env::current_exe().map_err(|_| Error("controller executable unavailable"))?;
        if super::provider::file_sha256(&executable)? != self.executable.sha256 {
            return Err(Error("running controller differs from approved executable"));
        }
        for a in [&self.executable, &self.runtime_file] {
            let m =
                fs::metadata(&a.path).map_err(|_| Error("control file metadata unavailable"))?;
            if m.uid() != 0 && m.uid() != self.controller_uid || m.mode() & 0o022 != 0 {
                return Err(Error("external control files permit other writers"));
            }
        }
        if output(
            "timedatectl",
            &["show", "--property=NTPSynchronized", "--value"],
        )? != "yes"
        {
            return Err(Error("external clock synchronization not established"));
        }
        for (name, expected) in self.units(package, controls_path)? {
            let fragment = output(
                "systemctl",
                &["show", &name, "--property=FragmentPath", "--value"],
            )?;
            if fragment.is_empty()
                || output(
                    "systemctl",
                    &["show", &name, "--property=DropInPaths", "--value"],
                )? != ""
            {
                return Err(Error(
                    "external units have missing fragments or unreviewed drop-ins",
                ));
            }
            if read_regular(Path::new(&fragment))? != expected.as_bytes() {
                return Err(Error(
                    "installed external unit differs from frozen controller configuration",
                ));
            }
            if output(
                "systemctl",
                &["show", &name, "--property=NeedDaemonReload", "--value"],
            )? != "no"
            {
                return Err(Error(
                    "external unit is not loaded from current configuration",
                ));
            }
            if name.ends_with(".timer")
                && (output("systemctl", &["is-active", &name])? != "active"
                    || output("systemctl", &["is-enabled", &name])? != "enabled")
            {
                return Err(Error(
                    "external deadline and periodic timers must be active and enabled",
                ));
            }
            if name.ends_with(".service")
                && output("systemctl", &["is-enabled", &name])? != "enabled"
            {
                return Err(Error(
                    "external startup reconciliation service must be enabled",
                ));
            }
        }
        Ok(())
    }
}
fn output(command: &str, args: &[&str]) -> Result<String> {
    // Fixed platform programs and non-secret arguments; stderr never enters errors.
    let output = Command::new(command)
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| Error("external systemd preflight command failed"))?;
    if !output.status.success() {
        return Err(Error("external systemd preflight command rejected"));
    }
    String::from_utf8(output.stdout)
        .map(|s| s.trim().to_owned())
        .map_err(|_| Error("external systemd preflight output invalid"))
}
pub fn export(
    controls: &Controls,
    package: &Package,
    controls_path: &Path,
    directory: &Path,
) -> Result<()> {
    fs::create_dir(directory).map_err(|_| Error("watchdog output must be a new directory"))?;
    for (name, text) in controls.units(package, controls_path)? {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(directory.join(name))
            .map_err(|_| Error("watchdog output creation failed"))?;
        f.write_all(text.as_bytes())
            .and_then(|_| f.sync_all())
            .map_err(|_| Error("watchdog export failed"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn controls_path_rejects_other_writer_and_symlink_replacement() {
        let root = std::env::temp_dir().join(format!(
            "zrpc-gcp-controls-synthetic-{}",
            crate::gcp::uuid().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let controls = root.join("controls.json");
        fs::write(&controls, b"synthetic controls").unwrap();
        fs::set_permissions(&controls, fs::Permissions::from_mode(0o600)).unwrap();
        let uid = unsafe { libc::geteuid() };
        verify_controls_path(&controls, uid).unwrap();

        fs::set_permissions(&controls, fs::Permissions::from_mode(0o620)).unwrap();
        assert!(verify_controls_path(&controls, uid).is_err());
        fs::set_permissions(&controls, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o770)).unwrap();
        assert!(verify_controls_path(&controls, uid).is_err());
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();

        let linked_file = root.join("linked.json");
        symlink(&controls, &linked_file).unwrap();
        assert!(verify_controls_path(&linked_file, uid).is_err());
        let linked_dir = root.with_extension("link");
        symlink(&root, &linked_dir).unwrap();
        assert!(verify_controls_path(&linked_dir.join("controls.json"), uid).is_err());

        fs::remove_file(linked_dir).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
