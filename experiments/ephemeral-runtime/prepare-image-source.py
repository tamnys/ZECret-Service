"""Derive a fail-closed dstack v0.5.9 source candidate, never a deployable image.

Inputs are read from the catalog-matched dstack Git commit object, never from
mutable working-tree files. The output is a small overlay to review in the
upstream image build; it is not installed here.
"""

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path


SOURCE_COMMIT = "282eeb27d22d8f091ad0fa5a90e638f85cf68751"
PREP_PATH = Path("basefiles/dstack-prepare.sh")
PREP_UNIT_PATH = Path("basefiles/dstack-prepare.service")
APP_LAUNCH_PATH = Path("basefiles/app-compose.sh")
APP_UNIT_PATH = Path("basefiles/app-compose.service")
GUEST_UNIT_PATH = Path("basefiles/dstack-guest-agent.service")
SOCKET_UNIT_PATH = Path("basefiles/dstack-guest-agent.socket")
JOURNAL_PATH = Path("basefiles/journald.conf")
SETUP_PATH = Path("dstack-util/src/system_setup.rs")
SOURCE_HASHES = {
    PREP_PATH: "1636030add2dfd5a85272a246939d7d1b472aa2a400e76b158dc39577a9c442a",
    PREP_UNIT_PATH: "50d727f02033e2d05638f93771e016e88e1c445abaaf29eca6cc160087bd44f2",
    APP_LAUNCH_PATH: "c84903b500b03c10fa4793e5d2c092defc10181789951aa351fda7c0c6bc8324",
    APP_UNIT_PATH: "68898fd5221ef132db072f2943163d0dbb00dc5cbd12b3aeb06a43e227138cad",
    GUEST_UNIT_PATH: "240b699c476b6adb3a3388801a6b340e1ed505505d528dfb4e6b711b52146b25",
    SOCKET_UNIT_PATH: "04b8955496918bc7f6eb6a147bc71f2bbf404940f742c8eb906a7713cfd1ea6f",
    JOURNAL_PATH: "015131f89b63debe0f33d691ea858f26f51993a0916eb683ee977ecb522f6ea2",
    SETUP_PATH: "d1403005276d343aa33a2ea4a62840e684641b30ef8c1c4b11c01d0366058db5",
}


def replace_once(source: str, old: str, new: str) -> str:
    if source.count(old) != 1:
        raise ValueError("pinned source anchor missing or ambiguous")
    return source.replace(old, new)


def pinned_source(repo: Path, path: Path) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repo), "show", f"{SOURCE_COMMIT}:{path}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode != 0:
        raise ValueError(f"pinned source object unavailable: {path}")
    data = result.stdout
    if hashlib.sha256(data).hexdigest() != SOURCE_HASHES[path]:
        raise ValueError(f"pinned source mismatch: {path}")
    return data


def candidate_prepare(source: str) -> str:
    source = replace_once(
        source,
        "DATA_DEVICE=$(choose_data_device \"$DATA_DEVICE_OVERRIDE\" || true)\n",
        """if [ -n "${DSTACK_DATA_DEVICE:-}" ] || [ -n "$DATA_DEVICE_OVERRIDE" ]; then
    log "Mutable data-device selection is disabled in this profile"
    exit 1
fi
DATA_DEVICE=$(choose_data_device "$DATA_DEVICE_OVERRIDE" || true)
""",
    )
    source = replace_once(
        source,
        """mount_overlay /etc $OVERLAY_TMP
""",
        """# Linux core(5): an empty pattern with core_uses_pid=0 writes no dump.
# Set this before KMS access; every runtime pre-start guard checks it again.
printf '\\n' > /proc/sys/kernel/core_pattern
printf '0\\n' > /proc/sys/kernel/core_uses_pid
printf '0\\n' > /proc/sys/fs/suid_dumpable
# Refuse any persistent or swap-backed overlay before loading mutable code.
/usr/bin/phala-runtime-guard --pre-overlay
mount_overlay /etc $OVERLAY_TMP
""",
    )
    source = replace_once(
        source,
        "dstack-util setup --work-dir $WORK_DIR --device \"$DATA_DEVICE\" --mount-point $DATA_MNT\n",
        """# An empty, newly mounted tmpfs owns every dstack work/configuration file.
# A previous preparation attempt in this boot is a terminal failure.
umask 077
if [ -L "$WORK_DIR" ]; then
    log "Refusing symbolic work directory"
    exit 1
fi
mkdir -p "$WORK_DIR"
shopt -s nullglob dotglob
existing_work=("$WORK_DIR"/*)
shopt -u nullglob dotglob
if ((${#existing_work[@]} != 0)) || mountpoint -q "$WORK_DIR"; then
    log "Refusing nonempty or already mounted work directory"
    exit 1
fi
mount -t tmpfs -o mode=0700,nosuid,nodev tmpfs "$WORK_DIR"
dstack-util setup --work-dir "$WORK_DIR" --device "$DATA_DEVICE" --mount-point "$DATA_MNT"
""",
    )
    source = replace_once(
        source,
        """log "Mounting container runtime dirs to persistent storage"
mkdir -p $DATA_MNT/var/lib/docker
mkdir -p $DATA_MNT/var/lib/containerd
mkdir -p $DATA_MNT/var/lib/sysbox
mkdir -p /var/lib/docker
mkdir -p /var/lib/containerd
mkdir -p /var/lib/sysbox
mount --rbind $DATA_MNT/var/lib/docker /var/lib/docker
mount --rbind $DATA_MNT/var/lib/containerd /var/lib/containerd
mount --rbind $DATA_MNT/var/lib/sysbox /var/lib/sysbox
mount --rbind $WORK_DIR /dstack
""",
        """log "Mounting fresh container runtime directories from memory"
for runtime in docker containerd sysbox; do
    mkdir -p "$WORK_DIR/runtime/$runtime" "/var/lib/$runtime"
    if mountpoint -q "/var/lib/$runtime"; then
        log "Refusing an existing runtime mount"
        exit 1
    fi
    mount --bind "$WORK_DIR/runtime/$runtime" "/var/lib/$runtime"
done
if mountpoint -q /dstack; then
    log "Refusing existing dstack mount"
    exit 1
fi
# A non-recursive bind keeps the nested persistent data mount out of /dstack.
mount --bind "$WORK_DIR" /dstack
/usr/bin/phala-runtime-guard
""",
    )
    source = replace_once(
        source,
        """if [ $(jq 'has("init_script")' app-compose.json) == true ]; then
\tlog "Running init script"
\tdstack-util notify-host -e "boot.progress" -d "init-script" || true
\tsource <(jq -r '.init_script' app-compose.json)
fi
""",
        """# This immutable profile has no runtime-supplied script execution.
# The dstack-util profile validation happens before disk setup and KMS use.
if ! jq -e '(.init_script == null or .init_script == "") and
    (.pre_launch_script == null or .pre_launch_script == "") and
    .storage_fs == "ext4" and .swap_size == 0' app-compose.json >/dev/null; then
    log "Approved app profile changed after setup"
    exit 1
fi
""",
    )
    source = replace_once(
        source,
        """\tif [[ ! -f docker-compose.yaml ]]; then
\t\tjq -r '.docker_compose_file' app-compose.json >docker-compose.yaml
\tfi
""",
        """\t# The only Compose file comes from the image-bound, copied JSON.
\t# A preexisting file could hide different container privileges or mounts.
\tif [[ -e docker-compose.yaml || -L docker-compose.yaml ]]; then
\t\texit 1
\tfi
\tjq -er '.docker_compose_file' app-compose.json >docker-compose.yaml
""",
    )
    # Orphan handling consumes container metadata and must see the fresh roots.
    assert source.index("/usr/bin/phala-runtime-guard") < source.index("remove-orphans")
    return source


def rust_hash_option(digest: bytes | None) -> str:
    if digest is None:
        return "None"
    return "Some([" + ", ".join(f"0x{byte:02x}" for byte in digest) + "])"


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate configuration key")
        value[key] = item
    return value


COMPOSE_SERVICE_FIELDS = frozenset({
    "image", "user", "read_only", "cap_drop", "security_opt", "logging",
    "restart", "environment", "network_mode",
})


def reject_non_json_constant(value: str) -> None:
    raise ValueError(f"non-JSON Compose constant: {value}")


def reject_interpolation(value: object) -> None:
    if isinstance(value, str):
        if "$" in value:
            raise ValueError("Compose interpolation is forbidden")
    elif isinstance(value, list):
        for item in value:
            reject_interpolation(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            reject_interpolation(key)
            reject_interpolation(item)


def validate_compose_file(content: str) -> None:
    # Docker Compose accepts JSON as YAML. Requiring JSON excludes aliases,
    # merge keys and tag processing, while unique_object rejects shadowed keys.
    # Mounts, ports and process overrides need a separately reviewed, exact
    # profile. This source candidate cannot yet represent them.
    try:
        compose = json.loads(content, object_pairs_hook=unique_object,
                             parse_constant=reject_non_json_constant)
    except (ValueError, UnicodeDecodeError) as error:
        raise ValueError("Compose content must be unambiguous JSON") from error
    if (not isinstance(compose, dict)
            or set(compose) - {"name", "services"}
            or ("name" in compose and
                (not isinstance(compose["name"], str) or not compose["name"]))):
        raise ValueError("unsupported Compose top-level fields")
    services = compose.get("services")
    if not isinstance(services, dict) or not services:
        raise ValueError("Compose services are required")
    reject_interpolation(compose)
    for name, service in services.items():
        if (not name or not isinstance(service, dict)
                or set(service) - COMPOSE_SERVICE_FIELDS):
            raise ValueError("unsupported Compose service fields")
        image = service.get("image")
        if (not isinstance(image, str)
                or not re.fullmatch(r"[A-Za-z0-9._:/-]+@sha256:[0-9a-f]{64}", image)):
            raise ValueError("Compose images require an exact SHA-256 digest")
        user = service.get("user")
        if (not isinstance(user, str)
                or not re.fullmatch(r"[1-9][0-9]*(?::[1-9][0-9]*)?", user)):
            raise ValueError("Compose services require a numeric non-root user")
        if (service.get("read_only") is not True
                or service.get("cap_drop") != ["ALL"]
                or service.get("security_opt") != ["no-new-privileges:true"]
                or service.get("logging") != {"driver": "none"}
                or service.get("restart", "no") != "no"):
            raise ValueError("Compose service violates private runtime policy")
        mode = service.get("network_mode")
        if mode is not None and (not isinstance(mode, str)
                                 or not mode.startswith("service:")
                                 or mode[8:] not in services
                                 or mode[8:] == name):
            raise ValueError("Compose network mode must name another service")
        environment = service.get("environment", {})
        if (not isinstance(environment, dict)
                or any(not isinstance(value, str) for value in environment.values())):
            raise ValueError("Compose environment must be explicit strings")


def launch_config_digest(path: Path | None) -> bytes | None:
    if path is None:
        return None
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise ValueError("launch configuration cannot be read") from error
    # The pinned dstack copy step enforces this same bound before setup.
    if len(payload) > 256 * 1024:
        raise ValueError("launch configuration exceeds pinned dstack copy bound")

    try:
        profile = json.loads(payload, object_pairs_hook=unique_object)
    except (ValueError, UnicodeDecodeError) as error:
        raise ValueError("invalid launch configuration JSON") from error
    port_policy = profile.get("port_policy") if isinstance(profile, dict) else None
    ports = port_policy.get("ports") if isinstance(port_policy, dict) else None
    only_port = ports[0] if isinstance(ports, list) and len(ports) == 1 else None
    safe_port_policy = (
        isinstance(port_policy, dict)
        and port_policy.get("restrict_mode") is True
        and isinstance(only_port, dict)
        and type(only_port.get("port")) is int
        and 1 <= only_port["port"] <= 65535
        and only_port.get("pp", False) is False
    )
    if not isinstance(profile, dict) or any((
        profile.get("runner") != "docker-compose",
        profile.get("storage_fs") != "ext4",
        type(profile.get("swap_size")) is not int or profile.get("swap_size") != 0,
        profile.get("key_provider") != "kms",
        not isinstance(profile.get("key_provider_id"), str),
        not profile.get("key_provider_id"),
        not isinstance(profile.get("docker_compose_file"), str),
        not profile.get("docker_compose_file"),
        profile.get("public_logs", False) is not False,
        profile.get("public_sysinfo", False) is not False,
        profile.get("allowed_envs", []) != [],
        not safe_port_policy,
        any(profile.get(key) not in (None, "") for key in (
            "init_script", "pre_launch_script", "bash_script"
        )),
    )):
        raise ValueError("launch configuration violates private RPC profile")
    validate_compose_file(profile["docker_compose_file"])
    return hashlib.sha256(payload).digest()


def sys_config_digest(path: Path | None) -> bytes | None:
    if path is None:
        return None
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise ValueError("system configuration cannot be read") from error
    if len(payload) > 32 * 1024:
        raise ValueError("system configuration exceeds pinned dstack copy bound")
    try:
        config = json.loads(payload, object_pairs_hook=unique_object)
    except (ValueError, UnicodeDecodeError) as error:
        raise ValueError("invalid system configuration JSON") from error
    if (not isinstance(config, dict)
            or not isinstance(config.get("vm_config"), str)
            or not config["vm_config"]
            or config.get("docker_registry") not in (None, "")):
        raise ValueError("system configuration violates private RPC profile")
    try:
        vm_config = json.loads(config["vm_config"], object_pairs_hook=unique_object)
    except (ValueError, UnicodeDecodeError) as error:
        raise ValueError("invalid embedded VM configuration JSON") from error
    if not isinstance(vm_config, dict):
        raise ValueError("embedded VM configuration must be an object")
    return hashlib.sha256(payload).digest()


def bound_digests(launch_path: Path | None, sys_path: Path | None) -> tuple[bytes | None, bytes | None]:
    if (launch_path is None) != (sys_path is None):
        raise ValueError("launch and system configurations must be bound together")
    return launch_config_digest(launch_path), sys_config_digest(sys_path)


def candidate_setup(source: str, launch_digest: bytes | None, sys_digest: bytes | None) -> str:
    source = replace_once(
        source,
        """impl HostShared {
""",
        """fn private_host_inputs_allowed(
    registry: Option<&str>,
    encrypted_env: &[u8],
    user_config_size: Option<u64>,
) -> bool {
    registry.is_none_or(str::is_empty)
        && encrypted_env.is_empty()
        && user_config_size.is_none_or(|size| size == 0)
}

#[cfg(test)]
mod private_host_input_tests {
    use super::private_host_inputs_allowed;

    #[test]
    fn rejects_mutable_host_inputs() {
        assert!(private_host_inputs_allowed(None, b"", None));
        assert!(private_host_inputs_allowed(Some(""), b"", Some(0)));
        assert!(!private_host_inputs_allowed(Some("https://registry.example"), b"", None));
        assert!(!private_host_inputs_allowed(None, b"ciphertext", None));
        assert!(!private_host_inputs_allowed(None, b"", Some(2)));
    }
}

impl HostShared {
""",
    )
    source = replace_once(
        source,
        """        let sys_config = deserialize_json_file(host_shared_dir.sys_config_file())?;
""",
        """        // The host's KMS, gateway and VM configuration is a boot control.
        // Parse the same copied bytes that this immutable image binds.
        let sys_config_bytes = fs::read(host_shared_dir.sys_config_file())?;
        let expected_sys_config_hash: Option<[u8; 32]> = __EXPECTED_SYS_HASH__;
        if Some(sha256(&sys_config_bytes)) != expected_sys_config_hash {
            bail!("private RPC system configuration is not bound to this image");
        }
        let sys_config: SysConfig = serde_json::from_slice(&sys_config_bytes)?;
""".replace("__EXPECTED_SYS_HASH__", rust_hash_option(sys_digest)),
    )
    source = replace_once(
        source,
        """    if let Some(fs) = &shared.app_compose.storage_fs {
        options.storage_fs = fs.parse().context("Failed to parse storage_fs")?;
    }
    Ok(options)
""",
        """    if let Some(fs) = &shared.app_compose.storage_fs {
        options.storage_fs = fs.parse().context("Failed to parse storage_fs")?;
    }
    if !options.storage_encrypted || options.storage_fs != FsType::Ext4 {
        bail!("private RPC profile requires encrypted ext4 storage");
    }
    Ok(options)
""",
    )
    source = replace_once(
        source,
        """    app_compose: AppCompose,
    encrypted_env: Vec<u8>,
""",
        """    app_compose: AppCompose,
    app_compose_hash: [u8; 32],
    encrypted_env: Vec<u8>,
""",
    )
    source = replace_once(
        source,
        """        let app_compose = deserialize_json_file(host_shared_dir.app_compose_file())?;
        let instance_info_file = host_shared_dir.instance_info_file();
""",
        """        // The copied host input is read once; policy and measurement use
        // the same bytes. Any invalid profile fails before disk setup.
        let app_compose_bytes = fs::read(host_shared_dir.app_compose_file())?;
        let app_compose_hash = sha256(&app_compose_bytes);
        let expected_app_compose_hash: Option<[u8; 32]> = __EXPECTED_LAUNCH_HASH__;
        if Some(app_compose_hash) != expected_app_compose_hash {
            bail!("private RPC launch configuration is not bound to this image");
        }
        let raw: Value = serde_json::from_slice(&app_compose_bytes)?;
        let app_compose: AppCompose = serde_json::from_slice(&app_compose_bytes)?;
        if raw.get("storage_fs") != Some(&Value::String("ext4".into()))
            || raw.get("swap_size") != Some(&Value::from(0))
            || raw.get("runner") != Some(&Value::String("docker-compose".into()))
            || app_compose.swap_size != 0
            || !app_compose.key_provider().is_kms()
            || app_compose.key_provider_id.is_empty()
            || !app_compose.port_policy.restrict_mode
            || app_compose.port_policy.ports.len() != 1
            || app_compose.port_policy.ports[0].port == 0
            || app_compose.port_policy.ports[0].pp
            || !raw.get("bash_script").is_none_or(|v| v.is_null() || v == "")
            || !raw.get("init_script").is_none_or(|v| v.is_null() || v == "")
            || !raw.get("pre_launch_script").is_none_or(|v| v.is_null() || v == "")
        {
            bail!("unsupported private RPC app profile");
        }
        let instance_info_file = host_shared_dir.instance_info_file();
""".replace("__EXPECTED_LAUNCH_HASH__", rust_hash_option(launch_digest)),
    )
    source = replace_once(
        source,
        """            app_compose,
            encrypted_env,
""",
        """            app_compose,
            app_compose_hash,
            encrypted_env,
""",
    )
    source = replace_once(
        source,
        """        let encrypted_env = fs::read(host_shared_dir.encrypted_env_file()).unwrap_or_default();
""",
        """        let encrypted_env = match fs::read(host_shared_dir.encrypted_env_file()) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(error.into()),
        };
        let user_config_file = host_shared_dir.join(USER_CONFIG);
        let user_config_size = match fs::metadata(&user_config_file) {
            Ok(metadata) if metadata.is_file() => Some(metadata.len()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            _ => bail!("private RPC profile forbids host-supplied user configuration"),
        };
        // Refuse the copied controls before KMS access or executable startup.
        if !private_host_inputs_allowed(
            sys_config.docker_registry.as_deref(),
            &encrypted_env,
            user_config_size,
        ) {
            bail!("private RPC profile forbids mutable host inputs");
        }
""",
    )
    source = replace_once(
        source,
        """            ln -sf ${HOST_SHARED_DIR_NAME}/${USER_CONFIG} user_config;
""",
        """            # No user_config link: containers cannot consume host configuration.
""",
    )
    source = replace_once(
        source,
        """        let compose_hash = sha256_file(self.shared.dir.app_compose_file())?;
        let truncated_compose_hash = truncate(&compose_hash, 20);
""",
        """        let compose_hash = self.shared.app_compose_hash;
        if sha256_file(self.shared.dir.app_compose_file())? != compose_hash {
            bail!("copied app configuration changed after validation");
        }
        let truncated_compose_hash = truncate(&compose_hash, 20);
""",
    )
    return source


def candidate_app_launch(source: str, launch_digest: bytes | None) -> str:
    if launch_digest is None:
        launch_check = "exit 1 # No launch configuration is bound to this image\n"
    else:
        launch_check = (
            "if ! printf '%s  app-compose.json\\n' '"
            + launch_digest.hex()
            + "' | sha256sum -c - >/dev/null 2>&1; then\n"
            "    exit 1\n"
            "fi\n"
        )
    source = replace_once(
        source,
        """if [ $(jq 'has("pre_launch_script")' app-compose.json) == true ]; then
    echo "Running pre-launch script"
    dstack-util notify-host -e "boot.progress" -d "pre-launch" || true
    source <(jq -r '.pre_launch_script' app-compose.json)
fi
""",
        """# Recheck the image-bound guest-owned profile; never execute host scripts.
__LAUNCH_CONFIG_CHECK__
if ! jq -e '(.pre_launch_script == null or .pre_launch_script == "") and
    (.init_script == null or .init_script == "") and
    .runner == "docker-compose"' app-compose.json >/dev/null; then
    exit 1
fi
""".replace("__LAUNCH_CONFIG_CHECK__\n", launch_check),
    )
    source = replace_once(
        source,
        """    if ! [ -f docker-compose.yaml ]; then
        jq -r '.docker_compose_file' app-compose.json >docker-compose.yaml
    fi
""",
        """    if [ ! -f docker-compose.yaml ] || [ -L docker-compose.yaml ]; then
        exit 1
    fi
""",
    )
    source = replace_once(
        source,
        """    if ! docker compose up --remove-orphans -d --build; then
        dstack-util notify-host -e "boot.error" -d "failed to start containers"
        exit 1
    fi
    echo "Pruning unused images"
    docker image prune -af
    echo "Pruning unused volumes"
    docker volume prune -f
""",
        """    # The prepared file must still render exactly from image-bound JSON.
    # A missing, symbolic or changed file cannot launch.
    if [ ! -f docker-compose.yaml ] || [ -L docker-compose.yaml ] ||
       ! cmp -s docker-compose.yaml <(jq -er '.docker_compose_file' app-compose.json); then
        exit 1
    fi
    # Keep Compose attached: a stopped container ends this process and fails
    # app-compose.service. Never treat a zero Compose exit as healthy recovery.
    # Select the local daemon, checked base file and empty environment file.
    # Ambient Docker context, neighboring files or .env cannot redirect launch.
    docker --host unix:///run/docker.sock compose --env-file /dev/null -f docker-compose.yaml up --remove-orphans --abort-on-container-exit --no-build --pull never >/dev/null 2>&1
    dstack-util notify-host -e "boot.error" -d "container supervision ended" || true
    exit 1
""",
    )
    source = replace_once(
        source,
        """"bash")
    echo "Running main script"
    dstack-util notify-host -e "boot.progress" -d "running main script" || true
    jq -r '.bash_script' app-compose.json | bash
    ;;
""",
        "",
    )
    return source


def candidate_prepare_unit(source: str) -> str:
    source = replace_once(source, "OnFailure=reboot.target\n", "")
    source = replace_once(source, "FailureAction=reboot\n", "")
    return candidate_private_unit(source)


def candidate_private_unit(source: str) -> str:
    source = replace_once(source, "StandardOutput=journal+console\n", "StandardOutput=null\n")
    source = replace_once(source, "StandardError=journal+console\n", "StandardError=null\n")
    return source


def candidate_app_unit(source: str) -> str:
    # A detached oneshot cannot observe later container death. This service
    # stays active only while its attached Compose supervisor is running.
    source = replace_once(source, "Type=oneshot\nRemainAfterExit=true\n", "Type=simple\n")
    source = replace_once(
        source,
        "After=docker.service dstack-prepare.service dstack-guest-agent.service\n",
        "BindsTo=zrpc-quote-proxy.service\n"
        "After=docker.service dstack-prepare.service dstack-guest-agent.service "
        "zrpc-quote-proxy.service\n",
    )
    return candidate_private_unit(source)


def candidate_guest_unit(source: str) -> str:
    source = replace_once(source, "Restart=always\n", "Restart=no\n")
    return candidate_private_unit(source)


def candidate_guest_socket(source: str) -> str:
    # Both sockets also expose key/signing APIs. Keep them root-only until a
    # measured quote-only broker can grant the wrapper narrower access.
    return replace_once(source, "SocketMode=0777\n", "SocketMode=0600\n")


def candidate_journal(source: str) -> str:
    if source.count("[Journal]\n") != 1:
        raise ValueError("pinned journal anchor missing or ambiguous")
    return """[Journal]
Storage=none
ForwardToSyslog=no
ForwardToKMsg=no
ForwardToConsole=no
ForwardToWall=no
ReadKMsg=no
"""


def dropins() -> dict[Path, str]:
    files = {}
    for service in (
        "docker", "containerd", "sysbox", "sysbox-mgr", "sysbox-fs", "app-compose",
        "dstack-guest-agent",
    ):
        files[Path(f"basefiles/{service}.service.d/zrpc-private-profile.conf")] = (
            "[Unit]\nRequires=dstack-prepare.service\nAfter=dstack-prepare.service\n"
            "FailureAction=poweroff-force\n"
            "[Service]\nRestart=no\nStandardOutput=null\nStandardError=null\n"
            f"ExecStartPre=/usr/bin/phala-runtime-guard --mark-start {service}\n"
        )
    files[Path("basefiles/dstack-prepare.service.d/zrpc-private-profile.conf")] = (
        "[Unit]\nOnFailure=\nFailureAction=poweroff-force\n"
        "[Service]\nRestart=no\nStandardOutput=null\nStandardError=null\n"
    )
    for socket in ("docker", "dstack-guest-agent", "tappd"):
        files[Path(f"basefiles/{socket}.socket.d/zrpc-private-profile.conf")] = (
            "[Unit]\nRequires=dstack-prepare.service\nAfter=dstack-prepare.service\n"
            "FailureAction=poweroff-force\n"
        )
    return files


def quote_proxy_unit() -> str:
    return """[Unit]
Description=Quote-only dstack bridge for the Zcash RPC wrapper
Requires=dstack-prepare.service
BindsTo=app-compose.service docker.service containerd.service sysbox.service sysbox-mgr.service sysbox-fs.service dstack-guest-agent.service
After=dstack-prepare.service docker.service containerd.service sysbox.service sysbox-mgr.service sysbox-fs.service dstack-guest-agent.service
Before=app-compose.service
FailureAction=poweroff-force

[Service]
Type=notify
NotifyAccess=main
ExecStartPre=/usr/bin/phala-runtime-guard --mark-start quote-proxy
ExecStart=/usr/bin/zrpc-quote-proxy
User=root
Group=zrpc-wrapper
UMask=0117
Restart=no
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
RestrictAddressFamilies=AF_UNIX
IPAddressDeny=any
ReadWritePaths=/run
CapabilityBoundingSet=
AmbientCapabilities=
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_git_dir", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--launch-config", type=Path,
                        help="exact reviewed app-compose JSON bytes to bind into the image")
    parser.add_argument("--sys-config", type=Path,
                        help="exact reviewed sys-config JSON bytes to bind into the image")
    args = parser.parse_args()
    try:
        head = subprocess.run(
            ["git", "-C", str(args.source_git_dir), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
        )
        if head.returncode != 0 or head.stdout.strip() != SOURCE_COMMIT:
            raise ValueError("source checkout is not at the pinned dstack commit")
        launch_digest, sys_digest = bound_digests(args.launch_config, args.sys_config)
        original = {path: pinned_source(args.source_git_dir, path).decode("utf-8")
                    for path in SOURCE_HASHES}
        files = {
            PREP_PATH: candidate_prepare(original[PREP_PATH]),
            PREP_UNIT_PATH: candidate_prepare_unit(original[PREP_UNIT_PATH]),
            APP_LAUNCH_PATH: candidate_app_launch(original[APP_LAUNCH_PATH], launch_digest),
            APP_UNIT_PATH: candidate_app_unit(original[APP_UNIT_PATH]),
            GUEST_UNIT_PATH: candidate_guest_unit(original[GUEST_UNIT_PATH]),
            SOCKET_UNIT_PATH: candidate_guest_socket(original[SOCKET_UNIT_PATH]),
            JOURNAL_PATH: candidate_journal(original[JOURNAL_PATH]),
            SETUP_PATH: candidate_setup(original[SETUP_PATH], launch_digest, sys_digest),
            Path("zrpc/phala-runtime-guard.rs"): Path(__file__).with_name("runtime-guard.rs").read_text(),
            Path("basefiles/zrpc-quote-proxy.service"): quote_proxy_unit(),
            **dropins(),
        }
    except ValueError as error:
        parser.error(str(error))
    # Exclusive output creation avoids changing an earlier review candidate.
    args.output_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
    hashes = {}
    for path, content in files.items():
        target = args.output_dir / path
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target.write_text(content)
        hashes[str(path)] = hashlib.sha256(content.encode()).hexdigest()
    (args.output_dir / "candidate-manifest.json").write_text(json.dumps({
        "source_commit": SOURCE_COMMIT,
        "source_tree_verified": False,
        "source_commit_object_verified": True,
        "source_identity_scope": "eight_files_from_pinned_git_commit",
        "source_sha256": {str(k): v for k, v in SOURCE_HASHES.items()},
        "candidate_sha256": hashes,
        "launch_profile_bound": launch_digest is not None and sys_digest is not None,
        "launch_config_sha256": launch_digest.hex() if launch_digest is not None else None,
        "sys_config_sha256": sys_digest.hex() if sys_digest is not None else None,
        "built_image": False,
        "private_accepted": False,
    }, indent=2, sort_keys=True) + "\n")
    print("Source overlay only: guard installation, image, measurements and private acceptance unavailable.")


if __name__ == "__main__":
    main()
