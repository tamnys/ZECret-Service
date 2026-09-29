#!/usr/bin/env python3
"""Observe an exact unsigned diagnostic disk with pinned QEMU and OVMF.

This program records QMP events and VGA pixels. It cannot authenticate guest
execution, infer a successful /init handoff, or approve a private release.
The caller supplies a separate no-route namespace, a read-only bind of the
staged QEMU root, and an empty writable mount at ROOT/observe. QEMU itself is
chrooted and drops to an explicitly supplied unprivileged UID/GID.
"""

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import socket
import stat
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))

import boot_qemu_toolchain as toolchain
import inspect_raw_gpt as gpt
import stage_builder_toolchain as stager
import verify_builder_packages as direct


STATUS = "diagnostic-qemu-vga-observation-unapproved"
TAMPER_STATUS = "diagnostic-qemu-root-data-tamper-observation-unapproved"
BOOT_DISK_STATUS = "diagnostic-unsigned-early-init-boot-disk-unapproved"
HEX = re.compile(r"[0-9a-f]{64}\Z")
NET_NAMESPACE = re.compile(r"net:\[[0-9]+\]\Z")
CHROOT_OUTPUT = "/observe"
QMP_SOCKET = "qmp.sock"
PR_SET_NO_NEW_PRIVS = 38  # Linux prctl(2)


def regular_bytes(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("diagnostic report or inventory is not a regular file")
    return path.read_bytes()


def json_file(path):
    return json.loads(regular_bytes(path), object_pairs_hook=direct.unique_object)


def sha256_file(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def mounted_at(path):
    """Linux mountinfo, unlike os.path.ismount, recognizes same-FS binds."""
    selected = str(path)
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        if len(fields) < 6:
            raise ValueError("Linux mountinfo is malformed")
        mountpoint = re.sub(r"\\([0-7]{3})",
                            lambda match: chr(int(match.group(1), 8)), fields[4])
        if mountpoint == selected:
            return True
    return False


def checked_stage(root, report_path):
    toolchain.real_directory(root, "staged QEMU root")
    if not mounted_at(root) or not os.statvfs(root).f_flag & os.ST_RDONLY:
        raise ValueError("staged QEMU root must be a separate read-only mount")
    if stat.S_IMODE(root.stat().st_mode) != 0o755:
        raise ValueError("staged QEMU root must be traversable by the dropped child")
    report = json_file(report_path)
    reported_root = report.get("stage_host_path") if type(report) is dict else None
    if (type(reported_root) is not str or not reported_root.startswith("/")
            or report.get("status") != "diagnostic-pinned-qemu-ovmf-staged-unapproved"
            or report.get("lock_sha256") != toolchain.LOCK_SHA256
            or report.get("package_scripts_executed") is not False
            or report.get("boot_verified") is not False
            or report.get("hardware_verified") is not False
            or report.get("private_mode_approved") is not False
            or report.get("post_start_plugin_loads_verified") is not False):
        raise ValueError("QEMU stage report is not the reviewed diagnostic stage")
    for field, relative in (("qemu_host_path", toolchain.QEMU),
                            ("ovmf_code_host_path", toolchain.OVMF_CODE),
                            ("ovmf_vars_template_host_path", toolchain.OVMF_VARS)):
        if report.get(field) != str(Path(reported_root) / relative):
            raise ValueError("QEMU stage report path relationship differs")
    manifest_path = root / stager.MANIFEST
    manifest_bytes = regular_bytes(manifest_path)
    if hashlib.sha256(manifest_bytes).hexdigest() != report.get("stage_inventory_sha256"):
        raise ValueError("staged QEMU inventory differs from stage report")
    manifest = json.loads(manifest_bytes, object_pairs_hook=direct.unique_object)
    if (type(manifest) is not dict or manifest.get("builder_closure_lock_sha256") !=
            toolchain.LOCK_SHA256 or manifest.get("package_scripts_executed") is not False
            or type(manifest.get("entries")) is not list):
        raise ValueError("staged QEMU inventory is not the reviewed package selection")
    entries = {entry["path"]: entry for entry in manifest["entries"]}
    if len(entries) != len(manifest["entries"]):
        raise ValueError("staged QEMU inventory repeats a path")
    paths = toolchain.dynamic_closure(root, entries)
    for field, expected in (("qemu_chroot_path", "/" + toolchain.QEMU),
                            ("ovmf_code_chroot_path", "/" + toolchain.OVMF_CODE),
                            ("ovmf_vars_template_chroot_path", "/" + toolchain.OVMF_VARS)):
        if report.get(field) != expected or paths[field] != expected:
            raise ValueError("QEMU stage chroot path differs")
    return report


def checked_disk(path, report_path):
    report = json_file(report_path)
    if type(report) is not dict:
        raise ValueError("disk report is not an object")
    expected_hash = report.get("raw_disk_sha256") if type(report) is dict else None
    expected_size = report.get("raw_disk_bytes") if type(report) is dict else None
    if (report.get("status") != BOOT_DISK_STATUS
            or report.get("production_image") is not False
            or report.get("synthetic_service_payloads") is not True
            or report.get("gpt_esp_verity_uki_inspected") is not True
            or report.get("secure_boot_signature_checked") is not False
            or report.get("boot_verified") is not False
            or report.get("hardware_verified") is not False
            or report.get("private_mode_approved") is not False
            or type(expected_hash) is not str or not HEX.fullmatch(expected_hash)
            or type(expected_size) is not int or expected_size <= 0):
        raise ValueError("disk report is not the exact unsigned boot diagnostic")
    if path.is_symlink() or path.name != "zrpc-gcp.raw":
        raise ValueError("diagnostic raw disk path differs")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        record = os.fstat(fd)
        if not stat.S_ISREG(record.st_mode) or record.st_size != expected_size:
            raise ValueError("diagnostic raw disk type or size differs")
        if digest_fd(fd, expected_size) != expected_hash:
            raise ValueError("diagnostic raw disk hash differs")
    except BaseException:
        os.close(fd)
        raise
    return fd, report


def digest_fd(fd, size):
    digest = hashlib.sha256()
    position = 0
    while position < size:
        chunk = os.pread(fd, min(1024 * 1024, size - position), position)
        if not chunk:
            raise ValueError("diagnostic raw disk truncated while hashing")
        digest.update(chunk)
        position += len(chunk)
    if os.fstat(fd).st_size != size:
        raise ValueError("diagnostic raw disk changed size while hashing")
    return digest.hexdigest()


def root_data_tamper(fd, path, report, output):
    """Derive a one-byte changed boot disk; retain the checked source intact."""
    size = report["raw_disk_bytes"]
    original = report["raw_disk_sha256"]
    layout = gpt.inspect(path, original, size, 512)
    root = next(entry for entry in layout["partitions"]
                if entry["type"] == "root-x86-64")
    offset = root["first_lba"] * 512
    if offset >= size:
        raise ValueError("root data mutation lies outside the diagnostic disk")
    target = output / "root-data-tampered.raw"
    derived_fd = None
    created = False
    try:
        with target.open("xb") as stream:
            created = True
            position = 0
            while position < size:
                chunk = os.pread(fd, min(1024 * 1024, size - position), position)
                if not chunk:
                    raise ValueError("checked diagnostic disk ended during copy")
                stream.write(chunk)
                position += len(chunk)
        writable = os.open(target, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            if os.fstat(writable).st_size != size:
                raise ValueError("derived diagnostic disk size differs")
            first = os.pread(writable, 1, offset)
            if len(first) != 1 or first != os.pread(fd, 1, offset):
                raise ValueError("derived root byte differs before mutation")
            if os.pwrite(writable, bytes((first[0] ^ 1,)), offset) != 1:
                raise ValueError("derived root byte could not be changed")
            if os.fstat(writable).st_size != size:
                raise ValueError("derived diagnostic disk size changed")
        finally:
            os.close(writable)
        derived_fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        changed = digest_fd(derived_fd, size)
        if changed == original or os.pread(derived_fd, 1, offset) == first:
            raise ValueError("derived diagnostic disk has no root data mutation")
        return derived_fd, {"source_disk_sha256": original,
                            "boot_disk_sha256": changed,
                            "root_partition_guid": root["partition_guid"],
                            "changed_disk_offset_bytes": offset,
                            "changed_byte_count": 1,
                            "synthetic_root_data_tamper": True}
    except BaseException:
        if derived_fd is not None:
            os.close(derived_fd)
        raise
    finally:
        if created:
            target.unlink(missing_ok=True)


def mapped_identity(path, selected):
    for row in Path(path).read_text().splitlines():
        inside, _outside, length = (int(value) for value in row.split())
        if inside <= selected < inside + length:
            return True
    return False


def checked_execution_context(parent_net_ns, uid, gid):
    if (platform.system() != "Linux" or platform.machine() != "x86_64"
            or os.geteuid() != 0 or type(uid) is not int or uid <= 0
            or type(gid) is not int or gid <= 0):
        raise ValueError("native Linux root supervisor and nonroot QEMU identity required")
    current = os.readlink("/proc/self/ns/net")
    if (not NET_NAMESPACE.fullmatch(parent_net_ns) or parent_net_ns == current
            or {name for _, name in socket.if_nameindex()} != {"lo"}
            or Path("/proc/self/setgroups").read_text().strip() != "allow"
            or not mapped_identity("/proc/self/uid_map", uid)
            or not mapped_identity("/proc/self/gid_map", gid)):
        raise ValueError("separate no-route namespace with usable nonroot identity required")
    routes4 = Path("/proc/net/route").read_text().splitlines()
    routes6 = Path("/proc/net/ipv6_route").read_text().splitlines()
    if (any(row.split()[0] != "lo" for row in routes4[1:])
            or any(row.split()[-1] != "lo" for row in routes6)):
        raise ValueError("diagnostic QEMU namespace has an external route")
    return current


def checked_output_mount(root, output):
    if output != root / "observe" or output.is_symlink() or not output.is_dir():
        raise ValueError("dedicated ROOT/observe output mount required")
    if (not mounted_at(output) or os.statvfs(output).f_flag & os.ST_RDONLY
            or any(output.iterdir())):
        raise ValueError("observation output must be a fresh writable mount")
    proc = root / "proc"
    if not proc.is_dir() or not mounted_at(proc):
        raise ValueError("QEMU chroot requires its private proc mount")
    for name in ("null", "zero", "urandom"):
        device = root / "dev" / name
        if device.is_symlink() or not stat.S_ISCHR(device.stat().st_mode):
            raise ValueError("QEMU chroot lacks reviewed minimal device: " + name)
    socket_path = output / QMP_SOCKET
    # Linux sockaddr_un.sun_path is 108 bytes including its NUL terminator.
    if len(os.fsencode(socket_path)) >= 108:
        raise ValueError("QMP Unix socket path exceeds Linux sun_path")


def prepare_output(root, output, uid, gid):
    os.chown(output, uid, gid, follow_symlinks=False)
    output.chmod(0o700)
    template = toolchain.checked_file(
        root, {entry["path"]: entry for entry in json_file(root / stager.MANIFEST)["entries"]},
        toolchain.OVMF_VARS, "ovmf")
    destination = output / "OVMF_VARS_4M.fd"
    with template.open("rb") as source, destination.open("xb") as target:
        while chunk := source.read(1024 * 1024):
            target.write(chunk)
    if sha256_file(destination) != sha256_file(template):
        raise ValueError("QEMU firmware variable template copy differs")
    os.chown(destination, uid, gid, follow_symlinks=False)
    destination.chmod(0o600)
    return sha256_file(template)


def qemu_command(fd, memory_mib, vcpus):
    if (type(fd) is not int or fd <= 2 or type(memory_mib) is not int
            or memory_mib <= 0 or type(vcpus) is not int or vcpus <= 0):
        raise ValueError("explicit QEMU disk descriptor, memory and CPU inputs required")
    # The package-only chroot need not have QEMU's absolute ELF interpreter
    # alias. Use the signed loader already checked in the stage.
    return ["/" + toolchain.LOADER, "--inhibit-cache", "--library-path",
            "/" + toolchain.LIBRARY, "/" + toolchain.QEMU,
            "-machine", "q35,accel=tcg", "-cpu", "max",
            "-m", str(memory_mib), "-smp", str(vcpus), "-nodefaults",
            "-vga", "std", "-display", "none", "-nic", "none",
            "-serial", "none", "-parallel", "none", "-monitor", "none",
            "-no-reboot", "-no-shutdown", "-L", "/usr/share/qemu",
            "-qmp", "unix:/observe/qmp.sock,server=on,wait=off",
            "-drive", "if=pflash,format=raw,unit=0,readonly=on,file=/" + toolchain.OVMF_CODE,
            "-drive", "if=pflash,format=raw,unit=1,file=/observe/OVMF_VARS_4M.fd",
            "-add-fd", f"fd={fd},set=1,opaque=rdonly:diagnostic-disk",
            "-drive", "if=none,id=diagnostic-disk,format=raw,readonly=on,file=/dev/fdset/1",
            "-device", "nvme,serial=zrpc-diagnostic,drive=diagnostic-disk,bootindex=1"]


def _drop_and_chroot(root, uid, gid, ready_fd):
    os.chroot(root)
    os.chdir("/")
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "cannot set no_new_privs for QEMU")
    status = Path("/proc/self/status").read_text().splitlines()
    fields = dict(line.split(":", 1) for line in status if ":" in line)
    if (os.geteuid() != uid or os.getegid() != gid or os.getgroups()
            or any(int(fields[name].strip(), 16) != 0 for name in
                   ("CapInh", "CapPrm", "CapEff", "CapAmb"))
            or fields["NoNewPrivs"].strip() != "1"):
        raise ValueError("QEMU child did not drop identity and capabilities")
    os.write(ready_fd, b"D")
    os.close(ready_fd)


class Qmp:
    def __init__(self, connection):
        self.connection = connection
        self.pending = b""
        self.events = []

    def receive(self, deadline):
        if time.monotonic() >= deadline:
            raise TimeoutError("QMP observation deadline reached")
        while b"\n" not in self.pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("QMP observation deadline reached")
            self.connection.settimeout(remaining)
            try:
                chunk = self.connection.recv(65536)
            except socket.timeout as error:
                raise TimeoutError("QMP observation deadline reached") from error
            if not chunk:
                raise EOFError("QMP Unix socket closed")
            self.pending += chunk
        line, self.pending = self.pending.split(b"\n", 1)
        message = json.loads(line.rstrip(b"\r"), object_pairs_hook=direct.unique_object)
        if type(message) is not dict:
            raise ValueError("QMP response is not an object")
        return message

    def command(self, name, arguments, deadline):
        token = name
        data = (json.dumps({"execute": name, "arguments": arguments, "id": token},
                           separators=(",", ":")) + "\r\n").encode()
        self.connection.settimeout(max(0, deadline - time.monotonic()))
        self.connection.sendall(data)
        while True:
            message = self.receive(deadline)
            if "event" in message:
                self.events.append(message)
                continue
            if message.get("id") != token:
                raise ValueError("QMP response ID differs")
            if "error" in message or "return" not in message:
                raise ValueError("QMP command failed: " + name)
            return message["return"]

    def next_event(self, deadline):
        try:
            message = self.receive(deadline)
        except TimeoutError:
            return None
        if "event" not in message:
            raise ValueError("unsolicited QMP response has no event")
        self.events.append(message)
        return message


def connect_qmp(path, process, deadline):
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise ValueError("QEMU exited before QMP became available")
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            connection.connect(str(path))
            qmp = Qmp(connection)
            greeting = qmp.receive(deadline)
            if type(greeting.get("QMP")) is not dict:
                raise ValueError("QMP greeting is absent")
            qmp.command("qmp_capabilities", {}, deadline)
            return qmp
        except (FileNotFoundError, ConnectionRefusedError):
            connection.close()
            # Scheduling cadence only; the caller's explicit deadline is the
            # sole acceptance boundary for connection and observation.
            time.sleep(min(0.1, max(0, deadline - time.monotonic())))
        except BaseException:
            connection.close()
            raise
    raise TimeoutError("QMP did not start before the explicit deadline")


def capture(qmp, output, label, deadline):
    name = f"vga-{len([path for path in output.iterdir() if path.name.startswith('vga-')])}-{label}.ppm"
    target = output / name
    if target.exists() or target.is_symlink():
        raise ValueError("QMP VGA target was not fresh")
    qmp.command("screendump", {"filename": CHROOT_OUTPUT + "/" + name}, deadline)
    descriptor = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        record = os.fstat(descriptor)
        if not stat.S_ISREG(record.st_mode) or record.st_size <= 3 or os.read(descriptor, 3) != b"P6\n":
            raise ValueError("QMP VGA capture is not a PPM image")
    finally:
        os.close(descriptor)
    return {"path": str(target), "sha256": sha256_file(target), "bytes": target.stat().st_size,
            "label": label}


def observe(qmp, process, output, deadline, started, offsets):
    captures = [capture(qmp, output, "initial", deadline)]
    initial_status = qmp.command("query-status", {}, deadline)
    next_offset = 0
    reason = "explicit_deadline"
    while time.monotonic() < deadline:
        if any(event.get("event") == "SHUTDOWN" for event in qmp.events):
            reason = "guest_shutdown_event"
            break
        if process.poll() is not None:
            reason = "qemu_exited"
            break
        now = time.monotonic()
        if next_offset < len(offsets) and now - started >= offsets[next_offset]:
            captures.append(capture(qmp, output, f"scheduled-{next_offset}", deadline))
            next_offset += 1
            continue
        wait_until = min(deadline, started + offsets[next_offset]) if next_offset < len(offsets) else deadline
        event = qmp.next_event(wait_until)
        if event is not None and event.get("event") == "SHUTDOWN":
            reason = "guest_shutdown_event"
            break
    if reason == "guest_shutdown_event" and time.monotonic() < deadline:
        captures.append(capture(qmp, output, "shutdown", deadline))
    status = None
    if time.monotonic() < deadline:
        status = qmp.command("query-status", {}, deadline)
    return {"observation_end": reason, "initial_qmp_status": initial_status,
            "final_qmp_status": status, "screenshots": captures,
            "qmp_events": qmp.events,
            "guest_shutdown_event": any(event.get("event") == "SHUTDOWN"
                                        and event.get("data", {}).get("guest") is True
                                        for event in qmp.events)}


def run(args):
    root = args.toolchain_root
    checked_execution_context(args.parent_net_ns, args.qemu_uid, args.qemu_gid)
    checked_stage(root, args.toolchain_report)
    checked_output_mount(root, args.output)
    if (type(args.deadline_seconds) is not int or args.deadline_seconds <= 0
            or type(args.memory_mib) is not int or args.memory_mib <= 0
            or type(args.vcpus) is not int or args.vcpus <= 0
            or args.capture_at_seconds != sorted(set(args.capture_at_seconds))
            or any(offset <= 0 or offset >= args.deadline_seconds
                   for offset in args.capture_at_seconds)):
        raise ValueError("explicit positive resources/deadline and ordered capture offsets required")
    fd, disk_report = checked_disk(args.disk, args.disk_report)
    boot_fd = fd
    tamper_report = None
    process = None
    qmp = None
    ready_read = None
    try:
        vars_sha256 = prepare_output(root, args.output, args.qemu_uid, args.qemu_gid)
        if args.tamper_root_data:
            boot_fd, tamper_report = root_data_tamper(
                fd, args.disk, disk_report, args.output)
        command = qemu_command(boot_fd, args.memory_mib, args.vcpus)
        ready_read, ready_write = os.pipe2(os.O_CLOEXEC)
        try:
            with (args.output / "qemu.log").open("xb") as log:
                process = subprocess.Popen(
                    command, stdin=subprocess.DEVNULL, stdout=log,
                    stderr=subprocess.STDOUT,
                    env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C"},
                    close_fds=True, pass_fds=(boot_fd, ready_write), start_new_session=True,
                    preexec_fn=lambda: _drop_and_chroot(root, args.qemu_uid,
                                                         args.qemu_gid, ready_write))
        finally:
            os.close(ready_write)
        if os.read(ready_read, 1) != b"D":
            raise ValueError("QEMU privilege-drop witness absent")
        os.close(ready_read)
        ready_read = None
        started = time.monotonic()
        deadline = started + args.deadline_seconds
        qmp = connect_qmp(args.output / QMP_SOCKET, process, deadline)
        observed = observe(qmp, process, args.output, deadline, started,
                           args.capture_at_seconds)
        report = {"schema_version": 1,
                  "status": TAMPER_STATUS if tamper_report else STATUS,
                  "qemu_attempted": True,
                  "qmp_connected": True, "qemu_unprivileged_witness": True,
                  "qemu_uid": args.qemu_uid, "qemu_gid": args.qemu_gid,
                  "guest_network_devices_configured": False,
                  "disk_sha256": (tamper_report["boot_disk_sha256"] if tamper_report
                                  else disk_report["raw_disk_sha256"]),
                  "disk_bytes": disk_report["raw_disk_bytes"],
                  "ovmf_vars_template_sha256": vars_sha256,
                  "memory_mib": args.memory_mib, "vcpus": args.vcpus,
                  "observation_deadline_seconds": args.deadline_seconds,
                  "secure_boot_verified": False, "hardware_verified": False,
                  "early_init_handoff_verified": False, "rootfs_ready_verified": False,
                  "boot_verified": False, "private_mode_approved": False,
                  **({"root_data_tamper": tamper_report} if tamper_report else {}),
                  **observed}
        return report
    finally:
        if ready_read is not None:
            os.close(ready_read)
        if qmp is not None:
            try:
                qmp.connection.close()
            except OSError:
                pass
        try:
            if process is not None:
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                process.wait(timeout=args.deadline_seconds)
        finally:
            try:
                if boot_fd != fd:
                    try:
                        if digest_fd(boot_fd, disk_report["raw_disk_bytes"]) != \
                                tamper_report["boot_disk_sha256"]:
                            raise ValueError("derived diagnostic disk changed during QEMU observation")
                    finally:
                        os.close(boot_fd)
                if digest_fd(fd, disk_report["raw_disk_bytes"]) != disk_report["raw_disk_sha256"]:
                    raise ValueError("diagnostic disk changed during QEMU observation")
            finally:
                os.close(fd)


def persist_report(root, output, report):
    """Write one fresh report only on the supervisor's dedicated output mount."""
    if (output != root / "observe" or output.is_symlink() or not output.is_dir()
            or not mounted_at(output) or os.statvfs(output).f_flag & os.ST_RDONLY):
        return False
    path = output / "observation.json"
    data = (json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    running = sub.add_parser("run")
    for name in ("toolchain-root", "toolchain-report", "disk", "disk-report", "output"):
        running.add_argument("--" + name, type=Path, required=True)
    for name in ("memory-mib", "vcpus", "deadline-seconds", "qemu-uid", "qemu-gid"):
        running.add_argument("--" + name, type=int, required=True)
    running.add_argument("--capture-at-seconds", type=int, action="append", default=[])
    running.add_argument("--tamper-root-data", action="store_true")
    running.add_argument("--parent-net-ns", required=True)
    args = parser.parse_args(argv)
    try:
        result = run(args)
        if not persist_report(args.toolchain_root, args.output, result):
            raise ValueError("observation report output mount disappeared")
    except (OSError, ValueError, KeyError, TypeError, IndexError, TimeoutError,
            EOFError, subprocess.SubprocessError) as error:
        blocked = {"schema_version": 1, "status": "blocked", "reason": str(error),
                   "boot_verified": False, "private_mode_approved": False}
        try:
            persist_report(args.toolchain_root, args.output, blocked)
        except (OSError, ValueError):
            pass
        print(json.dumps(blocked, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
