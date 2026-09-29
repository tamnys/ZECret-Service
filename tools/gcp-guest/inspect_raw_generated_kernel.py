#!/usr/bin/env python3
"""Derive raw-root kernel additions from authenticated Debian package data.

The caller supplies the payloads and rows returned together by
assemble_guest_base_tree.source_plan(preflight.authenticated_archives(...)).
No image-observed entry is an input to this plan. The caller must compare every
returned entry with the complete raw ext4 inventory and keep rejecting extras.
"""

import hashlib
import io
from pathlib import Path
import re
import tarfile
import tempfile
from types import SimpleNamespace

import export_rust_inputs as rust_inputs
import inspect_final_initrd as final_initrd
import prepare


HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
DEPMOD_CONFIG_FILES = frozenset({"etc/depmod.conf"})
DEPMOD_CONFIG_DIRS = (
    "etc/depmod.d", "run/depmod.d", "usr/local/lib/depmod.d",
    "usr/lib/depmod.d", "lib/depmod.d",
)


def _source_rows(rows):
    if type(rows) is not list or not rows:
        raise ValueError("authenticated kernel source rows required")
    source = {}
    for row in rows:
        if type(row) is not dict or type(row.get("path")) is not str:
            raise ValueError("authenticated kernel source row is malformed")
        path = row["path"]
        if path in source:
            raise ValueError("duplicate authenticated kernel source path: " + path)
        source[path] = row
    return source


def _no_depmod_configuration(source, overlay):
    """The existing replay uses -C /dev/null; reject inputs it would omit."""
    if type(overlay) is not dict:
        raise ValueError("verified source overlay required for depmod replay")
    for inventory, kind_field in ((source, "kind"), (overlay, "type")):
        for path, row in inventory.items():
            if type(path) is not str or type(row) is not dict:
                raise ValueError("depmod source inventory is malformed")
            if path in DEPMOD_CONFIG_FILES:
                raise ValueError("native-root depmod replay has configuration: " + path)
            for directory in DEPMOD_CONFIG_DIRS:
                if path == directory and row.get(kind_field) != "directory":
                    raise ValueError("native-root depmod configuration directory redirects: " + path)
                if path.startswith(directory + "/"):
                    raise ValueError("native-root depmod replay has configuration: " + path)


def _boot_image_row(source, overlay, kernel, version):
    boot = "boot/vmlinuz-" + version
    module_root = "usr/lib/modules/" + version
    target = module_root + "/vmlinuz"
    row = source.get(boot)
    module_dir = source.get(module_root)
    if (row is None or row.get("kind") != "file"
            or row.get("packages") != [kernel]
            or (row.get("uid"), row.get("gid")) != (0, 0)
            or type(row.get("size")) is not int or row["size"] <= 0
            or type(row.get("sha256")) is not str
            or not HEX_SHA256.fullmatch(row["sha256"])
            or type(row.get("source_mode")) is not int
            or type(row.get("output_mode")) is not int
            or row.get("output_mode") != row["source_mode"]
            or row["source_mode"] & 0o7022
            or module_dir is None or module_dir.get("kind") != "directory"
            or (module_dir.get("uid"), module_dir.get("gid")) != (0, 0)
            or target in source):
        raise ValueError("signed kernel boot image or module destination differs")
    if any(path == module_root or path.startswith(module_root + "/")
           for path in overlay):
        raise ValueError("source overlay supplies a kernel module path")
    return boot, target, row


def _stage_boot_image(payload, boot, target, row, root):
    """Copy the one exact signed boot member to mkosi's module-image location."""
    output = root / target
    if output.exists() or output.is_symlink():
        raise ValueError("signed kernel module image destination already exists")
    seen = False
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:xz") as archive:
        for member in archive:
            if member.name != "./" + boot:
                continue
            if (seen or not member.isfile() or member.pax_headers
                    or member.uid != 0 or member.gid != 0
                    or member.mode != row["source_mode"]
                    or member.size != row["size"]):
                raise ValueError("signed kernel boot member differs from source plan")
            seen = True
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("signed kernel boot member cannot be read")
            digest = hashlib.sha256()
            remaining = member.size
            with output.open("xb") as destination:
                while remaining:
                    data = stream.read(min(remaining, 1024 * 1024))
                    if not data:
                        raise ValueError("signed kernel boot member is truncated")
                    destination.write(data)
                    digest.update(data)
                    remaining -= len(data)
            if digest.hexdigest() != row["sha256"]:
                raise ValueError("signed kernel boot member bytes differ from source plan")
            output.chmod(row["source_mode"])
    if not seen:
        raise ValueError("signed kernel package omits boot image")
    return row["size"], row["sha256"], row["source_mode"]


def expected_entries(payloads, source_rows, verified_overlay, workspace):
    """Return exact raw-root vmlinuz and modules.* expectations.

    Production mkosi invokes depmod inside its root after copying vmlinuz.
    The existing signed-kmod replay uses an empty depmod configuration; this
    function rejects any source configuration it would omit. If native-root
    output differs despite those conditions, the raw inspector must reject it
    rather than admitting observed bytes.
    """
    if type(payloads) is not dict or any(
            type(payloads.get(name)) is not bytes
            for name in (prepare.KERNEL_PACKAGE, "kmod", "libkmod2")):
        raise ValueError("authenticated kernel and kmod payloads required")
    workspace = Path(workspace)
    if not workspace.is_absolute() or workspace.is_symlink() or not workspace.is_dir():
        raise ValueError("private workspace directory required for kernel replay")
    source = _source_rows(source_rows)
    _no_depmod_configuration(source, verified_overlay)
    version = prepare.KERNEL_VERSION
    boot, target, row = _boot_image_row(
        source, verified_overlay, prepare.KERNEL_PACKAGE, version)
    try:
        depmod = final_initrd.checked_depmod_tool(
            payloads["kmod"], payloads["libkmod2"],
            SimpleNamespace(rust_inputs=rust_inputs))
        with tempfile.TemporaryDirectory(prefix="zrpc-raw-kernel-", dir=workspace) as temporary:
            root = Path(temporary)
            signed = final_initrd.package_tree(
                payloads[prepare.KERNEL_PACKAGE], root, version)
            image = _stage_boot_image(
                payloads[prepare.KERNEL_PACKAGE], boot, target, row, root)
            signed[target] = image
            replayed, generated = final_initrd.reconstructed_members(
                root, signed, version, depmod)
    except (OSError, ValueError, tarfile.TarError) as error:
        raise ValueError("native-root depmod replay unresolved: " + str(error)) from error
    base = "usr/lib/modules/" + version + "/"
    if (type(generated) is not set or any(type(name) is not str for name in generated)
            or not {"modules.dep", "modules.dep.bin"} <= generated):
        raise ValueError("native-root depmod replay omitted required indexes")
    entries = {
        target: {"type": "regular", "mode": image[2], "uid": 0, "gid": 0,
                 "size": image[0], "sha256": image[1]},
    }
    for name in sorted(generated):
        path = base + name
        identity = replayed.get(path)
        if (not isinstance(name, str) or "/" in name
                or not name.startswith("modules.")
                or path in source or path in verified_overlay
                or type(identity) is not tuple or len(identity) != 3
                or type(identity[0]) is not int or identity[0] < 0
                or type(identity[1]) is not str
                or not HEX_SHA256.fullmatch(identity[1])
                or type(identity[2]) is not int
                or identity[2] & 0o133):
            raise ValueError("native-root depmod replay emitted an unreviewed index: " + str(name))
        entries[path] = {"type": "regular", "mode": identity[2],
                         "uid": 0, "gid": 0, "size": identity[0],
                         "sha256": identity[1]}
    return entries
