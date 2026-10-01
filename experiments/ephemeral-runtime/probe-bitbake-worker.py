#!/usr/bin/env python3
"""Probe the pinned BitBake worker's non-root network namespace setup.

Run this as a separate process: a successful probe has no network namespace
and must not continue into another command. It builds no guest artifact.
"""

import json
import os
from pathlib import Path
import socket
import subprocess
import sys


POKY_COMMIT = "cd44e6bd40b0c1f498b3feaeb5e9b72f8bf32d41"


def report(status: str, **details: object) -> int:
    print(json.dumps({
        "status": status,
        "guest_image_built": False,
        "private_mode_approved": False,
        **details,
    }, sort_keys=True))
    return 0 if status == "worker_namespace_probe_passed" else 1


def read_optional(path: str) -> str | None:
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


def main() -> int:
    if len(sys.argv) != 2:
        return report("blocked", reason="exactly one pinned Poky checkout is required")
    if sys.platform != "linux" or os.uname().machine != "x86_64" or os.geteuid() == 0:
        return report("blocked", reason="non-root native x86_64 Linux is required")

    poky = Path(sys.argv[1]).resolve()
    revision = subprocess.run(
        ["git", "-C", str(poky), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=False,
    )
    if revision.returncode != 0 or revision.stdout.strip() != POKY_COMMIT:
        return report("blocked", reason="Poky is not at the reviewed commit")

    sys.path.insert(0, str(poky / "bitbake" / "lib"))
    from bb import utils  # pylint: disable=import-outside-toplevel

    context = {
        "apparmor_userns_restriction": read_optional(
            "/proc/sys/kernel/apparmor_restrict_unprivileged_userns"),
        "apparmor_profile": read_optional("/proc/self/attr/current"),
    }
    original_user = os.readlink("/proc/self/ns/user")
    original_net = os.readlink("/proc/self/ns/net")
    uid, gid = os.getuid(), os.getgid()
    try:
        # This is the exact function called by the pinned BitBake worker before
        # ordinary task bodies. It may return without isolation if unshare fails.
        utils.disable_network(uid, gid)
        if (os.readlink("/proc/self/ns/user") == original_user
                or os.readlink("/proc/self/ns/net") == original_net):
            return report("blocked", reason="BitBake did not isolate the worker",
                          **context)
        if ((read_optional("/proc/self/uid_map") or "").split()
                != [str(uid), str(uid), "1"]
                or (read_optional("/proc/self/gid_map") or "").split()
                != [str(gid), str(gid), "1"]
                or read_optional("/proc/self/setgroups") != "deny"):
            return report("blocked", reason="worker identity map differs",
                          **context)
        if [name for _, name in socket.if_nameindex()] != ["lo"]:
            return report("blocked", reason="worker network is not loopback-only",
                          **context)
    except OSError as error:
        return report("blocked", reason=f"BitBake worker namespace: {error}",
                      **context)
    return report("worker_namespace_probe_passed", **context)


if __name__ == "__main__":
    raise SystemExit(main())
