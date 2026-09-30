#!/usr/bin/env python3
"""Exercise the preview image's local Docker mounts on a native Linux runner.

This is a Docker namespace and ownership smoke, not a dstack or TDX boot.
"""

import argparse
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import uuid


QUOTE_CHECK = r"""
import os
from pathlib import Path
import stat

def mount_type(path):
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        before, separator, after = line.partition(' - ')
        if separator and before.split()[4] == path:
            return after.split()[0]
    raise AssertionError(f'missing mount: {path}')

assert os.geteuid() == 10002
assert os.statvfs('/').f_flag & os.ST_RDONLY
assert mount_type('/run') == 'tmpfs'
assert stat.S_IMODE(os.stat('/run').st_mode) == 0o1775
assert stat.S_ISSOCK(os.stat('/run/dstack.sock').st_mode)
marker = Path('/run/zrpc-mount-probe')
with marker.open('xb') as output:
    output.write(b'quote')
marker.chmod(0o660)
"""


APP_CHECK = r"""
import os
from pathlib import Path
import stat

def mount_type(path):
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        before, separator, after = line.partition(' - ')
        if separator and before.split()[4] == path:
            return after.split()[0]
    raise AssertionError(f'missing mount: {path}')

assert os.geteuid() == 10001
assert os.statvfs('/').f_flag & os.ST_RDONLY
assert mount_type('/run') == 'tmpfs'
assert mount_type('/var/lib/zebra') != 'tmpfs'
backend = Path('/run/dstack.sock')
assert not backend.exists() or not stat.S_ISSOCK(backend.stat().st_mode)
marker = Path('/run/zrpc-mount-probe')
assert marker.read_bytes() == b'quote'
with marker.open('ab') as output:
    output.write(b'/app')
state = Path('/var/lib/zebra')
assert state.stat().st_uid == 10001
assert stat.S_IMODE(state.stat().st_mode) & 0o007 == 0
(state / 'zrpc-volume-probe').write_bytes(b'public state')
Path('/run/zrpc-cookie-probe').write_bytes(b'ephemeral')
"""


def docker(*args):
    subprocess.run(["docker", *args], check=True)


def container(image, user, runtime, state, backend, code):
    args = [
        "run", "--rm", "--pull=never", "--network", "none", "--read-only",
        "--cap-drop=ALL", "--security-opt", "no-new-privileges:true",
        "--user", user, "--mount", f"type=volume,source={runtime},target=/run",
    ]
    if state is not None:
        args += ["--mount", f"type=volume,source={state},target=/var/lib/zebra"]
    if backend is not None:
        args += ["--mount", (
            f"type=bind,source={backend},target=/run/dstack.sock,readonly")]
    docker(*args, "--entrypoint", "python3", image, "-I", "-c", code)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    suffix = uuid.uuid4().hex
    runtime = f"zrpc-mount-smoke-run-{suffix}"
    state = f"zrpc-mount-smoke-state-{suffix}"
    created = []
    try:
        docker("volume", "create", "--driver", "local", "--opt", "type=tmpfs",
               "--opt", "device=tmpfs", "--opt", "o=uid=0,gid=0,mode=1775",
               runtime)
        created.append(runtime)
        docker("volume", "create", state)
        created.append(state)
        with tempfile.TemporaryDirectory(prefix="zrpc-mount-smoke-") as directory:
            backend = Path(directory) / "dstack.sock"
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(backend))
                listener.listen(1)
                container(args.image, "10002:0", runtime, None, backend,
                          QUOTE_CHECK)
                container(args.image, "10001:0", runtime, state, None,
                          APP_CHECK)
        print("Native Docker mount/ownership smoke passed; no dstack guest was used.")
    finally:
        for volume in reversed(created):
            docker("volume", "rm", volume)


if __name__ == "__main__":
    main()
