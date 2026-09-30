#!/usr/bin/env python3
"""Exercise local quote, Zebra and wrapper runtime wiring on native Linux.

This is not a snapshot import, dstack boot, TDX boot, or full-guest fit test.
"""

import argparse
import ipaddress
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import uuid


QUOTE_CHECK = r"""
import os
from pathlib import Path
import signal
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
assert stat.S_ISSOCK(os.stat('/dstack.sock').st_mode)
marker = Path('/run/zrpc-mount-probe')
with marker.open('xb') as output:
    output.write(b'quote')
marker.chmod(0o660)
print('READY', flush=True)
signal.pause()
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
assert not Path('/run/dstack.sock').exists()
assert not Path('/dstack.sock').exists()
marker = Path('/run/zrpc-mount-probe')
assert marker.read_bytes() == b'quote'
with os.fdopen(os.open(marker, os.O_WRONLY | os.O_APPEND), 'wb') as output:
    output.write(b'/app')
state = Path('/var/lib/zebra')
assert state.stat().st_uid == 10001
assert stat.S_IMODE(state.stat().st_mode) & 0o007 == 0
(state / 'zrpc-volume-probe').write_bytes(b'public state')
Path('/run/zrpc-cookie-probe').write_bytes(b'ephemeral')
cookie_dir = Path('/run/zrpc-node')
cookie_dir.mkdir(mode=0o700)
assert cookie_dir.stat().st_uid == 10001
assert stat.S_IMODE(cookie_dir.stat().st_mode) == 0o700
"""


ZEBRA_RPC_CHECK = r"""
import base64
import json
from pathlib import Path
import time
import urllib.error
import urllib.request

cookie_path = Path('/run/zrpc-node/.cookie')
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
body = json.dumps({
    'jsonrpc': '2.0', 'method': 'getblockchaininfo', 'params': [], 'id': 1,
}).encode()
cookie_seen = False
while True:
    try:
        cookie = cookie_path.read_bytes().strip()
    except FileNotFoundError:
        time.sleep(1)
        continue
    if not cookie_seen:
        print('Zebra cookie is present; waiting for authenticated RPC', flush=True)
        cookie_seen = True
    request = urllib.request.Request('http://127.0.0.1:18232/', body, {
        'Content-Type': 'application/json',
        'Authorization': 'Basic ' + base64.b64encode(cookie).decode(),
    })
    try:
        with opener.open(request, timeout=15) as response:
            content = response.read(65537)
    except urllib.error.HTTPError as error:
        raise RuntimeError(f'Zebra RPC returned HTTP {error.code}') from error
    except urllib.error.URLError:
        time.sleep(1)
        continue
    if len(content) > 65536:
        raise ValueError('Zebra RPC response exceeded the client bound')
    result = json.loads(content)
    if result.get('error') is not None or result['result']['chain'] != 'test':
        raise ValueError('unexpected Zebra Testnet RPC response')
    print(json.dumps({
        'chain': result['result']['chain'],
        'blocks': result['result']['blocks'],
    }, sort_keys=True))
    break
"""


BRIDGE_RPC_CHECK = r"""
import socket
import sys

try:
    with socket.create_connection((sys.argv[1], 18232), timeout=15):
        raise AssertionError('Zebra RPC accepted a bridge-network connection')
except ConnectionRefusedError:
    print('Zebra RPC refused bridge-network access', flush=True)
"""


ROOT_BACKEND_CHECK = r"""
import os
from pathlib import Path
import signal
import socket
import stat

path = Path('/backend/stock-dstack.sock')
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
    listener.bind(str(path))
    os.chmod(path, 0o777)
    listener.listen(1)
    assert path.stat().st_uid == 0
    assert stat.S_ISSOCK(path.stat().st_mode)
    print('READY', flush=True)
    signal.pause()
"""


APP_BRIDGE_CHECK = r"""
from pathlib import Path
import socket
import stat

assert not Path('/run/dstack.sock').exists()
assert not Path('/dstack.sock').exists()
assert Path('/run/zrpc-quote-ready').stat().st_uid == 10002
for name in ('quote.sock', 'watch.sock'):
    item = Path('/run/zrpc-quote') / name
    metadata = item.stat()
    assert stat.S_ISSOCK(metadata.st_mode)
    assert metadata.st_uid == 10002
    assert stat.S_IMODE(metadata.st_mode) == 0o660
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
    client.connect('/run/zrpc-quote/quote.sock')
    client.sendall(b'POST /GetKey HTTP/1.1\r\nHost: dstack\r\n'
                   b'Content-Type: application/json\r\nContent-Length: 0\r\n\r\n')
    assert client.recv(128).startswith(b'HTTP/1.1 404 ')
print('Packaged quote bridge ready; app cannot access backend or nonquote route',
      flush=True)
"""


WRAPPER_TLS_CHECK = r"""
import socket
import ssl
import sys

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
# Synthetic transport probe only; client release/quote approval is never inferred.
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.maximum_version = ssl.TLSVersion.TLSv1_3
context.set_alpn_protocols(['http/1.1'])
try:
    raw = socket.create_connection(('127.0.0.1', 8443), timeout=15)
except ConnectionRefusedError:
    sys.exit(75)
with raw, context.wrap_socket(raw, server_hostname='localhost') as tls:
    assert tls.version() == 'TLSv1.3'
    assert tls.selected_alpn_protocol() == 'http/1.1'
    tls.sendall(b'POST /rpc HTTP/1.1\r\nHost: localhost\r\n'
                b'Content-Type: application/json\r\nContent-Length: 0\r\n\r\n')
    assert tls.recv(128).startswith(b'HTTP/1.1 403 ')
print('Synthetic TLS 1.3 wrapper refused RPC before attestation', flush=True)
"""


WRAPPER_DOWN_CHECK = r"""
import socket

try:
    with socket.create_connection(('127.0.0.1', 8443), timeout=15):
        raise AssertionError('wrapper listener survived quote bridge loss')
except ConnectionRefusedError:
    print('Wrapper listener closed after quote bridge loss', flush=True)
"""


def docker(*args):
    subprocess.run(["docker", *args], check=True)


def container(image, user, runtime, state, backend, code, name=None):
    args = [
        "run", "--pull=never", "--network", "none", "--read-only",
        "--cap-drop=ALL", "--security-opt", "no-new-privileges:true",
        "--user", user, "--mount", f"type=volume,source={runtime},target=/run",
    ]
    args += ["--detach", "--name", name] if name else ["--rm"]
    if state is not None:
        args += ["--mount", f"type=volume,source={state},target=/var/lib/zebra"]
    if backend is not None:
        args += ["--mount", (
            f"type=bind,source={backend},target=/dstack.sock,readonly")]
    docker(*args, "--entrypoint", "python3", image, "-I", "-c", code)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    suffix = uuid.uuid4().hex
    runtime = f"zrpc-mount-smoke-run-{suffix}"
    state = f"zrpc-mount-smoke-state-{suffix}"
    quote_name = f"zrpc-mount-smoke-quote-{suffix}"
    zebra_name = f"zrpc-mount-smoke-zebra-{suffix}"
    backend_name = f"zrpc-mount-smoke-backend-{suffix}"
    bridge_name = f"zrpc-mount-smoke-bridge-{suffix}"
    wrapper_name = f"zrpc-mount-smoke-wrapper-{suffix}"
    created = []
    quote_started = False
    zebra_started = False
    backend_started = False
    bridge_started = False
    wrapper_started = False
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
                          QUOTE_CHECK, quote_name)
                quote_started = True
                with subprocess.Popen(
                    ["docker", "logs", "--follow", quote_name],
                    stdout=subprocess.PIPE, text=True,
                ) as logs:
                    if logs.stdout.readline().strip() != "READY":
                        raise RuntimeError("quote mount probe stopped before readiness")
                    logs.terminate()
                container(args.image, "10001:0", runtime, state, None,
                          APP_CHECK)
                stock_backend = Path(directory) / "stock-dstack.sock"
                docker(
                    "run", "--detach", "--name", backend_name, "--pull=never",
                    "--network", "none", "--read-only", "--user", "0:0",
                    "--mount", f"type=bind,source={directory},target=/backend",
                    "--entrypoint", "python3", args.image, "-I", "-c",
                    ROOT_BACKEND_CHECK,
                )
                backend_started = True
                with subprocess.Popen(
                    ["docker", "logs", "--follow", backend_name],
                    stdout=subprocess.PIPE, text=True,
                ) as logs:
                    if logs.stdout.readline().strip() != "READY":
                        raise RuntimeError("root-owned backend fixture stopped before readiness")
                    logs.terminate()
                if stock_backend.stat().st_uid != 0:
                    raise AssertionError("synthetic stock backend is not root-owned")
                # The package test's one-second synthetic fixture exercises
                # readiness; it is not a selected deployment startup limit.
                docker(
                    "run", "--detach", "--name", bridge_name, "--pull=never",
                    "--network", "none", "--read-only", "--cap-drop=ALL",
                    "--security-opt", "no-new-privileges:true",
                    "--user", "10002:0", "--env", "QUOTE_STARTUP_TIMEOUT_SECS=1",
                    "--mount", f"type=volume,source={runtime},target=/run",
                    "--mount", (f"type=bind,source={stock_backend},"
                                "target=/dstack.sock,readonly"),
                    args.image, "quote",
                )
                bridge_started = True
                while subprocess.run(
                    ["docker", "exec", "--user", "10002:0", bridge_name,
                     "python3", "/opt/zrpc/supervisor.py", "quote-health"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                ).returncode != 0:
                    running = subprocess.check_output(
                        ["docker", "inspect", "--format", "{{.State.Running}}",
                         bridge_name], text=True).strip()
                    if running != "true":
                        docker("logs", bridge_name)
                        raise RuntimeError("packaged quote service stopped before readiness")
                    time.sleep(0.1)
                container(args.image, "10001:0", runtime, None, None,
                          APP_BRIDGE_CHECK)
                docker(
                    "run", "--detach", "--name", zebra_name, "--pull=never",
                    "--network", "bridge", "--read-only", "--memory", "8g",
                    "--cap-drop=ALL", "--security-opt", "no-new-privileges:true",
                    "--user", "10001:0",
                    "--mount", f"type=volume,source={runtime},target=/run",
                    "--mount", f"type=volume,source={state},target=/var/lib/zebra",
                    "--entrypoint", "/opt/zrpc/bin/zebrad", args.image,
                    "-c", "/opt/zrpc/zebra.toml", "start",
                )
                zebra_started = True
                docker("exec", "--user", "10001:0", zebra_name,
                       "python3", "-I", "-c", ZEBRA_RPC_CHECK)
                network = json.loads(subprocess.check_output(
                    ["docker", "inspect", "--format",
                     "{{json .NetworkSettings}}", zebra_name], text=True))
                bridge_ip = network["Networks"]["bridge"]["IPAddress"]
                address = ipaddress.ip_address(bridge_ip)
                if (not isinstance(address, ipaddress.IPv4Address)
                        or address.is_loopback or address.is_unspecified
                        or any(bindings for bindings in
                               (network.get("Ports") or {}).values())):
                    raise AssertionError("Zebra network or published ports differ")
                docker("run", "--rm", "--pull=never", "--network", "bridge",
                       "--read-only", "--cap-drop=ALL", "--security-opt",
                       "no-new-privileges:true", "--user", "10001:0",
                       "--entrypoint", "python3", args.image, "-I", "-c",
                       BRIDGE_RPC_CHECK, bridge_ip)
                # Type/CLI minima are synthetic harness values, never selected
                # production connection, quote or spacing limits.
                docker(
                    "run", "--detach", "--name", wrapper_name, "--pull=never",
                    "--network", f"container:{zebra_name}", "--read-only",
                    "--cap-drop=ALL", "--security-opt", "no-new-privileges:true",
                    "--user", "10001:0",
                    "--mount", f"type=volume,source={runtime},target=/run",
                    "--entrypoint", "/opt/zrpc/bin/zrpc-node-wrapper", args.image,
                    "--platform", "phala-dstack", "--listen", "0.0.0.0:8443",
                    "--node", "127.0.0.1:18232", "--max-connections", "1",
                    "--max-quotes", "1", "--quote-spacing-ms", "1",
                )
                wrapper_started = True
                while True:
                    probe = subprocess.run(
                        ["docker", "exec", "--user", "10001:0", zebra_name,
                         "python3", "-I", "-c", WRAPPER_TLS_CHECK],
                        capture_output=True, text=True,
                    )
                    if probe.returncode == 0:
                        print(probe.stdout.strip())
                        break
                    if probe.returncode != 75:
                        raise RuntimeError(f"wrapper TLS probe failed: {probe.stderr}")
                    running = subprocess.check_output(
                        ["docker", "inspect", "--format", "{{.State.Running}}",
                         wrapper_name], text=True).strip()
                    if running != "true":
                        docker("logs", wrapper_name)
                        raise RuntimeError("wrapper stopped or missed TLS readiness")
                    time.sleep(0.1)
                docker("rm", "--force", bridge_name)
                bridge_started = False
                stopped = subprocess.run(
                    ["docker", "wait", wrapper_name], capture_output=True,
                    text=True, check=True,
                )
                if stopped.stdout.strip() != "1":
                    raise AssertionError("wrapper did not fail closed on quote loss")
                docker("exec", "--user", "10001:0", zebra_name,
                       "python3", "-I", "-c", WRAPPER_DOWN_CHECK)
        print("Native quote, Zebra and wrapper shutdown smoke passed; no dstack guest was used.")
    finally:
        if wrapper_started:
            docker("rm", "--force", wrapper_name)
        if zebra_started:
            docker("rm", "--force", zebra_name)
        if bridge_started:
            docker("rm", "--force", bridge_name)
        if backend_started:
            docker("rm", "--force", backend_name)
        if quote_started:
            docker("rm", "--force", quote_name)
        for volume in reversed(created):
            docker("volume", "rm", volume)


if __name__ == "__main__":
    main()
