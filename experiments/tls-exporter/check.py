#!/usr/bin/env python3
"""Compare the retained Rustls TLS 1.3 exporter with OpenSSL on one loopback TLS connection.

Run inside the managed browser-profile container. This checks API interoperability,
not Tor routing, a quote, guest key ownership, or release approval.
"""

import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests/fixtures/tls"
SOURCE = Path(__file__).with_name("openssl_server.c")


def check_fixture_hashes():
    identities = json.loads((FIXTURES / "provenance.json").read_text())["files"]
    for name in ("end.der", "end.key"):
        actual = hashlib.sha256((FIXTURES / name).read_bytes()).hexdigest()
        if actual != identities[name]["sha256"]:
            raise RuntimeError(f"public TLS test fixture changed: {name}")


def main():
    if sys.platform != "linux" or not ROOT.samefile(Path.cwd()):
        raise RuntimeError("run from the repository root inside managed Linux")
    check_fixture_hashes()
    compiler = shutil.which("cc")
    if compiler is None:
        raise RuntimeError("the managed container lacks a C compiler")
    flags = shlex.split(
        subprocess.check_output(["pkg-config", "--cflags", "--libs", "openssl"], text=True)
    )
    scratch = ROOT / ".codex-tmp"
    scratch.mkdir(exist_ok=True)
    built = subprocess.run(
        ["cargo", "test", "--locked", "-p", "zrpc-transport", "--no-run"],
        cwd=ROOT, capture_output=True, text=True,
    )
    if built.returncode != 0:
        raise RuntimeError("Rustls test build failed\n" + built.stdout + built.stderr)
    with tempfile.TemporaryDirectory(prefix="tls-exporter-", dir=scratch) as directory:
        executable = Path(directory) / "openssl-exporter-server"
        subprocess.run(
            [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", str(SOURCE), "-o", str(executable), *flags],
            check=True,
        )
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]
            server = subprocess.Popen(
                [str(executable), str(listener.fileno()), str(FIXTURES / "end.der"), str(FIXTURES / "end.key")],
                pass_fds=(listener.fileno(),),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            try:
                environment = os.environ.copy()
                environment["ZRPC_OPENSSL_EXPORTER_PORT"] = str(port)
                test = subprocess.run(
                    ["cargo", "test", "--locked", "-p", "zrpc-transport",
                     "tls::tests::openssl_exporter_matches_independent_server", "--",
                     "--ignored", "--exact", "--nocapture"],
                    cwd=ROOT,
                    env=environment,
                    capture_output=True,
                    text=True,
                    timeout=300,  # Existing maximum lifetime for one TLS connection.
                )
                if test.returncode != 0 or "1 passed; 0 failed" not in test.stdout:
                    raise RuntimeError("Rustls interoperability test failed\n" + test.stdout + test.stderr)
                _, server_error = server.communicate(timeout=300)
                if server.returncode != 0:
                    raise RuntimeError(
                        f"OpenSSL fixture exit {server.returncode}: {server_error.decode(errors='replace')}"
                    )
            finally:
                if server.poll() is None:
                    server.kill()
                    server.wait()
    print("Rustls/OpenSSL TLS 1.3 exporter and nonce-context agreement passed")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        print(f"exporter interoperability check blocked: {error}", file=sys.stderr)
        sys.exit(1)
