"""Exercise the local public-only wrapper executable; never contacts Phala."""
import contextlib
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "target/debug/zrpc-wrapper"


def options(socket_path):
    # Harness settings, not release quotas. Three slots allow the two idle
    # sockets retained below plus an independent public HTTP exchange.
    return ["--listen", "127.0.0.1:0", "--dstack-socket", str(socket_path),
            "--max-connections", "3", "--max-quotes", "1",
            "--quote-spacing-ms", "1"]


def no_authority(report):
    for field in ("private_accepted", "query_sent", "private_rpc_enabled", "deployment_enabled"):
        assert report[field] is False, report


def tls_connect(address):
    # This fixture deliberately accepts the bootstrap certificate without PKI
    # trust. Successful TLS never constitutes attestation or private acceptance.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(["http/1.1"])
    stream = context.wrap_socket(socket.create_connection(address), server_hostname="localhost")
    assert stream.version() == "TLSv1.3"
    assert stream.selected_alpn_protocol() == "http/1.1"
    assert not stream.session_reused
    return stream


def request(address, path, body):
    with tls_connect(address) as stream:
        certificate = stream.getpeercert(binary_form=True)
        stream.sendall(b"POST " + path + b" HTTP/1.1\r\nHost: localhost\r\n"
                       b"Content-Type: application/json\r\nConnection: close\r\nContent-Length: "
                       + str(len(body)).encode() + b"\r\n\r\n" + body)
        response = http.client.HTTPResponse(stream)
        response.begin()
        return response.status, response.read(), certificate


@contextlib.contextmanager
def running(socket_path, keylog):
    env = dict(os.environ, SSLKEYLOGFILE=str(keylog))
    process = subprocess.Popen([str(BINARY), *options(socket_path)], env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        report = json.loads(process.stdout.readline())
        no_authority(report)
        assert report["state"] == "listening", report
        assert report["evidence_status"] == "unverified"
        assert report["approved_release"] is None
        host, port = report["listen"].rsplit(":", 1)
        assert host == "127.0.0.1"
        yield process, (host, int(port))
    finally:
        if process.poll() is None:
            process.terminate()
        stdout, stderr = process.communicate()
        assert process.returncode == 0, (stdout, stderr)
        assert not stderr, stderr
        stopped = json.loads(stdout)
        no_authority(stopped)
        assert stopped["state"] == "stopped"
        assert not keylog.exists(), "wrapper honored SSLKEYLOGFILE"


(ROOT / ".codex-tmp").mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(prefix="wrapper-check-", dir=ROOT / ".codex-tmp") as directory:
    socket_path = Path(directory) / "absent-dstack.sock"
    keylog = Path(directory) / "must-not-exist.keys"
    valid = options(socket_path)
    invalid = [[], valid + ["--listen", "127.0.0.1:0"],
               valid + ["--tls-key", "secret-input-marker"],
               valid + ["--rpc", "secret-input-marker"]]
    for flag, value in [("--listen", "0.0.0.0:0"), ("--listen", "[::]:0"),
                        ("--dstack-socket", "relative.sock"),
                        ("--max-connections", "0"), ("--max-quotes", "0"),
                        ("--quote-spacing-ms", "0")]:
        args = valid.copy()
        args[args.index(flag) + 1] = value
        invalid.append(args)
    for args in invalid:
        result = subprocess.run([str(BINARY), *args], capture_output=True, text=True)
        assert result.returncode != 0
        report = json.loads(result.stdout)
        no_authority(report)
        assert "error" in report and "listen" not in report
        assert not result.stderr and "secret-input-marker" not in result.stdout

    certificates = []
    for shutdown_signal in (signal.SIGTERM, signal.SIGINT):
        with running(socket_path, keylog) as (process, address):
            status, body, certificate = request(address, b"/rpc", b"secret-query-marker")
            assert status == 404 and b"secret-query-marker" not in body
            status, body, same_certificate = request(address, b"/attestation", json.dumps({"nonce": [0] * 32}).encode())
            assert status == 503, (status, body)
            assert certificate == same_certificate
            certificates.append(certificate)
            # Retain both an established session and an incomplete handshake.
            # Process shutdown must own and close both, rather than detach them.
            with tls_connect(address) as established, socket.create_connection(address) as incomplete:
                process.send_signal(shutdown_signal)
                process.wait()
                for stream in (established, incomplete):
                    try:
                        assert stream.recv(1) == b""
                    except (ConnectionResetError, ssl.SSLEOFError):
                        pass
            try:
                with socket.create_connection(address):
                    raise AssertionError("listener remained open after shutdown")
            except ConnectionRefusedError:
                pass
    assert certificates[0] != certificates[1], "TLS identity survived process restart"

print("Wrapper executable checks passed: loopback-only, public routes, fresh identities, no key log, sanitized refusal and owned shutdown.")
