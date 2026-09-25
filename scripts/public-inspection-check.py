"""Native public inspection through a local SOCKS/TLS fixture; no cloud calls.

Optional --strace uses an independently verified binary, tracing socket/connect
only. No TLS/session data, isolation credentials, file contents or RPC are traced.
"""
import argparse
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "target/debug/zrpc"
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--strace", type=Path)
options = parser.parse_args()
if options.strace:
    assert options.strace.is_absolute() and options.strace.is_file()

def exact(connection, count):
    data = bytearray()
    while len(data) < count:
        part = connection.recv(count - len(data))
        if not part:
            raise AssertionError("fixture connection ended early")
        data.extend(part)
    return bytes(data)

def process(args, environment, trace=None):
    command = [str(BIN), *args]
    if trace is not None:
        command = [str(options.strace), "-f", "-qq", "-e", "trace=socket,connect",
                   "-o", str(trace), *command]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            cwd=ROOT, env=environment, check=False)
    assert not result.stderr, "unexpected diagnostic stderr"
    output = json.loads(result.stdout)
    assert not output["private_accepted"] and not output["query_sent"]
    assert not output["deployment_enabled"]
    assert "SYNTHETIC_PRIVATE_MARKER" not in result.stdout.decode()
    return result.returncode, output

ROOT.joinpath(".codex-tmp").mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(dir=ROOT / ".codex-tmp") as temporary:
    directory = Path(temporary)
    # All policy measurements here are deliberately synthetic rejection inputs.
    policy = {"schema_version": 1,
              **{key: "00" * 48 for key in ("mrtd", "rtmr0", "rtmr1", "rtmr2")},
              **{key: "00" * 32 for key in ("os_image_hash", "compose_hash", "mr_kms")},
              **{key: "00" * 20 for key in ("app_id", "instance_id")},
              "storage_fs": "ext4", "key_provider": {"name": "kms", "id": "SYNTHETIC_ONLY"}}
    policy_path = directory / "policy.json"
    policy_path.write_text(json.dumps(policy))
    compose_path = directory / "app-compose.json"
    compose_path.write_text('{"synthetic":true}')
    collateral = ROOT / "tests/fixtures/dcap/tdx_quote_collateral.json"
    quote = ROOT.joinpath("tests/fixtures/dcap/tdx_quote.exact.bin").read_bytes().hex()
    certificate = directory / "public-test-cert.pem"
    certificate.write_text(ssl.DER_cert_to_PEM_cert(ROOT.joinpath("tests/fixtures/tls/end.der").read_bytes()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.num_tickets = 0
    context.set_alpn_protocols(["http/1.1"])
    context.load_cert_chain(certificate, ROOT / "tests/fixtures/tls/end.key")
    sni = []
    context.set_servername_callback(lambda _connection, hostname, _context: sni.append(hostname))

    def arguments(socks):
        return ["inspect-endpoint", "--endpoint-host", "unresolved-fixture.invalid",
                "--endpoint-port", "443", "--socks", socks,
                "--collateral", str(collateral), "--app-compose", str(compose_path),
                "--policy", str(policy_path)]

    # These proxy settings must have no effect on the maintained existing-stream
    # transport. A bound listener lets us observe any unexpected proxy connection.
    with socket.socket() as forbidden_proxy:
        forbidden_proxy.bind(("127.0.0.1", 0))
        forbidden_proxy.listen()
        forbidden_proxy.setblocking(False)
        proxy = f"http://127.0.0.1:{forbidden_proxy.getsockname()[1]}"
        environment = os.environ.copy()
        environment.update({key: proxy for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                                                   "http_proxy", "https_proxy", "all_proxy")})
        environment["NO_PROXY"] = environment["no_proxy"] = ""
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = listener.getsockname()[1]
            outcomes = []

            def serve():
                try:
                    with listener.accept()[0] as connection:
                        assert exact(connection, 4) == bytes([5, 2, 0, 2])
                        connection.sendall(bytes([5, 2]))
                        assert exact(connection, 1) == bytes([1])
                        username = exact(connection, exact(connection, 1)[0])
                        assert username == b"<torS0X>0"
                        isolation = exact(connection, exact(connection, 1)[0])
                        assert len(isolation) == 64 and all(c in b"0123456789abcdef" for c in isolation)
                        connection.sendall(bytes([1, 0]))
                        assert exact(connection, 4) == bytes([5, 1, 0, 3])
                        assert exact(connection, exact(connection, 1)[0]) == b"unresolved-fixture.invalid"
                        assert exact(connection, 2) == bytes([1, 187])
                        connection.sendall(bytes([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]))
                        with context.wrap_socket(connection, server_side=True) as tls:
                            assert tls.selected_alpn_protocol() == "http/1.1"
                            header = bytearray()
                            while not header.endswith(b"\r\n\r\n"):
                                header.extend(exact(tls, 1))
                            lines = header.decode("ascii").split("\r\n")
                            assert lines[0] == "POST /attestation HTTP/1.1"
                            headers = dict(line.lower().split(": ", 1) for line in lines[1:] if line)
                            assert headers["host"] == "unresolved-fixture.invalid:443"
                            assert "cookie" not in headers and "authorization" not in headers
                            assert "user-agent" not in headers
                            body = json.loads(exact(tls, int(headers["content-length"])))
                            assert set(body) == {"nonce"}
                            assert len(body["nonce"]) == 32 and all(type(x) is int and 0 <= x <= 255 for x in body["nonce"])
                            response = json.dumps({"nonce": body["nonce"], "quote": quote,
                                "event_log": "[]", "report_data": "00" * 64,
                                "vm_config": "{}"}).encode()
                            tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: "
                                        + str(len(response)).encode() + b"\r\n\r\n" + response)
                            # Remain open for the independent verifier, then require
                            # closure with no second HTTP request or private body.
                            assert not tls.recv(1)
                    outcomes.append(True)
                except Exception as error:
                    outcomes.append(type(error).__name__)

            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            trace = directory / "public-connect.trace" if options.strace else None
            code, output = process(arguments(f"127.0.0.1:{port}"), environment, trace)
            assert code == 1 and output["mode"] == "public_endpoint_inspection"
            assert not output["tor_process_identity_verified"] and output["approved_release"] is None
            inspection = output["inspection"]
            assert inspection["network_used"] and not inspection["private_accepted"]
            evidence = inspection["evidence"]
            assert evidence["hardware_authenticity"] == "rejected"
            assert evidence["time_source"] == "system_clock"
            assert evidence["authenticated_report_data_match"] == "not_checked"
            assert evidence["issue"] == "cryptographic_or_validity_check_failed"
            assert inspection["live_key_binding"] == inspection["freshness"] == "not_checked"
            thread.join()
            assert outcomes == [True] and sni == ["unresolved-fixture.invalid"]
            if trace:
                lines = trace.read_text().splitlines()
                connections = [line for line in lines if re.search(r"\bconnect\(", line)]
                assert len(connections) == 1
                assert 'sin_addr=inet_addr("127.0.0.1")' in connections[0]
                assert f"sin_port=htons({port})" in connections[0]
                assert not any("SOCK_DGRAM" in line or "AF_INET6" in line for line in lines)

        # Invalid/repeated options and invalid policy must fail before dialing.
        with socket.socket() as unused:
            unused.bind(("127.0.0.1", 0))
            unused.listen()
            unused.setblocking(False)
            args = arguments(f"127.0.0.1:{unused.getsockname()[1]}")
            for extra in [["--time", "1752919234"], ["--stdin"], ["--simulate"], ["--socks", "127.0.0.1:1"]]:
                assert process([*args, *extra], environment)[0] == 1
            policy_path.write_text('{"verified":true,"secret":"SYNTHETIC_PRIVATE_MARKER"}')
            assert process(args, environment)[1]["error"] == "workload policy rejected"
            try:
                unexpected, _ = unused.accept()
            except BlockingIOError:
                pass
            else:
                unexpected.close()
                raise AssertionError("invalid inputs opened a SOCKS connection")

        # Keep the port reserved without listening, so missing Tor rejects and
        # cannot accidentally reach a different service after port reuse.
        policy_path.write_text(json.dumps(policy))
        with socket.socket() as unavailable:
            unavailable.bind(("127.0.0.1", 0))
            result = process(arguments(f"127.0.0.1:{unavailable.getsockname()[1]}"), environment)
            assert result[0] == 1 and "SOCKS endpoint is unavailable" in result[1]["error"]
        try:
            unexpected, _ = forbidden_proxy.accept()
        except BlockingIOError:
            pass
        else:
            unexpected.close()
            raise AssertionError("environment proxy was contacted")

print("Public inspection CLI checks passed: nonce-only SOCKS/TLS exchange, current-clock rejection, no RPC, no environment-proxy fallback, pre-dial validation.")
if options.strace:
    print("Connect-only syscall trace passed: one configured loopback connection, no additional/DNS/UDP/IPv6 connection.")
