#!/usr/bin/env python3
"""Container-local process supervision for the public Phala preview."""

import os
from pathlib import Path
import queue
import select
import signal
import socket
import stat
import subprocess
import sys
import threading
import time


RUN = Path("/run")
QUOTE_READY = RUN / "zrpc-quote-ready"
NOTIFY = RUN / "zrpc-notify.sock"
COOKIE_DIR = RUN / "zrpc-node"
COOKIE = COOKIE_DIR / ".cookie"
BACKEND = Path("/dstack.sock")
STATE = Path("/var/lib/zebra")
BIN = Path("/opt/zrpc/bin")
NODE_RPC = ("127.0.0.1", 18232)


def required_positive(name):
    value = os.environ.get(name, "")
    if not value.isascii() or not value.isdecimal() or int(value) <= 0:
        raise RuntimeError(f"missing or invalid {name}")
    return int(value)


def mount_type(path):
    # The fixed paths contain no mountinfo escape characters.
    with open("/proc/self/mountinfo", encoding="ascii") as stream:
        for line in stream:
            before, separator, after = line.partition(" - ")
            if separator and before.split()[4] == str(path):
                return after.split()[0]
    raise RuntimeError("required mount is missing")


def require_runtime_mount():
    if mount_type(RUN) != "tmpfs":
        raise RuntimeError("shared runtime is not tmpfs")


def terminate_children(children):
    for child in children:
        if child.poll() is None:
            child.terminate()
    for child in children:
        child.wait()


def install_stop_handler(children):
    def stop(_signal, _frame):
        terminate_children(children)
        raise SystemExit(1)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)


def quote_health():
    try:
        marker = QUOTE_READY.stat()
        if not stat.S_ISREG(marker.st_mode) or marker.st_uid != os.geteuid():
            return False
        if stat.S_IMODE(marker.st_mode) != 0o600:
            return False
        for name in ("quote.sock", "watch.sock"):
            item = (RUN / "zrpc-quote" / name).stat()
            if not stat.S_ISSOCK(item.st_mode) or item.st_uid != os.geteuid():
                return False
            if stat.S_IMODE(item.st_mode) != 0o660:
                return False
        return True
    except OSError:
        return False


def run_quote():
    require_runtime_mount()
    backend = BACKEND.stat()
    if not stat.S_ISSOCK(backend.st_mode) or backend.st_uid != 0:
        raise RuntimeError("stock dstack socket is unavailable")
    timeout = required_positive("QUOTE_STARTUP_TIMEOUT_SECS")
    if NOTIFY.exists() or QUOTE_READY.exists():
        raise RuntimeError("stale quote readiness state")
    notify = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    prior_umask = os.umask(0o077)
    try:
        notify.bind(str(NOTIFY))
    finally:
        os.umask(prior_umask)
    os.chmod(NOTIFY, 0o600)
    wake_read, wake_write = socket.socketpair()
    children = []
    try:
        environment = {**os.environ, "NOTIFY_SOCKET": str(NOTIFY)}
        child = subprocess.Popen(
            [str(BIN / "zrpc-quote-proxy"), "--stock-preview"],
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        children.append(child)
        install_stop_handler(children)

        def watch_exit():
            child.wait()
            wake_write.send(b"X")

        watcher = threading.Thread(target=watch_exit, daemon=True)
        watcher.start()
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("quote bridge readiness timed out")
            readable, _, _ = select.select([notify, wake_read], [], [], remaining)
            if wake_read in readable or child.poll() is not None:
                raise RuntimeError("quote bridge stopped before readiness")
            if not readable:
                raise RuntimeError("quote bridge readiness timed out")
            if notify.recv(64) != b"READY=1\n":
                raise RuntimeError("invalid quote bridge readiness")
            marker = os.open(QUOTE_READY, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(marker)
            if not quote_health():
                raise RuntimeError("quote bridge sockets are unavailable")
            break
        watcher.join()
        raise RuntimeError("quote bridge stopped")
    finally:
        terminate_children(children)
        QUOTE_READY.unlink(missing_ok=True)
        NOTIFY.unlink(missing_ok=True)
        notify.close()
        wake_read.close()
        wake_write.close()


def run_app():
    from snapshot_import import ensure_snapshot

    require_runtime_mount()
    for path in (BACKEND, RUN / "dstack.sock"):
        if path.exists() and stat.S_ISSOCK(path.stat().st_mode):
            raise RuntimeError("app container exposes dstack socket")
    if mount_type(STATE) == "tmpfs":
        raise RuntimeError("public Zebra state is not persistent")
    state = STATE.stat()
    if not stat.S_ISDIR(state.st_mode) or state.st_uid != os.geteuid():
        raise RuntimeError("public Zebra state ownership is unavailable")
    if stat.S_IMODE(state.st_mode) & 0o007:
        raise RuntimeError("public Zebra state is world-accessible")
    ensure_snapshot()
    COOKIE_DIR.mkdir(mode=0o700)
    if COOKIE_DIR.stat().st_uid != os.geteuid():
        raise RuntimeError("cookie directory ownership is unavailable")

    timeout = required_positive("NODE_STARTUP_TIMEOUT_SECS")
    spacing = required_positive("NODE_POLL_INTERVAL_MS") / 1000
    limits = (
        required_positive("MAX_CONNECTIONS"),
        required_positive("MAX_QUOTES"),
        required_positive("QUOTE_SPACING_MS"),
    )
    children = []
    try:
        zebra = subprocess.Popen(
            [str(BIN / "zebrad"), "-c", "/opt/zrpc/zebra.toml", "start"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        children.append(zebra)
        install_stop_handler(children)
        deadline = time.monotonic() + timeout
        while not COOKIE.exists():
            if zebra.poll() is not None:
                raise RuntimeError("Zebra stopped before RPC cookie readiness")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("Zebra RPC cookie readiness timed out")
            time.sleep(min(spacing, remaining))
        wrapper = subprocess.Popen(
            [
                str(BIN / "zrpc-node-wrapper"),
                "--platform", "phala-dstack",
                "--listen", "0.0.0.0:8443",
                "--node", "127.0.0.1:18232",
                "--max-connections", str(limits[0]),
                "--max-quotes", str(limits[1]),
                "--quote-spacing-ms", str(limits[2]),
                "--access", "free-demo",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        children.append(wrapper)
        exits = queue.Queue()

        def watch_exit(child):
            child.wait()
            exits.put(child)

        for child in children:
            threading.Thread(target=watch_exit, args=(child,), daemon=True).start()
        exits.get()
        raise RuntimeError("Zebra or RPC wrapper stopped")
    finally:
        terminate_children(children)


def require_no_guest_control_sockets(paths):
    for path in paths:
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        raise RuntimeError("container exposes a guest control socket path")


def run_node():
    """Corrected-guest candidate: Zebra has no quote or dstack socket mount."""
    if os.geteuid() == 0 or os.getegid() == 0:
        raise RuntimeError("split node requires a dedicated non-root identity")
    from snapshot_import import ensure_snapshot

    require_runtime_mount()
    require_no_guest_control_sockets((
        BACKEND, RUN / "dstack.sock", RUN / "zrpc-quote" / "quote.sock",
        RUN / "zrpc-quote" / "watch.sock",
    ))
    if mount_type(STATE) == "tmpfs":
        raise RuntimeError("public Zebra state is not persistent")
    state = STATE.stat()
    if (not stat.S_ISDIR(state.st_mode) or state.st_uid != os.geteuid()
            or stat.S_IMODE(state.st_mode) & 0o007):
        raise RuntimeError("public Zebra state ownership is unavailable")
    if COOKIE.exists() or COOKIE.is_symlink():
        raise RuntimeError("stale Zebra RPC cookie")
    ensure_snapshot()
    COOKIE_DIR.mkdir(mode=0o700)
    cookie_dir = COOKIE_DIR.stat()
    if (cookie_dir.st_uid != os.geteuid()
            or stat.S_IMODE(cookie_dir.st_mode) != 0o700):
        raise RuntimeError("cookie directory ownership is unavailable")

    children = []
    try:
        zebra = subprocess.Popen(
            [str(BIN / "zebrad"), "-c", "/opt/zrpc/zebra.toml", "start"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        children.append(zebra)
        install_stop_handler(children)
        zebra.wait()
        raise RuntimeError("Zebra stopped")
    finally:
        terminate_children(children)


def node_health():
    try:
        require_runtime_mount()
        require_no_guest_control_sockets((
            BACKEND, RUN / "dstack.sock", RUN / "zrpc-quote" / "quote.sock",
            RUN / "zrpc-quote" / "watch.sock",
        ))
        cookie = COOKIE.lstat()
        if (not stat.S_ISREG(cookie.st_mode) or cookie.st_uid != os.geteuid()
                or stat.S_IMODE(cookie.st_mode) != 0o600):
            return False
        timeout = required_positive("NODE_POLL_INTERVAL_MS") / 1000
        with socket.create_connection(NODE_RPC, timeout=timeout):
            return True
    except (OSError, RuntimeError):
        return False


def run_wrapper():
    """Corrected-guest candidate: only this container receives quote sockets."""
    if os.geteuid() == 0 or os.getegid() == 0:
        raise RuntimeError("split wrapper requires a dedicated non-root identity")
    require_runtime_mount()
    require_no_guest_control_sockets((BACKEND, RUN / "dstack.sock"))
    quote_dir = RUN / "zrpc-quote"
    try:
        directory = quote_dir.lstat()
        if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != 0
                or directory.st_gid != os.getegid()
                or stat.S_IMODE(directory.st_mode) != 0o750):
            raise RuntimeError("quote-only bridge directory is unavailable")
        for name in ("quote.sock", "watch.sock"):
            item = (quote_dir / name).lstat()
            if (not stat.S_ISSOCK(item.st_mode) or item.st_uid != 0
                    or item.st_gid != os.getegid()
                    or stat.S_IMODE(item.st_mode) != 0o660):
                raise RuntimeError("quote-only bridge socket is unavailable")
    except OSError as error:
        raise RuntimeError("quote-only bridge socket is unavailable") from error

    timeout = required_positive("NODE_STARTUP_TIMEOUT_SECS")
    spacing = required_positive("NODE_POLL_INTERVAL_MS") / 1000
    limits = (
        required_positive("MAX_CONNECTIONS"),
        required_positive("MAX_QUOTES"),
        required_positive("QUOTE_SPACING_MS"),
    )
    deadline = time.monotonic() + timeout
    while not COOKIE.exists():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("Zebra RPC cookie readiness timed out")
        time.sleep(min(spacing, remaining))

    children = []
    try:
        wrapper = subprocess.Popen(
            [
                str(BIN / "zrpc-node-wrapper"),
                "--platform", "phala-dstack",
                "--listen", "0.0.0.0:8443",
                "--node", f"{NODE_RPC[0]}:{NODE_RPC[1]}",
                "--max-connections", str(limits[0]),
                "--max-quotes", str(limits[1]),
                "--quote-spacing-ms", str(limits[2]),
                "--access", "free-demo",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        children.append(wrapper)
        install_stop_handler(children)
        wrapper.wait()
        raise RuntimeError("RPC wrapper stopped")
    finally:
        terminate_children(children)


def main():
    if len(sys.argv) != 2:
        raise RuntimeError("exactly one service mode is required")
    mode = sys.argv[1]
    if mode == "quote-health":
        return 0 if quote_health() else 1
    if mode == "node-health":
        return 0 if node_health() else 1
    if mode == "quote":
        run_quote()
    elif mode == "app":
        run_app()
    elif mode == "node":
        run_node()
    elif mode == "wrapper":
        run_wrapper()
    else:
        raise RuntimeError("unknown service mode")
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as error:
        print(f"Phala public preview stopped: {error}", file=sys.stderr)
        raise SystemExit(1)
