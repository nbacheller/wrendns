"""Fixtures: a real WrenDNS node (the fork's debug build) with an agent token.

Set WRENDNS_BIN to use another binary; the default is the workspace's `target/debug/wrendns`.
"""

from __future__ import annotations

import http.cookiejar
import json
import os
import socket
import subprocess
import tempfile
import time
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest
import pytest_socket

pytest_plugins = "pytest_homeassistant_custom_component"

ROOT = Path(__file__).resolve().parents[3]
BIN = Path(os.environ.get("WRENDNS_BIN", ROOT / "target" / "debug" / "wrendns"))
API_PORT = 36992
DNS_PORT = 35992

CONFIG = """
[node]
data_dir = "{data}"
[[listen]]
proto = "udp"
addr = "127.0.0.1:{dns}"
[api]
listen = "127.0.0.1:{api}"
[telemetry.metrics]
listen = "127.0.0.1:37992"
[telemetry.qlog]
flush_interval_secs = 1
[[record]]
name = "nas.ha-test.arpa"
type = "A"
value = "10.0.0.8"
[[group]]
name = "kids"
networks = ["10.9.0.0/24"]
[[group]]
name = "quarantine"
schedules = ["quarantine-always"]
[[schedule]]
name = "quarantine-always"
action = "block_all"
window = [{{ days = ["daily"], start = "00:00", end = "24:00" }}]
"""


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    yield


class Node:
    """A running node and an agent token for it."""

    def __init__(self, url: str, token: str, opener: urllib.request.OpenerDirector, csrf: str) -> None:
        self.url = url
        self.token = token
        self._opener = opener
        self._csrf = csrf

    def admin(self, method: str, path: str, body: dict | None = None) -> dict:
        """A request as the admin (the session), for checking what the integration did."""
        req = urllib.request.Request(
            f"{self.url}{path}",
            data=json.dumps(body).encode() if body is not None else None,
            method=method,
            headers={"content-type": "application/json", "x-csrf-token": self._csrf},
        )
        with self._opener.open(req, timeout=10) as resp:
            raw = resp.read()
        return json.loads(raw) if raw else {}


def _wait(url: str, seconds: float = 20) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            with urllib.request.urlopen(f"{url}/api/v1/auth/status", timeout=1):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("WrenDNS didn't start")


@pytest.fixture(scope="session")
def wrendns_node() -> Iterator[Node]:
    if not BIN.exists():
        pytest.skip(f"no WrenDNS binary at {BIN} (cargo build -p wrendns)")
    tmp = Path(tempfile.mkdtemp(prefix="tt-ha-"))
    (tmp / "wrendns.toml").write_text(CONFIG.format(data=tmp / "data", dns=DNS_PORT, api=API_PORT))
    log = open(tmp / "node.log", "w")  # noqa: SIM115 (open for the process's lifetime; closed below)
    proc = subprocess.Popen([str(BIN), "run", "-c", str(tmp / "wrendns.toml")], stdout=log, stderr=log)
    url = f"http://127.0.0.1:{API_PORT}"
    # The Home Assistant test plugin blocks sockets per test; this fixture outlives one.
    pytest_socket.enable_socket()
    try:
        _wait(url)
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        setup = (tmp / "data" / "setup-token").read_text().strip()
        req = urllib.request.Request(
            f"{url}/api/v1/auth/setup",
            data=json.dumps({"setupToken": setup, "username": "admin", "password": "ha-test-pass-1"}).encode(),
            headers={"content-type": "application/json"},
        )
        with opener.open(req, timeout=10) as resp:
            csrf = json.load(resp)["csrfToken"]
        node = Node(url, "", opener, csrf)
        created = node.admin(
            "POST",
            "/api/v1/tokens",
            {
                "name": "home-assistant",
                "kind": "agent",
                "scopes": ["analytics:read", "config:read", "ops:pause", "ops:anomalies", "config:write:clients"],
            },
        )
        node.token = created["token"]
        pytest_socket.disable_socket(allow_unix_socket=True)
        yield node
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.close()


def ask_dns(name: str, source: str = "127.0.0.1") -> bytes:
    """One A query to the node's DNS listener from `source`; the raw answer."""
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + labels + b"\x00\x01\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.bind((source, 0))
    s.sendto(q, ("127.0.0.1", DNS_PORT))
    data, _ = s.recvfrom(4096)
    s.close()
    return data
