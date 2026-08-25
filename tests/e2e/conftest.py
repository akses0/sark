from __future__ import annotations

import os
import socket
import time

import pytest

E2E_ENABLED = os.environ.get("SARK_E2E") == "1"

EXPOSED_URI = os.environ.get("SARK_EXPOSED_URI", "redis://127.0.0.1:16379")
WEAK_URI = os.environ.get("SARK_WEAK_URI", "redis://127.0.0.1:16380")
HARDENED_URI = os.environ.get("SARK_HARDENED_URI", "redis://127.0.0.1:16382")

pytestmark = pytest.mark.skipif(not E2E_ENABLED, reason="SARK_E2E not set; harness offline")


def _port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


def wait_for(uri: str, attempts: int = 60) -> None:
    from sark.targets import Target

    target = Target.from_uri(uri)
    for _ in range(attempts):
        if _port_open(target.host, target.port):
            return
        time.sleep(0.5)
    pytest.fail(f"harness target {uri} never became reachable")


@pytest.fixture(scope="session", autouse=True)
def harness_ready() -> None:
    for uri in (EXPOSED_URI, WEAK_URI, HARDENED_URI):
        wait_for(uri)
