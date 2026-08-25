from __future__ import annotations

import os
import socket
from collections.abc import Iterator

import pytest
from typer.testing import CliRunner

from sark.cli import app
from sark.models import Event, Verdict
from sark.resp import encode_command

runner = CliRunner()

EXPOSED_URI = os.environ.get("SARK_EXPOSED_URI", "redis://127.0.0.1:16379")
WEAK_URI = os.environ.get("SARK_WEAK_URI", "redis://127.0.0.1:16380")
HARDENED_URI = os.environ.get("SARK_HARDENED_URI", "redis://127.0.0.1:16382")

SAFE_VECTOR_IDS = {"RED-UNAUTH", "RED-TLS-RESP3", "RED-ACL-ENUM", "RED-CVE-FP"}
RISK2_VECTOR_IDS = SAFE_VECTOR_IDS | {
    "RED-AUTH-CREDS",
    "RED-CENSUS",
    "RED-CONFIG-AUDIT",
    "RED-LUA-PROBE",
    "RED-VALUE-READ",
}


def run_scan(*args: str) -> tuple[list[Event], int]:
    result = runner.invoke(app, ["scan", *args])
    events = [
        Event.model_validate_json(line)
        for line in result.stdout.splitlines()
        if line.strip().startswith("{")
    ]
    return events, result.exit_code


def by_vector(events: list[Event]) -> dict[str, Event]:
    return {event.vector: event for event in events}


def seed_exposed(uri: str) -> None:
    from sark.targets import Target

    target = Target.from_uri(uri)
    commands = [
        encode_command("SET", "sark:e2e:string", "v"),
        encode_command("HSET", "sark:e2e:hash", "field", "value"),
        encode_command("RPUSH", "sark:e2e:list", "a", "b"),
    ]
    with socket.create_connection((target.host, target.port), timeout=2) as sock:
        for command in commands:
            sock.sendall(command)
            sock.recv(64)


@pytest.fixture(scope="session", autouse=True)
def seed_data() -> Iterator[None]:
    if os.environ.get("SARK_E2E") == "1":
        seed_exposed(EXPOSED_URI)
    yield


@pytest.fixture(scope="module")
def exposed_risk2() -> Iterator[dict[str, Event]]:
    events, exit_code = run_scan("-t", EXPOSED_URI, "--risk=2")
    assert exit_code == 2, [e.detail for e in events]
    yield by_vector(events)


def test_exposed_unauthenticated_access_confirmed(exposed_risk2: dict[str, Event]) -> None:
    unauth = exposed_risk2["RED-UNAUTH"]
    assert unauth.verdict is Verdict.CONFIRMED
    assert unauth.confidence == pytest.approx(1.0)
    wire = unauth.evidence.commands[0].wire
    assert "PING" in wire
    assert unauth.evidence.responses[0].sha256


def test_exposed_anonymous_dangerous_surface(exposed_risk2: dict[str, Event]) -> None:
    acl = exposed_risk2["RED-ACL-ENUM"]
    assert acl.verdict is Verdict.CONFIRMED
    assert "principal=default" in (acl.detail or "")
    assert "CONFIG" in (acl.detail or "")


def test_exposed_config_audit_confirmed(exposed_risk2: dict[str, Event]) -> None:
    config = exposed_risk2["RED-CONFIG-AUDIT"]
    assert config.verdict is Verdict.CONFIRMED
    assert "protected-mode=no" in (config.detail or "")


def test_exposed_lua_primitive_open(exposed_risk2: dict[str, Event]) -> None:
    lua = exposed_risk2["RED-LUA-PROBE"]
    assert lua.verdict is Verdict.CONFIRMED
    assert "arithmetic canary" in (lua.detail or "")


def test_exposed_census_finds_seeded_data(exposed_risk2: dict[str, Event]) -> None:
    census = exposed_risk2["RED-CENSUS"]
    assert census.verdict is Verdict.CONFIRMED
    assert "db0" in (census.detail or "")


def test_exposed_auth_creds_refuted_when_anonymous(exposed_risk2: dict[str, Event]) -> None:
    creds = exposed_risk2["RED-AUTH-CREDS"]
    assert creds.verdict is Verdict.REFUTED
    assert "authentication not required" in (creds.detail or "")


def test_exposed_emits_full_risk2_registry(exposed_risk2: dict[str, Event]) -> None:
    assert set(exposed_risk2) == RISK2_VECTOR_IDS


def test_weak_defaults_matrix_finds_redis_password() -> None:
    events, exit_code = run_scan("-t", WEAK_URI, "--risk=2")
    assert exit_code == 2, [e.detail for e in events]
    mapped = by_vector(events)
    creds = mapped["RED-AUTH-CREDS"]
    assert creds.verdict is Verdict.CONFIRMED
    assert "user=default" in (creds.detail or "")
    assert mapped["RED-UNAUTH"].verdict is Verdict.REFUTED
    serialized = "\n".join(event.model_dump_json() for event in events)
    assert "AUTH\\r\\n$5\\r\\nredis" not in serialized
    config = mapped["RED-CONFIG-AUDIT"]
    assert config.verdict is Verdict.CONFIRMED
    lua = mapped["RED-LUA-PROBE"]
    assert lua.verdict is Verdict.CONFIRMED


def test_hardened_matrix_exhausts_with_handoff() -> None:
    events, exit_code = run_scan("-t", HARDENED_URI, "--risk=2")
    assert exit_code == 0, [e.detail for e in events]
    mapped = by_vector(events)
    creds = mapped["RED-AUTH-CREDS"]
    assert creds.verdict is Verdict.REFUTED
    assert "no credential accepted" in (creds.detail or "")
    advisories = [event for event in events if event.vector == "RUN-HANDOFF"]
    assert advisories
    assert "hydra" in (advisories[0].detail or "")
    assert "legba" in (advisories[0].detail or "")
    config = mapped["RED-CONFIG-AUDIT"]
    assert config.verdict is Verdict.INCONCLUSIVE


def test_hardened_restricted_principal_detected(tmp_path: object) -> None:
    wordlist = tmp_path / "candidates.txt"
    wordlist.write_text("wrong-pass\nsarklow-pass\n", encoding="utf-8")
    events, exit_code = run_scan(
        "-t",
        HARDENED_URI,
        "--risk=2",
        "--user",
        "sarklow",
        "--wordlist",
        str(wordlist),
    )
    assert exit_code == 2, [e.detail for e in events]
    mapped = by_vector(events)
    creds = mapped["RED-AUTH-CREDS"]
    assert creds.verdict is Verdict.CONFIRMED
    assert "valid-but-restricted" in (creds.detail or "")
    config = mapped["RED-CONFIG-AUDIT"]
    assert config.verdict is Verdict.INCONCLUSIVE
    assert "NOPERM" in (config.detail or "")
    lua = mapped["RED-LUA-PROBE"]
    assert lua.verdict is Verdict.REFUTED
    assert "NOPERM" in (lua.detail or "")


def test_risk1_still_safe_tier_only_on_exposed() -> None:
    events, exit_code = run_scan("-t", EXPOSED_URI)
    assert exit_code == 2
    mapped = by_vector(events)
    assert set(mapped) == SAFE_VECTOR_IDS
