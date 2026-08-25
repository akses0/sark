from __future__ import annotations

import os
from collections.abc import Iterator

import pytest
from typer.testing import CliRunner

from sark.cli import app
from sark.models import Event, Verdict

runner = CliRunner()

EXPOSED_URI = os.environ.get("SARK_EXPOSED_URI", "redis://127.0.0.1:16379")
WEAK_URI = os.environ.get("SARK_WEAK_URI", "redis://127.0.0.1:16380")
HARDENED_URI = os.environ.get("SARK_HARDENED_URI", "redis://127.0.0.1:16382")

SAFE_VECTOR_IDS = {"RED-UNAUTH", "RED-TLS-RESP3", "RED-ACL-ENUM", "RED-CVE-FP"}


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


@pytest.fixture(scope="module")
def exposed() -> Iterator[dict[str, Event]]:
    events, exit_code = run_scan("-t", EXPOSED_URI)
    assert exit_code == 2, [e.detail for e in events]
    yield by_vector(events)


def test_exposed_unauthenticated_access_confirmed(exposed: dict[str, Event]) -> None:
    unauth = exposed["RED-UNAUTH"]
    assert unauth.verdict is Verdict.CONFIRMED
    assert unauth.confidence == pytest.approx(1.0)
    wire = unauth.evidence.commands[0].wire
    assert "PING" in wire
    assert unauth.evidence.responses[0].sha256


def test_exposed_plaintext_not_required_tls(exposed: dict[str, Event]) -> None:
    tls = exposed["RED-TLS-RESP3"]
    assert tls.verdict is Verdict.REFUTED
    assert "plaintext session functional" in (tls.detail or "")


def test_exposed_anonymous_dangerous_surface(exposed: dict[str, Event]) -> None:
    acl = exposed["RED-ACL-ENUM"]
    assert acl.verdict is Verdict.CONFIRMED
    assert "principal=default" in (acl.detail or "")


def test_exposed_cve_fingerprint_well_formed(exposed: dict[str, Event]) -> None:
    cve = exposed["RED-CVE-FP"]
    assert cve.verdict in (Verdict.CONFIRMED, Verdict.REFUTED)
    assert cve.confidence is not None
    assert cve.detail is not None and "version=" in cve.detail


def test_exposed_emits_exactly_safe_tier_events(exposed: dict[str, Event]) -> None:
    assert set(exposed) == SAFE_VECTOR_IDS


def test_weak_defaults_refuse_anonymous() -> None:
    events, exit_code = run_scan("-t", WEAK_URI)
    assert exit_code == 0, [e.detail for e in events]
    mapped = by_vector(events)
    unauth = mapped["RED-UNAUTH"]
    assert unauth.verdict is Verdict.REFUTED
    assert "authentication required" in (unauth.detail or "")
    acl = mapped["RED-ACL-ENUM"]
    assert acl.verdict is Verdict.INCONCLUSIVE
    assert acl.confidence is not None and acl.confidence < 0.5
    cve = mapped["RED-CVE-FP"]
    assert cve.verdict is Verdict.INCONCLUSIVE
    tls = mapped["RED-TLS-RESP3"]
    assert tls.verdict is Verdict.REFUTED
    assert set(mapped) == SAFE_VECTOR_IDS


def test_hardened_refuses_anonymous() -> None:
    events, exit_code = run_scan("-t", HARDENED_URI)
    assert exit_code == 0, [e.detail for e in events]
    mapped = by_vector(events)
    assert mapped["RED-UNAUTH"].verdict is Verdict.REFUTED
    assert mapped["RED-ACL-ENUM"].verdict is Verdict.INCONCLUSIVE
    assert set(mapped) == SAFE_VECTOR_IDS
