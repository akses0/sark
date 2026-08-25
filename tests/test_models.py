from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from sark.models import Channel, Event, Evidence, Verdict


def make_event(**overrides: object) -> Event:
    defaults: dict[str, object] = {
        "run_id": "a1b2c3",
        "target": "redis://10.0.0.5:6379",
        "vector": "RED-UNAUTH",
        "channel": Channel.DIRECT,
        "verdict": Verdict.ADVISORY,
    }
    defaults.update(overrides)
    return Event.model_validate(defaults)


def test_advisory_round_trips_through_json() -> None:
    event = make_event(detail="hello")
    encoded = event.model_dump_json()
    decoded = Event.model_validate_json(encoded)
    assert decoded == event
    assert decoded.ts.tzinfo is not None


def test_advisory_must_omit_confidence() -> None:
    with pytest.raises(ValidationError, match="advisory events omit confidence"):
        make_event(confidence=0.5)


def test_confirmed_requires_confidence() -> None:
    with pytest.raises(ValidationError, match="confirmed events require confidence"):
        make_event(verdict=Verdict.CONFIRMED)
    ok = make_event(verdict=Verdict.CONFIRMED, confidence=0.97)
    assert ok.confidence == pytest.approx(0.97)


def test_vector_id_pattern_enforced() -> None:
    with pytest.raises(ValidationError):
        make_event(vector="red-unauth")


def test_run_id_pattern_enforced() -> None:
    with pytest.raises(ValidationError):
        make_event(run_id="NOT-HEX")


def test_evidence_defaults_are_independent() -> None:
    first = make_event()
    second = make_event()
    first.evidence.commands.append({"wire": "*1\r\n$4\r\nPING\r\n"})
    assert isinstance(first.evidence, Evidence)
    assert second.evidence.commands == []
    assert first.ts <= datetime.now(tz=UTC)
