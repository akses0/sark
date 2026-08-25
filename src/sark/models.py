from __future__ import annotations

from datetime import UTC, datetime
from enum import IntEnum, StrEnum

from pydantic import BaseModel, Field, model_validator


class Verdict(StrEnum):
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"
    ADVISORY = "advisory"


class Channel(StrEnum):
    DIRECT = "direct"
    ERROR = "error"
    BOOLEAN = "boolean"
    TIMING = "timing"
    OOB = "oob"


class SafetyTier(IntEnum):
    SAFE = 1
    RISKY = 2
    DESTRUCTIVE = 3


class AuthState(StrEnum):
    ANONYMOUS = "anonymous"
    AUTHENTICATED = "authenticated-as-principal"
    RESTRICTED = "valid-but-restricted"


class CommandEvidence(BaseModel):
    wire: str | None = None
    wire_ref: str | None = None


class ResponseEvidence(BaseModel):
    prefix: str | None = None
    size: int | None = Field(default=None, ge=0)
    sha256: str | None = None
    body_ref: str | None = None


class Evidence(BaseModel):
    commands: list[CommandEvidence] = Field(default_factory=list)
    responses: list[ResponseEvidence] = Field(default_factory=list)
    timing_ms: list[float] = Field(default_factory=list)


class Event(BaseModel):
    ts: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    run_id: str = Field(pattern=r"^[a-f0-9]{6}$")
    target: str
    vector: str = Field(pattern=r"^[A-Z][A-Z0-9]+(-[A-Z0-9]+)*$")
    channel: Channel
    verdict: Verdict
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    repetitions: int = Field(default=1, ge=1)
    detail: str | None = None
    evidence: Evidence = Field(default_factory=Evidence)

    @model_validator(mode="after")
    def _confidence_rules(self) -> Event:
        if self.verdict is Verdict.ADVISORY and self.confidence is not None:
            raise ValueError("advisory events omit confidence")
        if self.verdict in (Verdict.CONFIRMED, Verdict.INCONCLUSIVE) and self.confidence is None:
            raise ValueError(f"{self.verdict.value} events require confidence")
        return self
