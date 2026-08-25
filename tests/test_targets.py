from __future__ import annotations

import pytest

from sark.targets import Target


def test_plain_host_defaults() -> None:
    target = Target.from_uri("redis://10.0.0.5")
    assert (target.host, target.port, target.tls) == ("10.0.0.5", 6379, False)


def test_explicit_port_and_rediss_tls() -> None:
    target = Target.from_uri("rediss://cache.internal:6380")
    assert (target.host, target.port, target.tls) == ("cache.internal", 6380, True)


def test_bare_host_gets_scheme_injected() -> None:
    target = Target.from_uri("10.0.0.9:7000")
    assert (target.host, target.port) == ("10.0.0.9", 7000)


def test_uri_round_trip_preserves_tls() -> None:
    original = Target(host="h", port=1234, tls=True)
    assert Target.from_uri(original.uri()) == original


def test_unsupported_scheme_rejected() -> None:
    with pytest.raises(ValueError, match="unsupported scheme"):
        Target.from_uri("postgres://db:5432")


def test_embedded_credentials_rejected() -> None:
    with pytest.raises(ValueError, match="credentials"):
        Target.from_uri("redis://admin:secret@10.0.0.5:6379")


def test_missing_host_rejected() -> None:
    with pytest.raises(ValueError, match="requires a host"):
        Target.from_uri("redis://:6379")
