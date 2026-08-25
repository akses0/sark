from __future__ import annotations

from sark.backends.base import Backend
from sark.backends.redis import RedisBackend
from sark.engine.plugins import load_plugins


def test_builtin_redis_backend_discoverable() -> None:
    backends, errors = load_plugins()
    assert errors == []
    assert "redis" in backends
    assert isinstance(backends["redis"], Backend)


def test_redis_backend_serves_registry() -> None:
    backend = RedisBackend()
    assert len(backend.vectors()) == 10


def test_broken_plugin_is_reported_not_fatal(monkeypatch: object) -> None:
    from importlib import metadata as importlib_metadata

    class BrokenEntryPoint:
        name = "broken"

        def load(self) -> object:
            raise RuntimeError("boom")

    def fake_entry_points(group: str) -> list[BrokenEntryPoint]:
        return [BrokenEntryPoint()]

    monkeypatch.setattr(importlib_metadata, "entry_points", fake_entry_points, raising=True)
    backends, errors = load_plugins()
    assert backends == {}
    assert len(errors) == 1
    assert "boom" in errors[0]
