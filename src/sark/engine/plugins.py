from __future__ import annotations

from importlib import metadata

from sark.backends.base import Backend

ENTRY_POINT_GROUP = "sark.backends"


def load_plugins() -> tuple[dict[str, Backend], list[str]]:
    backends: dict[str, Backend] = {}
    errors: list[str] = []
    for ep in metadata.entry_points(group=ENTRY_POINT_GROUP):
        try:
            loaded = ep.load()
            instance = loaded() if isinstance(loaded, type) else loaded
            if not isinstance(instance, Backend):
                raise TypeError("does not implement the Backend protocol")
            if instance.name in backends:
                raise ValueError("duplicate backend name; first registration wins")
            backends[instance.name] = instance
        except Exception as exc:
            errors.append(f"plugin {ep.name!r} failed to load: {exc}")
    return backends, errors
