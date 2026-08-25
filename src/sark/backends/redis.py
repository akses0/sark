from __future__ import annotations

from sark.backends.base import Backend
from sark.registry import VectorSpec, load_vectors


class RedisBackend(Backend):
    name = "redis"

    def vectors(self) -> list[VectorSpec]:
        return load_vectors(self.name)
