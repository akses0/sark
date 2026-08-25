from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Awaitable, Callable

from pydantic import BaseModel, Field

from sark.models import Event


class TokenBucket:
    def __init__(self, rate: float) -> None:
        if rate <= 0:
            raise ValueError("rate must be positive")
        self._interval = 1.0 / rate
        self._next_slot = time.monotonic()

    async def acquire(self) -> None:
        now = time.monotonic()
        wait = self._next_slot - now
        self._next_slot = max(now, self._next_slot) + self._interval
        if wait > 0:
            await asyncio.sleep(wait)


class ScanContext(BaseModel):
    run_id: str
    target_uri: str
    risk: int
    timeout: float = 5.0
    insecure: bool = False
    ca_file: str | None = None
    tls_fallback_used: bool = False
    auth_ping_ok: bool | None = None
    auth_detail: str | None = None
    extra: dict[str, str] = Field(default_factory=dict)

    def derived(self, **changes: object) -> ScanContext:
        update = {key: value for key, value in changes.items() if key in type(self).model_fields}
        return self.model_copy(update=update)


Executor = Callable[[], Awaitable[Event]]


async def run_vectors(
    ctx: ScanContext,
    jobs: list[tuple[str, Executor]],
    rps: float = 10.0,
) -> AsyncIterator[Event]:
    bucket = TokenBucket(rps)
    for _vector_id, executor in jobs:
        await bucket.acquire()
        yield await executor()
