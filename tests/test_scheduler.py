from __future__ import annotations

import asyncio
import time

import pytest

from sark.engine.scheduler import ScanContext, TokenBucket


def test_bucket_rejects_nonpositive_rate() -> None:
    with pytest.raises(ValueError):
        TokenBucket(0)
    with pytest.raises(ValueError):
        TokenBucket(-1)


def test_bucket_paces_calls() -> None:
    async def go() -> float:
        bucket = TokenBucket(200.0)
        start = time.monotonic()
        await bucket.acquire()
        await bucket.acquire()
        await bucket.acquire()
        return time.monotonic() - start

    elapsed = asyncio.run(go())
    assert 0.005 <= elapsed < 1.0


def test_context_derived_overrides() -> None:
    ctx = ScanContext(run_id="a1b2c3", target_uri="redis://h:6379", risk=1)
    derived = ctx.derived(risk=3, tls_fallback_used=True, extra={"k": "v"})
    assert derived.risk == 3
    assert derived.tls_fallback_used is True
    assert derived.run_id == "a1b2c3"
    assert ctx.risk == 1
    assert ctx.extra == {}
    assert derived.extra == {"k": "v"}
