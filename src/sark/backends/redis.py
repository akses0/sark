from __future__ import annotations

import functools

from sark.backends.base import Backend
from sark.backends.redis_vectors import EXECUTORS, IMPLEMENTED, PHASE_HANDLED
from sark.engine.scheduler import Executor, ScanContext
from sark.models import Channel, Event, Verdict
from sark.registry import VectorSpec, load_vectors

DEFERRED_MILESTONES = {"RED-VALUE-READ": "M3", "RED-CRLF-APP": "M5"}


class RedisBackend(Backend):
    name = "redis"

    def vectors(self) -> list[VectorSpec]:
        return load_vectors(self.name)

    def build_jobs(
        self,
        ctx: ScanContext,
        conn: object,
    ) -> list[tuple[str, Executor]]:
        jobs: list[tuple[str, Executor]] = []
        for spec in sorted(self.vectors(), key=lambda s: (s.tier.value, s.id)):
            if spec.tier.value > ctx.risk:
                continue
            if spec.id in PHASE_HANDLED:
                continue
            if spec.id in IMPLEMENTED:
                executor = EXECUTORS[spec.id]
                jobs.append((spec.id, functools.partial(executor, ctx, conn)))
            else:
                jobs.append(
                    (
                        spec.id,
                        functools.partial(
                            _deferred, ctx, spec, DEFERRED_MILESTONES.get(spec.id, "?")
                        ),
                    )
                )
        return jobs


async def _deferred(ctx: ScanContext, spec: VectorSpec, milestone: str) -> Event:
    return Event(
        run_id=ctx.run_id,
        target=ctx.target_uri,
        vector=spec.id,
        channel=Channel.DIRECT,
        verdict=Verdict.ADVISORY,
        detail=f"vector registered but not yet executed; lands in {milestone}",
    )
