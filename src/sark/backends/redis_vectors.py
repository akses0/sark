from __future__ import annotations

from collections.abc import Awaitable, Callable

from sark.backends.redis_cves import evaluate
from sark.engine.scheduler import ScanContext
from sark.models import (
    Channel,
    CommandEvidence,
    Event,
    Evidence,
    ResponseEvidence,
    Verdict,
)
from sark.resp import Reply, RespConnection, RespError, wire_preview

ScanFn = Callable[..., Awaitable[Event]]

DANGEROUS_COMMANDS = ("CONFIG", "EVAL", "MODULE", "REPLICAOF", "FLUSHALL", "DEBUG")

IMPLEMENTED_SAFE = frozenset({"RED-UNAUTH", "RED-TLS-RESP3", "RED-ACL-ENUM", "RED-CVE-FP"})


def mk_event(
    ctx: ScanContext,
    vector_id: str,
    verdict: Verdict,
    confidence: float | None,
    detail: str,
    *,
    replies: list[Reply] | None = None,
) -> Event:
    captured = replies or []
    evidence = Evidence(
        commands=[CommandEvidence(wire=wire_preview(r.raw_request)) for r in captured],
        responses=[
            ResponseEvidence(prefix=r.prefix, size=r.size, sha256=r.sha256) for r in captured
        ],
    )
    return Event(
        run_id=ctx.run_id,
        target=ctx.target_uri,
        vector=vector_id,
        channel=Channel.DIRECT,
        verdict=verdict,
        confidence=confidence,
        detail=detail,
        evidence=evidence,
    )


async def resolve_auth(conn: RespConnection) -> tuple[bool | None, str]:
    try:
        reply = await conn.execute("PING")
    except RespError as exc:
        upper = exc.message.upper()
        if "NOAUTH" in upper or "AUTHENTICATION" in upper or "WRONGPASS" in upper:
            return False, f"authentication required (-{exc.message})"
        return None, f"restricted principal (-{exc.message})"
    return True, reply.text()


def info_field(info_text: str, key: str) -> str | None:
    for line in info_text.splitlines():
        if line.startswith(f"{key}:"):
            return line.split(":", 1)[1].strip()
    return None


async def red_unauth(ctx: ScanContext, conn: RespConnection) -> Event:
    try:
        reply = await conn.execute("PING")
    except RespError as exc:
        upper = exc.message.upper()
        if "NOAUTH" in upper or "AUTHENTICATION" in upper or "WRONGPASS" in upper:
            return mk_event(
                ctx,
                "RED-UNAUTH",
                Verdict.REFUTED,
                1.0,
                f"authentication required (-{exc.message}); anonymous access refused",
            )
        return mk_event(
            ctx,
            "RED-UNAUTH",
            Verdict.INCONCLUSIVE,
            0.3,
            f"unexpected reply to PING: -{exc.message}",
        )
    return mk_event(
        ctx,
        "RED-UNAUTH",
        Verdict.CONFIRMED,
        1.0,
        "unauthenticated access granted (PING -> +PONG)",
        replies=[reply],
    )


async def red_tls_resp3(ctx: ScanContext, conn: RespConnection) -> Event:
    try:
        hello = await conn.execute("HELLO", "3")
    except RespError as exc:
        if "UNKNOWN COMMAND" in exc.message.upper():
            resp3_detail = "RESP3 unsupported (server predates Redis 6)"
        else:
            resp3_detail = f"HELLO declined: -{exc.message}"
        hello_reply = None
    else:
        resp3_detail = "RESP3 negotiated"
        hello_reply = hello
    if ctx.tls_fallback_used:
        verdict, confidence = Verdict.CONFIRMED, 1.0
        tls_detail = "plaintext connection reset; TLS accepted (server requires TLS)"
    elif ctx.extra.get("requested_tls") == "true":
        verdict, confidence = Verdict.INCONCLUSIVE, 0.5
        tls_detail = "connected over TLS by request; plaintext behavior not observed"
    else:
        verdict, confidence = Verdict.REFUTED, 1.0
        tls_detail = "plaintext session functional; TLS not required"
    replies = [hello_reply] if hello_reply else []
    return mk_event(
        ctx,
        "RED-TLS-RESP3",
        verdict,
        confidence,
        f"{tls_detail}; {resp3_detail}",
        replies=replies,
    )


async def red_acl_enum(ctx: ScanContext, conn: RespConnection) -> Event:
    if ctx.auth_ping_ok is False:
        return mk_event(
            ctx,
            "RED-ACL-ENUM",
            Verdict.INCONCLUSIVE,
            0.3,
            "principal requires credentials; capability surface deferred until authenticated",
        )
    available: list[str] = []
    renamed_or_missing: list[str] = []
    replies: list[Reply] = []
    whoami = None
    try:
        whoami_reply = await conn.execute("ACL", "WHOAMI")
        whoami = whoami_reply.text()
        replies.append(whoami_reply)
    except RespError:
        pass
    for command in DANGEROUS_COMMANDS:
        try:
            info = await conn.execute("COMMAND", "INFO", command)
        except RespError as exc:
            return mk_event(
                ctx,
                "RED-ACL-ENUM",
                Verdict.INCONCLUSIVE,
                0.3,
                f"COMMAND INFO denied: -{exc.message}",
            )
        replies.append(info)
        if isinstance(info.value, list) and info.value and info.value[0] is not None:
            available.append(command)
        else:
            renamed_or_missing.append(command)
    parts = [f"principal={whoami or 'default'}"]
    if available:
        parts.append(f"dangerous-available={','.join(available)}")
    if renamed_or_missing:
        parts.append(f"renamed-or-missing={','.join(renamed_or_missing)}")
    if available:
        return mk_event(
            ctx,
            "RED-ACL-ENUM",
            Verdict.CONFIRMED,
            0.9,
            "; ".join(parts),
            replies=replies,
        )
    return mk_event(
        ctx,
        "RED-ACL-ENUM",
        Verdict.REFUTED,
        0.9,
        "; ".join(parts),
        replies=replies,
    )


async def red_cve_fp(ctx: ScanContext, conn: RespConnection) -> Event:
    try:
        info = await conn.execute("INFO", "server")
    except RespError as exc:
        return mk_event(
            ctx,
            "RED-CVE-FP",
            Verdict.INCONCLUSIVE,
            0.3,
            f"INFO unavailable: -{exc.message}",
        )
    version_raw = info_field(info.text(), "redis_version")
    if version_raw is None:
        return mk_event(
            ctx,
            "RED-CVE-FP",
            Verdict.INCONCLUSIVE,
            0.2,
            "redis_version missing from INFO server output",
            replies=[info],
        )
    statuses = evaluate(version_raw)
    affected = [s for s in statuses if s.status == "affected"]
    review = [s for s in statuses if s.status == "packaging-review"]
    affected_bits = [
        f"{s.advisory.id} fixed-in={'.'.join(map(str, max(s.advisory.fixed_in)))}" for s in affected
    ]
    detail = f"version={version_raw}"
    if affected_bits:
        detail += f"; affected: {'; '.join(affected_bits)}"
    if review:
        detail += (
            f"; packaging-review: {', '.join(s.advisory.id for s in review)} "
            "(Debian-family packaging check required)"
        )
    if affected:
        urls = " ".join(s.advisory.url for s in affected)
        detail += f"; advisories: {urls}"
        return mk_event(
            ctx,
            "RED-CVE-FP",
            Verdict.CONFIRMED,
            0.9,
            detail,
            replies=[info],
        )
    if statuses:
        return mk_event(
            ctx,
            "RED-CVE-FP",
            Verdict.REFUTED,
            1.0,
            detail,
            replies=[info],
        )
    return mk_event(
        ctx,
        "RED-CVE-FP",
        Verdict.INCONCLUSIVE,
        0.2,
        detail,
        replies=[info],
    )


EXECUTORS: dict[str, ScanFn] = {
    "RED-UNAUTH": red_unauth,
    "RED-TLS-RESP3": red_tls_resp3,
    "RED-ACL-ENUM": red_acl_enum,
    "RED-CVE-FP": red_cve_fp,
}
