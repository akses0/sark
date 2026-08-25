from __future__ import annotations

import re
from collections.abc import Awaitable, Callable

from sark.backends.redis_cves import evaluate
from sark.data_layer import collect_keys, key_type
from sark.engine.scheduler import ScanContext
from sark.models import (
    Channel,
    CommandEvidence,
    Event,
    Evidence,
    ResponseEvidence,
    Verdict,
)
from sark.resp import AuthOutcome, Reply, RespError, SupportsResp, wire_preview

ScanFn = Callable[..., Awaitable[Event]]

DANGEROUS_COMMANDS = ("CONFIG", "EVAL", "MODULE", "REPLICAOF", "FLUSHALL", "DEBUG")

IMPLEMENTED = frozenset(
    {
        "RED-UNAUTH",
        "RED-TLS-RESP3",
        "RED-ACL-ENUM",
        "RED-CVE-FP",
        "RED-CONFIG-AUDIT",
        "RED-AUTH-CREDS",
        "RED-LUA-PROBE",
        "RED-CENSUS",
    }
)

PHASE_HANDLED = frozenset({"RED-AUTH-CREDS"})

CURATED_MATRIX: tuple[str, ...] = (
    "redis",
    "foobared",
    "root",
    "admin",
    "administrator",
    "password",
    "password1",
    "p@ssw0rd",
    "changeme",
    "changeit",
    "default",
    "test",
    "guest",
    "welcome",
    "admin123",
    "root123",
    "redis123",
    "redispass",
    "cache",
    "dev",
    "development",
    "staging",
    "prod",
    "production",
    "secret",
    "secret123",
    "mypass",
    "mypassword",
    "123456",
    "123456789",
    "qwerty",
    "letmein",
    "docker",
    "kubernetes",
    "sentinel",
    "cluster",
    "masterauth",
    "database",
    "dbpass",
    "node",
)


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


def masked_auth_evidence(reply: Reply | None = None) -> Evidence:
    masked_wire = "*2\r\n$4\r\nAUTH\r\n$3\r\n***"
    commands = [CommandEvidence(wire=masked_wire)]
    responses = []
    if reply is not None:
        responses.append(
            ResponseEvidence(prefix=reply.prefix, size=reply.size, sha256=reply.sha256)
        )
    return Evidence(commands=commands, responses=responses)


async def resolve_auth(conn: SupportsResp) -> tuple[bool | None, str]:
    try:
        reply = await conn.execute("PING")
    except RespError as exc:
        upper = exc.message.upper()
        if "NOAUTH" in upper or "AUTHENTICATION" in upper or "WRONGPASS" in upper:
            return False, f"authentication required (-{exc.message})"
        return None, f"restricted principal (-{exc.message})"
    return True, reply.text()


async def try_credentials(
    conn: SupportsResp,
    candidates: list[tuple[str | None, str]],
) -> AuthOutcome | None:
    for username, password in candidates:
        try:
            if username:
                await conn.execute("AUTH", username, password)
            else:
                await conn.execute("AUTH", password)
        except RespError as exc:
            upper = exc.message.upper()
            if "WRONGPASS" in upper or "invalid password" in upper.lower():
                continue
            if "NOAUTH" in upper or "AUTHENTICATION" in upper:
                continue
            raise
        restricted = False
        try:
            await conn.execute("PING")
        except RespError as exc:
            if "NOPERM" in exc.message.upper():
                restricted = True
        else:
            try:
                await conn.execute("CONFIG", "GET", "protected-mode")
            except RespError as exc:
                if "NOPERM" in exc.message.upper():
                    restricted = True
        return AuthOutcome(username=username, password=password, restricted=restricted)
    return None


def info_field(info_text: str, key: str) -> str | None:
    for line in info_text.splitlines():
        if line.startswith(f"{key}:"):
            return line.split(":", 1)[1].strip()
    return None


def parse_keyspace(info_text: str) -> dict[str, int]:
    databases: dict[str, int] = {}
    pattern = re.compile(r"^db(\d+):keys=(\d+)")
    for line in info_text.splitlines():
        match = pattern.match(line)
        if match:
            databases[f"db{match.group(1)}"] = int(match.group(2))
    return databases


async def red_unauth(ctx: ScanContext, conn: SupportsResp) -> Event:
    if ctx.auth_username is not None or ctx.auth_password is not None:
        return mk_event(
            ctx,
            "RED-UNAUTH",
            Verdict.REFUTED,
            1.0,
            "authentication required; anonymous access refused "
            "(auth-state resolved via credential phase)",
        )
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


async def red_tls_resp3(ctx: ScanContext, conn: SupportsResp) -> Event:
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


async def red_acl_enum(ctx: ScanContext, conn: SupportsResp) -> Event:
    if ctx.auth_ping_ok is False and not ctx.auth_restricted:
        return mk_event(
            ctx,
            "RED-ACL-ENUM",
            Verdict.INCONCLUSIVE,
            0.3,
            "principal requires credentials; capability surface deferred until authenticated",
        )
    available: list[str] = []
    renamed_or_missing: list[str] = []
    denied: list[str] = []
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
            if "NOPERM" in exc.message.upper():
                denied.append(command)
                continue
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
    if denied:
        parts.append(f"acl-denied={','.join(denied)}")
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


async def red_cve_fp(ctx: ScanContext, conn: SupportsResp) -> Event:
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


async def red_config_audit(ctx: ScanContext, conn: SupportsResp) -> Event:
    try:
        cfg_reply = await conn.execute("CONFIG", "GET", "*")
    except RespError as exc:
        upper = exc.message.upper()
        if "NOPERM" in upper:
            return mk_event(
                ctx,
                "RED-CONFIG-AUDIT",
                Verdict.INCONCLUSIVE,
                0.4,
                f"config surface hidden from principal (NOPERM): -{exc.message}",
            )
        if "UNKNOWN COMMAND" in upper:
            return mk_event(
                ctx,
                "RED-CONFIG-AUDIT",
                Verdict.REFUTED,
                0.9,
                "CONFIG renamed or unavailable; audit surface closed",
            )
        return mk_event(
            ctx,
            "RED-CONFIG-AUDIT",
            Verdict.INCONCLUSIVE,
            0.3,
            f"CONFIG GET failed: -{exc.message}",
        )
    raw_value = cfg_reply.value
    pairs: list[tuple[str, str]] = []
    if isinstance(raw_value, dict):
        pairs = [(str(key), str(value)) for key, value in raw_value.items()]
    elif isinstance(raw_value, list):
        pairs = [
            (str(raw_value[index]), str(raw_value[index + 1]))
            for index in range(0, len(raw_value) - 1, 2)
        ]
    config = dict(pairs)
    protected_mode = config.get("protected-mode", "")
    bind = config.get("bind", "")
    enable_module = config.get("enable-module-command", "")
    enable_protected_configs = config.get("enable-protected-configs", "")
    binds_all = bind == "" or bind.startswith("*") or "0.0.0.0" in bind or "::" in bind
    exposure = protected_mode == "no" and binds_all
    remote_primitives = enable_module == "yes" or enable_protected_configs == "yes"
    local_only_primitives = enable_module == "local" or enable_protected_configs == "local"
    bits = [
        f"protected-mode={protected_mode or 'n/a'}",
        f"bind={bind or '(all interfaces)'}",
        f"enable-module-command={enable_module or 'unset'}",
        f"enable-protected-configs={enable_protected_configs or 'unset'}",
    ]
    detail = "; ".join(bits)
    if remote_primitives:
        detail += "; RCE-enabling primitives reachable remotely"
        return mk_event(
            ctx,
            "RED-CONFIG-AUDIT",
            Verdict.CONFIRMED,
            0.95,
            detail,
            replies=[cfg_reply],
        )
    if exposure:
        detail += "; service bound to all interfaces with protected mode disabled"
        return mk_event(
            ctx,
            "RED-CONFIG-AUDIT",
            Verdict.CONFIRMED,
            0.9,
            detail,
            replies=[cfg_reply],
        )
    if local_only_primitives:
        detail += "; primitives restricted to local/loopback clients"
        return mk_event(
            ctx,
            "RED-CONFIG-AUDIT",
            Verdict.REFUTED,
            0.85,
            detail,
            replies=[cfg_reply],
        )
    return mk_event(
        ctx,
        "RED-CONFIG-AUDIT",
        Verdict.REFUTED,
        0.9,
        detail,
        replies=[cfg_reply],
    )


async def red_lua_probe(ctx: ScanContext, conn: SupportsResp) -> Event:
    try:
        reply = await conn.execute("EVAL", "return 1", "0")
    except RespError as exc:
        upper = exc.message.upper()
        if "NOPERM" in upper:
            return mk_event(
                ctx,
                "RED-LUA-PROBE",
                Verdict.REFUTED,
                0.9,
                f"EVAL denied by ACL (-{exc.message})",
            )
        if "UNKNOWN COMMAND" in upper or "RENAME" in upper:
            return mk_event(
                ctx,
                "RED-LUA-PROBE",
                Verdict.REFUTED,
                0.9,
                "EVAL renamed or removed; scripting entry closed",
            )
        return mk_event(
            ctx,
            "RED-LUA-PROBE",
            Verdict.INCONCLUSIVE,
            0.3,
            f"EVAL probe failed: -{exc.message}",
        )
    if reply.value == 1:
        return mk_event(
            ctx,
            "RED-LUA-PROBE",
            Verdict.CONFIRMED,
            0.7,
            "EVAL available; Lua sandbox arithmetic canary executed (scripting primitive open)",
            replies=[reply],
        )
    return mk_event(
        ctx,
        "RED-LUA-PROBE",
        Verdict.INCONCLUSIVE,
        0.3,
        f"EVAL returned unexpected value: {reply.value!r}",
        replies=[reply],
    )


async def red_census(ctx: ScanContext, conn: SupportsResp) -> Event:
    try:
        info = await conn.execute("INFO", "keyspace")
    except RespError as exc:
        return mk_event(
            ctx,
            "RED-CENSUS",
            Verdict.INCONCLUSIVE,
            0.3,
            f"keyspace inventory unavailable: -{exc.message}",
        )
    databases = parse_keyspace(info.text())
    total = sum(databases.values())
    summary = ", ".join(f"{name}={count} keys" for name, count in sorted(databases.items()))
    if not databases:
        return mk_event(
            ctx,
            "RED-CENSUS",
            Verdict.REFUTED,
            0.8,
            "keyspace empty across logical DBs visible to principal",
            replies=[info],
        )
    return mk_event(
        ctx,
        "RED-CENSUS",
        Verdict.CONFIRMED,
        0.8,
        f"data present ({total} keys): {summary}; full namespace mapping lands in M3 enum",
        replies=[info],
    )


async def red_value_read(ctx: ScanContext, conn: SupportsResp) -> Event:
    if ctx.auth_ping_ok is False and not ctx.auth_restricted:
        return mk_event(
            ctx,
            "RED-VALUE-READ",
            Verdict.INCONCLUSIVE,
            0.3,
            "keyspace requires credentials; value sampling deferred until authenticated",
        )
    keys, truncated = await collect_keys(conn, "*", max_keys=20)
    if not keys:
        return mk_event(
            ctx,
            "RED-VALUE-READ",
            Verdict.REFUTED,
            0.8,
            "keyspace empty; no values readable to principal",
        )
    types_seen: dict[str, str] = {}
    for key in keys[:10]:
        type_name = await key_type(conn, key)
        if type_name != "none" and type_name not in types_seen:
            types_seen[type_name] = key
    sampled: list[Reply] = []
    first = sorted(types_seen.items())[0] if types_seen else None
    if first is not None:
        type_name, key = first
        probe = {
            "string": ("GET", key),
            "hash": ("HSCAN", key, "0", "COUNT", "3"),
            "list": ("LRANGE", key, "0", "2"),
            "set": ("SSCAN", key, "0", "COUNT", "3"),
            "zset": ("ZRANGE", key, "0", "2", "WITHSCORES"),
            "stream": ("XLEN", key),
        }.get(type_name)
        if probe is not None:
            sampled.append(await conn.execute(*probe))
    detail_types = ",".join(sorted(types_seen)) or "none"
    cap_note = "; scan budget hit (truncated sample)" if truncated else ""
    return mk_event(
        ctx,
        "RED-VALUE-READ",
        Verdict.CONFIRMED,
        0.85,
        f"values readable to principal; types observed: {detail_types} "
        f"(sampled {min(len(keys), 10)} keys{cap_note})",
        replies=sampled,
    )


EXECUTORS: dict[str, ScanFn] = {
    "RED-UNAUTH": red_unauth,
    "RED-TLS-RESP3": red_tls_resp3,
    "RED-ACL-ENUM": red_acl_enum,
    "RED-CVE-FP": red_cve_fp,
    "RED-CONFIG-AUDIT": red_config_audit,
    "RED-LUA-PROBE": red_lua_probe,
    "RED-CENSUS": red_census,
    "RED-VALUE-READ": red_value_read,
}
