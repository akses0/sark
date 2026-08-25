from __future__ import annotations

import asyncio
import secrets
import sys
from pathlib import Path
from typing import Annotated

import typer

from sark.backends.redis import RedisBackend
from sark.backends.redis_vectors import (
    CURATED_MATRIX,
    masked_auth_evidence,
    resolve_auth,
    try_credentials,
)
from sark.data_layer import DUMP_BUDGET, build_record, collect_keys
from sark.engine.plugins import load_plugins
from sark.engine.scheduler import RateLimitedResp, ScanContext
from sark.models import (
    Channel,
    CommandEvidence,
    Event,
    Evidence,
    Record,
    ResponseEvidence,
    Verdict,
)
from sark.report.md import summarize
from sark.resp import RespConnection, RespError, Unreachable, wire_preview
from sark.targets import Target

MAX_WORDLIST_ENTRIES = 10_000

app = typer.Typer(
    name="sark",
    help="Redis exposure auditing: misconfiguration detection and safe data-layer enumeration.",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
    pretty_exceptions_show_locals=False,
)

TargetOption = Annotated[
    list[str] | None,
    typer.Option(
        "--target",
        "-t",
        help="redis://host[:port] or rediss:// for TLS. Repeatable.",
    ),
]
TargetsFileOption = Annotated[
    Path | None,
    typer.Option("--targets-file", help="Newline-delimited target list."),
]
RiskOption = Annotated[
    int,
    typer.Option(
        "--risk",
        min=1,
        max=3,
        help="1 read-only, 2 adds credential matrix and heavy reads, 3 adds canary writes.",
    ),
]


def _run_id() -> str:
    return secrets.token_hex(3)


def _emit(event: Event) -> None:
    print(event.model_dump_json())


def _advisory(run_id: str, target_uri: str, vector: str, detail: str) -> Event:
    return Event(
        run_id=run_id,
        target=target_uri,
        vector=vector,
        channel=Channel.DIRECT,
        verdict=Verdict.ADVISORY,
        detail=detail,
    )


def _resolve_targets(targets: list[str], targets_file: Path | None) -> list[Target]:
    uris = list(targets)
    if targets_file is not None:
        for line in targets_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                uris.append(line)
    if not uris:
        raise typer.BadParameter("no targets given; use -t redis://host[:port] or --targets-file")
    parsed: list[Target] = []
    for uri in uris:
        try:
            parsed.append(Target.from_uri(uri))
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from exc
    return parsed


async def _connect_probing_tls(
    target: Target,
    *,
    timeout: float,
    insecure: bool,
    ca_file: str | None,
) -> tuple[RespConnection, bool]:
    if target.tls:
        conn = await RespConnection.connect(
            target.host,
            target.port,
            tls=True,
            insecure=insecure,
            ca_file=ca_file,
            timeout=timeout,
        )
        return conn, False
    conn = await RespConnection.connect(
        target.host,
        target.port,
        timeout=timeout,
    )
    try:
        await conn.execute("PING")
    except (Unreachable, ConnectionError):
        await conn.close()
        tls_conn = await RespConnection.connect(
            target.host,
            target.port,
            tls=True,
            insecure=insecure,
            ca_file=ca_file,
            timeout=timeout,
        )
        return tls_conn, True
    except Exception:
        return conn, False
    return conn, False


def _load_wordlist(path: Path | None) -> list[str]:
    if path is None:
        return []
    entries = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        entry = line.strip()
        if entry:
            entries.append(entry)
        if len(entries) >= MAX_WORDLIST_ENTRIES:
            break
    return entries


async def _credential_phase(
    conn: RespConnection,
    ctx: ScanContext,
    candidates: list[tuple[str | None, str]],
) -> tuple[Event, ScanContext]:
    outcome = await try_credentials(conn, candidates)
    if outcome is not None:
        principal = outcome.username or "default"
        detail = f"default/common credential accepted for user={principal} (weak authentication)"
        state = "valid-but-restricted" if outcome.restricted else "authenticated"
        ping_ok = not outcome.restricted
        event = Event(
            run_id=ctx.run_id,
            target=ctx.target_uri,
            vector="RED-AUTH-CREDS",
            channel=Channel.DIRECT,
            verdict=Verdict.CONFIRMED,
            confidence=1.0,
            detail=f"{detail}; auth-state={state}",
            evidence=masked_auth_evidence(),
        )
        updated = ctx.derived(
            auth_username=outcome.username,
            auth_password=outcome.password,
            auth_restricted=outcome.restricted,
            auth_ping_ok=ping_ok or ctx.auth_ping_ok,
            auth_detail=f"authenticated as {principal} ({state})",
        )
        return event, updated
    event = Event(
        run_id=ctx.run_id,
        target=ctx.target_uri,
        vector="RED-AUTH-CREDS",
        channel=Channel.DIRECT,
        verdict=Verdict.REFUTED,
        confidence=0.85,
        detail=f"no credential accepted from {len(candidates)} curated/default candidates",
        evidence=masked_auth_evidence(),
    )
    return event, ctx


async def _scan_target_removed() -> None:
    return None


async def _open_session(
    run_id: str,
    target: Target,
    risk: int,
    timeout: float,
    insecure: bool,
    ca_file: str | None,
    user: str | None,
    password: str | None,
    wordlist_entries: list[str],
    emit_auth_event: bool,
) -> tuple[RespConnection | None, ScanContext | None, list[Event]]:
    events: list[Event] = []
    try:
        conn, fallback = await _connect_probing_tls(
            target,
            timeout=timeout,
            insecure=insecure,
            ca_file=ca_file,
        )
    except Unreachable as exc:
        events.append(
            _advisory(run_id, target.uri(), "RUN-UNREACHABLE", f"connection failed: {exc}")
        )
        return None, None, events
    auth_ok, auth_detail = await resolve_auth(conn)
    ctx = ScanContext(
        run_id=run_id,
        target_uri=target.uri(),
        risk=risk,
        timeout=timeout,
        insecure=insecure,
        ca_file=ca_file,
        tls_fallback_used=fallback,
        auth_ping_ok=auth_ok,
        auth_detail=auth_detail,
        extra={"requested_tls": "true" if target.tls else "false"},
    )
    if risk >= 2:
        if auth_ok:
            if emit_auth_event:
                events.append(
                    Event(
                        run_id=run_id,
                        target=target.uri(),
                        vector="RED-AUTH-CREDS",
                        channel=Channel.DIRECT,
                        verdict=Verdict.REFUTED,
                        confidence=1.0,
                        detail="authentication not required; anonymous principal active",
                    )
                )
        else:
            candidates: list[tuple[str | None, str]] = []
            if password and user:
                candidates.append((user, password))
            elif password:
                candidates.append((None, password))
            candidates.extend((None, entry) for entry in CURATED_MATRIX)
            candidates.extend((user, entry) for entry in wordlist_entries)
            cred_event, ctx = await _credential_phase(conn, ctx, candidates)
            if emit_auth_event:
                events.append(cred_event)
            if cred_event.verdict is Verdict.REFUTED and ctx.auth_ping_ok is False:
                handoff = (
                    "curated matrix exhausted; sark detects misconfigurations, it does not "
                    "brute-force. For proper rotation use hydra, legba, "
                    "nmap --script redis-brute or msf auxiliary/scanner/redis/redis_login, "
                    "then rerun with --user/--pass."
                )
                events.append(_advisory(run_id, target.uri(), "RUN-HANDOFF", handoff))
    return conn, ctx, events


@app.command()
def scan(
    targets: TargetOption = None,
    targets_file: TargetsFileOption = None,
    risk: RiskOption = 1,
    user: Annotated[
        str | None, typer.Option("--user", help="ACL username for authentication attempts.")
    ] = None,
    password: Annotated[
        str | None, typer.Option("--pass", help="Password for resumed runs with known creds.")
    ] = None,
    wordlist: Annotated[
        Path | None,
        typer.Option("--wordlist", help="Opt-in credential spray; stops on first hit."),
    ] = None,
    timeout: Annotated[float, typer.Option("--timeout", min=0.5)] = 5.0,
    rps: Annotated[float, typer.Option("--rps", min=0.1)] = 10.0,
    insecure: Annotated[
        bool, typer.Option("--insecure", help="Skip TLS certificate verification.")
    ] = False,
    ca_file: Annotated[
        str | None, typer.Option("--tls-ca", help="CA bundle for TLS verification.")
    ] = None,
) -> None:
    """Fingerprint a Redis instance and run exposure vectors up to the chosen risk."""
    resolved = _resolve_targets(list(targets or []), targets_file)
    backends, plugin_errors = load_plugins()
    if "redis" not in backends:
        raise typer.Exit(code=70)
    wordlist_entries = _load_wordlist(wordlist)
    all_events: list[Event] = []
    run_id = _run_id()
    for error in plugin_errors:
        print(_advisory(run_id, "-", "RUN-PLUGIN-ERROR", error).model_dump_json())

    async def drive() -> None:
        for target in resolved:
            conn, ctx, session_events = await _open_session(
                run_id,
                target,
                risk=risk,
                timeout=timeout,
                insecure=insecure,
                ca_file=ca_file,
                user=user,
                password=password,
                wordlist_entries=wordlist_entries,
                emit_auth_event=True,
            )
            all_events.extend(session_events)
            if conn is None or ctx is None:
                return
            backend = RedisBackend()
            jobs = backend.build_jobs(ctx, conn)
            for _, executor in jobs:
                all_events.append(await executor())
            await conn.close()

    asyncio.run(drive())
    for event in all_events:
        _emit(event)
    verdicts = {event.verdict for event in all_events}
    if Verdict.CONFIRMED in verdicts:
        raise typer.Exit(code=2)


def _emit_err(event: Event) -> None:
    print(event.model_dump_json(), file=sys.stderr)


async def _data_session(
    run_id: str,
    target: Target,
    timeout: float,
    insecure: bool,
    ca_file: str | None,
    user: str | None,
    password: str | None,
    wordlist_entries: list[str],
) -> tuple[RespConnection | None, ScanContext | None, list[Event], bool]:
    conn, ctx, events = await _open_session(
        run_id,
        target,
        risk=2,
        timeout=timeout,
        insecure=insecure,
        ca_file=ca_file,
        user=user,
        password=password,
        wordlist_entries=wordlist_entries,
        emit_auth_event=True,
    )
    authenticated_or_anonymous = ctx is not None and (
        ctx.auth_ping_ok is not False or ctx.auth_restricted
    )
    return conn, ctx, events, authenticated_or_anonymous


async def _run_enum(
    run_id: str,
    target: Target,
    sample: int,
    pattern: str | None,
    timeout: float,
    insecure: bool,
    ca_file: str | None,
    user: str | None,
    password: str | None,
    wordlist_entries: list[str],
    rps: float,
) -> tuple[list[Event], list[Record], bool]:
    from sark.data_layer import PREVIEW_BUDGET, collect_keys, namespace_of, parse_databases

    conn, ctx, events, usable = await _data_session(
        run_id, target, timeout, insecure, ca_file, user, password, wordlist_entries
    )
    if conn is None or ctx is None:
        return events, [], False
    if not usable:
        events.append(
            Event(
                run_id=run_id,
                target=target.uri(),
                vector="ENUM-SUMMARY",
                channel=Channel.DIRECT,
                verdict=Verdict.INCONCLUSIVE,
                confidence=0.3,
                detail="authentication required; keyspace mapping unavailable",
            )
        )
        await conn.close()
        return events, [], False
    glob = pattern or "*"
    try:
        info = await conn.execute("INFO", "keyspace")
    except RespError as exc:
        events.append(
            Event(
                run_id=run_id,
                target=target.uri(),
                vector="ENUM-SUMMARY",
                channel=Channel.DIRECT,
                verdict=Verdict.INCONCLUSIVE,
                confidence=0.3,
                detail=f"keyspace inventory unavailable: -{exc.message}",
            )
        )
        await conn.close()
        return events, [], False
    records: list[Record] = []
    namespace_counts: dict[str, int] = {}
    truncated_any = False
    databases = parse_databases(info.text()) or {"db0": 0}
    for db in databases:
        if db != "db0":
            try:
                await conn.execute("SELECT", db.removeprefix("db"))
            except RespError:
                continue
        keys, truncated = await collect_keys(conn, glob, max_keys=5000)
        truncated_any = truncated_any or truncated
        for key in keys:
            ns = namespace_of(key)
            namespace_counts[ns] = namespace_counts.get(ns, 0) + 1
        if sample > 0:
            for key in keys[:sample]:
                record = await build_record(conn, key, PREVIEW_BUDGET, db=db)
                if record is not None:
                    records.append(record)
    if namespace_counts:
        summary = ", ".join(f"{ns}={count}" for ns, count in sorted(namespace_counts.items()))
        detail = f"namespaces: {summary}"
        if truncated_any:
            detail += "; scan budget hit (truncated)"
        events.append(
            Event(
                run_id=run_id,
                target=target.uri(),
                vector="ENUM-SUMMARY",
                channel=Channel.DIRECT,
                verdict=Verdict.CONFIRMED,
                confidence=0.8,
                detail=detail,
                evidence=mk_summary_evidence([info]),
            )
        )
    else:
        events.append(
            Event(
                run_id=run_id,
                target=target.uri(),
                vector="ENUM-SUMMARY",
                channel=Channel.DIRECT,
                verdict=Verdict.REFUTED,
                confidence=0.8,
                detail="no keys visible to principal under the given pattern",
                evidence=mk_summary_evidence([info]),
            )
        )
    await conn.close()
    return events, records, bool(namespace_counts)


def mk_summary_evidence(replies: list[object]) -> Evidence:
    from sark.resp import Reply

    commands = []
    responses = []
    for reply in replies:
        assert isinstance(reply, Reply)
        commands.append(CommandEvidence(wire=wire_preview(reply.raw_request)))
        responses.append(
            ResponseEvidence(prefix=reply.prefix, size=reply.size, sha256=reply.sha256)
        )
    return Evidence(commands=commands, responses=responses)


async def _run_dump(
    run_id: str,
    target: Target,
    pattern: str | None,
    start: int,
    stop: int,
    timeout: float,
    insecure: bool,
    ca_file: str | None,
    user: str | None,
    password: str | None,
    wordlist_entries: list[str],
    rps: float,
) -> tuple[list[Event], list[Record], bool]:
    conn, ctx, events, usable = await _data_session(
        run_id, target, timeout, insecure, ca_file, user, password, wordlist_entries
    )
    if conn is None or ctx is None:
        return events, [], False
    if not usable:
        events.append(
            Event(
                run_id=run_id,
                target=target.uri(),
                vector="DUMP-SUMMARY",
                channel=Channel.DIRECT,
                verdict=Verdict.INCONCLUSIVE,
                confidence=0.3,
                detail="authentication required; extraction unavailable",
            )
        )
        await conn.close()
        return events, [], False
    limited = RateLimitedResp(conn, rps)
    glob = pattern or "*"
    keys, _truncated = await collect_keys(limited, glob, max_keys=stop + start + 1)
    window = keys[start : start + stop]
    records: list[Record] = []
    for key in window:
        try:
            record = await build_record(limited, key, DUMP_BUDGET)
        except RespError:
            continue
        if record is not None:
            records.append(record)
    cap_hit = len(keys) >= start + stop + 1
    detail = f"extracted {len(records)} records (window [{start}, {start + stop}])"
    if cap_hit:
        detail += "; scan budget reached — narrow --pattern or raise --stop for full coverage"
    events.append(
        Event(
            run_id=run_id,
            target=target.uri(),
            vector="DUMP-SUMMARY",
            channel=Channel.DIRECT,
            verdict=(Verdict.CONFIRMED if records else Verdict.REFUTED),
            confidence=0.85 if records else 0.8,
            detail=detail,
        )
    )
    await conn.close()
    return events, records, bool(records)


@app.command(name="enum")
def enum_(
    targets: TargetOption = None,
    targets_file: TargetsFileOption = None,
    sample: Annotated[
        int, typer.Option("--sample", min=0, help="Preview N values per namespace.")
    ] = 20,
    pattern: Annotated[
        str | None, typer.Option("--pattern", help="Key glob, e.g. 'session:*'.")
    ] = None,
    user: Annotated[
        str | None, typer.Option("--user", help="ACL username for authentication attempts.")
    ] = None,
    password: Annotated[
        str | None, typer.Option("--pass", help="Password for resumed runs with known creds.")
    ] = None,
    wordlist: Annotated[
        Path | None,
        typer.Option("--wordlist", help="Opt-in credential spray; stops on first hit."),
    ] = None,
    timeout: Annotated[float, typer.Option("--timeout", min=0.5)] = 5.0,
    insecure: Annotated[
        bool, typer.Option("--insecure", help="Skip TLS certificate verification.")
    ] = False,
    ca_file: Annotated[
        str | None, typer.Option("--tls-ca", help="CA bundle for TLS verification.")
    ] = None,
    rps: Annotated[float, typer.Option("--rps", min=0.1)] = 100.0,
    out: Annotated[Path | None, typer.Option("--out", help="Write NDJSON records here.")] = None,
) -> None:
    """Map the keyspace: logical DBs, namespaces, types and counts.

    Records stream to stdout (or --out); events stream to stderr.
    """
    resolved = _resolve_targets(list(targets or []), targets_file)
    wordlist_entries = _load_wordlist(wordlist)
    run_id = _run_id()
    all_events: list[Event] = []
    all_records: list[Record] = []
    found = False

    async def drive() -> None:
        nonlocal found
        for target in resolved:
            events, records, hit = await _run_enum(
                run_id,
                target,
                sample=sample,
                pattern=pattern,
                timeout=timeout,
                insecure=insecure,
                ca_file=ca_file,
                user=user,
                password=password,
                wordlist_entries=wordlist_entries,
                rps=rps,
            )
            all_events.extend(events)
            all_records.extend(records)
            found = found or hit

    asyncio.run(drive())
    out_handle = out.open("w", encoding="utf-8") if out else sys.stdout
    try:
        for record in all_records:
            out_handle.write(record.model_dump_json() + "\n")
    finally:
        if out is not None:
            out_handle.close()
    for event in all_events:
        _emit_err(event)
    verdicts = {event.verdict for event in all_events if event.vector != "RUN-UNREACHABLE"}
    if found or Verdict.CONFIRMED in verdicts:
        raise typer.Exit(code=2)
    if not usable_session(all_events):
        raise typer.Exit(code=3)


def usable_session(events: list[Event]) -> bool:
    return not any(event.vector == "RUN-UNREACHABLE" for event in events) and not any(
        event.detail is not None and "authentication required" in event.detail
        for event in events
        if event.vector in ("ENUM-SUMMARY", "DUMP-SUMMARY")
    )


@app.command()
def dump(
    targets: TargetOption = None,
    targets_file: TargetsFileOption = None,
    pattern: Annotated[
        str | None, typer.Option("--pattern", help="Key glob, e.g. 'session:*'.")
    ] = None,
    start: Annotated[int, typer.Option("--start", min=0)] = 0,
    stop: Annotated[int, typer.Option("--stop", min=0)] = 1000,
    dump_format: Annotated[
        str, typer.Option("--dump-format", help="Record format; ndjson only pre-M4.")
    ] = "ndjson",
    user: Annotated[
        str | None, typer.Option("--user", help="ACL username for authentication attempts.")
    ] = None,
    password: Annotated[
        str | None, typer.Option("--pass", help="Password for resumed runs with known creds.")
    ] = None,
    wordlist: Annotated[
        Path | None,
        typer.Option("--wordlist", help="Opt-in credential spray; stops on first hit."),
    ] = None,
    timeout: Annotated[float, typer.Option("--timeout", min=0.5)] = 5.0,
    insecure: Annotated[
        bool, typer.Option("--insecure", help="Skip TLS certificate verification.")
    ] = False,
    ca_file: Annotated[
        str | None, typer.Option("--tls-ca", help="CA bundle for TLS verification.")
    ] = None,
    rps: Annotated[float, typer.Option("--rps", min=0.1)] = 100.0,
    out: Annotated[Path | None, typer.Option("--out", help="Write NDJSON records here.")] = None,
) -> None:
    """Extract records matching a key pattern, capped and evidence-referenced.

    Records stream to stdout (or --out); events stream to stderr.
    """
    if dump_format != "ndjson":
        raise typer.BadParameter(f"unsupported format {dump_format!r}: only 'ndjson' ships pre-M4")
    resolved = _resolve_targets(list(targets or []), targets_file)
    wordlist_entries = _load_wordlist(wordlist)
    run_id = _run_id()
    all_events: list[Event] = []
    all_records: list[Record] = []
    found = False

    async def drive() -> None:
        nonlocal found
        for target in resolved:
            events, records, hit = await _run_dump(
                run_id,
                target,
                pattern=pattern,
                start=start,
                stop=stop,
                timeout=timeout,
                insecure=insecure,
                ca_file=ca_file,
                user=user,
                password=password,
                wordlist_entries=wordlist_entries,
                rps=rps,
            )
            all_events.extend(events)
            all_records.extend(records)
            found = found or hit

    asyncio.run(drive())
    out_handle = out.open("w", encoding="utf-8") if out else sys.stdout
    try:
        for record in all_records:
            out_handle.write(record.model_dump_json() + "\n")
    finally:
        if out is not None:
            out_handle.close()
    for event in all_events:
        _emit_err(event)
    if found:
        raise typer.Exit(code=2)
    if not usable_session(all_events):
        raise typer.Exit(code=3)


@app.command()
def report(
    events_path: Annotated[Path, typer.Option("--events", help="NDJSON event stream from a run.")],
    format: Annotated[str, typer.Option("--format", help="Output format.")] = "md",
) -> None:
    """Render an event stream into a human-readable report."""
    if format != "md":
        raise typer.BadParameter(f"unsupported format {format!r}: only 'md' ships pre-M4")
    parsed: list[Event] = []
    for number, line in enumerate(events_path.read_text(encoding="utf-8").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            parsed.append(Event.model_validate_json(line))
        except ValueError as exc:
            print(f"skipping malformed event on line {number}: {exc}", file=sys.stderr)
    print(summarize(parsed))
    verdicts = {event.verdict for event in parsed}
    if Verdict.CONFIRMED in verdicts:
        raise typer.Exit(code=2)
    if verdicts and verdicts <= {Verdict.INCONCLUSIVE}:
        raise typer.Exit(code=3)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
