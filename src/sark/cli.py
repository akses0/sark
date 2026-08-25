from __future__ import annotations

import secrets
import sys
from pathlib import Path
from typing import Annotated

import typer

from sark.backends.redis import RedisBackend
from sark.backends.redis_vectors import resolve_auth
from sark.engine.plugins import load_plugins
from sark.engine.scheduler import ScanContext
from sark.models import Channel, Event, Verdict
from sark.report.md import summarize
from sark.resp import RespConnection, Unreachable
from sark.targets import Target

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


async def _scan_target(
    run_id: str,
    target: Target,
    risk: int,
    timeout: float,
    insecure: bool,
    ca_file: str | None,
    rps: float,
) -> list[Event]:
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
        return events
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
    backend = RedisBackend()
    jobs = backend.build_jobs(ctx, conn)
    for _, executor in jobs:
        events.append(await executor())
    await conn.close()
    return events


@app.command()
def scan(
    targets: TargetOption = None,
    targets_file: TargetsFileOption = None,
    risk: RiskOption = 1,
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
    all_events: list[Event] = []
    run_id = _run_id()
    for error in plugin_errors:
        print(_advisory(run_id, "-", "RUN-PLUGIN-ERROR", error).model_dump_json())

    import asyncio

    async def drive() -> None:
        for target in resolved:
            all_events.extend(
                await _scan_target(
                    run_id,
                    target,
                    risk=risk,
                    timeout=timeout,
                    insecure=insecure,
                    ca_file=ca_file,
                    rps=rps,
                )
            )

    asyncio.run(drive())
    for event in all_events:
        _emit(event)
    verdicts = {event.verdict for event in all_events}
    if Verdict.CONFIRMED in verdicts:
        raise typer.Exit(code=2)


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
) -> None:
    """Map the keyspace: logical DBs, namespaces, types and counts."""
    run_id = _run_id()
    resolved = _resolve_targets(list(targets or []), targets_file)
    for target in resolved:
        scope = f" pattern={pattern}" if pattern else ""
        _emit(
            _advisory(
                run_id,
                target.uri(),
                "ENUM-STUB",
                f"skeleton build: census with sample={sample}{scope} lands in M3",
            )
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
    out: Annotated[Path | None, typer.Option("--out", help="Write NDJSON records here.")] = None,
) -> None:
    """Extract records matching a key pattern, capped and evidence-referenced."""
    run_id = _run_id()
    resolved = _resolve_targets(list(targets or []), targets_file)
    for target in resolved:
        scope = f" pattern={pattern}" if pattern else ""
        _emit(
            _advisory(
                run_id,
                target.uri(),
                "DUMP-STUB",
                f"skeleton build: window [{start}, {stop}]{scope} lands in M3",
            )
        )


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
