from __future__ import annotations

import secrets
import sys
from pathlib import Path
from typing import Annotated

import typer

from sark.backends.redis import RedisBackend
from sark.engine.plugins import load_plugins
from sark.models import Channel, Event, Verdict
from sark.report.md import summarize
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
    typer.Option("--targets-file", help="TOML or newline-delimited target list."),
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


def _stub_event(run_id: str, target_uri: str, vector: str, detail: str) -> Event:
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


@app.command()
def scan(
    targets: TargetOption = None,
    targets_file: TargetsFileOption = None,
    risk: RiskOption = 1,
    wordlist: Annotated[
        Path | None,
        typer.Option("--wordlist", help="Opt-in credential spray; stops on first hit."),
    ] = None,
) -> None:
    """Fingerprint a Redis instance and run exposure vectors up to the chosen risk."""
    run_id = _run_id()
    resolved = _resolve_targets(list(targets or []), targets_file)
    backends, plugin_errors = load_plugins()
    for error in plugin_errors:
        _emit(
            Event(
                run_id=run_id,
                target="-",
                vector="RUN-PLUGIN-ERROR",
                channel=Channel.DIRECT,
                verdict=Verdict.ADVISORY,
                detail=error,
            )
        )
    backend = backends.get("redis") or RedisBackend()
    registry = backend.vectors()
    eligible = [spec for spec in registry if spec.tier.value <= risk]
    for target in resolved:
        _emit(
            _stub_event(
                run_id,
                target.uri(),
                "RUN-STUB",
                f"skeleton build: {len(registry)} vectors registered, "
                f"{len(eligible)} eligible at risk={risk}; execution lands M1-M2",
            )
        )


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
            _stub_event(
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
            _stub_event(
                run_id,
                target.uri(),
                "DUMP-STUB",
                f"skeleton build: window [{start}, {stop}]{scope} lands in M3",
            )
        )


@app.command()
def report(
    events: Annotated[Path, typer.Option("--events", help="NDJSON event stream from a run.")],
    format: Annotated[str, typer.Option("--format", help="Output format.")] = "md",
) -> None:
    """Render an event stream into a human-readable report."""
    if format != "md":
        raise typer.BadParameter(f"unsupported format {format!r}: only 'md' ships pre-M4")
    parsed: list[Event] = []
    rejected = 0
    for number, line in enumerate(events.read_text(encoding="utf-8").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            parsed.append(Event.model_validate_json(line))
        except ValueError as exc:
            rejected += 1
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
