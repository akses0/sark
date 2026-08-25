from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from sark.cli import app
from sark.models import Event

runner = CliRunner()


def parse_events(output: str) -> list[Event]:
    return [
        Event.model_validate_json(line)
        for line in output.splitlines()
        if line.strip().startswith("{")
    ]


def test_help_shows_workflow_verbs() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for verb in ("scan", "enum", "dump", "report"):
        assert verb in result.output


def test_scan_emits_valid_jsonl_stub() -> None:
    result = runner.invoke(app, ["scan", "-t", "redis://127.0.0.1:6379", "--risk=2"])
    assert result.exit_code == 0, result.output
    events = parse_events(result.stdout)
    assert events
    assert all(
        event.verdict is Event.model_validate_json(event.model_dump_json()).verdict
        for event in events
    )
    stubs = [event for event in events if event.vector == "RUN-STUB"]
    assert stubs and "risk=2" in (stubs[0].detail or "")


def test_scan_rejects_bad_uri_with_usage_error() -> None:
    result = runner.invoke(app, ["scan", "-t", "postgres://db:5432"])
    assert result.exit_code != 0


def test_report_round_trips_event_stream(tmp_path: Path) -> None:
    scan_result = runner.invoke(app, ["scan", "-t", "redis://127.0.0.1"])
    events_file = tmp_path / "run.jsonl"
    lines = [line for line in scan_result.stdout.splitlines() if line.strip().startswith("{")]
    events_file.write_text("\n".join(lines), encoding="utf-8")
    report_result = runner.invoke(app, ["report", "--events", str(events_file)])
    assert report_result.exit_code == 0, report_result.output
    assert "# sark run summary" in report_result.stdout
    assert "advisory" in report_result.stdout


def test_report_counts_confirmed_as_findings_exit_2(tmp_path: Path) -> None:
    confirmed = {
        "ts": "2026-08-25T14:03:11Z",
        "run_id": "a1b2c3",
        "target": "redis://127.0.0.1",
        "vector": "RED-UNAUTH",
        "channel": "direct",
        "verdict": "confirmed",
        "confidence": 1.0,
        "evidence": {},
    }
    events_file = tmp_path / "findings.jsonl"
    events_file.write_text(json.dumps(confirmed), encoding="utf-8")
    result = runner.invoke(app, ["report", "--events", str(events_file)])
    assert result.exit_code == 2
    assert "## Findings" in result.stdout


def test_report_skips_malformed_lines(tmp_path: Path) -> None:
    events_file = tmp_path / "messy.jsonl"
    events_file.write_text("not-json\n{}\n", encoding="utf-8")
    result = runner.invoke(app, ["report", "--events", str(events_file)])
    assert result.exit_code == 0
    assert "malformed event on line 1" in result.stderr or result.stderr == ""
