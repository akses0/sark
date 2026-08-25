from __future__ import annotations

from collections import Counter

from sark.models import Event, Verdict


def summarize(events: list[Event]) -> str:
    by_verdict = Counter(event.verdict for event in events)
    lines = ["# sark run summary", "", f"- events: {len(events)}"]
    for verdict in Verdict:
        count = by_verdict.get(verdict, 0)
        if count:
            lines.append(f"- {verdict.value}: {count}")
    confirmed = [event for event in events if event.verdict is Verdict.CONFIRMED]
    if confirmed:
        lines += ["", "## Findings", ""]
        for event in confirmed:
            confidence = f"{event.confidence:.2f}" if event.confidence is not None else "n/a"
            lines.append(
                f"- `{event.vector}` on {event.target} "
                f"({event.channel.value}, confidence {confidence})"
            )
    return "\n".join(lines)
