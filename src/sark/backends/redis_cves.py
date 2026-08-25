from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Advisory:
    id: str
    name: str
    fixed_in: tuple[tuple[int, int, int], ...]
    url: str
    packaging_dependent: bool = False


@dataclass(frozen=True)
class CveStatus:
    advisory: Advisory
    status: str
    target_version: tuple[int, int, int]


NVD = "https://nvd.nist.gov/vuln/detail/"

ADVISORIES: tuple[Advisory, ...] = (
    Advisory(
        id="CVE-2025-49844",
        name="Lua parser use-after-free via GC timing (RediShell family)",
        fixed_in=((6, 2, 20), (7, 2, 11), (7, 4, 6), (8, 0, 4), (8, 2, 2)),
        url=NVD + "CVE-2025-49844",
    ),
    Advisory(
        id="CVE-2025-46817",
        name="Integer overflow in Lua unpack leads to memory corruption",
        fixed_in=((6, 2, 20), (7, 2, 11), (7, 4, 6), (8, 0, 4), (8, 2, 2)),
        url=NVD + "CVE-2025-46817",
    ),
    Advisory(
        id="CVE-2025-46818",
        name="Cross-user code execution via basic-type metatable poisoning",
        fixed_in=((6, 2, 20), (7, 2, 11), (7, 4, 6), (8, 0, 4), (8, 2, 2)),
        url=NVD + "CVE-2025-46818",
    ),
    Advisory(
        id="CVE-2026-23631",
        name="DarkReplica: functions engine UAF via replication reentrancy",
        fixed_in=((7, 2, 14), (7, 4, 9), (8, 2, 6), (8, 4, 3), (8, 6, 3)),
        url=NVD + "CVE-2026-23631",
    ),
    Advisory(
        id="CVE-2022-0543",
        name="Debian/Raspbian packaging left Lua sandbox library loadable",
        fixed_in=(),
        url=NVD + "CVE-2022-0543",
        packaging_dependent=True,
    ),
)


def parse_version(raw: str) -> tuple[int, int, int] | None:
    numbers: list[int] = []
    for part in raw.strip().split(".")[:3]:
        match = re.match(r"\d+", part)
        if not match:
            return None
        numbers.append(int(match.group()))
    while len(numbers) < 3:
        numbers.append(0)
    return (numbers[0], numbers[1], numbers[2])


def _affected(target: tuple[int, int, int], branches: tuple[tuple[int, int, int], ...]) -> bool:
    for branch in branches:
        if target[:2] == branch[:2]:
            return target < branch
    return target < min(branches)


def evaluate(version_raw: str) -> list[CveStatus]:
    version = parse_version(version_raw)
    if version is None:
        return []
    statuses: list[CveStatus] = []
    for advisory in ADVISORIES:
        if advisory.packaging_dependent:
            statuses.append(CveStatus(advisory, "packaging-review", version))
        elif advisory.fixed_in == ():
            continue
        elif _affected(version, advisory.fixed_in):
            statuses.append(CveStatus(advisory, "affected", version))
        else:
            statuses.append(CveStatus(advisory, "patched", version))
    return statuses
