from __future__ import annotations

from sark.backends.redis_cves import evaluate, parse_version


def test_parse_version_basic() -> None:
    assert parse_version("7.4.6") == (7, 4, 6)


def test_parse_version_partial_pads() -> None:
    assert parse_version("8.0") == (8, 0, 0)


def test_parse_version_junk_suffix_digits_extracted() -> None:
    assert parse_version("7.2rc1") == (7, 2, 0)
    assert parse_version("5.0.9") == (5, 0, 9)


def test_parse_version_garbage_returns_none() -> None:
    assert parse_version("unknown") is None


def test_redishell_family_affected_below_fix() -> None:
    statuses = {s.advisory.id: s.status for s in evaluate("7.4.5")}
    assert statuses["CVE-2025-49844"] == "affected"
    assert statuses["CVE-2025-46817"] == "affected"
    assert statuses["CVE-2025-46818"] == "affected"


def test_darkreplica_branch_logic() -> None:
    statuses = {s.advisory.id: s.status for s in evaluate("7.4.8")}
    assert statuses["CVE-2026-23631"] == "affected"

    patched = {s.advisory.id: s.status for s in evaluate("7.4.9")}
    assert patched["CVE-2026-23631"] == "patched"


def test_older_than_all_branches_counts_affected() -> None:
    statuses = {s.advisory.id: s.status for s in evaluate("6.2.19")}
    assert statuses["CVE-2026-23631"] == "affected"
    assert statuses["CVE-2025-49844"] == "affected"


def test_newer_version_all_patched() -> None:
    statuses = {s.advisory.id: s.status for s in evaluate("9.9.9")}
    assert all(status == "patched" for cid, status in statuses.items() if cid != "CVE-2022-0543")


def test_packaging_dependent_always_review() -> None:
    for version in ("7.4.9", "5.0.0"):
        statuses = {s.advisory.id: s.status for s in evaluate(version)}
        assert statuses["CVE-2022-0543"] == "packaging-review"


def test_exact_fix_boundary_not_affected() -> None:
    statuses = {s.advisory.id: s.status for s in evaluate("7.4.6")}
    assert statuses["CVE-2025-49844"] == "patched"


def test_garbage_version_yields_no_statuses() -> None:
    assert evaluate("nonsense") == []


def test_advisory_urls_are_nvd_links() -> None:
    for status in evaluate("7.4.5"):
        assert status.advisory.url.startswith("https://nvd.nist.gov/vuln/detail/CVE-")
