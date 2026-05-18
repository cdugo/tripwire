"""Rendered report.html includes funnel, MTTR, and cost-per-fix.

Cost per fix LEADS. Per-cycle snapshots persist; the rolling report.html
is also overwritten so there's always a "latest" pointer.
"""

from pathlib import Path

from tripwire.findings import Finding
from tripwire.report import render_report
from tripwire.store import Store


def _f(manifest: str) -> Finding:
    return Finding(
        manifest_path=manifest, ecosystem="npm", package="marked",
        installed_version="0.7.0", advisory_ids=["GHSA-rrrm-qjm4-v8hf"],
        vulnerable_ranges=["<4.0.10"], severity="high",
    )


def test_report_contains_funnel_mttr_and_cost(tmp_path: Path):
    store = Store(tmp_path / "tw.sqlite")
    store.upsert_findings([_f("web-dashboard/p.json")])
    store.start_session("web-dashboard/p.json", "sess-1")
    store.record_pr_opened("web-dashboard/p.json")
    store.advance_manifest("web-dashboard/p.json", "resolved")
    store.record_acu_usage("web-dashboard/p.json", 3.0)

    render_report(store, out_dir=tmp_path, cycle_number=2)

    html = (tmp_path / "report.html").read_text()
    # Cost leads.
    cost_pos = html.find("Cost per fix")
    funnel_pos = html.find("Funnel")
    assert 0 <= cost_pos < funnel_pos, "cost-per-fix must lead funnel in the report"

    assert "MTTR" in html or "mttr" in html.lower()
    # Funnel stages all named.
    for stage in ("findings", "manifests", "sessions", "PRs", "CI", "merged"):
        assert stage.lower() in html.lower(), f"funnel stage missing: {stage}"


def test_per_cycle_snapshot_is_distinct_from_rolling_report(tmp_path: Path):
    store = Store(tmp_path / "tw.sqlite")
    store.upsert_findings([_f("a/p.json")])
    render_report(store, out_dir=tmp_path, cycle_number=1)

    # Add a new finding before cycle 2.
    store.upsert_findings([_f("b/p.json")])
    render_report(store, out_dir=tmp_path, cycle_number=2)

    cycle1 = (tmp_path / "report-1.html").read_text()
    cycle2 = (tmp_path / "report-2.html").read_text()
    rolling = (tmp_path / "report.html").read_text()

    # Cycle 1 snapshot is frozen at 1 manifest.
    assert "a/p.json" in cycle1 and "b/p.json" not in cycle1
    # Cycle 2 + rolling both reflect both manifests.
    assert "a/p.json" in cycle2 and "b/p.json" in cycle2
    assert rolling == cycle2  # rolling is the latest


def test_report_cost_per_fix_shows_pending_when_no_prs_landed(tmp_path: Path):
    store = Store(tmp_path / "tw.sqlite")
    store.upsert_findings([_f("a/p.json")])
    store.start_session("a/p.json", "sess-a")
    store.advance_manifest("a/p.json", "needs_human")
    store.record_acu_usage("a/p.json", 1.0)

    render_report(store, out_dir=tmp_path, cycle_number=1)
    html = (tmp_path / "report.html").read_text()

    # Cost per fix must NOT show as $0 or N/A — it's pending, no PRs yet.
    assert "pending" in html.lower() or "—" in html or "no PRs" in html.lower()
