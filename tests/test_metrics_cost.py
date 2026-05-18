"""Cost per fix.

ACUs from Devin → dollars and engineer-hours. Division by zero (no PRs
landed) reports None for cost_per_fix, not infinity or NaN.

ACUs are sometimes reported as 0.0 right after completion (async/aggregated
on the API side). The orchestrator's reconcile pass records whatever the
API last reported; later cycles overwrite with refreshed numbers. We test
the metric, not the freshness.
"""

from pathlib import Path

from tripwire.findings import Finding
from tripwire.metrics import compute_cost
from tripwire.store import Store


def _f(manifest: str) -> Finding:
    return Finding(
        manifest_path=manifest, ecosystem="npm", package="x",
        installed_version="1.0.0", advisory_ids=["GHSA-x"],
        vulnerable_ranges=[">=0"], severity="high",
    )


def _drive_to_resolved(store: Store, path: str) -> None:
    store.start_session(path, f"sess-{path}")
    store.record_pr_opened(path)
    store.advance_manifest(path, "resolved")


def test_cost_per_fix_divides_total_dollars_by_prs_landed(tmp_path: Path):
    store = Store(tmp_path / "tw.sqlite")
    store.upsert_findings([_f("a/p.json"), _f("b/p.json"), _f("c/p.json")])

    _drive_to_resolved(store, "a/p.json")
    store.record_acu_usage("a/p.json", 2.5)
    _drive_to_resolved(store, "b/p.json")
    store.record_acu_usage("b/p.json", 1.5)
    # c is needs_human (no PR).
    store.start_session("c/p.json", "sess-c")
    store.advance_manifest("c/p.json", "needs_human")
    store.record_acu_usage("c/p.json", 0.5)

    cost = compute_cost(store, dollars_per_acu=2.0, hours_per_acu=0.5)

    # All ACUs count toward total cost (Devin charged us either way).
    assert cost["total_acus"] == 4.5
    assert cost["total_dollars"] == 9.0
    assert cost["total_engineer_hours"] == 2.25

    # Cost per fix only divides by manifests that produced a landed PR.
    assert cost["prs_landed"] == 2
    assert cost["cost_per_fix_dollars"] == 4.5  # 9.0 / 2
    assert cost["cost_per_fix_hours"] == 1.125  # 2.25 / 2


def test_cost_per_fix_is_none_when_no_prs_landed(tmp_path: Path):
    store = Store(tmp_path / "tw.sqlite")
    store.upsert_findings([_f("a/p.json")])
    store.start_session("a/p.json", "sess-a")
    store.advance_manifest("a/p.json", "needs_human")
    store.record_acu_usage("a/p.json", 0.7)

    cost = compute_cost(store, dollars_per_acu=2.0, hours_per_acu=0.5)
    assert cost["prs_landed"] == 0
    assert cost["cost_per_fix_dollars"] is None
    assert cost["cost_per_fix_hours"] is None


def test_cost_with_no_acus_reported_is_zero_not_crash(tmp_path: Path):
    """ACUs may be 0 right after completion (API lag). Treat None or 0
    as zero, not as missing data."""
    store = Store(tmp_path / "tw.sqlite")
    store.upsert_findings([_f("a/p.json")])
    _drive_to_resolved(store, "a/p.json")
    # Note: no record_acu_usage call — ACUs are 0/None.

    cost = compute_cost(store, dollars_per_acu=2.0, hours_per_acu=0.5)
    assert cost["total_acus"] == 0.0
    assert cost["cost_per_fix_dollars"] == 0.0
    assert cost["prs_landed"] == 1
