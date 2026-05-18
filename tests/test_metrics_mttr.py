"""Per-manifest MTTR (detected_at → pr_opened).

Manifests that have not opened a PR yet are reported as 'in_flight', NOT
as zero — a zero would falsely advertise instant resolution.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path

from tripwire.findings import Finding
from tripwire.metrics import compute_mttr_seconds
from tripwire.store import Store


def _utc(ts: str) -> datetime:
    return datetime.fromisoformat(ts).replace(tzinfo=timezone.utc)


def _f(manifest: str, pkg: str = "marked") -> Finding:
    return Finding(
        manifest_path=manifest, ecosystem="npm", package=pkg,
        installed_version="1.0.0", advisory_ids=[f"GHSA-{pkg}"],
        vulnerable_ranges=[">=0"], severity="high",
    )


def test_mttr_seconds_for_resolved_manifest_is_delta_between_detected_and_pr_open(tmp_path: Path):
    clock_ticks = iter([
        _utc("2026-05-17T12:00:00"),  # detected
        _utc("2026-05-17T12:00:05"),  # start_session (unused for MTTR)
        _utc("2026-05-17T12:03:20"),  # record_pr_opened
    ])
    store = Store(tmp_path / "tw.sqlite", clock=lambda: next(clock_ticks))

    store.upsert_findings([_f("api-gateway/p.json")])
    store.start_session("api-gateway/p.json", "sess-1")
    store.record_pr_opened("api-gateway/p.json")

    mttr = compute_mttr_seconds(store)
    assert mttr["api-gateway/p.json"] == 200  # 3 min 20 sec


def test_mttr_for_manifest_without_pr_open_yet_is_none(tmp_path: Path):
    clock_ticks = iter([
        _utc("2026-05-17T12:00:00"),  # detected
        _utc("2026-05-17T12:00:05"),  # start_session — no PR yet
    ])
    store = Store(tmp_path / "tw.sqlite", clock=lambda: next(clock_ticks))

    store.upsert_findings([_f("api-gateway/p.json")])
    store.start_session("api-gateway/p.json", "sess-1")

    mttr = compute_mttr_seconds(store)
    assert mttr["api-gateway/p.json"] is None


def test_mttr_for_needs_human_before_pr_is_none(tmp_path: Path):
    """Escalation before a PR was opened: in-flight is the wrong story
    (it's done), but MTTR doesn't apply — there's no PR to measure to."""
    clock_ticks = iter([
        _utc("2026-05-17T12:00:00"),  # detected
        _utc("2026-05-17T12:00:05"),  # start_session
        _utc("2026-05-17T12:01:00"),  # needs_human
    ])
    store = Store(tmp_path / "tw.sqlite", clock=lambda: next(clock_ticks))

    store.upsert_findings([_f("api-gateway/p.json")])
    store.start_session("api-gateway/p.json", "sess-1")
    store.advance_manifest("api-gateway/p.json", "needs_human")

    mttr = compute_mttr_seconds(store)
    assert mttr["api-gateway/p.json"] is None


def test_mttr_handles_multiple_manifests_independently(tmp_path: Path):
    clock = iter([
        _utc("2026-05-17T12:00:00"),  # a detected
        _utc("2026-05-17T12:00:01"),  # b detected
        _utc("2026-05-17T12:00:30"),  # a start_session
        _utc("2026-05-17T12:01:00"),  # a record_pr_opened
        _utc("2026-05-17T12:02:00"),  # b start_session
        _utc("2026-05-17T12:05:00"),  # b record_pr_opened
    ])
    store = Store(tmp_path / "tw.sqlite", clock=lambda: next(clock))

    store.upsert_findings([_f("a/p.json"), _f("b/p.json")])
    store.start_session("a/p.json", "sess-a")
    store.record_pr_opened("a/p.json")
    store.start_session("b/p.json", "sess-b")
    store.record_pr_opened("b/p.json")

    mttr = compute_mttr_seconds(store)
    assert mttr["a/p.json"] == 60
    assert mttr["b/p.json"] == 299  # 12:05:00 - 12:00:01


# Sanity check the real-clock path doesn't crash and produces a non-negative MTTR.
def test_mttr_with_real_clock_is_non_negative(tmp_path: Path):
    import time
    store = Store(tmp_path / "tw.sqlite")
    store.upsert_findings([_f("api-gateway/p.json")])
    store.start_session("api-gateway/p.json", "sess-1")
    time.sleep(0.01)
    store.record_pr_opened("api-gateway/p.json")

    mttr = compute_mttr_seconds(store)["api-gateway/p.json"]
    assert mttr is not None and mttr >= 0
