"""Funnel computation.

Six stages:
  findings → manifests_affected → sessions → prs → ci_green → merged.

merged is always 0 — merging stays a human action by design.
"""

from pathlib import Path

from tripwire.findings import Finding
from tripwire.metrics import compute_funnel
from tripwire.store import Store


def _f(manifest: str, pkg: str) -> Finding:
    return Finding(
        manifest_path=manifest, ecosystem="npm", package=pkg,
        installed_version="1.0.0", advisory_ids=[f"GHSA-{pkg}"],
        vulnerable_ranges=[">=0"], severity="high",
    )


def test_funnel_from_empty_store_is_all_zero(tmp_path: Path):
    store = Store(tmp_path / "tw.sqlite")
    funnel = compute_funnel(store)
    assert funnel == {
        "findings": 0,
        "manifests_affected": 0,
        "sessions": 0,
        "prs_opened": 0,
        "ci_green": 0,
        "merged": 0,
    }


def test_funnel_counts_findings_and_manifests(tmp_path: Path):
    store = Store(tmp_path / "tw.sqlite")
    store.upsert_findings([
        _f("a/p.json", "marked"),
        _f("a/p.json", "lodash"),  # same manifest
        _f("b/p.json", "request"),
    ])

    funnel = compute_funnel(store)
    assert funnel["findings"] == 3
    assert funnel["manifests_affected"] == 2  # a/ and b/


def test_funnel_tracks_sessions_prs_and_ci_through_state_machine(tmp_path: Path):
    store = Store(tmp_path / "tw.sqlite")
    store.upsert_findings([_f("a/p.json", "marked"), _f("b/p.json", "request")])

    store.start_session("a/p.json", "sess-a")
    store.record_pr_opened("a/p.json")
    store.advance_manifest("a/p.json", "resolved")

    store.start_session("b/p.json", "sess-b")  # in flight, no PR yet

    funnel = compute_funnel(store)
    assert funnel["sessions"] == 2
    assert funnel["prs_opened"] == 1
    assert funnel["ci_green"] == 1
    assert funnel["merged"] == 0  # ALWAYS zero (human action by design)


def test_funnel_counts_needs_human_as_session_but_not_pr(tmp_path: Path):
    store = Store(tmp_path / "tw.sqlite")
    store.upsert_findings([_f("a/p.json", "marked")])
    store.start_session("a/p.json", "sess-a")
    store.advance_manifest("a/p.json", "needs_human")  # escalated before PR

    funnel = compute_funnel(store)
    assert funnel["sessions"] == 1
    assert funnel["prs_opened"] == 0
    assert funnel["ci_green"] == 0
