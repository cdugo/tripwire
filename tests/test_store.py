"""Tests for the SQLite state store.

The store is the idempotency anchor (finding fingerprint dedupes across
polls) AND the per-manifest state machine. One component, multiple jobs.
"""

import pytest

from tripwire.findings import Finding
from tripwire.store import InvalidTransition, Store


def _fnd(pkg: str, manifest="api-gateway/package.json", advisory="GHSA-aaaa") -> Finding:
    return Finding(
        manifest_path=manifest,
        ecosystem="npm",
        package=pkg,
        installed_version="1.0.0",
        advisory_ids=[advisory],
        vulnerable_ranges=[">=0"],
        severity="high",
    )


def test_store_persists_and_lists_findings(tmp_path):
    store = Store(tmp_path / "tw.sqlite")
    store.upsert_findings([_fnd("request"), _fnd("tough-cookie")])

    persisted = store.list_findings()
    fingerprints = {f.fingerprint for f in persisted}
    assert fingerprints == {
        ("api-gateway/package.json", "npm", "request"),
        ("api-gateway/package.json", "npm", "tough-cookie"),
    }


def test_upserting_same_finding_twice_does_not_duplicate(tmp_path):
    store = Store(tmp_path / "tw.sqlite")
    store.upsert_findings([_fnd("request")])
    store.upsert_findings([_fnd("request")])

    assert len(store.list_findings()) == 1


def test_upsert_updates_advisory_list_for_same_fingerprint(tmp_path):
    store = Store(tmp_path / "tw.sqlite")
    store.upsert_findings([_fnd("request", advisory="GHSA-aaaa")])

    updated = Finding(
        manifest_path="api-gateway/package.json",
        ecosystem="npm",
        package="request",
        installed_version="1.0.0",
        advisory_ids=["GHSA-aaaa", "GHSA-bbbb"],
        vulnerable_ranges=[">=0", "<3"],
        severity="critical",
    )
    store.upsert_findings([updated])

    [persisted] = store.list_findings()
    assert persisted.advisory_ids == ["GHSA-aaaa", "GHSA-bbbb"]
    assert persisted.severity == "critical"


def test_manifest_starts_in_detected_when_findings_first_seen(tmp_path):
    store = Store(tmp_path / "tw.sqlite")
    store.upsert_findings([_fnd("request")])

    assert store.manifest_state("api-gateway/package.json") == "detected"


def test_manifest_advances_through_legal_state_chain(tmp_path):
    store = Store(tmp_path / "tw.sqlite")
    store.upsert_findings([_fnd("request")])
    path = "api-gateway/package.json"

    store.start_session(path, "sess-1")
    assert store.manifest_state(path) == "in_flight"
    store.advance_manifest(path, "resolved")
    assert store.manifest_state(path) == "resolved"


def test_manifest_rejects_illegal_state_skip(tmp_path):
    store = Store(tmp_path / "tw.sqlite")
    store.upsert_findings([_fnd("request")])
    path = "api-gateway/package.json"

    with pytest.raises(InvalidTransition):
        # Skipping in_flight: detected → resolved is illegal.
        store.advance_manifest(path, "resolved")


def test_manifest_can_escalate_to_needs_human_from_any_nonterminal(tmp_path):
    store = Store(tmp_path / "tw.sqlite")
    store.upsert_findings([_fnd("request")])
    path = "api-gateway/package.json"

    store.start_session(path, "sess-1")
    store.advance_manifest(path, "needs_human")
    assert store.manifest_state(path) == "needs_human"


def test_terminal_state_is_immutable(tmp_path):
    store = Store(tmp_path / "tw.sqlite")
    store.upsert_findings([_fnd("request")])
    path = "api-gateway/package.json"

    store.start_session(path, "sess-1")
    store.advance_manifest(path, "resolved")

    with pytest.raises(InvalidTransition):
        store.advance_manifest(path, "needs_human")
