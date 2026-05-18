"""SQLite persists across Store instances.

SQLite is mounted as a file (not a tmpfs volume), so the data survives
container restart. The Python-level analog is closing and reopening the
Store with the same path.
"""

from pathlib import Path

from tripwire.findings import Finding
from tripwire.store import Store


def _f(manifest: str = "a/p.json", pkg: str = "marked") -> Finding:
    return Finding(
        manifest_path=manifest, ecosystem="npm", package=pkg,
        installed_version="1.0.0", advisory_ids=[f"GHSA-{pkg}"],
        vulnerable_ranges=[">=0"], severity="high",
    )


def test_findings_and_state_survive_store_reopen(tmp_path: Path):
    db = tmp_path / "tw.sqlite"

    s1 = Store(db)
    s1.upsert_findings([_f()])
    s1.start_session("a/p.json", "sess-1")
    s1.record_pr_opened("a/p.json")
    s1.record_acu_usage("a/p.json", 2.5)
    s1.close()

    s2 = Store(db)
    assert {f.fingerprint for f in s2.list_findings()} == {("a/p.json", "npm", "marked")}
    assert s2.manifest_state("a/p.json") == "in_flight"
    assert s2.manifest_timestamps("a/p.json")["pr_opened_at"] is not None
    assert s2.manifest_acu_usage()["a/p.json"] == 2.5


def test_reopen_does_not_reset_detected_at(tmp_path: Path):
    """Tampering with timing on reopen would invalidate MTTR."""
    db = tmp_path / "tw.sqlite"

    s1 = Store(db)
    s1.upsert_findings([_f()])
    original = s1.manifest_timestamps("a/p.json")["detected_at"]
    s1.close()

    s2 = Store(db)
    s2.upsert_findings([_f()])  # idempotent re-upsert mustn't change detected_at
    assert s2.manifest_timestamps("a/p.json")["detected_at"] == original
