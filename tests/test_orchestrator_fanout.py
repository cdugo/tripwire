"""Manifest-grained fan-out.

One Devin session per manifest (not per finding). N findings across M
manifests → exactly M session creations.
"""

from pathlib import Path

from tripwire.boundaries import Boundaries
from tripwire.boundaries.devin import FakeDevinClient
from tripwire.boundaries.github import FakeGitHubClient
from tripwire.boundaries.osv import FakeOsvClient
from tripwire.orchestrator import Orchestrator
from tripwire.store import Store


def test_n_findings_across_m_manifests_produce_m_sessions(tmp_path: Path):
    vulns = {
        # web-dashboard: 2 distinct vulnerable packages
        ("npm", "marked", "0.7.0"): [{"id": "GHSA-marked", "database_specific": {"severity": "HIGH"}}],
        ("npm", "lodash", "4.17.4"): [{"id": "GHSA-lodash", "database_specific": {"severity": "HIGH"}}],
        # api-gateway: 2 packages
        ("npm", "request", "2.88.2"): [{"id": "GHSA-req", "database_specific": {"severity": "MODERATE"}}],
        ("npm", "tough-cookie", "2.5.0"): [{"id": "GHSA-tc", "database_specific": {"severity": "MODERATE"}}],
        # etl-worker: 1 package
        ("PyPI", "Jinja2", "2.10"): [{"id": "GHSA-jinja", "database_specific": {"severity": "CRITICAL"}}],
    }
    manifests = [
        {"path": "web-dashboard/package.json", "ecosystem": "npm",
         "packages": [{"name": "marked", "version": "0.7.0"}, {"name": "lodash", "version": "4.17.4"}]},
        {"path": "api-gateway/package.json", "ecosystem": "npm",
         "packages": [{"name": "request", "version": "2.88.2"}, {"name": "tough-cookie", "version": "2.5.0"}]},
        {"path": "etl-worker/requirements.txt", "ecosystem": "PyPI",
         "packages": [{"name": "Jinja2", "version": "2.10"}]},
    ]
    devin = FakeDevinClient()
    bounds = Boundaries(
        osv=FakeOsvClient(vulns),
        github=FakeGitHubClient(owner="cdugo", repo="superset"),
        devin=devin,
    )
    orch = Orchestrator(
        boundaries=bounds, store=Store(tmp_path / "tw.sqlite"),
        manifests=manifests, playbook_id="pb", knowledge_ids=[], report_dir=tmp_path,
    )

    orch.run_cycle(cycle_number=1)

    # 5 findings, 3 manifests → 3 sessions (not 5).
    assert len(devin.created_sessions) == 3

    by_manifest = {sess["prompt"].split("manifest ", 1)[1].split(".", 1)[0]: sess
                   for sess in devin.created_sessions}
    # Each session's prompt names ONLY the packages in its own manifest.
    web = next(s for s in devin.created_sessions if "web-dashboard" in s["prompt"])
    api = next(s for s in devin.created_sessions if "api-gateway" in s["prompt"])
    etl = next(s for s in devin.created_sessions if "etl-worker" in s["prompt"])

    assert "marked" in web["prompt"] and "lodash" in web["prompt"]
    assert "request" not in web["prompt"]  # other manifests' packages excluded

    assert "request" in api["prompt"] and "tough-cookie" in api["prompt"]
    assert "marked" not in api["prompt"]

    assert "Jinja2" in etl["prompt"]
    assert "marked" not in etl["prompt"] and "request" not in etl["prompt"]
    _ = by_manifest  # silence unused
