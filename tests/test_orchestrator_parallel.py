"""Issue + session are fired in parallel; one failing does not block the other.

The GitHub issue is a sink (audit record), never a trigger, never on the
critical path for Devin.
"""

from pathlib import Path

import pytest

from tripwire.boundaries import Boundaries
from tripwire.boundaries.devin import FakeDevinClient
from tripwire.boundaries.github import FakeGitHubClient
from tripwire.boundaries.osv import FakeOsvClient
from tripwire.orchestrator import Orchestrator
from tripwire.store import Store


class _ExplodingGitHub(FakeGitHubClient):
    def create_issue(self, *, title: str, body: str, labels: list[str]) -> str:
        raise RuntimeError("github 503")


class _ExplodingDevin(FakeDevinClient):
    def create_session(self, *, playbook_id: str, knowledge_ids: list[str], prompt: str) -> str:
        raise RuntimeError("devin 502")


_VULNS = {
    ("npm", "marked", "0.7.0"): [
        {"id": "GHSA-rrrm-qjm4-v8hf", "database_specific": {"severity": "HIGH"}},
    ],
}
_MANIFESTS = [
    {"path": "web-dashboard/package.json", "ecosystem": "npm",
     "packages": [{"name": "marked", "version": "0.7.0"}]},
]


def _orch(tmp_path: Path, *, github, devin) -> tuple[Orchestrator, Boundaries, Store]:
    bounds = Boundaries(osv=FakeOsvClient(_VULNS), github=github, devin=devin)
    store = Store(tmp_path / "tw.sqlite")
    orch = Orchestrator(
        boundaries=bounds, store=store, manifests=_MANIFESTS,
        playbook_id="pb", knowledge_ids=[], report_dir=tmp_path,
    )
    return orch, bounds, store


def test_issue_failure_does_not_block_session_creation(tmp_path):
    devin = FakeDevinClient()
    orch, _, store = _orch(tmp_path, github=_ExplodingGitHub(), devin=devin)

    result = orch.run_cycle(cycle_number=1)

    # Devin session was created despite GitHub failure.
    assert len(devin.created_sessions) == 1
    assert result.new_sessions == 1
    # Manifest advanced through the success path.
    assert store.manifest_state("web-dashboard/package.json") == "resolved"
    # We record the issue failure but don't crash.
    assert result.failed_issues == 1
    assert result.new_issues == 0


def test_session_failure_does_not_block_issue_creation(tmp_path):
    github = FakeGitHubClient(owner="cdugo", repo="superset")
    orch, _, store = _orch(tmp_path, github=github, devin=_ExplodingDevin())

    result = orch.run_cycle(cycle_number=1)

    # Issue was still filed.
    assert len(github.created_issues) == 1
    assert result.new_issues == 1
    # Manifest escalates to needs_human because the session never started.
    assert store.manifest_state("web-dashboard/package.json") == "needs_human"
    assert result.failed_sessions == 1
    assert result.new_sessions == 0


def test_both_succeed_concurrently(tmp_path):
    """Sanity check: when both work, both happen in a single cycle."""
    devin = FakeDevinClient()
    github = FakeGitHubClient(owner="cdugo", repo="superset")
    orch, _, store = _orch(tmp_path, github=github, devin=devin)

    result = orch.run_cycle(cycle_number=1)

    assert result.new_issues == 1
    assert result.new_sessions == 1
    assert result.failed_issues == 0
    assert result.failed_sessions == 0
    assert store.manifest_state("web-dashboard/package.json") == "resolved"
