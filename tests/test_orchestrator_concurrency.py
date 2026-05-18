"""Per-manifest fan-out runs in parallel under a bounded worker pool.

Sessions run in parallel, code-orchestrated, with a concurrency cap.
Sequential would make Devin look like a slow batch job; unbounded would
melt the API.
"""

import threading
import time
from pathlib import Path

from tripwire.boundaries import Boundaries
from tripwire.boundaries.devin import FakeDevinClient
from tripwire.boundaries.github import FakeGitHubClient
from tripwire.boundaries.osv import FakeOsvClient
from tripwire.orchestrator import Orchestrator
from tripwire.store import Store


class _SlowConcurrencyTrackingDevin(FakeDevinClient):
    """Sleeps in create_session so concurrent calls overlap, recording peak."""

    def __init__(self) -> None:
        super().__init__()
        self.in_flight = 0
        self.peak = 0
        self._lock = threading.Lock()

    def create_session(self, *, playbook_id: str, knowledge_ids: list[str], prompt: str) -> str:
        with self._lock:
            self.in_flight += 1
            self.peak = max(self.peak, self.in_flight)
        try:
            time.sleep(0.05)
            return super().create_session(playbook_id=playbook_id, knowledge_ids=knowledge_ids, prompt=prompt)
        finally:
            with self._lock:
                self.in_flight -= 1


def _make_manifests(n: int) -> tuple[list[dict], dict]:
    manifests = []
    vulns = {}
    for i in range(n):
        path = f"svc-{i}/package.json"
        pkg = f"pkg-{i}"
        manifests.append({
            "path": path, "ecosystem": "npm",
            "packages": [{"name": pkg, "version": "1.0.0"}],
        })
        vulns[("npm", pkg, "1.0.0")] = [{"id": f"GHSA-{i:04d}", "database_specific": {"severity": "HIGH"}}]
    return manifests, vulns


def test_session_creation_respects_concurrency_cap(tmp_path: Path):
    manifests, vulns = _make_manifests(8)
    devin = _SlowConcurrencyTrackingDevin()
    bounds = Boundaries(
        osv=FakeOsvClient(vulns),
        github=FakeGitHubClient(owner="cdugo", repo="superset"),
        devin=devin,
    )
    orch = Orchestrator(
        boundaries=bounds, store=Store(tmp_path / "tw.sqlite"),
        manifests=manifests, playbook_id="pb", knowledge_ids=[], report_dir=tmp_path,
        max_parallel_manifests=4,
    )

    orch.run_cycle(cycle_number=1)

    assert len(devin.created_sessions) == 8
    assert devin.peak <= 4, f"concurrency cap breached: peak={devin.peak}"
    # And we DID actually parallelize — peak should be > 1.
    assert devin.peak >= 2, f"never parallelized: peak={devin.peak}"


def test_default_concurrency_cap_is_at_least_four(tmp_path: Path):
    """Concurrency cap ≥ 4 by default."""
    manifests, vulns = _make_manifests(6)
    devin = _SlowConcurrencyTrackingDevin()
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

    assert devin.peak >= 4, f"default cap < 4 effective concurrency, peak={devin.peak}"
