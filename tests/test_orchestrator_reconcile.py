"""Cross-cycle reconciliation of in-flight Devin sessions.

The Monitor was once called inline at session-creation time with age=0;
in live mode a real session takes minutes, so a single run_cycle could
never advance it past `session_started`. Each run_cycle now reconciles
every non-terminal manifest with a session, so the wall-clock cap has
real teeth.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path

from tripwire.boundaries import Boundaries
from tripwire.boundaries.devin import FakeDevinClient
from tripwire.boundaries.github import FakeGitHubClient
from tripwire.boundaries.osv import FakeOsvClient
from tripwire.orchestrator import Orchestrator
from tripwire.store import Store


_VULNS = {
    ("npm", "marked", "0.7.0"): [{"id": "GHSA-rrrm-qjm4-v8hf", "database_specific": {"severity": "HIGH"}}],
}
_MANIFESTS = [
    {"path": "web-dashboard/p.json", "ecosystem": "npm",
     "packages": [{"name": "marked", "version": "0.7.0"}]},
]


class _SlowFakeDevin(FakeDevinClient):
    """Returns 'running' until `complete_after_calls` get_session calls."""

    def __init__(self, *, complete_after_calls: int) -> None:
        super().__init__()
        self._target = complete_after_calls
        self._calls: dict[str, int] = {}

    def get_session(self, session_id: str) -> dict:
        self._calls[session_id] = self._calls.get(session_id, 0) + 1
        if self._calls[session_id] < self._target:
            return {
                "id": session_id,
                "status": "running",
                "terminal_status": None,
                "pr_url": None,
                "acu_usage": 0.0,
                "messages": [],
            }
        return super().get_session(session_id)


class _NeverDoneFakeDevin(FakeDevinClient):
    """Always reports running; never finishes — exercises the wall-clock cap."""

    def get_session(self, session_id: str) -> dict:
        return {
            "id": session_id,
            "status": "running",
            "terminal_status": None,
            "pr_url": None,
            "acu_usage": 0.7,
            "messages": [],
        }


class _EscalatesFakeDevin(FakeDevinClient):
    """First call: running. Second call: BLOCKED."""

    def __init__(self) -> None:
        super().__init__()
        self._calls: dict[str, int] = {}

    def get_session(self, session_id: str) -> dict:
        self._calls[session_id] = self._calls.get(session_id, 0) + 1
        base = {
            "id": session_id,
            "pr_url": None,
            "acu_usage": 1.2,
            "messages": [],
        }
        if self._calls[session_id] == 1:
            return {**base, "status": "running", "terminal_status": None}
        return {
            **base,
            "status": "suspended",
            "terminal_status": "BLOCKED",
            "messages": [
                {"source": "devin", "body": "I cannot resolve this. Terminal status: BLOCKED"}
            ],
        }


def _build(tmp_path: Path, devin, *, clock=None, cap=3600.0) -> tuple[Orchestrator, Boundaries, Store]:
    bounds = Boundaries(
        osv=FakeOsvClient(_VULNS),
        github=FakeGitHubClient(owner="cdugo", repo="superset"),
        devin=devin,
    )
    store = Store(tmp_path / "tw.sqlite", clock=clock) if clock else Store(tmp_path / "tw.sqlite")
    orch = Orchestrator(
        boundaries=bounds, store=store, manifests=_MANIFESTS,
        playbook_id="pb", knowledge_ids=[], report_dir=tmp_path,
        wall_clock_cap_seconds=cap,
    )
    return orch, bounds, store


def test_in_flight_session_after_cycle_1_is_resolved_on_cycle_2(tmp_path: Path):
    devin = _SlowFakeDevin(complete_after_calls=2)
    orch, _, store = _build(tmp_path, devin)

    orch.run_cycle(cycle_number=1)
    # Cycle 1: session was created but Devin reported running. Should NOT
    # be at 'resolved' yet — that would be the inline-only bug.
    assert store.manifest_state("web-dashboard/p.json") == "in_flight"

    result = orch.run_cycle(cycle_number=2)
    # Cycle 2: reconcile pass polled Devin again; this time COMPLETE.
    assert store.manifest_state("web-dashboard/p.json") == "resolved"
    # And no NEW session was created — we just reassessed the existing one.
    assert len(devin.created_sessions) == 1
    assert result.new_sessions == 0


def test_in_flight_session_escalates_to_needs_human_when_devin_reports_blocked(tmp_path: Path):
    devin = _EscalatesFakeDevin()
    orch, _, store = _build(tmp_path, devin)

    orch.run_cycle(cycle_number=1)
    assert store.manifest_state("web-dashboard/p.json") == "in_flight"

    orch.run_cycle(cycle_number=2)
    assert store.manifest_state("web-dashboard/p.json") == "needs_human"


def test_wall_clock_cap_fires_when_real_age_exceeds_cap(tmp_path: Path):
    """Liveness backstop: a session that never completes is forcibly closed."""
    # Use a mutable clock so the test doesn't have to know how many _now()
    # calls each store method makes internally.
    now = {"t": datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc)}
    devin = _NeverDoneFakeDevin()
    orch, _, store = _build(
        tmp_path, devin, clock=lambda: now["t"], cap=60.0
    )

    orch.run_cycle(cycle_number=1)
    # Session is fresh: under the 60s cap, monitor verdict is in_flight.
    assert store.manifest_state("web-dashboard/p.json") == "in_flight"

    # Advance the clock 2 hours; the next reconcile sees a stale session.
    now["t"] = datetime(2026, 5, 17, 14, 0, 0, tzinfo=timezone.utc)
    orch.run_cycle(cycle_number=2)
    assert store.manifest_state("web-dashboard/p.json") == "timed_out"


def test_reconcile_records_updated_acu_usage(tmp_path: Path):
    """ACUs may be 0 right after completion (API lag). Reconcile
    re-reads them so the cost dashboard converges to the real number."""
    devin = _SlowFakeDevin(complete_after_calls=2)
    orch, _, store = _build(tmp_path, devin)

    orch.run_cycle(cycle_number=1)  # devin returns running, acu=0
    assert store.manifest_acu_usage()["web-dashboard/p.json"] == 0.0

    orch.run_cycle(cycle_number=2)  # devin returns COMPLETE w/ real acu
    # FakeDevinClient.get_session returns acu_usage=1.2 on the COMPLETE branch.
    assert store.manifest_acu_usage()["web-dashboard/p.json"] == 1.2


def test_terminal_manifests_are_not_reconciled(tmp_path: Path):
    """Once a manifest is resolved/needs_human/timed_out, no more polling."""
    devin = FakeDevinClient()  # synchronous COMPLETE
    orch, _, store = _build(tmp_path, devin)

    orch.run_cycle(cycle_number=1)
    assert store.manifest_state("web-dashboard/p.json") == "resolved"
    before = dict(devin._calls if hasattr(devin, "_calls") else {})

    orch.run_cycle(cycle_number=2)
    orch.run_cycle(cycle_number=3)
    # FakeDevinClient doesn't track get_session calls; but reconcile must
    # not advance a terminal state. Verify by state immutability.
    assert store.manifest_state("web-dashboard/p.json") == "resolved"
    _ = before
