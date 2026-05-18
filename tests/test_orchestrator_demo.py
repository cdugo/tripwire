"""End-to-end dry-run test.

A single `demo` invocation walks detect → group → fan-out → reconcile →
report, all against fakes, with deterministic output.
"""

from pathlib import Path

from tripwire.boundaries import Boundaries
from tripwire.boundaries.devin import FakeDevinClient
from tripwire.boundaries.github import FakeGitHubClient
from tripwire.boundaries.osv import FakeOsvClient
from tripwire.orchestrator import Orchestrator
from tripwire.store import Store


_VULNS = {
    ("npm", "marked", "0.7.0"): [
        {
            "id": "GHSA-rrrm-qjm4-v8hf",
            "affected": [{"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}],
            "database_specific": {"severity": "HIGH"},
        }
    ],
    ("PyPI", "Jinja2", "2.10"): [
        {
            "id": "GHSA-462w-v97r-4m45",
            "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.10.1"}]}]}],
            "database_specific": {"severity": "CRITICAL"},
        }
    ],
}

_MANIFESTS = [
    {
        "path": "web-dashboard/package.json",
        "ecosystem": "npm",
        "packages": [
            {"name": "marked", "version": "0.7.0"},
            {"name": "react", "version": "18.2.0"},  # clean
        ],
    },
    {
        "path": "etl-worker/requirements.txt",
        "ecosystem": "PyPI",
        "packages": [
            {"name": "Jinja2", "version": "2.10"},
            {"name": "requests", "version": "2.32.0"},  # clean
        ],
    },
]


def _make_orchestrator(tmp_path: Path) -> tuple[Orchestrator, Boundaries, Store]:
    devin = FakeDevinClient()
    github = FakeGitHubClient(owner="cdugo", repo="superset")
    osv = FakeOsvClient(_VULNS)
    boundaries = Boundaries(osv=osv, github=github, devin=devin)
    store = Store(tmp_path / "tw.sqlite")
    orch = Orchestrator(
        boundaries=boundaries,
        store=store,
        manifests=_MANIFESTS,
        playbook_id="pb-test",
        knowledge_ids=["kn-test"],
        report_dir=tmp_path,
    )
    return orch, boundaries, store


def test_demo_run_detects_findings_files_issues_creates_sessions_writes_report(tmp_path):
    orch, boundaries, store = _make_orchestrator(tmp_path)

    result = orch.run_cycle(cycle_number=1)

    # Detect: both vulnerable packages captured, clean packages ignored.
    assert result.new_findings == 2
    fingerprints = {f.fingerprint for f in store.list_findings()}
    assert fingerprints == {
        ("web-dashboard/package.json", "npm", "marked"),
        ("etl-worker/requirements.txt", "PyPI", "Jinja2"),
    }

    # Fan-out: one issue + one session per affected manifest (2 manifests, 2 each).
    assert len(boundaries.github.created_issues) == 2
    assert len(boundaries.devin.created_sessions) == 2

    # Each session received the playbook + knowledge IDs.
    for sess in boundaries.devin.created_sessions:
        assert sess["playbook_id"] == "pb-test"
        assert sess["knowledge_ids"] == ["kn-test"]

    # Monitor advanced both manifests to a terminal state (fake returns COMPLETE).
    states = dict(store.list_manifests())
    assert states["web-dashboard/package.json"] == "resolved"
    assert states["etl-worker/requirements.txt"] == "resolved"

    # Report artifact exists.
    rolling = tmp_path / "report.html"
    snapshot = tmp_path / "report-1.html"
    assert rolling.exists()
    assert snapshot.exists()
    html = rolling.read_text()
    assert "marked" in html and "Jinja2" in html


def test_demo_run_is_idempotent(tmp_path):
    orch, boundaries, store = _make_orchestrator(tmp_path)

    first = orch.run_cycle(cycle_number=1)
    second = orch.run_cycle(cycle_number=2)

    # First cycle filed; second cycle saw nothing new.
    assert first.new_findings == 2
    assert second.new_findings == 0
    assert second.new_issues == 0
    assert second.new_sessions == 0

    # The store is still correct (still 2 findings, no dupes).
    assert len(store.list_findings()) == 2
    assert len(boundaries.github.created_issues) == 2
    assert len(boundaries.devin.created_sessions) == 2


def test_demo_run_emits_session_prompt_naming_every_finding_in_the_manifest(tmp_path):
    """One session per manifest, prompt carries every finding for that
    manifest."""
    vulns = {
        ("npm", "request", "2.88.2"): [{"id": "GHSA-p8p7-x288-28g6", "database_specific": {"severity": "MODERATE"}}],
        ("npm", "tough-cookie", "2.5.0"): [{"id": "GHSA-72xf-g2v4-qvf3", "database_specific": {"severity": "MODERATE"}}],
    }
    manifests = [
        {
            "path": "api-gateway/package.json",
            "ecosystem": "npm",
            "packages": [
                {"name": "request", "version": "2.88.2"},
                {"name": "tough-cookie", "version": "2.5.0"},
            ],
        }
    ]
    devin = FakeDevinClient()
    boundaries = Boundaries(
        osv=FakeOsvClient(vulns),
        github=FakeGitHubClient(owner="cdugo", repo="superset"),
        devin=devin,
    )
    orch = Orchestrator(
        boundaries=boundaries,
        store=Store(tmp_path / "tw.sqlite"),
        manifests=manifests,
        playbook_id="pb",
        knowledge_ids=[],
        report_dir=tmp_path,
    )

    orch.run_cycle(cycle_number=1)

    assert len(devin.created_sessions) == 1
    prompt = devin.created_sessions[0]["prompt"]
    assert "api-gateway/package.json" in prompt
    assert "request" in prompt
    assert "tough-cookie" in prompt
    assert "GHSA-p8p7-x288-28g6" in prompt
    assert "GHSA-72xf-g2v4-qvf3" in prompt
