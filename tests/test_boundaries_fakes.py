"""Tests for the boundary fakes.

Every external boundary (Devin, GitHub, OSV) sits behind an interface with
a real and a fake implementation. Demo mode uses ONLY fakes — never
accidentally falls back to a real client.
"""

import pytest

from tripwire.boundaries import Boundaries, demo_boundaries
from tripwire.boundaries.devin import DevinClient, FakeDevinClient
from tripwire.boundaries.github import FakeGitHubClient, GitHubClient
from tripwire.boundaries.osv import FakeOsvClient, OsvClient


# ---- protocol conformance ---------------------------------------------------


def test_fake_devin_client_implements_protocol():
    assert isinstance(FakeDevinClient(), DevinClient)


def test_fake_github_client_implements_protocol():
    assert isinstance(FakeGitHubClient(), GitHubClient)


def test_fake_osv_client_implements_protocol():
    assert isinstance(FakeOsvClient({}), OsvClient)


# ---- fake behavior ----------------------------------------------------------


def test_fake_devin_session_is_deterministic_and_terminal():
    fake = FakeDevinClient()
    session_id = fake.create_session(
        playbook_id="pb-1",
        knowledge_ids=["kn-1"],
        prompt="remediate api-gateway",
    )
    # Same prompt → same id, every run.
    assert session_id == fake.create_session(
        playbook_id="pb-1", knowledge_ids=["kn-1"], prompt="remediate api-gateway"
    )

    status = fake.get_session(session_id)
    assert status["terminal_status"] == "COMPLETE"
    assert status["pr_url"].startswith("https://github.com/")


def test_fake_devin_records_creates_for_inspection():
    fake = FakeDevinClient()
    fake.create_session(playbook_id="pb", knowledge_ids=[], prompt="a")
    fake.create_session(playbook_id="pb", knowledge_ids=[], prompt="b")
    assert len(fake.created_sessions) == 2


def test_fake_github_creates_issue_with_stable_url():
    fake = FakeGitHubClient(owner="cdugo", repo="superset")
    url = fake.create_issue(
        title="Tripwire: api-gateway findings", body="...", labels=["security"]
    )
    assert url.startswith("https://github.com/cdugo/superset/issues/")
    assert len(fake.created_issues) == 1


def test_fake_osv_returns_configured_vulns():
    vulns = {
        ("npm", "request", "2.88.2"): [{"id": "GHSA-p8p7-x288-28g6"}],
    }
    fake = FakeOsvClient(vulns)
    result = fake.query_batch(
        [{"package": {"ecosystem": "npm", "name": "request"}, "version": "2.88.2"}]
    )
    assert result == [[{"id": "GHSA-p8p7-x288-28g6"}]]


# ---- demo bundle ------------------------------------------------------------


def test_demo_boundaries_uses_only_fakes():
    bundle = demo_boundaries()
    assert isinstance(bundle, Boundaries)
    assert isinstance(bundle.devin, FakeDevinClient)
    assert isinstance(bundle.github, FakeGitHubClient)
    assert isinstance(bundle.osv, FakeOsvClient)


def test_demo_boundaries_rejects_credentials_in_env(monkeypatch):
    """Defense-in-depth: demo mode must not silently upgrade to real
    clients even if .env happens to be populated."""
    monkeypatch.setenv("DEVIN_API_KEY", "leaked-key")
    monkeypatch.setenv("GITHUB_PAT", "leaked-pat")

    bundle = demo_boundaries()

    assert isinstance(bundle.devin, FakeDevinClient)
    assert isinstance(bundle.github, FakeGitHubClient)
