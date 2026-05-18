"""External-system boundaries.

Every boundary (Devin, GitHub, OSV) has a Protocol contract, a real
httpx-backed client, and a deterministic fake. The orchestrator takes a
`Boundaries` bundle, never raw clients, so demo/live wiring is one seam.
"""

from __future__ import annotations

from dataclasses import dataclass

from tripwire.boundaries.devin import DevinClient, FakeDevinClient, RealDevinClient
from tripwire.boundaries.github import FakeGitHubClient, GitHubClient, RealGitHubClient
from tripwire.boundaries.osv import FakeOsvClient, OsvClient, RealOsvClient

__all__ = [
    "Boundaries",
    "demo_boundaries",
    "live_boundaries",
    "DevinClient",
    "GitHubClient",
    "OsvClient",
    "FakeDevinClient",
    "FakeGitHubClient",
    "FakeOsvClient",
    "RealDevinClient",
    "RealGitHubClient",
    "RealOsvClient",
]


@dataclass(frozen=True)
class Boundaries:
    osv: OsvClient
    github: GitHubClient
    devin: DevinClient


def demo_boundaries(*, osv_vulns: dict | None = None) -> Boundaries:
    """Dry-run bundle: only fakes, even if real credentials are in the env."""
    return Boundaries(
        osv=FakeOsvClient(osv_vulns or {}),
        github=FakeGitHubClient(owner="demo-org", repo="demo-repo"),
        devin=FakeDevinClient(),
    )


def live_boundaries(env: dict) -> Boundaries:
    """Real-API bundle. Caller is responsible for validating `env` first."""
    return Boundaries(
        osv=RealOsvClient(),
        github=RealGitHubClient(
            owner=env["GITHUB_OWNER"], repo=env["GITHUB_REPO"], token=env["GITHUB_PAT"]
        ),
        devin=RealDevinClient(org_id=env["DEVIN_ORG_ID"], token=env["DEVIN_API_KEY"]),
    )
