"""GitHub REST API boundary.

Protocol + real httpx-backed client + deterministic fake. Issues are an
audit sink, never a trigger.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

import httpx


@runtime_checkable
class GitHubClient(Protocol):
    def create_issue(self, *, title: str, body: str, labels: list[str]) -> str:
        ...


class RealGitHubClient:
    """POST /repos/{owner}/{repo}/issues via the REST API."""

    def __init__(
        self,
        *,
        owner: str,
        repo: str,
        token: str,
        http_client: httpx.Client | None = None,
        base_url: str = "https://api.github.com",
        timeout: float = 30.0,
    ) -> None:
        self._owner = owner
        self._repo = repo
        self._http = http_client or httpx.Client(base_url=base_url, timeout=timeout)
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def create_issue(self, *, title: str, body: str, labels: list[str]) -> str:
        resp = self._http.post(
            f"/repos/{self._owner}/{self._repo}/issues",
            json={"title": title, "body": body, "labels": list(labels)},
            headers=self._headers,
        )
        resp.raise_for_status()
        return resp.json()["html_url"]


class FakeGitHubClient:
    def __init__(self, *, owner: str = "demo-org", repo: str = "demo-repo") -> None:
        self._owner = owner
        self._repo = repo
        self.created_issues: list[dict] = []

    def create_issue(self, *, title: str, body: str, labels: list[str]) -> str:
        number = len(self.created_issues) + 1
        url = f"https://github.com/{self._owner}/{self._repo}/issues/{number}"
        self.created_issues.append(
            {"number": number, "title": title, "body": body, "labels": list(labels), "url": url}
        )
        return url
