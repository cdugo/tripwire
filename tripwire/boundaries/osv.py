"""OSV.dev boundary.

Protocol + real /v1/querybatch httpx client + deterministic fake.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

import httpx


@runtime_checkable
class OsvClient(Protocol):
    def query_batch(self, queries: list[dict]) -> list[list[dict]]:
        ...


class RealOsvClient:
    """OSV.dev /v1/querybatch — one POST regardless of query count."""

    def __init__(
        self,
        *,
        base_url: str = "https://api.osv.dev",
        http_client: httpx.Client | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._http = http_client or httpx.Client(base_url=base_url, timeout=timeout)

    def query_batch(self, queries: list[dict]) -> list[list[dict]]:
        if not queries:
            return []
        resp = self._http.post("/v1/querybatch", json={"queries": queries})
        resp.raise_for_status()
        results = resp.json().get("results", [])
        return [(r or {}).get("vulns") or [] for r in results]


class FakeOsvClient:
    """Looks up canned vuln lists by (ecosystem, name, version)."""

    def __init__(self, vulns_by_pkg: dict | None = None) -> None:
        self._vulns = dict(vulns_by_pkg or {})
        self.calls = 0

    def query_batch(self, queries: list[dict]) -> list[list[dict]]:
        self.calls += 1
        return [
            self._vulns.get(
                (q["package"]["ecosystem"], q["package"]["name"], q["version"]),
                [],
            )
            for q in queries
        ]
