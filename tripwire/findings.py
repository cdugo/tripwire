"""Package-level Finding model and advisory-hit collapser.

A Finding represents one vulnerable package in one manifest. Multiple
advisories on the same package collapse into one Finding with an advisory-ID
list — the fingerprint is (manifest, ecosystem, package), so re-polling is
idempotent regardless of how many advisories appear against a single pin.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Mapping

# Lowest → highest. Used to escalate severity when multiple advisories collapse
# onto the same package. "medium" (npm-audit term) normalizes to "moderate".
_SEVERITY_ORDER = ("none", "low", "moderate", "high", "critical")


def _severity_rank(sev: str) -> int:
    s = (sev or "none").lower()
    if s == "medium":
        s = "moderate"
    try:
        return _SEVERITY_ORDER.index(s)
    except ValueError:
        return 0


@dataclass(frozen=True)
class Finding:
    manifest_path: str
    ecosystem: str
    package: str
    installed_version: str
    advisory_ids: list[str] = field(default_factory=list)
    vulnerable_ranges: list[str] = field(default_factory=list)
    severity: str = "none"

    @property
    def fingerprint(self) -> tuple[str, str, str]:
        return (self.manifest_path, self.ecosystem, self.package)


def collapse(raw_hits: Iterable[Mapping[str, str]]) -> list[Finding]:
    """Group advisory-level hits into package-level Findings.

    Stable in insertion order: the first time a (manifest, ecosystem, package)
    is seen sets that finding's position in the returned list.
    """
    by_key: dict[tuple[str, str, str], dict] = {}
    order: list[tuple[str, str, str]] = []

    for hit in raw_hits:
        key = (hit["manifest_path"], hit["ecosystem"], hit["package"])
        if key not in by_key:
            order.append(key)
            by_key[key] = {
                "installed_version": hit["installed_version"],
                "advisory_ids": [],
                "vulnerable_ranges": [],
                "severity": "none",
            }
        agg = by_key[key]
        agg["advisory_ids"].append(hit["advisory_id"])
        agg["vulnerable_ranges"].append(hit.get("vulnerable_range", ""))
        if _severity_rank(hit.get("severity", "none")) > _severity_rank(agg["severity"]):
            agg["severity"] = hit.get("severity", "none")

    return [
        Finding(
            manifest_path=key[0],
            ecosystem=key[1],
            package=key[2],
            installed_version=by_key[key]["installed_version"],
            advisory_ids=list(by_key[key]["advisory_ids"]),
            vulnerable_ranges=list(by_key[key]["vulnerable_ranges"]),
            severity=by_key[key]["severity"],
        )
        for key in order
    ]
