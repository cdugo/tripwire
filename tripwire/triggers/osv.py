"""OSV-backed TriggerSource.

Reads each configured manifest's package list, batch-queries OSV, and
normalizes raw advisory hits into package-level Findings. Multiple
advisories on the same package collapse into one Finding.
"""

from __future__ import annotations

from typing import Iterable

from tripwire.boundaries.osv import OsvClient
from tripwire.findings import Finding, collapse


def _severity_from_vuln(vuln: dict) -> str:
    db = vuln.get("database_specific", {}) or {}
    return str(db.get("severity", "none")).lower()


def _vulnerable_range(vuln: dict) -> str:
    affected = vuln.get("affected") or []
    if not affected:
        return ""
    ranges = (affected[0] or {}).get("ranges") or []
    if not ranges:
        return ""
    events = (ranges[0] or {}).get("events") or []
    parts = []
    for ev in events:
        if "introduced" in ev:
            parts.append(f">={ev['introduced']}")
        if "fixed" in ev:
            parts.append(f"<{ev['fixed']}")
    return ",".join(parts)


class OsvPoller:
    """TriggerSource that walks configured manifests and queries OSV."""

    def __init__(self, client: OsvClient, manifests: Iterable[dict]) -> None:
        self._client = client
        self._manifests = list(manifests)

    def poll(self) -> list[Finding]:
        raw_hits: list[dict] = []
        for manifest in self._manifests:
            ecosystem = manifest["ecosystem"]
            path = manifest["path"]
            packages = manifest.get("packages", [])
            if not packages:
                continue
            queries = [
                {"package": {"ecosystem": ecosystem, "name": p["name"]}, "version": p["version"]}
                for p in packages
            ]
            results = self._client.query_batch(queries)
            for pkg, vulns in zip(packages, results):
                for vuln in vulns or []:
                    raw_hits.append(
                        {
                            "manifest_path": path,
                            "ecosystem": ecosystem,
                            "package": pkg["name"],
                            "installed_version": pkg["version"],
                            "advisory_id": vuln["id"],
                            "vulnerable_range": _vulnerable_range(vuln),
                            "severity": _severity_from_vuln(vuln),
                        }
                    )
        return collapse(raw_hits)
