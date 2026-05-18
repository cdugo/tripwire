"""Tests for the package-level Finding model.

Fingerprint is (manifest, ecosystem, package), not advisory-level. A
package with N advisories is ONE finding with N advisory IDs, not N
findings — keeps re-polling idempotent.
"""

from tripwire.findings import Finding, collapse


def test_two_advisories_on_one_package_collapse_into_one_finding():
    raw_hits = [
        {
            "manifest_path": "api-gateway/package.json",
            "ecosystem": "npm",
            "package": "request",
            "installed_version": "2.88.2",
            "advisory_id": "GHSA-p8p7-x288-28g6",
            "vulnerable_range": ">=0",
            "severity": "moderate",
        },
        {
            "manifest_path": "api-gateway/package.json",
            "ecosystem": "npm",
            "package": "request",
            "installed_version": "2.88.2",
            "advisory_id": "GHSA-aaaa-bbbb-cccc",
            "vulnerable_range": "<3.0.0",
            "severity": "high",
        },
    ]

    findings = collapse(raw_hits)

    assert len(findings) == 1
    finding = findings[0]
    assert isinstance(finding, Finding)
    assert finding.manifest_path == "api-gateway/package.json"
    assert finding.ecosystem == "npm"
    assert finding.package == "request"
    assert finding.installed_version == "2.88.2"
    assert finding.advisory_ids == ["GHSA-p8p7-x288-28g6", "GHSA-aaaa-bbbb-cccc"]
    # Two vulnerable ranges, one per advisory, preserved in input order.
    assert finding.vulnerable_ranges == [">=0", "<3.0.0"]
    # Severity escalates to the worst across collapsed advisories.
    assert finding.severity == "high"


def test_fingerprint_is_manifest_ecosystem_package():
    finding = Finding(
        manifest_path="api-gateway/package.json",
        ecosystem="npm",
        package="request",
        installed_version="2.88.2",
        advisory_ids=["GHSA-p8p7-x288-28g6"],
        vulnerable_ranges=[">=0"],
        severity="moderate",
    )
    assert finding.fingerprint == ("api-gateway/package.json", "npm", "request")
