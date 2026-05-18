"""Tests for the OSV trigger source.

TriggerSource is an interface; OSV poller is one implementation. Poll is
deterministic so the orchestrator's diff against prior state is zero on
unchanged inputs.
"""

from tripwire.boundaries.osv import FakeOsvClient
from tripwire.triggers import TriggerSource
from tripwire.triggers.osv import OsvPoller


_MANIFEST_API_GATEWAY = {
    "path": "api-gateway/package.json",
    "ecosystem": "npm",
    "packages": [
        {"name": "request", "version": "2.88.2"},
        {"name": "tough-cookie", "version": "2.5.0"},
        {"name": "express", "version": "4.18.2"},  # clean in fixture
    ],
}

_FIXTURE_VULNS = {
    ("npm", "request", "2.88.2"): [
        {
            "id": "GHSA-p8p7-x288-28g6",
            "affected": [{"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}],
            "database_specific": {"severity": "MODERATE"},
        }
    ],
    ("npm", "tough-cookie", "2.5.0"): [
        {
            "id": "GHSA-72xf-g2v4-qvf3",
            "affected": [{"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.1.3"}]}]}],
            "database_specific": {"severity": "MODERATE"},
        }
    ],
}


def test_osv_poller_implements_trigger_source_interface():
    poller = OsvPoller(client=FakeOsvClient({}), manifests=[])
    assert isinstance(poller, TriggerSource)


def test_osv_poller_emits_one_finding_per_vulnerable_package():
    poller = OsvPoller(
        client=FakeOsvClient(_FIXTURE_VULNS),
        manifests=[_MANIFEST_API_GATEWAY],
    )

    findings = poller.poll()

    fingerprints = {f.fingerprint for f in findings}
    assert fingerprints == {
        ("api-gateway/package.json", "npm", "request"),
        ("api-gateway/package.json", "npm", "tough-cookie"),
    }


def test_osv_poller_attaches_all_advisory_ids_for_a_package():
    vulns = {
        ("npm", "request", "2.88.2"): [
            {"id": "GHSA-p8p7-x288-28g6", "database_specific": {"severity": "MODERATE"}},
            {"id": "GHSA-xxxx-yyyy-zzzz", "database_specific": {"severity": "HIGH"}},
        ],
    }
    poller = OsvPoller(
        client=FakeOsvClient(vulns),
        manifests=[
            {
                "path": "api-gateway/package.json",
                "ecosystem": "npm",
                "packages": [{"name": "request", "version": "2.88.2"}],
            }
        ],
    )

    findings = poller.poll()

    assert len(findings) == 1
    assert findings[0].advisory_ids == ["GHSA-p8p7-x288-28g6", "GHSA-xxxx-yyyy-zzzz"]
    assert findings[0].severity.lower() == "high"


def test_osv_poller_second_poll_against_unchanged_state_is_identical():
    client = FakeOsvClient(_FIXTURE_VULNS)
    poller = OsvPoller(client=client, manifests=[_MANIFEST_API_GATEWAY])

    first = poller.poll()
    second = poller.poll()

    # Idempotency: the orchestrator's diff against prior state must be empty.
    assert first == second
    assert client.calls == 2  # the poller didn't silently cache
