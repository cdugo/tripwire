"""Canned fixture data for `tripwire demo`.

Four manifest scenarios with realistic-looking companion packages and
OSV-style vuln payloads. Demo mode uses these via FakeOsvClient — no
network, no credentials, deterministic.
"""

from __future__ import annotations

DEMO_MANIFESTS = [
    {
        "path": "web-dashboard/package.json",
        "ecosystem": "npm",
        "packages": [
            {"name": "marked", "version": "0.7.0"},
            {"name": "react", "version": "18.2.0"},
            {"name": "lodash", "version": "4.17.21"},
        ],
    },
    {
        "path": "api-gateway/package.json",
        "ecosystem": "npm",
        "packages": [
            {"name": "request", "version": "2.88.2"},
            {"name": "tough-cookie", "version": "2.5.0"},
            {"name": "express", "version": "4.19.2"},
        ],
    },
    {
        "path": "etl-worker/requirements.txt",
        "ecosystem": "PyPI",
        "packages": [
            {"name": "Jinja2", "version": "2.10"},
            {"name": "requests", "version": "2.32.0"},
        ],
    },
    {
        "path": "report-api/requirements.txt",
        "ecosystem": "PyPI",
        "packages": [
            {"name": "Werkzeug", "version": "2.0.3"},
            {"name": "Flask", "version": "2.0.3"},
        ],
    },
]


DEMO_OSV_VULNS = {
    ("npm", "marked", "0.7.0"): [
        {
            "id": "GHSA-rrrm-qjm4-v8hf",
            "affected": [{"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.0.10"}]}]}],
            "database_specific": {"severity": "HIGH"},
        },
        {
            "id": "GHSA-vwqq-5j12-x2ms",
            "affected": [{"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.0.10"}]}]}],
            "database_specific": {"severity": "MODERATE"},
        },
    ],
    ("npm", "request", "2.88.2"): [
        {
            "id": "GHSA-p8p7-x288-28g6",
            "affected": [{"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}],
            "database_specific": {"severity": "MODERATE"},
        },
    ],
    ("npm", "tough-cookie", "2.5.0"): [
        {
            "id": "GHSA-72xf-g2v4-qvf3",
            "affected": [{"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.1.3"}]}]}],
            "database_specific": {"severity": "MODERATE"},
        },
    ],
    ("PyPI", "Jinja2", "2.10"): [
        {
            "id": "GHSA-462w-v97r-4m45",
            "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.10.1"}]}]}],
            "database_specific": {"severity": "CRITICAL"},
        },
        {
            "id": "GHSA-h5c8-rqwp-cp95",
            "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.11.3"}]}]}],
            "database_specific": {"severity": "HIGH"},
        },
    ],
    ("PyPI", "Werkzeug", "2.0.3"): [
        {
            "id": "CVE-2023-23934",
            "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.2.3"}]}]}],
            "database_specific": {"severity": "MODERATE"},
        },
        {
            "id": "CVE-2023-25577",
            "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.2.3"}]}]}],
            "database_specific": {"severity": "HIGH"},
        },
    ],
    ("PyPI", "Flask", "2.0.3"): [
        {
            "id": "CVE-2023-30861",
            "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.2.5"}]}]}],
            "database_specific": {"severity": "HIGH"},
        },
    ],
}
