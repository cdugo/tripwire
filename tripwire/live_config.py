"""Live-mode configuration: env vars + manifest slate.

The manifest list mirrors the fixtures committed to the Superset fork's
`tripwire/demo` branch. Versions here must stay in sync with what's
actually pinned on the fork, or OSV will return zero hits.
"""

from __future__ import annotations

import os

LIVE_REQUIRED_ENV = (
    "DEVIN_API_KEY",
    "DEVIN_ORG_ID",
    "DEVIN_PLAYBOOK_ID",
    "DEVIN_KNOWLEDGE_IDS",  # comma-separated
    "GITHUB_PAT",
    "GITHUB_OWNER",
    "GITHUB_REPO",
)


class MissingEnvError(RuntimeError):
    def __init__(self, missing: list[str]) -> None:
        super().__init__(
            "live mode requires these environment variables: " + ", ".join(missing)
        )
        self.missing = list(missing)


def read_env(env: dict[str, str] | None = None) -> dict[str, str]:
    env = env if env is not None else dict(os.environ)
    missing = [k for k in LIVE_REQUIRED_ENV if not env.get(k)]
    if missing:
        raise MissingEnvError(missing)
    return {k: env[k] for k in LIVE_REQUIRED_ENV} | {
        "GITHUB_BASE_BRANCH": env.get("GITHUB_BASE_BRANCH", "master"),
    }


# The pins that the fork's tripwire/demo branch carries.
LIVE_MANIFESTS = [
    {
        "path": "fixtures/tripwire/web-dashboard/package.json",
        "ecosystem": "npm",
        "packages": [{"name": "marked", "version": "4.0.0"}],
    },
    {
        "path": "fixtures/tripwire/api-gateway/package.json",
        "ecosystem": "npm",
        "packages": [
            {"name": "request", "version": "2.88.2"},
            {"name": "tough-cookie", "version": "2.5.0"},
        ],
    },
    {
        "path": "fixtures/tripwire/etl-worker/requirements.txt",
        "ecosystem": "PyPI",
        "packages": [{"name": "Jinja2", "version": "2.10"}],
    },
    {
        "path": "fixtures/tripwire/report-api/requirements.txt",
        "ecosystem": "PyPI",
        "packages": [
            {"name": "Werkzeug", "version": "2.0.3"},
            {"name": "Flask", "version": "2.0.3"},
        ],
    },
]
