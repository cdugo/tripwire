#!/usr/bin/env python3
"""Single-manifest smoke test: identical wiring to `tripwire live` but
restricted to the cheapest manifest (web-dashboard / marked@0.7.0).

Use this before the full-slate recording run to confirm the live wiring
end-to-end with minimal ACU burn: 1 finding -> 1 issue -> 1 Devin session.
"""

from __future__ import annotations

import sys
from pathlib import Path

from tripwire.boundaries import live_boundaries
from tripwire.live_config import LIVE_MANIFESTS, MissingEnvError, read_env
from tripwire.orchestrator import Orchestrator
from tripwire.store import Store

SMOKE_PATH = "fixtures/tripwire/web-dashboard/package.json"


def main() -> int:
    try:
        env = read_env()
    except MissingEnvError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    manifests = [m for m in LIVE_MANIFESTS if m["path"] == SMOKE_PATH]
    if not manifests:
        print(f"error: {SMOKE_PATH} not in LIVE_MANIFESTS", file=sys.stderr)
        return 2

    knowledge_ids = [k.strip() for k in env["DEVIN_KNOWLEDGE_IDS"].split(",") if k.strip()]
    boundaries = live_boundaries(env)
    store = Store(Path("./tripwire-smoke.sqlite"))
    orch = Orchestrator(
        boundaries=boundaries,
        store=store,
        manifests=manifests,
        playbook_id=env["DEVIN_PLAYBOOK_ID"],
        knowledge_ids=knowledge_ids,
        report_dir=Path("./reports-smoke"),
        base_branch=env["GITHUB_BASE_BRANCH"],
        wall_clock_cap_seconds=1200.0,
    )
    print(f"smoke: 1 manifest ({SMOKE_PATH}) on {env['GITHUB_OWNER']}/{env['GITHUB_REPO']}")
    result = orch.run_cycle(cycle_number=1)
    print(f"cycle: {result.cycle_number}")
    print(f"new findings: {result.new_findings}")
    print(f"new issues:   {result.new_issues}")
    print(f"new sessions: {result.new_sessions}")
    print(f"resolved:     {len(result.resolved_manifests)} manifest(s)")
    print(f"escalated:    {len(result.escalated_manifests)} manifest(s)")
    print(f"report:       {result.report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
