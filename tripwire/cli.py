"""Tripwire CLI.

Two subcommands:
  demo   — offline dry-run against fakes; what a reviewer runs.
  live   — real OSV / GitHub / Devin against the Superset fork.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from tripwire.boundaries import Boundaries, live_boundaries
from tripwire.boundaries.devin import FakeDevinClient
from tripwire.boundaries.github import FakeGitHubClient
from tripwire.boundaries.osv import FakeOsvClient
from tripwire.demo_fixtures import DEMO_MANIFESTS, DEMO_OSV_VULNS
from tripwire.live_config import LIVE_MANIFESTS, MissingEnvError, read_env
from tripwire.orchestrator import Orchestrator
from tripwire.store import Store


def _cmd_demo(args: argparse.Namespace) -> int:
    boundaries = Boundaries(
        osv=FakeOsvClient(DEMO_OSV_VULNS),
        github=FakeGitHubClient(owner="cdugo", repo="superset"),
        devin=FakeDevinClient(),
    )
    store = Store(args.state_db)
    orch = Orchestrator(
        boundaries=boundaries,
        store=store,
        manifests=DEMO_MANIFESTS,
        playbook_id="pb-demo",
        knowledge_ids=["kn-demo"],
        report_dir=args.report_dir,
    )
    result = orch.run_cycle(cycle_number=args.cycle)
    print(f"cycle: {result.cycle_number}")
    print(f"new findings: {result.new_findings}")
    print(f"new issues:   {result.new_issues}")
    print(f"new sessions: {result.new_sessions}")
    print(f"resolved:     {len(result.resolved_manifests)} manifest(s)")
    print(f"escalated:    {len(result.escalated_manifests)} manifest(s)")
    print(f"report:       {result.report_path}")
    return 0


def _cmd_live(args: argparse.Namespace) -> int:
    try:
        env = read_env()
    except MissingEnvError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    knowledge_ids = [k.strip() for k in env["DEVIN_KNOWLEDGE_IDS"].split(",") if k.strip()]
    boundaries = live_boundaries(env)
    store = Store(args.state_db)
    orch = Orchestrator(
        boundaries=boundaries,
        store=store,
        manifests=LIVE_MANIFESTS,
        playbook_id=env["DEVIN_PLAYBOOK_ID"],
        knowledge_ids=knowledge_ids,
        report_dir=args.report_dir,
        base_branch=env["GITHUB_BASE_BRANCH"],
        wall_clock_cap_seconds=args.wall_clock_cap_seconds,
    )
    result = orch.run_cycle(cycle_number=args.cycle)
    print(f"cycle: {result.cycle_number}")
    print(f"new findings: {result.new_findings}")
    print(f"new issues:   {result.new_issues}")
    print(f"new sessions: {result.new_sessions}")
    print(f"resolved:     {len(result.resolved_manifests)} manifest(s)")
    print(f"escalated:    {len(result.escalated_manifests)} manifest(s)")
    print(f"report:       {result.report_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tripwire")
    sub = p.add_subparsers(dest="cmd", required=True)

    # Defaults honour TRIPWIRE_REPORT_DIR / TRIPWIRE_STATE_DB if set so the
    # docker entrypoint (which exports both to /data/...) Just Works without
    # the caller having to re-pass them after `docker compose run`.
    default_report_dir = Path(os.environ.get("TRIPWIRE_REPORT_DIR", "./reports"))
    default_state_db = Path(os.environ.get("TRIPWIRE_STATE_DB", "./tripwire.sqlite"))

    demo = sub.add_parser("demo", help="offline dry-run against fakes")
    demo.add_argument("--report-dir", type=Path, default=default_report_dir)
    demo.add_argument("--state-db", type=Path, default=default_state_db)
    demo.add_argument("--cycle", type=int, default=1)
    demo.set_defaults(func=_cmd_demo)

    live = sub.add_parser("live", help="real pipeline against the fork")
    live.add_argument("--report-dir", type=Path, default=default_report_dir)
    live.add_argument("--state-db", type=Path, default=default_state_db)
    live.add_argument("--cycle", type=int, default=1)
    live.add_argument("--wall-clock-cap-seconds", type=float, default=3600.0)
    live.set_defaults(func=_cmd_live)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
