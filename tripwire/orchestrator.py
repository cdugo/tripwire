"""Single-brain orchestrator.

Walks one poll cycle:
    detect → group-by-manifest → fan-out → reconcile → report

Per-manifest fan-out (one Devin session per manifest, not per finding); the
GitHub issue is an audit sink, fired in parallel with the session and never
on the trigger path. The Monitor is read-only — it records terminal signal
but never re-prompts a session; Devin (Autofix) owns the fix loop.
"""

from __future__ import annotations

from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from tripwire.boundaries import Boundaries
from tripwire.findings import Finding
from tripwire.monitor import Monitor
from tripwire.prompts import build_session_prompt
from tripwire.report import render_report
from tripwire.store import Store
from tripwire.triggers.osv import OsvPoller


@dataclass
class CycleResult:
    cycle_number: int
    new_findings: int = 0
    new_issues: int = 0
    new_sessions: int = 0
    failed_issues: int = 0
    failed_sessions: int = 0
    resolved_manifests: list[str] = field(default_factory=list)
    escalated_manifests: list[str] = field(default_factory=list)
    report_path: Path | None = None


class Orchestrator:
    def __init__(
        self,
        *,
        boundaries: Boundaries,
        store: Store,
        manifests: Iterable[dict],
        playbook_id: str,
        knowledge_ids: list[str],
        report_dir: Path,
        base_branch: str = "master",
        max_parallel_manifests: int = 4,
        wall_clock_cap_seconds: float = 3600.0,
    ) -> None:
        self._b = boundaries
        self._store = store
        self._manifests = list(manifests)
        self._playbook_id = playbook_id
        self._knowledge_ids = list(knowledge_ids)
        self._report_dir = Path(report_dir)
        self._base_branch = base_branch
        self._max_parallel = max(1, max_parallel_manifests)
        self._monitor = Monitor(wall_clock_cap_seconds=wall_clock_cap_seconds)

    def run_cycle(self, *, cycle_number: int = 1) -> CycleResult:
        result = CycleResult(cycle_number=cycle_number)

        before = {f.fingerprint for f in self._store.list_findings()}

        # 1. Detect — OSV poll, normalize, persist.
        poller = OsvPoller(client=self._b.osv, manifests=self._manifests)
        current_findings = poller.poll()
        self._store.upsert_findings(current_findings)

        after = {f.fingerprint for f in self._store.list_findings()}
        result.new_findings = len(after - before)

        # 2. Group findings by manifest (the fan-out unit).
        by_manifest: dict[str, list[Finding]] = defaultdict(list)
        for f in current_findings:
            by_manifest[f.manifest_path].append(f)

        # 3. For each affected manifest still in 'detected', file issue +
        #    create session. Per-manifest pipelines run in parallel under
        #    a bounded worker pool.
        todo = [
            (path, findings)
            for path, findings in by_manifest.items()
            if self._store.manifest_state(path) == "detected"
        ]
        with ThreadPoolExecutor(max_workers=self._max_parallel) as pool:
            futures = [
                pool.submit(self._process_manifest, path, findings, result)
                for path, findings in todo
            ]
            for fut in futures:
                fut.result()  # surface unexpected exceptions

        # 4. Reconcile in-flight sessions from prior cycles. The Monitor was
        #    formerly called only inline at session-creation time with
        #    age_seconds=0, so a live session that took longer than one
        #    cycle would be abandoned at `session_started` and the wall-clock
        #    cap could never fire. This pass closes that gap.
        self._reconcile_in_flight(result)

        # 5. Render report.
        result.report_path = render_report(
            self._store, out_dir=self._report_dir, cycle_number=cycle_number
        )
        return result

    def _reconcile_in_flight(self, result: CycleResult) -> None:
        """Re-poll every in_flight manifest, advance state on terminal signal."""
        for path, session_id in self._store.in_flight_manifests():
            self._reconcile_manifest(path, session_id, result)

    # -- per-manifest pipeline -----------------------------------------------

    def _process_manifest(
        self, manifest_path: str, findings: list[Finding], result: CycleResult
    ) -> None:
        # Fire issue + session in parallel. The issue is an audit sink — if
        # it fails, the session still goes; if the session fails, the issue
        # still gets filed so a human can pick up.
        with ThreadPoolExecutor(max_workers=2) as pool:
            issue_fut = pool.submit(self._file_issue, manifest_path, findings)
            session_fut = pool.submit(self._create_session, manifest_path, findings)

            issue_err = issue_fut.exception()
            session_err = session_fut.exception()

        if issue_err is None:
            result.new_issues += 1
        else:
            result.failed_issues += 1

        if session_err is None:
            session_id = session_fut.result()
            result.new_sessions += 1
            self._store.start_session(manifest_path, session_id)
            # No inline reconcile — `run_cycle` calls _reconcile_in_flight()
            # at end of cycle, which assesses this session (and every other
            # in-flight session from prior cycles) through the same code
            # path with the real session age.
        else:
            result.failed_sessions += 1
            # No session = no remediation in flight = escalate.
            self._store.advance_manifest(manifest_path, "needs_human")
            result.escalated_manifests.append(manifest_path)

    def _file_issue(self, manifest_path: str, findings: list[Finding]) -> str:
        title = f"Tripwire: {len(findings)} supply-chain finding(s) in {manifest_path}"
        body = self._issue_body(manifest_path, findings)
        labels = sorted({"tripwire", "security"} | {f"severity:{f.severity}" for f in findings})
        return self._b.github.create_issue(title=title, body=body, labels=labels)

    def _create_session(self, manifest_path: str, findings: list[Finding]) -> str:
        prompt = build_session_prompt(
            manifest_path=manifest_path,
            base_branch=self._base_branch,
            findings=findings,
        )
        return self._b.devin.create_session(
            playbook_id=self._playbook_id,
            knowledge_ids=self._knowledge_ids,
            prompt=prompt,
        )

    def _reconcile_manifest(
        self, manifest_path: str, session_id: str, result: CycleResult
    ) -> None:
        """Re-poll a session, refresh ACUs, advance state per Monitor verdict.

        Called once per cycle for every in_flight manifest. The Monitor
        verdict + the Store's own clock give the wall-clock cap real teeth.
        """
        session = self._b.devin.get_session(session_id)
        self._store.record_acu_usage(
            manifest_path, float(session.get("acu_usage") or 0.0)
        )
        if session.get("pr_url"):
            self._store.record_pr_opened(manifest_path)

        age = self._store.session_age_seconds(manifest_path)
        verdict = self._monitor.assess(session=session, age_seconds=age)

        if verdict == "resolved":
            self._store.advance_manifest(manifest_path, "resolved")
            result.resolved_manifests.append(manifest_path)
        elif verdict == "needs_human":
            self._store.advance_manifest(manifest_path, "needs_human")
            result.escalated_manifests.append(manifest_path)
        elif verdict == "timed_out":
            self._store.advance_manifest(manifest_path, "timed_out")
            result.escalated_manifests.append(manifest_path)
        # in_flight: leave state; next cycle re-polls.

    @staticmethod
    def _issue_body(manifest_path: str, findings: list[Finding]) -> str:
        lines = [f"Tripwire detected supply-chain advisories in `{manifest_path}`.", ""]
        for f in findings:
            lines.append(
                f"- **{f.package}** ({f.ecosystem}) {f.installed_version} — "
                f"{', '.join(f.advisory_ids)} ({f.severity})"
            )
        lines.append("")
        lines.append("This issue is an audit record. The remediation PR is filed by Devin.")
        return "\n".join(lines)
