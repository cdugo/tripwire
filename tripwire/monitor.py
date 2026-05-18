"""Signal-first session monitor.

Read-only. The Monitor *records*, Devin (Autofix) *acts*. There is no
'no-progress' rule — judging whether a fix is still progressing belongs to
Devin, not us. The wall-clock cap is a liveness backstop only.

Observed Devin behavior:
  - `status` stays at "running" for the lifetime of a session; the API does
    not transition it to a "done" value on its own.
  - The real "Devin is idle / done working" signal is `status_detail` ==
    "waiting_for_user". Paired with a populated `pull_requests`, that's a
    completed remediation. Paired with no PR, it means Devin asked a
    clarifying question instead of opening one — escalate.
  - A "Terminal status: COMPLETE/BLOCKED" message-body marker is kept as a
    text-marker fallback in case a playbook emits one.
"""

from __future__ import annotations

from typing import Iterable, Literal

Verdict = Literal["in_flight", "resolved", "needs_human", "timed_out"]


def parse_terminal_status(messages: Iterable[dict]) -> str | None:
    """Find the last source:'devin' message and extract terminal status."""
    for msg in reversed(list(messages or [])):
        if msg.get("source") != "devin":
            continue
        body = msg.get("body", "") or ""
        if "Terminal status: COMPLETE" in body:
            return "COMPLETE"
        if "Terminal status: BLOCKED" in body:
            return "BLOCKED"
        return None  # last devin message had no terminal marker
    return None


class Monitor:
    def __init__(self, *, wall_clock_cap_seconds: float = 3600.0) -> None:
        self._cap = wall_clock_cap_seconds

    def assess(self, *, session: dict, age_seconds: float = 0.0) -> Verdict:
        terminal = session.get("terminal_status")
        if terminal is None:
            terminal = parse_terminal_status(session.get("messages") or [])
        terminal = (terminal or "").upper() or None

        status = (session.get("status") or "").lower()
        status_detail = (session.get("status_detail") or "").lower()
        pr_url = session.get("pr_url")

        # 1. Optional text-marker fallback (kept for playbooks that emit it).
        if terminal == "COMPLETE" and pr_url:
            return "resolved"
        if terminal == "BLOCKED":
            return "needs_human"

        # 2. Hard-error statuses from the API.
        if status in {"suspended", "error"}:
            return "needs_human"

        # 3. The canonical Devin "done" signal: status_detail says the agent
        #    is idle. A PR means success; no PR means it asked a question.
        if status_detail == "waiting_for_user":
            return "resolved" if pr_url else "needs_human"

        # 4. Liveness backstop.
        if age_seconds > self._cap:
            return "timed_out"

        # 5. Still working.
        return "in_flight"
