"""Signal-first session monitor.

Read-only — Devin owns the fix loop (Autofix); the Monitor only records.
Verdict precedence:
  1. terminal_status COMPLETE + PR open → resolved (text-marker fallback)
  2. terminal_status BLOCKED  → needs_human
  3. status in {suspended, error} → needs_human
  4. status_detail == "waiting_for_user":
       PR present → resolved; PR absent → needs_human
  5. wall-clock cap breach  → timed_out (liveness backstop)
  6. anything else → in_flight (NOT 'no_progress' — judging fix progress
     belongs to Devin, not us)

Top-level `status` stays "running" for the session's lifetime; the real
"done" signal is `status_detail == "waiting_for_user"`. The "Terminal
status: COMPLETE/BLOCKED" text-marker logic is retained as a fallback in
case a playbook ever posts one.
"""

from tripwire.monitor import Monitor, parse_terminal_status


# ---- last-message parsing (text-marker fallback) ---------------------------


def test_parse_terminal_status_finds_complete_in_last_devin_message():
    messages = [
        {"source": "devin", "body": "starting work"},
        {"source": "user", "body": "thanks"},
        {"source": "devin", "body": "Done. Terminal status: COMPLETE\nPR opened at ..."},
    ]
    assert parse_terminal_status(messages) == "COMPLETE"


def test_parse_terminal_status_finds_blocked():
    messages = [
        {"source": "devin", "body": "encountered issue\nTerminal status: BLOCKED"},
    ]
    assert parse_terminal_status(messages) == "BLOCKED"


def test_parse_terminal_status_only_inspects_devin_authored_messages():
    messages = [
        {"source": "devin", "body": "working"},
        {"source": "user", "body": "Terminal status: COMPLETE"},  # user fakes it
    ]
    assert parse_terminal_status(messages) is None


def test_parse_terminal_status_returns_none_when_absent():
    assert parse_terminal_status([]) is None
    assert parse_terminal_status([{"source": "devin", "body": "working"}]) is None


# ---- Monitor verdict --------------------------------------------------------


def _session(**overrides) -> dict:
    base = {
        "id": "sess-1",
        "status": "running",
        "terminal_status": None,
        "pr_url": None,
        "messages": [],
    }
    base.update(overrides)
    return base


def test_resolved_when_terminal_complete_and_pr_open():
    m = Monitor(wall_clock_cap_seconds=3600)
    s = _session(terminal_status="COMPLETE", pr_url="https://github.com/x/y/pull/1")
    assert m.assess(session=s, age_seconds=120) == "resolved"


def test_needs_human_when_terminal_blocked():
    m = Monitor(wall_clock_cap_seconds=3600)
    assert m.assess(session=_session(terminal_status="BLOCKED"), age_seconds=300) == "needs_human"


def test_needs_human_when_status_suspended_or_error():
    m = Monitor(wall_clock_cap_seconds=3600)
    assert m.assess(session=_session(status="suspended"), age_seconds=10) == "needs_human"
    assert m.assess(session=_session(status="error"), age_seconds=10) == "needs_human"


def test_status_detail_waiting_for_user_with_pr_is_resolved():
    """The real Devin happy path: top-level status stays 'running' forever;
    status_detail flips to 'waiting_for_user' when the agent is idle. With a
    PR populated, the work is done."""
    m = Monitor(wall_clock_cap_seconds=3600)
    s = _session(
        status="running",
        status_detail="waiting_for_user",
        pr_url="https://github.com/x/y/pull/1",
    )
    assert m.assess(session=s, age_seconds=600) == "resolved"


def test_status_detail_waiting_for_user_without_pr_escalates():
    """No PR on an idle session means Devin asked a clarifying question
    instead of opening a remediation PR — escalate."""
    m = Monitor(wall_clock_cap_seconds=3600)
    s = _session(status="running", status_detail="waiting_for_user", pr_url=None)
    assert m.assess(session=s, age_seconds=600) == "needs_human"


def test_wall_clock_cap_breach_is_timed_out():
    m = Monitor(wall_clock_cap_seconds=60)
    assert m.assess(session=_session(status="running"), age_seconds=61) == "timed_out"


def test_wall_clock_cap_only_fires_on_running_sessions_not_resolved_ones():
    """The cap is a liveness backstop — it should never override a real
    resolved signal even if reported late."""
    m = Monitor(wall_clock_cap_seconds=60)
    s = _session(
        terminal_status="COMPLETE",
        pr_url="https://github.com/x/y/pull/1",
    )
    assert m.assess(session=s, age_seconds=3600) == "resolved"


def test_running_session_under_cap_is_in_flight_not_no_progress():
    """There is NO 'no-progress' rule by design. A long-running
    session is still in_flight as long as it's under the cap and hasn't
    signalled."""
    m = Monitor(wall_clock_cap_seconds=3600)
    assert m.assess(session=_session(status="running"), age_seconds=1500) == "in_flight"


def test_monitor_falls_back_to_last_message_when_terminal_status_field_absent():
    """If the boundary client didn't pre-parse terminal_status, the monitor
    derives it from session messages (text-marker fallback)."""
    m = Monitor(wall_clock_cap_seconds=3600)
    s = _session(
        terminal_status=None,
        pr_url="https://github.com/x/y/pull/1",
        messages=[{"source": "devin", "body": "All checks green. Terminal status: COMPLETE"}],
    )
    assert m.assess(session=s, age_seconds=120) == "resolved"
