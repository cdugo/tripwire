"""Funnel, MTTR, and cost computations derived from the SQLite store.

Cost-per-fix is the headline metric; the funnel's `merged` stage is always
zero because merging is a human action by design.
"""

from __future__ import annotations

from datetime import datetime

from tripwire.store import Store


# Manifest states that imply progression through the funnel.
# pr_opened and ci_green are observations, not states: pr_opened is
# "pr_opened_at is set"; ci_green is "state == resolved" since Devin only
# resolves after CI is green per the Playbook.
_HAS_SESSION = frozenset({"in_flight", "resolved", "needs_human", "timed_out"})


def compute_mttr_seconds(store: Store) -> dict[str, int | None]:
    """Per-manifest detected_at → pr_opened_at, in whole seconds.

    None for any manifest that hasn't opened a PR yet (in-flight OR escalated
    before PR). Reporting zero would falsely advertise instant resolution.
    """
    out: dict[str, int | None] = {}
    for path, _state in store.list_manifests():
        ts = store.manifest_timestamps(path)
        detected = ts.get("detected_at")
        pr_opened = ts.get("pr_opened_at")
        if not detected or not pr_opened:
            out[path] = None
            continue
        out[path] = int((datetime.fromisoformat(pr_opened) - datetime.fromisoformat(detected)).total_seconds())
    return out


def compute_cost(
    store: Store,
    *,
    dollars_per_acu: float = 2.25,
    hours_per_acu: float = 0.5,
) -> dict[str, float | int | None]:
    """ACUs → dollars and engineer-hours, with a safe cost-per-fix denominator.

    The denominator is *PRs landed*, not sessions started — a needs_human
    escalation still burned ACUs but produced no fix to amortize against.
    Zero PRs returns None for cost_per_fix (NOT zero, which would imply
    a free fix; NOT infinity).
    """
    acu_by_path = store.manifest_acu_usage()
    states = dict(store.list_manifests())

    total_acus = sum(acu_by_path.values())
    total_dollars = total_acus * dollars_per_acu
    total_hours = total_acus * hours_per_acu

    # "PR landed" = pr_opened_at observation is set (regardless of state).
    prs_landed = sum(
        1 for path in states
        if store.manifest_timestamps(path).get("pr_opened_at")
    )

    return {
        "total_acus": total_acus,
        "total_dollars": total_dollars,
        "total_engineer_hours": total_hours,
        "prs_landed": prs_landed,
        "cost_per_fix_dollars": (total_dollars / prs_landed) if prs_landed else None,
        "cost_per_fix_hours": (total_hours / prs_landed) if prs_landed else None,
    }


def compute_funnel(store: Store) -> dict[str, int]:
    findings = store.list_findings()
    manifests = store.list_manifests()
    prs_opened = sum(
        1 for path, _ in manifests
        if store.manifest_timestamps(path).get("pr_opened_at")
    )

    return {
        "findings": len(findings),
        "manifests_affected": len({f.manifest_path for f in findings}),
        "sessions": sum(1 for _, state in manifests if state in _HAS_SESSION),
        "prs_opened": prs_opened,
        "ci_green": sum(1 for _, state in manifests if state == "resolved"),
        "merged": 0,  # human action; deliberately zero
    }
