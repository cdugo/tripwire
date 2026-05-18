"""Report rendering — funnel, MTTR, cost-per-fix, finding listing.

Cost per fix leads; merged stage is always zero. Per-cycle snapshots
persist (`report-{cycle}.html`); the rolling `report.html` is also
overwritten so a reviewer always has a "latest" pointer.
"""

from __future__ import annotations

import html
from pathlib import Path

from tripwire.metrics import compute_cost, compute_funnel, compute_mttr_seconds
from tripwire.store import Store


def _fmt_dollars(v: float | None) -> str:
    return "pending — no PRs landed yet" if v is None else f"${v:,.2f}"


def _fmt_hours(v: float | None) -> str:
    return "—" if v is None else f"{v:,.2f} h"


def _fmt_seconds(v: int | None) -> str:
    if v is None:
        return "in flight"
    if v < 60:
        return f"{v}s"
    if v < 3600:
        return f"{v // 60}m {v % 60}s"
    return f"{v // 3600}h {(v % 3600) // 60}m"


def render_report(store: Store, *, out_dir: Path, cycle_number: int) -> Path:
    cost = compute_cost(store)
    funnel = compute_funnel(store)
    mttr = compute_mttr_seconds(store)
    manifests = store.list_manifests()
    findings = store.list_findings()

    parts: list[str] = []
    parts.append("<!doctype html><html><head><meta charset='utf-8'>")
    parts.append("<title>Tripwire report</title>")
    parts.append(
        "<style>"
        "body{font-family:system-ui,sans-serif;max-width:980px;margin:2rem auto;padding:0 1rem;color:#111}"
        "h1,h2{border-bottom:1px solid #ddd;padding-bottom:.25rem}"
        ".lead{display:flex;gap:1.5rem;flex-wrap:wrap;margin:1.5rem 0}"
        ".lead .stat{flex:1;min-width:180px;border:1px solid #ddd;padding:1rem;border-radius:6px;background:#fafafa}"
        ".lead .stat .v{font-size:1.6rem;font-weight:600;display:block;margin-top:.25rem}"
        "table{border-collapse:collapse;width:100%;margin:1rem 0}"
        "th,td{border:1px solid #ddd;padding:.4rem .6rem;text-align:left;font-size:.92rem}"
        "th{background:#f3f3f3}"
        ".funnel li{margin:.25rem 0}"
        ".state-resolved{color:#0a6e22;font-weight:600}"
        ".state-needs_human,.state-timed_out{color:#a31515;font-weight:600}"
        "</style></head><body>"
    )
    parts.append(f"<h1>Tripwire — cycle {cycle_number}</h1>")

    # ---- Cost per fix LEADS ------------------------------------------------
    parts.append("<h2>Cost per fix</h2>")
    parts.append("<div class='lead'>")
    parts.append(
        f"<div class='stat'>cost / fix<span class='v'>{_fmt_dollars(cost['cost_per_fix_dollars'])}</span></div>"
        f"<div class='stat'>engineer-hours / fix<span class='v'>{_fmt_hours(cost['cost_per_fix_hours'])}</span></div>"
        f"<div class='stat'>total ACUs<span class='v'>{cost['total_acus']:.2f}</span></div>"
        f"<div class='stat'>total spend<span class='v'>${cost['total_dollars']:,.2f}</span></div>"
    )
    parts.append("</div>")

    # ---- Funnel ------------------------------------------------------------
    parts.append("<h2>Funnel</h2><ul class='funnel'>")
    parts.append(f"<li>findings detected: <strong>{funnel['findings']}</strong></li>")
    parts.append(f"<li>manifests affected: <strong>{funnel['manifests_affected']}</strong></li>")
    parts.append(f"<li>Devin sessions started: <strong>{funnel['sessions']}</strong></li>")
    parts.append(f"<li>PRs opened: <strong>{funnel['prs_opened']}</strong></li>")
    parts.append(f"<li>CI green: <strong>{funnel['ci_green']}</strong></li>")
    parts.append(f"<li>merged: <strong>{funnel['merged']}</strong> (human action — always zero)</li>")
    parts.append("</ul>")

    # ---- MTTR --------------------------------------------------------------
    parts.append("<h2>MTTR — detected to PR open</h2>")
    parts.append("<table><tr><th>Manifest</th><th>State</th><th>MTTR</th></tr>")
    for path, state in manifests:
        parts.append(
            "<tr>"
            f"<td>{html.escape(path)}</td>"
            f"<td class='state-{html.escape(state)}'>{html.escape(state)}</td>"
            f"<td>{_fmt_seconds(mttr.get(path))}</td>"
            "</tr>"
        )
    parts.append("</table>")

    # ---- Findings ----------------------------------------------------------
    parts.append("<h2>Findings</h2>")
    parts.append("<table><tr><th>Manifest</th><th>Ecosystem</th><th>Package</th>"
                 "<th>Version</th><th>Severity</th><th>Advisories</th></tr>")
    for f in findings:
        parts.append(
            "<tr>"
            f"<td>{html.escape(f.manifest_path)}</td>"
            f"<td>{html.escape(f.ecosystem)}</td>"
            f"<td>{html.escape(f.package)}</td>"
            f"<td>{html.escape(f.installed_version)}</td>"
            f"<td>{html.escape(f.severity)}</td>"
            f"<td>{html.escape(', '.join(f.advisory_ids))}</td>"
            "</tr>"
        )
    parts.append("</table>")

    parts.append("</body></html>")

    out_dir.mkdir(parents=True, exist_ok=True)
    snapshot = out_dir / f"report-{cycle_number}.html"
    rolling = out_dir / "report.html"
    body = "\n".join(parts)
    snapshot.write_text(body)
    rolling.write_text(body)
    return snapshot
