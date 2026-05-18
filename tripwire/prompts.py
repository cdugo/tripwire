"""Per-session prompt template.

The Playbook + Knowledge notes carry the durable doctrine and environment
context; this template only fills in the variable per-session specifics
(manifest path + findings). Playbook ID and Knowledge IDs ride on dedicated
API fields, not in the prompt body.
"""

from __future__ import annotations

from typing import Iterable

from tripwire.findings import Finding


def build_session_prompt(
    *, manifest_path: str, base_branch: str, findings: Iterable[Finding]
) -> str:
    findings = list(findings)
    slug = manifest_path.replace("/", "-").replace(".", "-")

    blocks = []
    for f in findings:
        blocks.append(
            f"  - {f.package} ({f.ecosystem}) {f.installed_version}\n"
            f"      vulnerable: {', '.join(f.vulnerable_ranges) or 'see advisory'}\n"
            f"      advisories: {', '.join(f.advisory_ids)}"
        )

    return (
        f"Remediate the supply-chain advisories in manifest {manifest_path}.\n\n"
        "FINDINGS (remediate all of them in one PR)\n"
        f"{chr(10).join(blocks)}\n\n"
        "TASK\n"
        f"  Open one PR against {base_branch} on branch remediate/{slug}\n"
        "  that removes every resolved version inside a vulnerable range.\n\n"
        "PREFERENCE ORDER (per finding)\n"
        "  1. Upgrade to the lowest patched version above the range.\n"
        "  2. If none exists, pin to the last known-good version below it.\n"
        "  3. If transitive, add an npm override / pip constraint rather than\n"
        "     editing a direct dependency you don't own.\n"
        "  4. If the package is abandoned with no fix, replace it with a\n"
        "     maintained equivalent -- and explain the choice.\n\n"
        "ACCEPTANCE\n"
        "  - The lockfile resolves no version in any vulnerable range.\n"
        "  - Build and existing tests pass in your sandbox before you open the PR.\n"
        "  - After the PR is open, ensure all GitHub CI checks pass; fix any failures\n"
        "    (including breakage caused by the upgrade itself).\n"
        "  - No unrelated changes.\n"
        "  - PR body names each advisory, the mitigation, and the reasoning.\n"
        "  - If blocked, stop and comment on the tracking issue.\n"
    )
