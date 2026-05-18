"""Trigger sources — the pluggable front door.

A TriggerSource turns external state into a normalized list of Findings.
The OSV poller is the only implementation today; webhooks, Dependabot feeds,
human-filed issues are future implementations behind the same interface.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from tripwire.findings import Finding


@runtime_checkable
class TriggerSource(Protocol):
    """Anything that can produce the current list of Findings on demand."""

    def poll(self) -> list[Finding]:
        ...
