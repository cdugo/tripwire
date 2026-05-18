"""SQLite-backed state store.

Three jobs, one component: finding fingerprint dedupe (poll idempotency),
per-manifest state machine (Monitor + escalation), and the data source for
the report.

State machine:
    detected → in_flight → {resolved, needs_human, timed_out}

`pr_opened_at` is an observation (recorded when reconcile first sees a non-
null PR URL), not a state transition — we don't observe pr_open and
ci_running as distinct events from Devin's API, so collapsing them keeps
the model honest.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

from tripwire.findings import Finding


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class InvalidTransition(Exception):
    """Raised when advance_manifest is called with a non-allowed next state."""


_TERMINAL = frozenset({"resolved", "needs_human", "timed_out"})
_TRANSITIONS = {
    "detected": frozenset({"in_flight", "needs_human", "timed_out"}),
    "in_flight": frozenset({"resolved", "needs_human", "timed_out"}),
    "resolved": frozenset(),
    "needs_human": frozenset(),
    "timed_out": frozenset(),
}


_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    manifest_path     TEXT NOT NULL,
    ecosystem         TEXT NOT NULL,
    package           TEXT NOT NULL,
    installed_version TEXT NOT NULL,
    advisory_ids      TEXT NOT NULL,  -- JSON list
    vulnerable_ranges TEXT NOT NULL,  -- JSON list
    severity          TEXT NOT NULL,
    detected_at       TEXT NOT NULL,
    PRIMARY KEY (manifest_path, ecosystem, package)
);

CREATE TABLE IF NOT EXISTS manifests (
    path           TEXT PRIMARY KEY,
    state          TEXT NOT NULL,
    session_id     TEXT,
    detected_at    TEXT NOT NULL,
    started_at     TEXT,             -- session create time; reconcile age basis
    pr_opened_at   TEXT,             -- observation, not a transition
    acu_usage      REAL NOT NULL DEFAULT 0.0,
    updated_at     TEXT NOT NULL
);
"""


class Store:
    def __init__(
        self,
        db_path: str | Path,
        *,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        # check_same_thread=False because the orchestrator drives per-manifest
        # work across a ThreadPoolExecutor; we serialize writes with _lock.
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._lock = threading.Lock()
        self._clock = clock

    def _now_iso(self) -> str:
        return self._clock().isoformat()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ---- findings ---------------------------------------------------------

    def upsert_findings(self, findings: Iterable[Finding]) -> None:
        with self._lock:
            cur = self._conn.cursor()
            for f in findings:
                now = self._now_iso()
                cur.execute(
                    """
                    INSERT INTO findings (
                        manifest_path, ecosystem, package, installed_version,
                        advisory_ids, vulnerable_ranges, severity, detected_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(manifest_path, ecosystem, package) DO UPDATE SET
                        installed_version = excluded.installed_version,
                        advisory_ids      = excluded.advisory_ids,
                        vulnerable_ranges = excluded.vulnerable_ranges,
                        severity          = excluded.severity
                    """,
                    (
                        f.manifest_path, f.ecosystem, f.package, f.installed_version,
                        json.dumps(f.advisory_ids), json.dumps(f.vulnerable_ranges),
                        f.severity, now,
                    ),
                )
                cur.execute(
                    """INSERT OR IGNORE INTO manifests
                       (path, state, detected_at, updated_at)
                       VALUES (?, 'detected', ?, ?)""",
                    (f.manifest_path, now, now),
                )
            self._conn.commit()

    def list_findings(self) -> list[Finding]:
        with self._lock:
            rows = self._conn.execute(
                """SELECT manifest_path, ecosystem, package, installed_version,
                          advisory_ids, vulnerable_ranges, severity
                   FROM findings
                   ORDER BY manifest_path, ecosystem, package"""
            ).fetchall()
        return [
            Finding(
                manifest_path=r[0], ecosystem=r[1], package=r[2],
                installed_version=r[3],
                advisory_ids=json.loads(r[4]),
                vulnerable_ranges=json.loads(r[5]),
                severity=r[6],
            )
            for r in rows
        ]

    # ---- per-manifest state ----------------------------------------------

    def manifest_state(self, path: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT state FROM manifests WHERE path = ?", (path,)
            ).fetchone()
        return row[0] if row else None

    def list_manifests(self) -> list[tuple[str, str]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT path, state FROM manifests ORDER BY path"
            ).fetchall()
        return [(r[0], r[1]) for r in rows]

    def start_session(self, path: str, session_id: str) -> None:
        """Atomic: detected → in_flight, plus record session_id and started_at."""
        with self._lock:
            row = self._conn.execute(
                "SELECT state FROM manifests WHERE path = ?", (path,)
            ).fetchone()
            if row is None:
                raise InvalidTransition(f"unknown manifest: {path!r}")
            if "in_flight" not in _TRANSITIONS.get(row[0], frozenset()):
                raise InvalidTransition(
                    f"cannot start session for {path!r} from state {row[0]!r}"
                )
            now = self._now_iso()
            self._conn.execute(
                """UPDATE manifests
                   SET state = 'in_flight', session_id = ?, started_at = ?, updated_at = ?
                   WHERE path = ?""",
                (session_id, now, now, path),
            )
            self._conn.commit()

    def advance_manifest(self, path: str, new_state: str) -> None:
        """Move to a terminal state (or in_flight, used by start_session path)."""
        with self._lock:
            row = self._conn.execute(
                "SELECT state FROM manifests WHERE path = ?", (path,)
            ).fetchone()
            if row is None:
                raise InvalidTransition(f"unknown manifest: {path!r}")
            current = row[0]
            if new_state not in _TRANSITIONS.get(current, frozenset()):
                raise InvalidTransition(
                    f"cannot transition manifest {path!r} from {current!r} to {new_state!r}"
                )
            now = self._now_iso()
            self._conn.execute(
                "UPDATE manifests SET state = ?, updated_at = ? WHERE path = ?",
                (new_state, now, path),
            )
            self._conn.commit()

    def record_pr_opened(self, path: str) -> None:
        """Idempotent: set pr_opened_at on first sighting, no-op thereafter."""
        now = self._now_iso()
        with self._lock:
            self._conn.execute(
                """UPDATE manifests
                   SET pr_opened_at = COALESCE(pr_opened_at, ?), updated_at = ?
                   WHERE path = ?""",
                (now, now, path),
            )
            self._conn.commit()

    def manifest_timestamps(self, path: str) -> dict[str, str | None]:
        with self._lock:
            row = self._conn.execute(
                """SELECT detected_at, started_at, pr_opened_at
                   FROM manifests WHERE path = ?""",
                (path,),
            ).fetchone()
        if row is None:
            return {}
        return {"detected_at": row[0], "started_at": row[1], "pr_opened_at": row[2]}

    # ---- reconcile + cost -------------------------------------------------

    def record_acu_usage(self, path: str, acu: float) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE manifests SET acu_usage = ?, updated_at = ? WHERE path = ?",
                (float(acu or 0.0), self._now_iso(), path),
            )
            self._conn.commit()

    def manifest_acu_usage(self) -> dict[str, float]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT path, acu_usage FROM manifests"
            ).fetchall()
        return {r[0]: float(r[1] or 0.0) for r in rows}

    def in_flight_manifests(self) -> list[tuple[str, str]]:
        """Manifests with a session that haven't reached a terminal state.

        Returns (path, session_id). The reconcile pass re-polls each one.
        """
        with self._lock:
            rows = self._conn.execute(
                """SELECT path, session_id FROM manifests
                   WHERE session_id IS NOT NULL AND state = 'in_flight'
                   ORDER BY path"""
            ).fetchall()
        return [(r[0], r[1]) for r in rows]

    def session_age_seconds(self, path: str) -> float:
        """Seconds since started_at, on the Store's own clock. 0 if no session."""
        with self._lock:
            row = self._conn.execute(
                "SELECT started_at FROM manifests WHERE path = ?", (path,)
            ).fetchone()
        if not row or not row[0]:
            return 0.0
        started = datetime.fromisoformat(row[0])
        now = self._clock()
        return max(0.0, (now - started).total_seconds())
