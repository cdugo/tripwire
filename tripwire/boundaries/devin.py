"""Devin API boundary.

Protocol + real httpx-backed client + deterministic fake. The fake's
get_session shape mirrors the real-API quirk that terminal state never
appears in the top-level `status` field — that stays "running" for the
session's lifetime — so callers should read `terminal_status` /
`status_detail` instead.
"""

from __future__ import annotations

import hashlib
from typing import Protocol, runtime_checkable

import httpx


@runtime_checkable
class DevinClient(Protocol):
    def create_session(
        self, *, playbook_id: str, knowledge_ids: list[str], prompt: str
    ) -> str:
        ...

    def get_session(self, session_id: str) -> dict:
        ...


class RealDevinClient:
    """Three-layer context wiring.

    Playbook + Knowledge IDs go in dedicated API fields. The prompt body
    carries the per-session specifics only — manifest path + findings.

    get_session combines the session record with the last source:'devin'
    message body's terminal status, so callers don't have to know about
    Devin's two-endpoint shape.
    """

    def __init__(
        self,
        *,
        org_id: str,
        token: str,
        http_client: httpx.Client | None = None,
        base_url: str = "https://api.devin.ai",
        timeout: float = 60.0,
    ) -> None:
        self._org = org_id
        self._http = http_client or httpx.Client(base_url=base_url, timeout=timeout)
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }

    def _root(self) -> str:
        return f"/v3/organizations/{self._org}"

    def create_session(
        self, *, playbook_id: str, knowledge_ids: list[str], prompt: str
    ) -> str:
        resp = self._http.post(
            f"{self._root()}/sessions",
            json={
                "prompt": prompt,
                "playbook_id": playbook_id,
                "knowledge_ids": list(knowledge_ids),
            },
            headers=self._headers,
        )
        resp.raise_for_status()
        return resp.json()["session_id"]

    def get_session(self, session_id: str) -> dict:
        sess_resp = self._http.get(
            f"{self._root()}/sessions/{session_id}", headers=self._headers
        )
        sess_resp.raise_for_status()
        session = sess_resp.json()

        # The Devin API uses acus_consumed / pull_requests; the orchestrator
        # and Monitor read acu_usage / pr_url. Normalize here so callers don't
        # need to know either spelling.
        session["acu_usage"] = float(session.get("acus_consumed") or 0.0)
        prs = session.get("pull_requests") or []
        first = prs[0] if prs else None
        if isinstance(first, dict):
            session["pr_url"] = (
                first.get("pr_url") or first.get("url") or first.get("html_url")
            )
        elif isinstance(first, str):
            session["pr_url"] = first
        else:
            session["pr_url"] = None

        # Terminal status can also live in the last source:'devin' message
        # body. The /messages endpoint returns items shaped {source,
        # message, ...}; the Monitor expects {source, body}.
        msg_resp = self._http.get(
            f"{self._root()}/sessions/{session_id}/messages", headers=self._headers
        )
        msg_resp.raise_for_status()
        raw = msg_resp.json().get("items") or msg_resp.json().get("messages") or []
        session["messages"] = [
            {"source": m.get("source"), "body": m.get("message") or m.get("body", "")}
            for m in raw
        ]

        return session


def _stable_id(prompt: str) -> str:
    return "devin-" + hashlib.sha256(prompt.encode("utf-8")).hexdigest()[:12]


class FakeDevinClient:
    """In-memory, deterministic Devin. Same prompt → same session id."""

    def __init__(self) -> None:
        self.created_sessions: list[dict] = []

    def create_session(
        self, *, playbook_id: str, knowledge_ids: list[str], prompt: str
    ) -> str:
        sid = _stable_id(prompt)
        self.created_sessions.append(
            {
                "id": sid,
                "playbook_id": playbook_id,
                "knowledge_ids": list(knowledge_ids),
                "prompt": prompt,
            }
        )
        return sid

    def get_session(self, session_id: str) -> dict:
        # Demo path: every session reaches a clean terminal COMPLETE with a PR.
        return {
            "id": session_id,
            "status": "running",  # Devin's literal status; terminal_status is the real signal
            "terminal_status": "COMPLETE",
            "pr_url": f"https://github.com/demo-org/demo-repo/pull/{abs(hash(session_id)) % 1000}",
            "acu_usage": 1.2,
        }
