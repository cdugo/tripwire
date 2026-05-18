"""Real Devin client — three-layer context wiring.

Per-session prompt carries the variable specifics ONLY. Playbook ID and
Knowledge note IDs are attached via dedicated API fields, NEVER inlined
as text in the prompt body.

Completion can also be reported in the LAST source:'devin' message body
('Terminal status: COMPLETE' / 'BLOCKED'). The client's get_session must
surface that path too, for the Monitor.
"""

import json

import httpx
import pytest

from tripwire.boundaries.devin import DevinClient, RealDevinClient


def _capturing_transport(captured, response_factory):
    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return response_factory(request)

    return httpx.MockTransport(handler)


def test_real_devin_client_implements_protocol():
    http = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"session_id": "x"})))
    client = RealDevinClient(org_id="org-1", token="x", http_client=http)
    assert isinstance(client, DevinClient)


def test_create_session_posts_prompt_playbook_and_knowledge_as_separate_fields():
    captured: list[httpx.Request] = []

    def resp(req):
        return httpx.Response(200, json={"session_id": "sess-abc"})

    http = httpx.Client(
        transport=_capturing_transport(captured, resp),
        base_url="https://api.devin.ai",
    )
    client = RealDevinClient(org_id="org-1", token="token-xyz", http_client=http)

    sid = client.create_session(
        playbook_id="playbook-c273",
        knowledge_ids=["note-993f"],
        prompt="Remediate api-gateway",
    )

    assert sid == "sess-abc"
    [req] = captured
    assert req.method == "POST"
    assert req.url.path == "/v3/organizations/org-1/sessions"
    assert req.headers["Authorization"] == "Bearer token-xyz"
    body = json.loads(req.content)

    # Three-layer wiring: separate fields, not crammed into the prompt.
    assert body["prompt"] == "Remediate api-gateway"
    assert body["playbook_id"] == "playbook-c273"
    assert body["knowledge_ids"] == ["note-993f"]

    # Negative: the prompt body itself must not contain the IDs.
    assert "playbook-c273" not in body["prompt"]
    assert "note-993f" not in body["prompt"]


def test_get_session_attaches_messages_so_monitor_can_parse_terminal_signal():
    """Terminal status can live in the last source:'devin' message body.
    The client fetches the messages and attaches them under `messages`;
    parsing belongs to the Monitor.

    The Devin API returns the messages payload as {items: [{source, message}]}
    and session fields as acus_consumed / pull_requests; the boundary
    normalizes both to the legacy keys the Monitor + orchestrator read.
    """
    def resp(req):
        path = req.url.path
        if path.endswith("/messages"):
            return httpx.Response(200, json={
                "items": [
                    {"source": "devin", "message": "starting"},
                    {"source": "user", "message": "ack"},
                    {"source": "devin", "message": "PR opened. Terminal status: COMPLETE"},
                ]
            })
        return httpx.Response(200, json={
            "session_id": "sess-1",
            "status": "waiting_for_user",
            "pull_requests": [{"url": "https://github.com/cdugo/superset/pull/123"}],
            "acus_consumed": 2.7,
        })

    captured: list[httpx.Request] = []
    http = httpx.Client(
        transport=_capturing_transport(captured, resp),
        base_url="https://api.devin.ai",
    )
    client = RealDevinClient(org_id="org-1", token="t", http_client=http)

    s = client.get_session("sess-1")

    # Two GETs: the session itself + its messages.
    paths = [r.url.path for r in captured]
    assert "/v3/organizations/org-1/sessions/sess-1" in paths
    assert "/v3/organizations/org-1/sessions/sess-1/messages" in paths

    assert s["status"] == "waiting_for_user"
    assert s["pr_url"] == "https://github.com/cdugo/superset/pull/123"
    assert s["acu_usage"] == 2.7
    assert s["messages"][-1]["body"].endswith("Terminal status: COMPLETE")


def test_create_session_raises_on_non_2xx():
    http = httpx.Client(
        transport=httpx.MockTransport(lambda r: httpx.Response(401, json={"error": "unauthorized"})),
        base_url="https://api.devin.ai",
    )
    client = RealDevinClient(org_id="org-1", token="bad", http_client=http)
    with pytest.raises(httpx.HTTPStatusError):
        client.create_session(playbook_id="pb", knowledge_ids=[], prompt="x")
