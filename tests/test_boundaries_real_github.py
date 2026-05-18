"""Real GitHub client — POST /repos/{owner}/{repo}/issues.

Tested via httpx.MockTransport. Auth header carries the PAT.
"""

import json

import httpx
import pytest

from tripwire.boundaries.github import GitHubClient, RealGitHubClient


def _make_handler(captured):
    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        body = json.loads(request.content)
        return httpx.Response(
            201,
            json={
                "number": 42,
                "html_url": f"https://github.com/cdugo/superset/issues/42",
                "title": body["title"],
            },
        )

    return handler


def test_real_github_client_implements_protocol():
    transport = httpx.MockTransport(lambda r: httpx.Response(201, json={"number": 1, "html_url": "u"}))
    client = RealGitHubClient(
        owner="cdugo", repo="superset", token="x",
        http_client=httpx.Client(transport=transport, base_url="https://api.github.com"),
    )
    assert isinstance(client, GitHubClient)


def test_real_github_create_issue_posts_to_correct_endpoint_with_auth():
    captured: list[httpx.Request] = []
    http = httpx.Client(transport=httpx.MockTransport(_make_handler(captured)), base_url="https://api.github.com")
    client = RealGitHubClient(owner="cdugo", repo="superset", token="ghp_secret", http_client=http)

    url = client.create_issue(
        title="Tripwire: api-gateway findings",
        body="some markdown",
        labels=["security", "tripwire"],
    )

    assert url == "https://github.com/cdugo/superset/issues/42"
    [req] = captured
    assert req.method == "POST"
    assert req.url.path == "/repos/cdugo/superset/issues"
    assert req.headers["Authorization"] == "Bearer ghp_secret"
    assert req.headers["Accept"] == "application/vnd.github+json"
    payload = json.loads(req.content)
    assert payload["title"] == "Tripwire: api-gateway findings"
    assert payload["body"] == "some markdown"
    assert payload["labels"] == ["security", "tripwire"]


def test_real_github_raises_on_non_2xx():
    def handler(req):
        return httpx.Response(403, json={"message": "Forbidden"})

    http = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://api.github.com")
    client = RealGitHubClient(owner="cdugo", repo="superset", token="x", http_client=http)

    with pytest.raises(httpx.HTTPStatusError):
        client.create_issue(title="t", body="b", labels=[])
