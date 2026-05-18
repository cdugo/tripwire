"""Real OSV client — hits OSV.dev /v1/querybatch.

One batch POST regardless of query count. Tested via httpx.MockTransport
(cassette-style); no real network.
"""

import json

import httpx

from tripwire.boundaries.osv import OsvClient, RealOsvClient


def _capturing_transport(captured):
    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        # Real OSV response shape: { results: [{vulns: [...]}, ...] }
        body = {
            "results": [
                {"vulns": [{"id": "GHSA-rrrm-qjm4-v8hf"}, {"id": "GHSA-vwqq-5j12-x2ms"}]},
                {"vulns": []},
                {"vulns": [{"id": "GHSA-462w-v97r-4m45"}]},
            ]
        }
        return httpx.Response(200, json=body)

    return httpx.MockTransport(handler)


def test_real_osv_client_implements_protocol():
    client = RealOsvClient(http_client=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"results": []}))))
    assert isinstance(client, OsvClient)


def test_real_osv_client_uses_single_batch_call_not_n_calls():
    captured: list[httpx.Request] = []
    http = httpx.Client(transport=_capturing_transport(captured), base_url="https://api.osv.dev")
    client = RealOsvClient(http_client=http)

    queries = [
        {"package": {"ecosystem": "npm", "name": "marked"}, "version": "0.7.0"},
        {"package": {"ecosystem": "npm", "name": "react"}, "version": "18.2.0"},
        {"package": {"ecosystem": "PyPI", "name": "Jinja2"}, "version": "2.10"},
    ]
    results = client.query_batch(queries)

    # ONE network call, regardless of query count.
    assert len(captured) == 1
    req = captured[0]
    assert req.method == "POST"
    assert req.url.path == "/v1/querybatch"
    sent_body = json.loads(req.content)
    assert sent_body == {"queries": queries}

    # Results are unpacked parallel to queries.
    assert len(results) == 3
    assert {v["id"] for v in results[0]} == {"GHSA-rrrm-qjm4-v8hf", "GHSA-vwqq-5j12-x2ms"}
    assert results[1] == []
    assert results[2] == [{"id": "GHSA-462w-v97r-4m45"}]


def test_real_osv_client_handles_empty_query_list_without_calling_api():
    captured: list[httpx.Request] = []
    http = httpx.Client(transport=_capturing_transport(captured), base_url="https://api.osv.dev")
    client = RealOsvClient(http_client=http)

    assert client.query_batch([]) == []
    assert captured == []
