#!/usr/bin/env python3
"""Pre-flight sanity check that mirrors what `tripwire live` will actually do.

Two checks:
  1. For each pin in LIVE_MANIFESTS, query OSV and print advisories.
     Predicts cycle 1's finding count.
  2. For each manifest path in LIVE_MANIFESTS, confirm the file exists on
     the fork's tripwire/demo branch (so Devin has a real file to edit).

Run before any live invocation — costs nothing (no ACUs) and catches
fixture drift before it burns a session.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tripwire.live_config import LIVE_MANIFESTS  # noqa: E402

OWNER = os.environ["GITHUB_OWNER"]
REPO = os.environ["GITHUB_REPO"]
PAT = os.environ["GITHUB_PAT"]
BRANCH = "tripwire/demo"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"


def osv_query(queries: list[dict]) -> list[list[dict]]:
    body = json.dumps({"queries": queries}).encode()
    req = urllib.request.Request(
        OSV_BATCH_URL, data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        results = json.loads(resp.read())["results"]
    return [r.get("vulns") or [] for r in results]


def head_on_branch(path: str) -> tuple[int, int | None]:
    url = f"https://api.github.com/repos/{OWNER}/{REPO}/contents/{path}?ref={BRANCH}"
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {PAT}",
            "Accept": "application/vnd.github+json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
            return resp.status, data.get("size")
    except urllib.error.HTTPError as e:
        return e.code, None


def main() -> int:
    print(f"fork: {OWNER}/{REPO}@{BRANCH}\n", file=sys.stderr)

    print("== 1. OSV would fire for these pins ==")
    grand_total = 0
    for m in LIVE_MANIFESTS:
        eco, path, pkgs = m["ecosystem"], m["path"], m["packages"]
        queries = [{"package": {"ecosystem": eco, "name": p["name"]}, "version": p["version"]} for p in pkgs]
        results = osv_query(queries)
        hits = sum(1 for r in results if r)
        grand_total += hits
        print(f"\n  {path}  ({eco}, {len(pkgs)} pins, {hits} vulnerable)")
        for pkg, vulns in zip(pkgs, results):
            ids = ",".join(v["id"] for v in vulns)
            status = ids if ids else "CLEAN — no advisory; manifest will produce no findings"
            print(f"    {pkg['name']}@{pkg['version']}  ->  {status}")
    print(f"\n  total vulnerable pins across manifests: {grand_total}\n")

    print("== 2. Manifest files exist on the fork ==")
    ok = True
    for m in LIVE_MANIFESTS:
        status, size = head_on_branch(m["path"])
        marker = "OK " if status == 200 else "FAIL"
        size_str = f"{size} bytes" if size is not None else f"http {status}"
        print(f"  [{marker}] {m['path']}  ({size_str})")
        if status != 200:
            ok = False
    print()
    if not ok:
        print("FAIL: at least one manifest is missing on tripwire/demo", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
