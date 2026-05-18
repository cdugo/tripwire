#!/usr/bin/env python3
"""Batch-query OSV for every (name, version) in an npm or pip lockfile.

Usage:
    osv_lockfile_scan.py npm <path/to/package-lock.json>
    osv_lockfile_scan.py pip <path/to/requirements.txt>

Prints one finding per line: "<ecosystem>:<name>@<version> -> <comma-separated-ids>".
Exits 0 even if findings exist (this is verification, not a gate).
"""

from __future__ import annotations

import json
import re
import sys
import urllib.request
from pathlib import Path

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
BATCH_SIZE = 500


def npm_packages(lockfile: Path) -> list[tuple[str, str]]:
    data = json.loads(lockfile.read_text())
    out: list[tuple[str, str]] = []
    for key, val in (data.get("packages") or {}).items():
        if not key or not isinstance(val, dict):
            continue
        ver = val.get("version")
        if not ver:
            continue
        name = key.rsplit("node_modules/", 1)[-1]
        out.append((name, ver))
    return sorted(set(out))


def pip_packages(requirements: Path) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for raw in requirements.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-]+)", line)
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def query(ecosystem: str, pkgs: list[tuple[str, str]]) -> dict[tuple[str, str], list[str]]:
    findings: dict[tuple[str, str], list[str]] = {}
    for i in range(0, len(pkgs), BATCH_SIZE):
        chunk = pkgs[i : i + BATCH_SIZE]
        body = json.dumps({
            "queries": [
                {"package": {"name": n, "ecosystem": ecosystem}, "version": v}
                for n, v in chunk
            ]
        }).encode()
        req = urllib.request.Request(
            OSV_BATCH_URL, data=body, headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            results = json.loads(resp.read())["results"]
        for (n, v), result in zip(chunk, results):
            vulns = result.get("vulns") or []
            if vulns:
                findings[(n, v)] = [vv["id"] for vv in vulns]
    return findings


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    kind, path_str = sys.argv[1], sys.argv[2]
    path = Path(path_str)
    if kind == "npm":
        ecosystem, pkgs = "npm", npm_packages(path)
    elif kind == "pip":
        ecosystem, pkgs = "PyPI", pip_packages(path)
    else:
        print(f"unknown kind: {kind}", file=sys.stderr)
        return 2
    print(f"scanning {len(pkgs)} {ecosystem} packages from {path}", file=sys.stderr)
    findings = query(ecosystem, pkgs)
    for (n, v), ids in sorted(findings.items()):
        print(f"{ecosystem}:{n}@{v} -> {','.join(ids)}")
    print(f"total findings: {len(findings)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
