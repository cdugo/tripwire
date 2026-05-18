#!/usr/bin/env python3
"""Poll every in-flight session in the smoke/live store until all are
terminal (status_detail=='waiting_for_user' or status in {'exit',
'suspended','error'}) or the cap elapses. Prints one line per poll.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import httpx

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
from tripwire.store import Store  # noqa: E402


def _load_dotenv(path: Path) -> None:
    """Tiny .env loader so the script Just Works without `source .env`."""
    if not path.exists():
        return
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv(REPO_ROOT / ".env")

_REQUIRED = ("DEVIN_ORG_ID", "DEVIN_API_KEY")
_missing = [k for k in _REQUIRED if not os.environ.get(k)]
if _missing:
    print(
        "error: missing env var(s): " + ", ".join(_missing) +
        "\n       populate .env (see .env.example) or `export` them in your shell.",
        file=sys.stderr,
    )
    sys.exit(2)

DB = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("./tripwire.sqlite")
INTERVAL_S = int(sys.argv[2]) if len(sys.argv) > 2 else 75
CAP_S = int(sys.argv[3]) if len(sys.argv) > 3 else 2100

ORG = os.environ["DEVIN_ORG_ID"]
TOKEN = os.environ["DEVIN_API_KEY"]
ROOT = f"https://api.devin.ai/v3/organizations/{ORG}"
H = {"Authorization": f"Bearer {TOKEN}", "Accept": "application/json"}


def is_terminal(s: dict) -> bool:
    return (s.get("status") or "").lower() in {"exit", "suspended", "error"} or (
        s.get("status_detail") or ""
    ).lower() == "waiting_for_user"


def main() -> int:
    store = Store(DB)
    in_flight = store.in_flight_manifests()
    if not in_flight:
        print("no in-flight manifests", file=sys.stderr)
        return 0

    print(f"polling {len(in_flight)} sessions every {INTERVAL_S}s (cap {CAP_S}s)")
    for path, sid in in_flight:
        print(f"  {sid[:8]}  {path}")
    print()

    start = time.time()
    client = httpx.Client(timeout=30)
    try:
        while True:
            elapsed = int(time.time() - start)
            done = 0
            parts = []
            for path, sid in in_flight:
                try:
                    r = client.get(f"{ROOT}/sessions/{sid}", headers=H)
                    s = r.json() if r.status_code == 200 else {}
                except Exception:
                    s = {}
                term = is_terminal(s)
                if term:
                    done += 1
                parts.append(
                    f"{sid[:8]}={s.get('status')}:{s.get('status_detail')}(prs={len(s.get('pull_requests') or [])})"
                )
            print(f"[t+{elapsed}s] done={done}/{len(in_flight)}  " + "  ".join(parts), flush=True)
            if done == len(in_flight) or elapsed > CAP_S:
                print(f"\n-- exit: {done}/{len(in_flight)} terminal in {elapsed}s --")
                return 0
            time.sleep(INTERVAL_S)
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
