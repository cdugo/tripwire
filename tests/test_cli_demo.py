"""CLI smoke for `python -m tripwire demo`.

A reviewer can run the demo with zero credentials and get a deterministic
report.html.
"""

import os
import subprocess
import sys
from pathlib import Path


def test_python_m_tripwire_demo_produces_report(tmp_path: Path):
    env = os.environ.copy()
    # Defense-in-depth: even with creds in the env, demo must not touch real network.
    env["DEVIN_API_KEY"] = "leaked"
    env["GITHUB_PAT"] = "leaked"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "tripwire",
            "demo",
            "--report-dir",
            str(tmp_path),
            "--state-db",
            str(tmp_path / "tw.sqlite"),
        ],
        check=True,
        env=env,
        capture_output=True,
        text=True,
    )

    rolling = tmp_path / "report.html"
    snapshot = tmp_path / "report-1.html"
    assert rolling.exists(), result.stdout + result.stderr
    assert snapshot.exists()
    html = rolling.read_text()
    # The four manifests from the canonical demo fixture.
    for needle in ("web-dashboard", "api-gateway", "etl-worker", "report-api"):
        assert needle in html, f"missing {needle} in report"


def test_python_m_tripwire_demo_is_idempotent(tmp_path: Path):
    """Two cycles back-to-back; the second files no new issues/sessions."""
    cmd = [
        sys.executable,
        "-m",
        "tripwire",
        "demo",
        "--report-dir",
        str(tmp_path),
        "--state-db",
        str(tmp_path / "tw.sqlite"),
    ]
    first = subprocess.run(cmd, check=True, capture_output=True, text=True)
    second = subprocess.run(cmd + ["--cycle", "2"], check=True, capture_output=True, text=True)

    assert "new findings: 0" in second.stdout.lower(), second.stdout
    assert "new sessions: 0" in second.stdout.lower()
    assert (tmp_path / "report-1.html").exists()
    assert (tmp_path / "report-2.html").exists()
    _ = first  # not asserting on first, only that it succeeded
