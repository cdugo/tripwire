"""Structural validation of the packaging assets.

Slim single-stage Dockerfile, single-service compose, SQLite as a mounted
file (not a volume) so the data survives `docker compose down`. We don't
run `docker build` in pytest — that's a manual step. We do verify the
assets are present and well-formed.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_dockerfile_exists_and_is_single_stage():
    p = ROOT / "Dockerfile"
    assert p.exists(), "Dockerfile is required for packaging"
    text = p.read_text()
    from_lines = [l for l in text.splitlines() if l.strip().lower().startswith("from ")]
    assert len(from_lines) == 1, f"expected single-stage, got {len(from_lines)} FROMs"
    assert "python:" in from_lines[0].lower(), "base image should be a Python slim"


def test_dockerfile_installs_project_and_sets_entrypoint():
    text = (ROOT / "Dockerfile").read_text()
    # Project is installed editable or via wheel/sdist.
    assert "pip install" in text
    assert "tripwire" in text.lower()
    # ENTRYPOINT or CMD invokes the CLI.
    assert re.search(r"(ENTRYPOINT|CMD).*tripwire", text), \
        "Dockerfile must launch the tripwire CLI"


def test_dockerignore_excludes_secrets_and_state():
    p = ROOT / ".dockerignore"
    assert p.exists(), ".dockerignore is required so .env etc never bake into the image"
    text = p.read_text()
    for needle in (".env", "*.sqlite", "__pycache__", ".venv"):
        assert needle in text, f".dockerignore must exclude {needle}"


def test_compose_yaml_mounts_sqlite_as_a_file_not_a_volume():
    p = ROOT / "docker-compose.yml"
    assert p.exists(), "docker-compose.yml is required"
    text = p.read_text()
    # The state DB must be bind-mounted from the host as a file path.
    assert "tripwire.sqlite" in text or "state-db" in text or "/data/" in text
    # demo + live are both invokable.
    assert "demo" in text or "command:" in text


def test_readme_documents_demo_and_live():
    p = ROOT / "README.md"
    assert p.exists(), "README.md is required"
    text = p.read_text().lower()
    assert "docker compose" in text or "docker-compose" in text
    assert "demo" in text and "live" in text
