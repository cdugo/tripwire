"""Live mode env validation + boundary wiring."""

import pytest

from tripwire.boundaries import live_boundaries
from tripwire.boundaries.devin import RealDevinClient
from tripwire.boundaries.github import RealGitHubClient
from tripwire.boundaries.osv import RealOsvClient
from tripwire.live_config import LIVE_REQUIRED_ENV, MissingEnvError, read_env


def _good_env() -> dict[str, str]:
    return {
        "DEVIN_API_KEY": "k",
        "DEVIN_ORG_ID": "org",
        "DEVIN_PLAYBOOK_ID": "pb",
        "DEVIN_KNOWLEDGE_IDS": "n1,n2",
        "GITHUB_PAT": "ghp",
        "GITHUB_OWNER": "cdugo",
        "GITHUB_REPO": "superset",
    }


def test_read_env_returns_known_keys_when_all_present():
    env = read_env(_good_env())
    for key in LIVE_REQUIRED_ENV:
        assert env[key]
    assert env["GITHUB_BASE_BRANCH"] == "master"  # default


def test_read_env_lists_every_missing_key():
    bad = _good_env()
    del bad["DEVIN_PLAYBOOK_ID"]
    del bad["GITHUB_PAT"]
    with pytest.raises(MissingEnvError) as exc:
        read_env(bad)
    assert set(exc.value.missing) == {"DEVIN_PLAYBOOK_ID", "GITHUB_PAT"}


def test_read_env_treats_empty_string_as_missing():
    bad = _good_env()
    bad["DEVIN_API_KEY"] = ""
    with pytest.raises(MissingEnvError) as exc:
        read_env(bad)
    assert "DEVIN_API_KEY" in exc.value.missing


def test_live_boundaries_uses_real_clients():
    bundle = live_boundaries(read_env(_good_env()))
    assert isinstance(bundle.osv, RealOsvClient)
    assert isinstance(bundle.github, RealGitHubClient)
    assert isinstance(bundle.devin, RealDevinClient)
