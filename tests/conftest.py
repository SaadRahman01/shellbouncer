import pytest

from shellbouncer.engine import Action, evaluate
from shellbouncer.policy import build_policy


@pytest.fixture
def project(tmp_path, monkeypatch):
    root = tmp_path / "project"
    root.mkdir()
    (root / ".git").mkdir()
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("SHELLBOUNCER_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("TMPDIR", "/tmp")
    return root


@pytest.fixture
def check(project):
    """check("cmd") -> decision, using the balanced preset unless a policy dict is given."""

    def _check(command, policy=None, kind="shell"):
        policy = dict(policy or {})
        # tmp_path lives in /tmp, which shellbouncer treats as writable; use another temp dir in tests.
        policy.setdefault("files", {}).setdefault("temp_dirs", ["/var/tmp"])
        p = build_policy(policy, str(project))
        return evaluate(Action(kind, command, cwd=str(project)), p)

    return _check
