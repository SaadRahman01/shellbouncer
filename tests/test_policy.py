import pytest

from shellbouncer.policy import build_policy, load_policy, path_matches


def test_user_deny_and_ask_patterns(check):
    policy = {"shell": {"deny": ["git push * main"], "ask": ["docker *"]}}
    assert check("git push origin main", policy).decision == "deny"
    assert check("docker run alpine", policy).decision == "ask"
    assert check("git push origin feature", policy).decision == "allow"


def test_user_allow_overrides_builtin_rule(check):
    assert check("git push --force origin my-branch").decision == "ask"
    policy = {"shell": {"allow": ["git push --force origin my-branch"]}}
    assert check("git push --force origin my-branch", policy).decision == "allow"


def test_user_deny_beats_user_allow(check):
    policy = {"shell": {"allow": ["git *"], "deny": ["git push*"]}}
    assert check("git push", policy).decision == "deny"


def test_patterns_match_inside_chains_and_wrappers(check):
    policy = {"shell": {"deny": ["terraform apply*"]}}
    assert check("cd infra && sudo terraform apply", policy).decision == "deny"
    assert check("bash -c 'terraform apply -auto-approve'", policy).decision == "deny"


def test_rule_override_and_disable(check):
    assert check("sudo ls", {"rules": {"overrides": {"privilege": "deny"}}}).decision == "deny"
    assert check("sudo ls", {"rules": {"disable": ["privilege"]}}).decision == "allow"


def test_allow_read_exception(check):
    assert check("cat config/dev.env").decision == "deny"
    assert check("cat config/dev.env", {"files": {"allow_read": ["config/dev.env"]}}).decision == "allow"


def test_custom_secret_patterns(check):
    policy = {"files": {"deny_read": ["secrets/**"]}}
    assert check("cat secrets/db.txt", policy).decision == "deny"


def test_outside_project_setting(check):
    assert check("touch ~/notes.txt").decision == "ask"
    assert check("touch ~/notes.txt", {"files": {"outside_project_write": "allow"}}).decision == "allow"
    assert check("touch ~/notes.txt", {"preset": "strict"}).decision == "deny"


def test_network_allow_list_in_strict(check):
    assert check("curl https://unknown.example", {"preset": "strict"}).decision == "ask"
    assert check("curl https://pypi.org/simple", {"preset": "strict"}).decision == "allow"
    assert check("curl https://api.mycorp.dev", {"preset": "strict", "network": {"allow": ["*.mycorp.dev"]}}).decision == "allow"


def test_chill_preset_is_quieter(check):
    assert check("sudo apt install jq", {"preset": "chill"}).decision == "allow"
    assert check("rm -rf ~", {"preset": "chill"}).decision == "deny"


def test_direct_read_write_fetch_actions(check, project):
    assert check(".env", kind="read").decision == "deny"
    assert check("src/app.py", kind="read").decision == "allow"
    assert check(".git/config", kind="write").decision == "deny"
    assert check(".github/workflows/ci.yml", kind="write").decision == "ask"
    assert check("https://x.ngrok-free.app/a", kind="fetch").decision == "deny"


def test_invalid_values_raise(project):
    with pytest.raises(ValueError):
        build_policy({"preset": "yolo"}, str(project))
    with pytest.raises(ValueError):
        build_policy({"rules": {"overrides": {"privilege": "maybe"}}}, str(project))


def test_load_policy_walks_up_to_project_root(project):
    (project / "shellbouncer.toml").write_text('preset = "strict"\n')
    sub = project / "src" / "deep"
    sub.mkdir(parents=True)
    policy = load_policy(str(sub))
    assert policy.preset == "strict"
    assert policy.project_root == str(project.resolve())


def test_glob_semantics(tmp_path):
    root = "/work/app"
    assert path_matches("/work/app/a/b/.env", ".env", root)
    assert path_matches("/work/app/.git/config", ".git/**", root)
    assert path_matches("/work/app/.git", ".git/**", root)
    assert not path_matches("/work/app/src/.git_stuff", ".git/**", root)
    assert path_matches("/x/y/.claude/settings.json", "**/.claude/settings*.json", root)
