"""Bypass attempts and false-alarm traps found while hardening the rules."""

import pytest

BYPASS_ATTEMPTS = [
    # spelling the same deletion differently
    ("rm -r -f ~", "deny"),
    ("rm --recursive --force ~", "deny"),
    ("/bin/rm -rf ~", "deny"),
    ("command rm -rf ~", "deny"),
    ('rm -rf "$HOME/"', "deny"),
    ("rm -rf ${HOME}", "deny"),
    ("cd ~ && rm -rf *", "deny"),
    ("cd / && rm -rf *", "deny"),
    ("cd /var/tmp/build-cache && rm -rf *", "allow"),
    # secret reads, spelled differently
    ("cat ./.env", "deny"),
    ("less < .env", "deny"),
    ("cat .env | head -1", "deny"),
    ('cat "$HOME/.ssh/id_rsa"', "deny"),
    ("cat ${HOME}/.aws/credentials", "deny"),
    ("ls ~/.ssh && cat ~/.ssh/config", "deny"),
    # git with global options in front
    ("git -C /some/repo push --force", "ask"),
    ("git -c core.hooksPath=/dev/null commit --no-verify -m x", "ask"),
]

FALSE_ALARM_TRAPS = [
    "source .env && npm start",          # sourcing is how apps load config
    "echo 'rm -rf ~' > notes.md",          # text that merely mentions a command
    "git commit -m 'block rm -rf ~ in hooks'",
    "grep -rn 'password' src/",
    "cat package.json | jq .scripts",
    "curl localhost:3000/health",
    "pip install -r requirements.txt",
    "npm run lint -- --fix",
    "python manage.py migrate",
    "git log --oneline | head",
    "ls ~/.ssh",                           # listing names is fine, reading keys is not
]

KNOWN_GAPS = [
    # Documented limitations: shellbouncer reads commands, it does not run them.
    'X=rm; $X -rf ~',
    'python3 -c "import shutil; shutil.rmtree(\'/\')"',
]


@pytest.mark.parametrize("command,expected", BYPASS_ATTEMPTS)
def test_bypass_attempts(check, command, expected):
    assert check(command).decision == expected, check(command).reason


@pytest.mark.parametrize("command", FALSE_ALARM_TRAPS)
def test_no_false_alarm(check, command):
    verdict = check(command)
    assert verdict.decision == "allow", verdict.reason


@pytest.mark.parametrize("command", KNOWN_GAPS)
def test_known_gaps_are_documented(check, command):
    # If one of these starts getting caught, move it to BYPASS_ATTEMPTS and update the README.
    assert check(command).decision == "allow"
