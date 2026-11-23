"""Policy loading, presets and path/domain matching."""

from __future__ import annotations

import copy
import fnmatch
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

POLICY_FILENAMES = ("shellbouncer.toml", ".shellbouncer.toml")
DECISIONS = ("allow", "ask", "deny")
RANK = {"allow": 0, "ask": 1, "deny": 2}

SECRET_FILES = [
    ".env", ".env.*", "*.env", ".envrc", ".netrc", ".npmrc", ".pypirc", ".pgpass",
    "*.pem", "*.key", "*.p12", "*.pfx", "*.keystore", "*.jks",
    "id_rsa*", "id_ed25519*", "id_ecdsa*", "id_dsa*",
    "credentials.json", "service-account*.json", "*.tfstate", "*.tfvars",
    "~/.ssh/**", "~/.aws/**", "~/.gnupg/**", "~/.kube/config", "~/.docker/config.json",
    "~/.config/gcloud/**", "~/.azure/**", "~/.config/gh/hosts.yml",
    "~/.git-credentials", "~/.password-store/**",
    "~/Library/Keychains/**", "~/.local/share/keyrings/**",
]
# Keep obviously-safe templates readable.
SECRET_EXCEPTIONS = [".env.example", ".env.sample", ".env.template", ".env.dist", "*.example.json"]

EXFIL_DOMAINS = [
    "webhook.site", "requestbin.com", "*.requestbin.net", "pipedream.net", "*.m.pipedream.net",
    "pastebin.com", "paste.ee", "hastebin.com", "ghostbin.com", "transfer.sh", "file.io",
    "0x0.st", "termbin.com", "*.ngrok.io", "*.ngrok-free.app", "*.ngrok.app",
    "*.trycloudflare.com", "*.oast.fun", "*.oast.me", "*.interact.sh", "*.burpcollaborator.net",
    "*.serveo.net", "*.loca.lt", "discord.com/api/webhooks", "api.telegram.org",
]
def default_temp_dirs() -> list[str]:
    dirs = ["/tmp", "/var/tmp", "/private/tmp", "/private/var/folders", "/var/folders", "/dev/shm"]
    if os.environ.get("TMPDIR"):
        dirs.append(os.path.normpath(os.environ["TMPDIR"]))
    return dirs


DEV_DOMAINS = [
    "github.com", "*.github.com", "*.githubusercontent.com", "gitlab.com", "bitbucket.org",
    "pypi.org", "files.pythonhosted.org", "registry.npmjs.org", "*.npmjs.org", "npmjs.com",
    "crates.io", "*.crates.io", "proxy.golang.org", "pkg.go.dev", "rubygems.org",
    "docs.python.org", "developer.mozilla.org", "stackoverflow.com", "*.readthedocs.io",
    "*.docker.io", "*.docker.com", "ghcr.io", "deno.land", "jsr.io",
]

PRESETS: dict[str, dict] = {
    "chill": {
        "description": "Only blocks catastrophic or clearly malicious actions.",
        "files": {
            "deny_read": [], "deny_write": ["~/.ssh/**", "~/.aws/**"], "ask_write": [],
            "outside_project_write": "allow",
        },
        "network": {"default": "allow", "allow": [], "deny": EXFIL_DOMAINS, "ask": []},
        "rules": {"overrides": {
            "privilege": "allow", "git-history": "allow", "publish": "allow",
            "env-dump": "allow", "network-tools": "allow", "infra-destroy": "ask",
            "data-destroy": "allow", "upload": "ask",
        }},
    },
    "balanced": {
        "description": "Blocks destruction and secret leaks, asks before risky-but-normal actions.",
        "files": {
            "deny_read": SECRET_FILES, "deny_write": ["~/.ssh/**", "~/.aws/**", "~/.gnupg/**", ".git/**"],
            "ask_write": [
                ".github/workflows/**", "~/.bashrc", "~/.zshrc", "~/.profile", "~/.bash_profile",
                "~/.gitconfig", "~/.config/**", "**/.claude/settings*.json", "**/.codex/**",
                "**/.gemini/settings.json", "shellbouncer.toml", ".shellbouncer.toml",
            ],
            "outside_project_write": "ask",
        },
        "network": {"default": "allow", "allow": [], "deny": EXFIL_DOMAINS, "ask": []},
        "rules": {"overrides": {}},
    },
    "strict": {
        "description": "For untrusted repos or unattended agents. Unknown network and outside writes are blocked.",
        "files": {
            "deny_read": SECRET_FILES + ["~/.bash_history", "~/.zsh_history"],
            "deny_write": ["~/**/.ssh/**", "~/.aws/**", "~/.gnupg/**", ".git/**", "~/.bashrc", "~/.zshrc"],
            "ask_write": [
                ".github/workflows/**", "**/.claude/**", "**/.codex/**", "**/.gemini/**",
                "Dockerfile", "**/*.lock", "package.json", "pyproject.toml", "Makefile",
                "shellbouncer.toml", ".shellbouncer.toml",
            ],
            "outside_project_write": "deny",
        },
        "network": {"default": "ask", "allow": DEV_DOMAINS, "deny": EXFIL_DOMAINS, "ask": []},
        "rules": {"overrides": {
            "privilege": "deny", "git-history": "deny", "publish": "deny", "infra-destroy": "deny",
            "env-dump": "deny", "upload": "deny",
        }},
    },
}


@dataclass
class Policy:
    preset: str = "balanced"
    project_root: str = field(default_factory=os.getcwd)
    source: str | None = None
    shell_deny: list[str] = field(default_factory=list)
    shell_ask: list[str] = field(default_factory=list)
    shell_allow: list[str] = field(default_factory=list)
    deny_read: list[str] = field(default_factory=list)
    allow_read: list[str] = field(default_factory=list)
    deny_write: list[str] = field(default_factory=list)
    ask_write: list[str] = field(default_factory=list)
    allow_write: list[str] = field(default_factory=list)
    outside_project_write: str = "ask"
    temp_dirs: list[str] = field(default_factory=default_temp_dirs)
    network_default: str = "allow"
    network_allow: list[str] = field(default_factory=list)
    network_ask: list[str] = field(default_factory=list)
    network_deny: list[str] = field(default_factory=list)
    disabled_rules: set[str] = field(default_factory=set)
    rule_overrides: dict[str, str] = field(default_factory=dict)
    audit_log: bool = True
    log_allowed: bool = False
    fail_closed: bool = False

    # ------------------------------------------------------------------ matching

    def resolve(self, path: str, cwd: str | None = None) -> str:
        return resolve_path(path, cwd or self.project_root)

    def in_project(self, abspath: str) -> bool:
        root = os.path.normpath(self.project_root)
        return abspath == root or abspath.startswith(root.rstrip(os.sep) + os.sep)

    def match_path(self, abspath: str, patterns: list[str]) -> str | None:
        for pattern in patterns:
            if path_matches(abspath, pattern, self.project_root):
                return pattern
        return None

    def is_secret(self, abspath: str) -> str | None:
        if self.match_path(abspath, SECRET_EXCEPTIONS) or self.match_path(abspath, self.allow_read):
            return None
        return self.match_path(abspath, self.deny_read)


def resolve_path(path: str, cwd: str) -> str:
    path = path.strip().strip("'\"")
    home = os.path.expanduser("~")
    path = re.sub(r"^(\$HOME|\$\{HOME\})(?=/|$)", home, path)
    path = os.path.expanduser(path)
    if not os.path.isabs(path):
        path = os.path.join(cwd, path)
    return os.path.normpath(path)


def _glob_to_regex(pattern: str) -> re.Pattern:
    out, i = [], 0
    while i < len(pattern):
        if pattern.endswith("/**") and i == len(pattern) - 3:
            out.append("(?:/.*)?")  # `dir/**` also matches `dir` itself
            i += 3
        elif pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("^" + "".join(out) + "$")


_REGEX_CACHE: dict[str, re.Pattern] = {}


def path_matches(abspath: str, pattern: str, project_root: str) -> bool:
    """gitignore-style matching.

    * no slash (``.env``, ``*.pem``)   -> matches the file name anywhere
    * starts with ``~`` or ``/``       -> absolute pattern
    * anything else (``.git/**``)      -> relative to the project root
    """
    if "/" not in pattern:
        return fnmatch.fnmatchcase(os.path.basename(abspath), pattern)
    if pattern.startswith("~"):
        pattern = os.path.expanduser("~") + pattern[1:]
    elif not pattern.startswith("/"):
        if pattern.startswith("**/"):
            pattern = "/" + pattern  # match at any depth, anywhere
            regex = _REGEX_CACHE.setdefault(pattern, _glob_to_regex(pattern))
            return bool(regex.match(abspath))
        pattern = os.path.normpath(project_root).rstrip("/") + "/" + pattern
    regex = _REGEX_CACHE.setdefault(pattern, _glob_to_regex(pattern))
    return bool(regex.match(abspath))


def domain_matches(host: str, url_path: str, pattern: str) -> bool:
    host = host.lower().rstrip(".")
    pattern = pattern.lower()
    path_part = ""
    if "/" in pattern:
        pattern, path_part = pattern.split("/", 1)
    if pattern.startswith("*."):
        base = pattern[2:]
        ok = host == base or host.endswith("." + base)
    else:
        ok = host == pattern or host.endswith("." + pattern)
    if ok and path_part:
        ok = url_path.lstrip("/").startswith(path_part)
    return ok


# ---------------------------------------------------------------------- loading

def find_policy_file(start: str) -> Path | None:
    current = Path(start).resolve()
    for directory in (current, *current.parents):
        for name in POLICY_FILENAMES:
            candidate = directory / name
            if candidate.is_file():
                return candidate
        if (directory / ".git").exists():
            break
    user = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "shellbouncer" / "shellbouncer.toml"
    return user if user.is_file() else None


def find_project_root(start: str) -> str:
    current = Path(start).resolve()
    for directory in (current, *current.parents):
        if (directory / ".git").exists() or any((directory / n).is_file() for n in POLICY_FILENAMES):
            return str(directory)
    return str(current)


def load_policy(cwd: str | None = None, path: str | None = None) -> Policy:
    cwd = cwd or os.getcwd()
    policy_path = Path(path) if path else find_policy_file(cwd)
    data: dict = {}
    if policy_path:
        if tomllib is None:  # pragma: no cover
            raise RuntimeError("shellbouncer needs Python 3.11+ to read TOML policy files")
        with open(policy_path, "rb") as fh:
            data = tomllib.load(fh)
    return build_policy(data, find_project_root(cwd), str(policy_path) if policy_path else None)


def build_policy(data: dict, project_root: str, source: str | None = None) -> Policy:
    preset_name = data.get("preset", "balanced")
    if preset_name not in PRESETS:
        raise ValueError(f"unknown preset {preset_name!r}; choose one of {', '.join(PRESETS)}")
    preset = copy.deepcopy(PRESETS[preset_name])
    shell = data.get("shell", {})
    files = data.get("files", {})
    net = data.get("network", {})
    rules = data.get("rules", {})

    def merged(section_default: dict, section: dict, key: str) -> list[str]:
        return list(section_default.get(key, [])) + list(section.get(key, []))

    overrides = dict(preset["rules"].get("overrides", {}))
    overrides.update(rules.get("overrides", {}))
    for name, value in overrides.items():
        if value not in DECISIONS:
            raise ValueError(f"rules.overrides.{name} must be one of {DECISIONS}, got {value!r}")

    policy = Policy(
        preset=preset_name,
        project_root=project_root,
        source=source,
        shell_deny=list(shell.get("deny", [])),
        shell_ask=list(shell.get("ask", [])),
        shell_allow=list(shell.get("allow", [])),
        deny_read=merged(preset["files"], files, "deny_read"),
        allow_read=list(files.get("allow_read", [])),
        deny_write=merged(preset["files"], files, "deny_write"),
        ask_write=merged(preset["files"], files, "ask_write"),
        allow_write=list(files.get("allow_write", [])),
        outside_project_write=files.get("outside_project_write", preset["files"]["outside_project_write"]),
        temp_dirs=list(files["temp_dirs"]) if "temp_dirs" in files else default_temp_dirs(),
        network_default=net.get("default", preset["network"]["default"]),
        network_allow=merged(preset["network"], net, "allow"),
        network_ask=merged(preset["network"], net, "ask"),
        network_deny=merged(preset["network"], net, "deny"),
        disabled_rules=set(rules.get("disable", [])),
        rule_overrides=overrides,
        audit_log=data.get("audit", {}).get("enabled", True),
        log_allowed=data.get("audit", {}).get("log_allowed", False),
        fail_closed=data.get("fail_closed", False),
    )
    for name in ("outside_project_write", "network_default"):
        if getattr(policy, name) not in DECISIONS:
            raise ValueError(f"{name} must be one of {DECISIONS}")
    return policy
