"""Add / remove the shellbouncer hook in each agent's settings file."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

MARKER = "shellbouncer hook"

TARGETS = {
    # agent: (project settings path, global settings path, event name, matcher)
    "claude": (".claude/settings.json", "~/.claude/settings.json", "PreToolUse",
               "Bash|Read|Write|Edit|MultiEdit|NotebookEdit|Grep|Glob|WebFetch"),
    "codex": (".codex/hooks.json", "~/.codex/hooks.json", "PreToolUse", ".*"),
    "gemini": (".gemini/settings.json", "~/.gemini/settings.json", "BeforeTool",
               "run_shell_command|write_file|replace|read_file|read_many_files|list_directory|glob|search_file_content|web_fetch"),
}


def hook_command(agent: str) -> str:
    exe = shutil.which("shellbouncer")
    if exe:
        return f"shellbouncer hook {agent}"
    return f'"{sys.executable}" -m shellbouncer hook {agent}'


def settings_path(agent: str, global_: bool, project_root: str) -> Path:
    project, user, _, _ = TARGETS[agent]
    return Path(user).expanduser() if global_ else Path(project_root) / project


def _load(path: Path) -> dict:
    if not path.exists() or not path.read_text().strip():
        return {}
    try:
        return json.loads(path.read_text())
    except ValueError as exc:
        raise SystemExit(f"error: {path} is not valid JSON ({exc}); fix it and try again") from exc


def _is_ours(entry: dict) -> bool:
    return any(MARKER in str(h.get("command", "")) for h in entry.get("hooks", []))


def install(agent: str, global_: bool, project_root: str) -> tuple[Path, bool]:
    """Returns (settings path, changed?)."""
    _, _, event, matcher = TARGETS[agent]
    path = settings_path(agent, global_, project_root)
    data = _load(path)
    entries = data.setdefault("hooks", {}).setdefault(event, [])
    if any(_is_ours(e) for e in entries):
        return path, False
    hook = {"type": "command", "command": hook_command(agent), "timeout": 10}
    if agent == "gemini":
        hook = {"name": "shellbouncer", "type": "command", "command": hook_command(agent), "timeout": 10000,
                "description": "Blocks dangerous commands and secret access (shellbouncer)"}
    # Put shellbouncer first so it runs before any hook that might auto-approve.
    entries.insert(0, {"matcher": matcher, "hooks": [hook]})
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        shutil.copy2(path, path.with_suffix(path.suffix + ".bak"))
    path.write_text(json.dumps(data, indent=2) + "\n")
    return path, True


def uninstall(agent: str, global_: bool, project_root: str) -> tuple[Path, bool]:
    _, _, event, _ = TARGETS[agent]
    path = settings_path(agent, global_, project_root)
    data = _load(path)
    entries = data.get("hooks", {}).get(event, [])
    kept = [e for e in entries if not _is_ours(e)]
    if len(kept) == len(entries):
        return path, False
    if kept:
        data["hooks"][event] = kept
    else:
        data["hooks"].pop(event, None)
        if not data["hooks"]:
            data.pop("hooks")
    path.write_text(json.dumps(data, indent=2) + "\n")
    return path, True


def status(agent: str, project_root: str) -> list[str]:
    found = []
    for global_ in (False, True):
        path = settings_path(agent, global_, project_root)
        try:
            data = _load(path)
        except SystemExit:
            continue
        event = TARGETS[agent][2]
        if any(_is_ours(e) for e in data.get("hooks", {}).get(event, [])):
            found.append(str(path))
    return found
