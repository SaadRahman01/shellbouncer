"""Translate between each agent's hook protocol and shellbouncer actions.

Every supported agent sends a JSON payload on stdin before a tool runs and
reads a JSON decision from stdout. The shapes differ slightly:

* Claude Code  -> PreToolUse, ``hookSpecificOutput.permissionDecision`` (allow/ask/deny)
* Codex CLI    -> PreToolUse, same output fields, but only "deny" is honoured
* Gemini CLI   -> BeforeTool, top-level ``decision`` ("allow"/"deny") + ``reason``

shellbouncer never *approves* anything on the agent's behalf: when the policy
says "allow" it prints nothing, so the agent's normal permission prompts
still apply.
"""

from __future__ import annotations

import json
import re
import shlex

from .engine import Action, Verdict

AGENTS = ("claude", "codex", "gemini")

SHELL_TOOLS = {"bash", "shell", "local_shell", "exec_command", "run_shell_command", "terminal",
               "run_terminal_cmd", "execute_command", "powershell", "container.exec"}
WRITE_HINTS = ("write", "edit", "replace", "create", "patch", "notebook", "insert", "delete_file", "move")
READ_HINTS = ("read", "view", "cat", "grep", "glob", "search_file", "list_dir", "ls", "open")
FETCH_HINTS = ("fetch", "web", "browse", "http", "url")
PATH_KEYS = ("file_path", "path", "absolute_path", "notebook_path", "filePath", "filename", "target_file", "dir_path")
URL_RE = re.compile(r"https?://[^\s\"'<>)]+")
PATCH_FILE_RE = re.compile(r"^\*\*\* (?:Add|Update|Delete) File: (.+)$|^\*\*\* Move to: (.+)$", re.M)


def actions_from_payload(payload: dict) -> list[Action]:
    tool = str(payload.get("tool_name") or payload.get("toolName") or "")
    tool_input = payload.get("tool_input") or payload.get("toolArgs") or payload.get("input") or {}
    if isinstance(tool_input, str):
        try:
            tool_input = json.loads(tool_input)
        except ValueError:
            tool_input = {"command": tool_input}
    cwd = payload.get("cwd")
    lowered = tool.lower()
    actions: list[Action] = []

    # Patches can arrive under any key (Codex apply_patch).
    patch_text = next((v for v in _strings(tool_input) if "*** Begin Patch" in v), None)
    if patch_text:
        for m in PATCH_FILE_RE.finditer(patch_text):
            actions.append(Action("write", (m.group(1) or m.group(2)).strip(), tool, cwd))
        return actions

    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if command is not None and (lowered in SHELL_TOOLS or "shell" in lowered or "bash" in lowered or "exec" in lowered or "command" in lowered):
        if isinstance(command, list):
            # ["bash", "-lc", "..."] is how Codex often sends commands.
            command = command[-1] if len(command) >= 3 and command[1] in {"-c", "-lc", "-ic"} else shlex.join(command)
        actions.append(Action("shell", str(command), tool, tool_input.get("workdir") or tool_input.get("cwd") or cwd))
        return actions

    if not isinstance(tool_input, dict):
        return actions

    paths = [str(tool_input[k]) for k in PATH_KEYS if isinstance(tool_input.get(k), str) and tool_input.get(k)]
    for key in ("paths", "file_paths", "edits"):
        value = tool_input.get(key)
        if isinstance(value, list):
            paths += [p if isinstance(p, str) else str(p.get("file_path", "")) for p in value if p]
    if any(h in lowered for h in WRITE_HINTS) and paths:
        actions += [Action("write", p, tool, cwd) for p in paths if p]
    elif any(h in lowered for h in READ_HINTS) and paths:
        actions += [Action("read", p, tool, cwd) for p in paths if p]

    if any(h in lowered for h in FETCH_HINTS) and "search" not in lowered:
        urls = [tool_input["url"]] if isinstance(tool_input.get("url"), str) else []
        if not urls:
            urls = [u for s in _strings(tool_input) for u in URL_RE.findall(s)]
        actions += [Action("fetch", u, tool, cwd) for u in urls]
    return actions


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v)


def format_response(agent: str, verdict: Verdict) -> str:
    """Return what to print on stdout (empty string = no opinion)."""
    if verdict.decision == "allow":
        return ""
    reason = f"shellbouncer: {verdict.reason}"
    decision = verdict.decision
    if agent == "claude":
        if decision == "deny":
            reason += ". Do not try to work around this; tell the user what was blocked and why."
        return json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision,
                "permissionDecisionReason": reason,
            }
        })
    if decision == "ask":
        # Codex and Gemini hooks can't open an approval prompt, so stop and hand it to the human.
        reason += (". This needs the user's approval: stop and ask the user to run it themselves "
                   "or to allow it in shellbouncer.toml. Do not retry it a different way.")
    else:
        reason += ". Do not try to work around this; tell the user what was blocked and why."
    if agent == "codex":
        return json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        })
    if agent == "gemini":
        return json.dumps({"decision": "deny", "reason": reason})
    raise ValueError(f"unknown agent {agent!r}")
