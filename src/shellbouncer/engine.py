"""Turn an agent action into a single allow / ask / deny verdict."""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field

from . import rules as R
from .policy import RANK, Policy
from .shell import parse


@dataclass
class Action:
    """What the agent wants to do, independent of which agent it is."""

    kind: str  # "shell" | "read" | "write" | "fetch" | "other"
    value: str = ""
    tool: str = ""
    cwd: str | None = None


@dataclass
class Finding:
    rule: str
    decision: str
    message: str


@dataclass
class Verdict:
    decision: str = "allow"
    findings: list[Finding] = field(default_factory=list)

    @property
    def reason(self) -> str:
        relevant = [f for f in self.findings if f.decision == self.decision] or self.findings
        lines = [f"[{f.rule}] {f.message}" for f in relevant]
        return "; ".join(dict.fromkeys(lines))

    def merge(self, other: Verdict) -> Verdict:
        decision = max(self.decision, other.decision, key=RANK.__getitem__)
        return Verdict(decision, self.findings + other.findings)


def evaluate(action: Action, policy: Policy) -> Verdict:
    ctx = R.Context(policy=policy, cwd=action.cwd or policy.project_root)
    hits: list[R.Hit] = []

    if action.kind == "shell":
        hits = list(_shell_hits(action.value, ctx))
    elif action.kind == "read":
        hits = list(R.check_read(ctx.path(action.value), ctx))
    elif action.kind == "write":
        hits = list(R.check_write(ctx.path(action.value), ctx))
    elif action.kind == "fetch":
        hits = list(R.check_url(action.value, ctx, "fetch"))

    findings = []
    for rule, decision, message in hits:
        if rule in policy.disabled_rules:
            continue
        if rule in policy.rule_overrides and not rule.startswith("policy:"):
            decision = policy.rule_overrides[rule]
        if decision != "allow":
            findings.append(Finding(rule, decision, message))
    decision = max((f.decision for f in findings), key=RANK.__getitem__, default="allow")
    return Verdict(decision, findings)


def evaluate_all(actions: list[Action], policy: Policy) -> Verdict:
    verdict = Verdict()
    for action in actions:
        verdict = verdict.merge(evaluate(action, policy))
    return verdict


def _shell_hits(command: str, ctx: R.Context):
    parsed = parse(command)
    policy = ctx.policy
    explicitly_allowed: set[int] = set()

    cwd = ctx.cwd
    for cmd in parsed.commands():
        # Follow `cd dir && ...` so later commands are judged in the right folder.
        if cmd.name in {"cd", "pushd"}:
            target = next((a for a in cmd.args if not a.startswith("-")), "~")
            if "__SUBST" not in target:
                cwd = R.resolve_path(target, cwd)
            continue
        ctx = R.Context(policy=policy, cwd=cwd)
        candidates = {cmd.text, " ".join(cmd.wrappers + cmd.argv)}
        user = _user_shell_decision(candidates, policy)
        if user == "deny":
            yield ("policy:shell.deny", "deny", f"matches your shell.deny list: {cmd.text}")
        elif user == "ask":
            yield ("policy:shell.ask", "ask", f"matches your shell.ask list: {cmd.text}")
        if user == "allow":
            explicitly_allowed.add(id(cmd))
            continue
        yield from R.command_rules(cmd, ctx)

    # Whole-command rules (pipelines, substitutions) can't be allow-listed per command,
    # unless every command involved was explicitly allowed.
    all_cmds = list(parsed.commands())
    if not all_cmds or not all(id(c) in explicitly_allowed for c in all_cmds):
        yield from R.shell_rules(parsed, ctx)

    # Raw-string user patterns, for things like "*--no-preserve-root*".
    raw = " ".join(command.split())
    for pattern in policy.shell_deny:
        if any(ch in pattern for ch in "*?[") and fnmatch.fnmatchcase(raw, pattern) and not any(
            fnmatch.fnmatchcase(c.text, pattern) for c in all_cmds
        ):
            yield ("policy:shell.deny", "deny", f"matches your shell.deny pattern {pattern!r}")


def _user_shell_decision(candidates: set[str], policy: Policy) -> str | None:
    def hit(patterns: list[str]) -> bool:
        return any(fnmatch.fnmatchcase(c, p) or c == p for c in candidates for p in patterns)

    if hit(policy.shell_deny):
        return "deny"
    if hit(policy.shell_ask):
        return "ask"
    if hit(policy.shell_allow):
        return "allow"
    return None


def describe_cwd(action: Action) -> str:
    return action.cwd or os.getcwd()
