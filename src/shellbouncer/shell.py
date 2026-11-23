"""Parse shell command strings into simple commands.

Coding agents rarely run a single command. They chain them with ``&&``,
pipe them, hide them in ``$(...)``, wrap them in ``sudo`` or ``bash -c``.
A regex over the raw string misses most of that, so shellbouncer splits the
string into pipelines of simple commands first and checks each one.

The parser is deliberately forgiving: it never raises on odd input and
falls back to a plain whitespace split when quoting is unbalanced.
"""

from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass, field

SEPARATORS = {";", "&&", "||", "&", ";;", "(", ")", "\n", "{", "}"}
PIPES = {"|", "|&"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "ash"}
INTERPRETERS = SHELLS | {"python", "python3", "python2", "perl", "ruby", "node", "deno", "bun", "php", "pwsh", "powershell"}

# Prefix commands that run another command. Value = how many option-less
# arguments they take before the real command starts.
WRAPPERS = {
    "sudo": 0, "doas": 0, "nohup": 0, "time": 0, "command": 0, "exec": 0,
    "nice": 0, "ionice": 0, "stdbuf": 0, "env": 0, "timeout": 1, "watch": 0,
    "caffeinate": 0, "chronic": 0, "unbuffer": 0, "builtin": 0,
}
# Wrapper options that consume a value (e.g. ``sudo -u root``).
WRAPPER_VALUE_FLAGS = {
    "sudo": {"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U"},
    "doas": {"-u", "-C"},
    "nice": {"-n"},
    "ionice": {"-c", "-n", "-p"},
    "timeout": {"-s", "-k", "--signal", "--kill-after"},
    "env": {"-u", "-C", "-S", "--unset", "--chdir"},
    "watch": {"-n", "-d", "--interval"},
}

ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
FORK_BOMB = re.compile(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;?\s*:")


@dataclass
class Command:
    """One simple command, e.g. ``rm -rf build`` inside ``make && rm -rf build``."""

    argv: list[str]
    wrappers: list[str] = field(default_factory=list)
    writes: list[str] = field(default_factory=list)  # output redirection targets
    reads: list[str] = field(default_factory=list)  # input redirection sources
    substitutions: list[int] = field(default_factory=list)  # ids of $(...) used as args

    @property
    def name(self) -> str:
        return os.path.basename(self.argv[0]) if self.argv else ""

    @property
    def args(self) -> list[str]:
        return self.argv[1:]

    @property
    def text(self) -> str:
        return " ".join(self.argv)

    def has_flag(self, *flags: str) -> bool:
        """True if any flag is present. Short flags also match inside bundles (-rf)."""
        for arg in self.args:
            if arg == "--":
                break
            for flag in flags:
                if arg == flag or (flag.startswith("--") and arg.startswith(flag + "=")):
                    return True
                if len(flag) == 2 and flag[0] == "-" and flag[1] != "-":
                    if arg.startswith("-") and not arg.startswith("--") and flag[1] in arg[1:]:
                        return True
        return False

    def positional(self) -> list[str]:
        out, after_dd = [], False
        for arg in self.args:
            if after_dd:
                out.append(arg)
            elif arg == "--":
                after_dd = True
            elif not arg.startswith("-") or arg == "-":
                out.append(arg)
        return out


@dataclass
class ParsedShell:
    pipelines: list[list[Command]]
    substitutions: dict[int, ParsedShell]
    raw: str

    def commands(self):
        """Every simple command, including ones nested in substitutions and bash -c."""
        for pipeline in self.pipelines:
            yield from pipeline
        for sub in self.substitutions.values():
            yield from sub.commands()

    def all_pipelines(self):
        yield from self.pipelines
        for sub in self.substitutions.values():
            yield from sub.all_pipelines()


def parse(command: str, _depth: int = 0) -> ParsedShell:
    raw = command or ""
    text = _strip_heredocs(raw)
    text, subs = _extract_substitutions(text, _depth)
    tokens = _tokenize(text)
    pipelines = _build_pipelines(tokens)

    # Recurse into `bash -c "..."`, `eval ...`, `xargs cmd`, `find -exec cmd`.
    if _depth < 4:
        extra: list[list[Command]] = []
        for pipeline in pipelines:
            for cmd in pipeline:
                inner = _inner_script(cmd)
                if inner:
                    nested = parse(inner, _depth + 1)
                    extra.extend(nested.pipelines)
                    subs.update(nested.substitutions)
        pipelines.extend(extra)
    return ParsedShell(pipelines=pipelines, substitutions=subs, raw=raw)


def has_fork_bomb(command: str) -> bool:
    return bool(FORK_BOMB.search(command or ""))


# --------------------------------------------------------------------------- internals

def _strip_heredocs(text: str) -> str:
    """Drop heredoc bodies so their *content* isn't mistaken for commands."""
    lines = text.split("\n")
    out, i = [], 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        match = HEREDOC.search(line)
        i += 1
        if match:
            delim = match.group(2)
            while i < len(lines) and lines[i].strip() != delim:
                i += 1
            i += 1  # skip the delimiter line
    return "\n".join(out)


_SUB_COUNTER = [0]


def _extract_substitutions(text: str, depth: int) -> tuple[str, dict[int, ParsedShell]]:
    """Replace $(...), `...`, <(...) and >(...) with placeholders and parse their insides."""
    subs: dict[int, ParsedShell] = {}
    out: list[str] = []
    i, n = 0, len(text)
    in_single = in_double = False
    while i < n:
        ch = text[i]
        if ch == "\\" and not in_single and i + 1 < n:
            out.append(text[i : i + 2])
            i += 2
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        if not in_single:
            opener = None
            if text.startswith("$(", i) and not text.startswith("$((", i):
                opener = 2
            elif text.startswith(("<(", ">("), i) and not in_double:
                opener = 2
            if opener:
                end = _matching_paren(text, i + opener - 1)
                inner = text[i + opener : end]
                sid = _next_id()
                subs[sid] = parse(inner, depth + 1) if depth < 4 else ParsedShell([], {}, inner)
                out.append(f" __SUBST{sid}__ " if not in_double else f"__SUBST{sid}__")
                i = end + 1
                continue
            if ch == "`":
                end = text.find("`", i + 1)
                end = n if end == -1 else end
                inner = text[i + 1 : end]
                sid = _next_id()
                subs[sid] = parse(inner, depth + 1) if depth < 4 else ParsedShell([], {}, inner)
                out.append(f"__SUBST{sid}__")
                i = end + 1
                continue
        out.append(ch)
        i += 1
    return "".join(out), subs


def _next_id() -> int:
    _SUB_COUNTER[0] += 1
    return _SUB_COUNTER[0]


def _matching_paren(text: str, open_idx: int) -> int:
    depth, i = 0, open_idx
    in_single = in_double = False
    while i < len(text):
        ch = text[i]
        if ch == "\\" and not in_single:
            i += 2
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif not in_single and not in_double:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    return len(text)


def _tokenize(text: str) -> list[str]:
    # Unquoted newlines separate commands; shlex would treat them as spaces.
    text = _newlines_to_separators(text)
    try:
        lexer = shlex.shlex(text, posix=True, punctuation_chars=";&|<>()")
        lexer.whitespace_split = True
        lexer.commenters = "#"
        return _split_operators(list(lexer))
    except ValueError:
        # Unbalanced quotes: degrade to a rough split rather than failing open.
        rough = re.sub(r"(\|\||&&|[;|&<>()])", r" \1 ", text.replace('"', " ").replace("'", " "))
        return rough.split()


_OPERATORS = sorted(
    ["&&", "||", ";;", "|&", ">>", "<<<", "<<-", "<<", "&>>", "&>", ">&", "<&", ">|",
     ";", "&", "|", "(", ")", "<", ">"],
    key=len, reverse=True,
)
_PUNCT = set(";&|<>()")


def _split_operators(tokens: list[str]) -> list[str]:
    """shlex glues adjacent operators together (`);`), so split them apart."""
    out: list[str] = []
    for tok in tokens:
        if not tok or not set(tok) <= _PUNCT or tok in _OPERATORS:
            out.append(tok)
            continue
        i = 0
        while i < len(tok):
            for op in _OPERATORS:
                if tok.startswith(op, i):
                    out.append(op)
                    i += len(op)
                    break
            else:
                out.append(tok[i])
                i += 1
    return out


def _newlines_to_separators(text: str) -> str:
    out, in_single, in_double, i = [], False, False, 0
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text) and text[i + 1] == "\n":
            i += 2  # line continuation
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        out.append(" ; " if ch == "\n" and not in_single and not in_double else ch)
        i += 1
    return "".join(out)


def _build_pipelines(tokens: list[str]) -> list[list[Command]]:
    pipelines: list[list[Command]] = []
    current: list[Command] = []
    words: list[str] = []
    writes: list[str] = []
    reads: list[str] = []

    def flush_command():
        nonlocal words, writes, reads
        if words or writes or reads:
            cmd = _make_command(words)
            cmd.writes.extend(writes)
            cmd.reads.extend(reads)
            current.append(cmd)
        words, writes, reads = [], [], []

    def flush_pipeline():
        nonlocal current
        flush_command()
        if current:
            pipelines.append(current)
        current = []

    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in SEPARATORS:
            flush_pipeline()
        elif tok in PIPES:
            flush_command()
        elif tok and set(tok) <= set("<>&|") and ("<" in tok or ">" in tok):
            # Redirection. Drop a preceding fd number (2>file).
            if words and words[-1] in {"0", "1", "2"}:
                words.pop()
            target = tokens[i + 1] if i + 1 < len(tokens) else ""
            i += 1
            if tok in {"<<", "<<-", "<<<"}:
                pass  # heredoc / herestring, not a file
            elif target.isdigit() or target == "-":
                pass  # fd duplication like 2>&1
            elif ">" in tok:
                writes.append(target)
            else:
                reads.append(target)
        else:
            words.append(tok)
        i += 1
    flush_pipeline()
    return pipelines


def _make_command(words: list[str]) -> Command:
    words = list(words)
    wrappers: list[str] = []
    changed = True
    while words and changed:
        changed = False
        while words and ASSIGNMENT.match(words[0]):
            words.pop(0)
            changed = True
        if words and os.path.basename(words[0]) in WRAPPERS:
            before = list(words)
            name = os.path.basename(words.pop(0))
            value_flags = WRAPPER_VALUE_FLAGS.get(name, set())
            while words and words[0].startswith("-") and words[0] != "--":
                flag = words.pop(0)
                if flag in value_flags and words:
                    words.pop(0)
            if words and words[0] == "--":
                words.pop(0)
            for _ in range(WRAPPERS[name]):
                if words:
                    words.pop(0)
            while words and ASSIGNMENT.match(words[0]):
                words.pop(0)
            if not words:
                # Bare `env` / `sudo -l`: the wrapper *is* the command.
                words = before
                break
            wrappers.append(name)
            changed = True
    subs = [int(m.group(1)) for w in words for m in re.finditer(r"__SUBST(\d+)__", w)]
    return Command(argv=words, wrappers=wrappers, substitutions=subs)


def _inner_script(cmd: Command) -> str | None:
    """Return the script hidden inside a command, if any."""
    name = cmd.name
    args = cmd.args
    if name in SHELLS:
        for idx, arg in enumerate(args):
            if arg.startswith("-") and not arg.startswith("--") and "c" in arg[1:] and idx + 1 < len(args):
                return args[idx + 1]
    if name == "eval" and args:
        return " ".join(args)
    if name == "xargs":
        rest = list(args)
        while rest and rest[0].startswith("-"):
            flag = rest.pop(0)
            if flag in {"-I", "-n", "-P", "-L", "-d", "-E", "-s", "-a"} and rest:
                rest.pop(0)
        return shlex.join(rest) if rest else None
    if name == "find":
        for flag in ("-exec", "-execdir", "-ok", "-okdir"):
            if flag in args:
                start = args.index(flag) + 1
                inner = []
                for arg in args[start:]:
                    if arg in {";", "+", "\\;"}:
                        break
                    inner.append(arg)
                return shlex.join(inner) if inner else None
    return None
