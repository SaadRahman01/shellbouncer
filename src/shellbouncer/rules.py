"""Built-in rules: the dangerous things agents actually do.

Each rule looks at one simple command (or one pipeline) and yields
``(rule_id, decision, message)`` tuples. Users can switch rules off or
change their decision in ``shellbouncer.toml``::

    [rules]
    disable = ["privilege"]
    overrides = { git-history = "deny" }
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterator
from dataclasses import dataclass

from .policy import Policy, resolve_path
from .shell import INTERPRETERS, Command, ParsedShell, has_fork_bomb

Hit = tuple[str, str, str]  # (rule id, decision, message)

RULES: dict[str, str] = {
    "recursive-delete": "rm -rf (or find -delete) on /, your home folder, a system folder or the whole project",
    "pipe-to-shell": "Runs a downloaded or base64-decoded script in one go (curl ... | sh, bash <(curl ...))",
    "disk-destroy": "Formats disks, writes raw to devices, fork bombs, chmod -R 777 /, shutdown",
    "secret-file": "Reads, copies or uploads a secret file (.env, SSH keys, cloud credentials)",
    "secret-commit": "Stages a secret file in git",
    "env-dump": "Prints all environment variables or a secret-looking variable",
    "upload": "Sends local files or data to a remote server (curl -d @file, -T, scp, rsync)",
    "network-tools": "Raw sockets and tunnels (nc, socat, telnet, ssh -R)",
    "reverse-shell": "Gives a remote machine control of your shell (nc -e, bash -i >& /dev/tcp/...)",
    "privilege": "Runs as root (sudo, doas, su)",
    "git-history": "Force push, reset --hard, clean -f, branch -D, --no-verify, discarding changes",
    "publish": "Publishes packages, images or releases (npm publish, twine upload, docker push)",
    "infra-destroy": "Destroys cloud or cluster resources (terraform destroy, kubectl delete)",
    "data-destroy": "DROP / TRUNCATE / FLUSHALL against a database",
    "protected-path": "Writes to a path your policy protects",
    "outside-project": "Writes outside the project folder",
    "network": "Contacts a domain your policy blocks or hasn't allowed",
}

READERS = {
    "cat", "less", "more", "head", "tail", "bat", "batcat", "grep", "egrep", "fgrep", "rg", "ag",
    "strings", "xxd", "hexdump", "od", "base64", "base32", "nl", "tac", "sort", "uniq", "awk",
    "sed", "cut", "diff", "cmp", "jq", "yq", "openssl", "gpg", "tar", "zip", "7z", "gzip",
    "bzip2", "xz", "scp", "rsync", "pbcopy", "xclip", "xsel", "python",
    "python3", "node", "ruby", "perl", "type", "Get-Content", "gc", "view", "vim", "nano", "code",
    "cp", "dd", "iconv", "column", "fold", "paste", "split",
}
DOWNLOADERS = {"curl", "wget", "fetch", "aria2c", "http", "https", "xh", "iwr", "irm", "Invoke-WebRequest"}
NETWORK_TOOLS = {"curl", "wget", "http", "https", "xh", "aria2c", "fetch"}
SECRET_VAR = re.compile(r"\$\{?[A-Za-z0-9_]*(SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIAL)[A-Za-z0-9_]*\}?", re.I)
URL = re.compile(r"^(?:[a-zA-Z][a-zA-Z0-9+.-]*://)([^/\s:?#@]+@)?([^/\s:?#]+)(?::\d+)?([^\s]*)")
BARE_HOST = re.compile(r"^([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,})(?::\d+)?(/\S*)?$")
SYSTEM_DIRS = {
    "/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64", "/opt", "/proc", "/root",
    "/sbin", "/srv", "/sys", "/usr", "/var", "/System", "/Library", "/Applications", "/Users",
    "/private", "/Volumes", "C:", "C:\\",
}
HARMLESS_WRITES = {"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty", "/dev/zero"}


@dataclass
class Context:
    policy: Policy
    cwd: str

    @property
    def home(self) -> str:
        return os.path.expanduser("~")

    def path(self, p: str) -> str:
        return resolve_path(p, self.cwd)


# ------------------------------------------------------------------ file checks

def check_read(abspath: str, ctx: Context, how: str = "read") -> Iterator[Hit]:
    pattern = ctx.policy.is_secret(abspath)
    if pattern:
        yield ("secret-file", "deny", f"{how} {_short(abspath, ctx)} looks like a secret (matches {pattern!r})")


def check_write(abspath: str, ctx: Context, how: str = "write to") -> Iterator[Hit]:
    p = ctx.policy
    if abspath in HARMLESS_WRITES or abspath.startswith("/dev/fd/"):
        return
    pattern = p.match_path(abspath, p.deny_write)
    if pattern:
        yield ("protected-path", "deny", f"{how} {_short(abspath, ctx)} is blocked (matches {pattern!r})")
        return
    if p.match_path(abspath, p.allow_write):
        return
    pattern = p.match_path(abspath, p.ask_write)
    if pattern:
        yield ("protected-path", "ask", f"{how} {_short(abspath, ctx)} needs approval (matches {pattern!r})")
        return
    temp = tuple(d.rstrip("/") + "/" for d in p.temp_dirs)
    if not p.in_project(abspath) and not (abspath + "/").startswith(temp):
        if p.outside_project_write != "allow":
            yield ("outside-project", p.outside_project_write, f"{how} {_short(abspath, ctx)} is outside the project")


def check_url(url: str, ctx: Context, how: str = "contact") -> Iterator[Hit]:
    host, path = split_url(url)
    if not host:
        return
    p = ctx.policy
    from .policy import domain_matches

    for pattern in p.network_deny:
        if domain_matches(host, path, pattern):
            yield ("network", "deny", f"{how} {host} is blocked (matches {pattern!r}; often used to exfiltrate data)")
            return
    for pattern in p.network_allow:
        if domain_matches(host, path, pattern):
            return
    for pattern in p.network_ask:
        if domain_matches(host, path, pattern):
            yield ("network", "ask", f"{how} {host} needs approval (matches {pattern!r})")
            return
    if p.network_default != "allow":
        yield ("network", p.network_default, f"{how} {host}: domain is not on the allow list")


def split_url(url: str) -> tuple[str | None, str]:
    url = url.strip().strip("'\"")
    m = URL.match(url)
    if m:
        return m.group(2).lower(), m.group(3) or ""
    m = BARE_HOST.match(url)
    if m and not os.path.exists(url):
        return m.group(1).lower(), m.group(2) or ""
    return None, ""


def _short(abspath: str, ctx: Context) -> str:
    root = ctx.policy.project_root.rstrip("/") + "/"
    if abspath.startswith(root):
        return abspath[len(root):]
    home = ctx.home.rstrip("/") + "/"
    if abspath.startswith(home):
        return "~/" + abspath[len(home):]
    return abspath


# ------------------------------------------------------------------ per-command rules

def command_rules(cmd: Command, ctx: Context) -> Iterator[Hit]:
    name = cmd.name
    if not name and not cmd.writes:
        return

    # privilege ----------------------------------------------------------
    if any(w in {"sudo", "doas"} for w in cmd.wrappers) or name in {"su", "pkexec", "sudo", "doas"}:
        yield ("privilege", "ask", f"runs as root: {cmd.text or name}")

    # redirections -------------------------------------------------------
    for target in cmd.writes + cmd.reads:
        if target.startswith(("/dev/tcp/", "/dev/udp/")):
            yield ("reverse-shell", "deny", f"connects the shell to a remote machine via {target}")
    for target in cmd.writes:
        if target.startswith(("/dev/tcp/", "/dev/udp/")):
            continue
        if re.match(r"^/dev/(sd|hd|nvme|disk|mmcblk|xvd|vd)", target):
            yield ("disk-destroy", "deny", f"writes raw data to device {target}")
        elif target and "__SUBST" not in target:
            yield from check_write(ctx.path(target), ctx)
    for source in cmd.reads:
        if not source.startswith(("/dev/tcp/", "/dev/udp/")) and "__SUBST" not in source:
            yield from check_read(ctx.path(source), ctx)

    yield from _recursive_delete(cmd, ctx)
    yield from _disk_and_system(cmd, ctx)
    yield from _file_effects(cmd, ctx)
    yield from _git(cmd, ctx)
    yield from _env_dump(cmd)
    yield from _network(cmd, ctx)
    yield from _publish_and_infra(cmd)
    yield from _data_destroy(cmd)


def _danger_target(abspath: str, ctx: Context) -> str | None:
    home = os.path.normpath(ctx.home)
    root = os.path.normpath(ctx.policy.project_root)
    if abspath == "/":
        return "the whole disk"
    if abspath == home:
        return "your home folder"
    if abspath in SYSTEM_DIRS or os.path.dirname(abspath) == "/":
        return "a system folder"
    if os.path.dirname(abspath) == os.path.dirname(home) and abspath.startswith(("/home/", "/Users/")):
        return "a user's home folder"
    if root == abspath or root.startswith(abspath.rstrip("/") + "/"):
        return "the whole project" if root == abspath else "a folder containing the project"
    return None


def _expand_glob_target(arg: str, ctx: Context) -> str:
    # `rm -rf *` deletes everything in the folder, so treat it as the folder itself.
    stripped = re.sub(r"/?\*+$", "", arg) if re.search(r"(^|/)\*+$", arg) else arg
    if stripped in {"", "."} and arg.startswith("/"):
        stripped = "/"
    return ctx.path(stripped or ".")


def _recursive_delete(cmd: Command, ctx: Context) -> Iterator[Hit]:
    targets: list[str] = []
    if cmd.name == "rm" and cmd.has_flag("-r", "-R", "--recursive"):
        targets = cmd.positional()
    elif cmd.name in {"rmdir", "shred", "srm"}:
        targets = cmd.positional()
    elif cmd.name == "find" and ("-delete" in cmd.args or any(a in cmd.args for a in ("-exec", "-execdir"))):
        filters = {"-name", "-iname", "-path", "-ipath", "-regex", "-iregex", "-type", "-mtime", "-mmin",
                   "-newer", "-size", "-empty", "-user", "-perm", "-wholename", "-atime", "-ctime"}
        if any(a in filters for a in cmd.args):
            return  # targeted cleanup like `find . -name '*.pyc' -delete`
        paths = []
        for arg in cmd.args:
            if arg.startswith(("-", "(", "!")):
                break
            paths.append(arg)
        if "-delete" in cmd.args or re.search(r"-exec(dir)? (rm|shred)\b", cmd.text):
            targets = paths or ["."]
    elif cmd.name in {"Remove-Item", "rd"} and any(a.lower() in {"-recurse", "/s"} for a in cmd.args):
        targets = [a for a in cmd.args if not a.startswith(("-", "/"))]
    for target in targets:
        what = _danger_target(_expand_glob_target(target, ctx), ctx)
        if what:
            yield ("recursive-delete", "deny", f"recursively deletes {what} ({cmd.text})")


def _disk_and_system(cmd: Command, ctx: Context) -> Iterator[Hit]:
    name, args = cmd.name, cmd.args
    wipes = (
        name.startswith("mkfs")
        or name == "wipefs"
        or (name == "diskutil" and any(a in {"eraseDisk", "eraseVolume", "partitionDisk", "zeroDisk", "secureErase"} for a in args))
        or (name in {"fdisk", "sfdisk", "parted", "gdisk", "sgdisk"} and not any(a in {"-l", "--list", "print"} for a in args))
    )
    if wipes:
        yield ("disk-destroy", "deny", f"formats or wipes a disk ({cmd.text})")
    if name == "dd" and any(a.startswith("of=/dev/") and not a.startswith("of=/dev/null") for a in args):
        yield ("disk-destroy", "deny", f"writes raw data to a device ({cmd.text})")
    if name in {"shutdown", "reboot", "halt", "poweroff"} or (name in {"init", "telinit"} and args[:1] in (["0"], ["6"])):
        yield ("disk-destroy", "deny", f"shuts down or reboots the machine ({cmd.text})")
    if name == "kill" and "-1" in args and any(a in {"-9", "-KILL", "-s"} for a in args):
        yield ("disk-destroy", "deny", "kills every process you own (kill -9 -1)")
    if name in {"chmod", "chown", "chgrp"} and cmd.has_flag("-R", "--recursive"):
        for target in cmd.positional()[1:]:
            what = _danger_target(ctx.path(target), ctx)
            if what and what not in {"the whole project"}:
                yield ("disk-destroy", "deny", f"recursively changes permissions on {what} ({cmd.text})")


def _file_effects(cmd: Command, ctx: Context) -> Iterator[Hit]:
    name, pos = cmd.name, cmd.positional()
    # reads of secret files
    if name in READERS:
        candidates = pos
        if name in {"grep", "egrep", "fgrep", "rg", "ag", "awk", "sed"} and pos and not cmd.has_flag("-e", "-f"):
            candidates = pos[1:]  # first positional is the pattern / program
        elif name in {"cp", "scp", "rsync"}:
            candidates = pos[:-1]  # last positional is the destination
        for arg in candidates:
            if arg.startswith(("http://", "https://")) or "__SUBST" in arg:
                continue
            if "=" in arg and name == "dd":
                key, _, val = arg.partition("=")
                if key == "if":
                    yield from check_read(ctx.path(val), ctx, "reading")
                continue
            yield from check_read(ctx.path(arg.lstrip("@")), ctx, f"{name}")

    # writes
    targets: list[tuple[str, str]] = []
    if name in {"cp", "install", "ln"} and len(pos) >= 2:
        targets.append((pos[-1], "copy to"))
    elif name == "mv" and len(pos) >= 2:
        targets.append((pos[-1], "move to"))
        targets.extend((p, "move away") for p in pos[:-1])
    elif name in {"rm", "unlink", "shred", "rmdir"}:
        targets.extend((p, "delete") for p in pos)
    elif name in {"touch", "mkdir", "truncate", "tee"}:
        targets.extend((p, "write to") for p in pos if not p.isdigit())
    elif name in {"chmod", "chown", "chgrp"} and len(pos) >= 2:
        targets.extend((p, "change permissions of") for p in pos[1:])
    elif name in {"sed", "perl"} and any(a.startswith(("-i", "--in-place")) or (a.startswith("-") and not a.startswith("--") and "i" in a) for a in cmd.args):
        targets.extend((p, "edit") for p in pos[1:])
    elif name == "dd":
        targets.extend((a[3:], "write to") for a in cmd.args if a.startswith("of=") and not a.startswith("of=/dev/"))
    for target, how in targets:
        if target and "__SUBST" not in target:
            yield from check_write(ctx.path(target), ctx, how)


def _git(cmd: Command, ctx: Context) -> Iterator[Hit]:
    if cmd.name != "git" or not cmd.args:
        return
    args = list(cmd.args)
    # skip global options like -C dir, -c key=val
    while args and args[0].startswith("-"):
        flag = args.pop(0)
        if flag in {"-C", "-c", "--git-dir", "--work-tree"} and args:
            args.pop(0)
    if not args:
        return
    sub, rest = args[0], args[1:]
    text = "git " + " ".join(args)

    def has(*flags: str) -> bool:
        return Command(argv=["git", *rest]).has_flag(*flags)

    if "--no-verify" in rest:
        yield ("git-history", "ask", f"skips git hooks ({text})")
    if sub == "push":
        force = any(a in {"--force", "-f"} or (a.startswith("-") and not a.startswith("--") and "f" in a) for a in rest)
        if force and not any(a.startswith("--force-with-lease") or a.startswith("--force-if-includes") for a in rest):
            yield ("git-history", "ask", f"force-pushes and can overwrite remote history ({text})")
        elif any(a.startswith("+") for a in rest):
            yield ("git-history", "ask", f"force-pushes a refspec ({text})")
        if has("--delete", "-d") or any(a.startswith(":") and len(a) > 1 for a in rest):
            yield ("git-history", "ask", f"deletes a remote branch ({text})")
        if "--mirror" in rest:
            yield ("git-history", "ask", f"mirror-push overwrites every remote ref ({text})")
    elif sub == "reset" and "--hard" in rest:
        yield ("git-history", "ask", f"throws away uncommitted work ({text})")
    elif sub == "clean" and has("-f", "--force"):
        yield ("git-history", "ask", f"deletes untracked files ({text})")
    elif sub == "checkout" and ("--" in rest and any(p in {".", ":/", "*"} for p in rest) or has("-f", "--force")):
        yield ("git-history", "ask", f"discards local changes ({text})")
    elif sub == "restore" and any(p in {".", ":/", "*"} for p in rest) and "--staged" not in rest:
        yield ("git-history", "ask", f"discards local changes ({text})")
    elif sub == "branch" and (has("-D") or ("--delete" in rest and "--force" in rest)):
        yield ("git-history", "ask", f"force-deletes a branch ({text})")
    elif sub in {"filter-branch", "filter-repo"} or (sub == "rebase" and "--root" in rest):
        yield ("git-history", "ask", f"rewrites history ({text})")
    elif sub == "stash" and rest[:1] in (["clear"], ["drop"]):
        yield ("git-history", "ask", f"deletes stashed work ({text})")
    elif sub == "update-ref" and has("-d"):
        yield ("git-history", "ask", f"deletes a ref ({text})")
    elif sub == "add":
        for path in Command(argv=["git", *rest]).positional():
            abspath = ctx.path(path)
            if ctx.policy.is_secret(abspath):
                yield ("secret-commit", "ask", f"stages a secret file in git: {path}")


def _env_dump(cmd: Command) -> Iterator[Hit]:
    name, args = cmd.name, cmd.args
    if name in {"env", "printenv"} and not cmd.positional() and not any(a.startswith("-") and a not in {"-0", "--null"} for a in args):
        yield ("env-dump", "ask", "prints every environment variable (often contains API keys)")
    elif name == "printenv" and any(SECRET_VAR.search("$" + a) for a in args):
        yield ("env-dump", "ask", f"prints a secret-looking variable ({cmd.text})")
    elif name in {"set", "declare", "typeset"} and not args or (name == "export" and args in (["-p"], [])):
        yield ("env-dump", "ask", "prints every shell variable (often contains API keys)")
    elif name in {"echo", "printf"} and any(SECRET_VAR.search(a) for a in args):
        yield ("env-dump", "ask", f"prints a secret-looking variable ({cmd.text})")
    elif name in {"cat", "strings", "xargs", "tr"} and any(re.match(r"^/proc/(self|\d+|\*)/environ$", a) for a in args):
        yield ("env-dump", "ask", "reads a process environment from /proc")


def _network(cmd: Command, ctx: Context) -> Iterator[Hit]:
    name, args = cmd.name, cmd.args
    if name in NETWORK_TOOLS:
        skip_next = False
        value_flags = {"-o", "-H", "-A", "-e", "-u", "-x", "--proxy", "-X", "--header", "--user-agent",
                       "-O", "--output", "-w", "--write-out", "-b", "-c", "--cookie", "-m", "--max-time",
                       "--connect-timeout", "-r", "--range", "-E", "--cert", "--key", "-P", "--directory-prefix"}
        upload_flags = {"-d", "--data", "--data-binary", "--data-raw", "--data-urlencode", "-F", "--form",
                        "-T", "--upload-file", "--post-file", "--body-file", "--json"}
        for i, arg in enumerate(args):
            if skip_next:
                skip_next = False
                continue
            flag, _, inline = arg.partition("=") if arg.startswith("--") else (arg, "", "")
            if flag in upload_flags:
                value = inline or (args[i + 1] if i + 1 < len(args) else "")
                skip_next = not inline
                filename = None
                if value.startswith("@"):
                    filename = value[1:]
                elif "=@" in value or "=<" in value:
                    filename = re.split(r"=[@<]", value, maxsplit=1)[1].split(";")[0]
                elif flag in {"-T", "--upload-file", "--post-file", "--body-file"}:
                    filename = value
                if filename and filename != "-":
                    secret = list(check_read(ctx.path(filename), ctx, "uploading"))
                    yield from secret
                    if not secret:
                        yield ("upload", "ask", f"uploads {filename} to a remote server")
                continue
            if flag in value_flags:
                skip_next = not inline
                continue
            if arg.startswith("-"):
                continue
            yield from check_url(arg, ctx)
    elif name in {"git"} and cmd.args[:1] in (["clone"], ["fetch"], ["pull"], ["remote"]):
        for arg in cmd.args:
            if "://" in arg or re.match(r"^[\w.-]+@[\w.-]+:", arg):
                host = arg.split("@", 1)[1].split(":", 1)[0] if re.match(r"^[\w.-]+@[\w.-]+:", arg) else arg
                yield from check_url(host if "://" in host else "ssh://" + host, ctx)
    elif name in {"nc", "ncat", "netcat", "socat", "telnet", "cryptcat"}:
        if cmd.has_flag("-e", "-c", "--exec", "--sh-exec") or any("exec:" in a.lower() or "system:" in a.lower() for a in args):
            yield ("reverse-shell", "deny", f"hands a shell to a remote machine ({cmd.text})")
        else:
            yield ("network-tools", "ask", f"opens a raw network connection ({cmd.text})")
    elif name == "ssh" and any(a in {"-R", "-D"} or a.startswith(("-R", "-D")) for a in args):
        yield ("network-tools", "ask", f"opens an SSH tunnel ({cmd.text})")
    elif name in {"scp", "rsync", "sftp"}:
        pos = cmd.positional()
        if pos and ":" in pos[-1] and not pos[-1].startswith(("/", "./")):
            yield ("upload", "ask", f"copies files to a remote machine ({cmd.text})")


def _publish_and_infra(cmd: Command) -> Iterator[Hit]:
    name, args = cmd.name, cmd.args
    first = args[0] if args else ""
    publish = (
        (name in {"npm", "pnpm", "yarn", "bun"} and first == "publish")
        or (name == "twine" and first == "upload")
        or (name in {"cargo", "poetry", "uv", "hatch", "flit", "gem", "dotnet", "mvn"} and first in {"publish", "push", "deploy"})
        or (name in {"docker", "podman"} and first == "push")
        or (name == "gh" and args[:2] in (["release", "create"], ["repo", "delete"]))
        or (name == "vsce" and first == "publish")
    )
    if publish:
        yield ("publish", "ask", f"publishes to the outside world ({cmd.text})")

    destroy = (
        (name in {"terraform", "tofu", "pulumi", "cdk"} and first == "destroy")
        or (name in {"terraform", "tofu"} and first == "apply" and "-auto-approve" in args)
        or (name in {"kubectl", "oc"} and first in {"delete", "drain"})
        or (name == "helm" and first in {"uninstall", "delete"})
        or (name in {"aws"} and any(re.match(r"^(delete|terminate|rm$|rb$|remove|deregister)", a) for a in args[1:3]))
        or (name in {"gcloud", "az", "doctl", "flyctl", "fly", "heroku", "vercel", "netlify"} and any(a in {"delete", "destroy", "remove", "rm"} for a in args))
        or (name in {"docker", "podman"} and (args[:2] in (["system", "prune"], ["volume", "prune"], ["volume", "rm"])))
    )
    if destroy:
        yield ("infra-destroy", "ask", f"destroys infrastructure or data volumes ({cmd.text})")


SQL_DESTROY = re.compile(r"\b(drop\s+(table|database|schema|collection)|truncate\s+(table\s+)?\w|delete\s+from\s+\w+\s*(;|$))", re.I)


def _data_destroy(cmd: Command) -> Iterator[Hit]:
    name = cmd.name
    joined = " ".join(cmd.args)
    if name in {"psql", "mysql", "mariadb", "sqlite3", "duckdb", "clickhouse-client", "cockroach", "sqlcmd", "mongosh", "mongo"}:
        if SQL_DESTROY.search(joined) or re.search(r"\.drop(Database)?\(\)", joined):
            yield ("data-destroy", "ask", f"destroys database data ({cmd.text[:120]})")
    if name == "redis-cli" and any(a.upper() in {"FLUSHALL", "FLUSHDB"} for a in cmd.args):
        yield ("data-destroy", "ask", f"wipes a Redis database ({cmd.text})")
    if name in {"dropdb", "dropuser"}:
        yield ("data-destroy", "ask", f"drops a database ({cmd.text})")


# ------------------------------------------------------------------ whole-command rules

def _is_decoder(cmd: Command) -> bool:
    return (
        (cmd.name in {"base64", "base32", "basenc"} and cmd.has_flag("-d", "-D", "--decode"))
        or (cmd.name == "xxd" and cmd.has_flag("-r"))
        or (cmd.name == "openssl" and "-d" in cmd.args)
        or cmd.name in {"uudecode", "rev"}
    )


def shell_rules(parsed: ParsedShell, ctx: Context) -> Iterator[Hit]:
    if has_fork_bomb(parsed.raw):
        yield ("disk-destroy", "deny", "fork bomb: would freeze the machine")

    for pipeline in parsed.all_pipelines():
        source = None
        for cmd in pipeline:
            if cmd.name in DOWNLOADERS:
                source = "downloaded"
            elif _is_decoder(cmd):
                source = source or "decoded (obfuscated)"
            elif source and (cmd.name in INTERPRETERS or cmd.name in {"source", ".", "eval", "iex", "Invoke-Expression"}):
                yield ("pipe-to-shell", "deny", f"pipes a {source} script straight into {cmd.name}")
                break

    # bash <(curl ...), sh -c "$(curl ...)", eval "$(wget ...)", python <(curl...)
    for cmd in parsed.commands():
        if cmd.name in INTERPRETERS | {"eval", "source", "."} and cmd.substitutions:
            for sid in cmd.substitutions:
                sub = parsed.substitutions.get(sid)
                if sub and any(c.name in DOWNLOADERS or _is_decoder(c) for c in sub.commands()):
                    yield ("pipe-to-shell", "deny", f"runs a downloaded script with {cmd.name}")
                    break
