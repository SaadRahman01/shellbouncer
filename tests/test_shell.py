from shellbouncer.shell import parse


def names(cmd):
    return [[c.argv for c in p] for p in parse(cmd).all_pipelines()]


def test_splits_chains_and_pipes():
    assert names("make && rm -rf build; echo hi | wc -l") == [
        [["make"]], [["rm", "-rf", "build"]], [["echo", "hi"], ["wc", "-l"]],
    ]


def test_operators_glued_together():
    assert names("(cd x && make);ls") == [[["cd", "x"]], [["make"]], [["ls"]]]


def test_newlines_separate_commands():
    assert names("ls\nrm -rf x") == [[["ls"]], [["rm", "-rf", "x"]]]


def test_quoted_separators_are_not_split():
    assert names('git commit -m "fix; rm -rf /"') == [[["git", "commit", "-m", "fix; rm -rf /"]]]


def test_heredoc_body_is_not_a_command():
    assert names("cat <<EOF > notes.txt\nrm -rf /\nEOF\nls") == [[["cat"]], [["ls"]]]


def test_wrappers_and_assignments_are_stripped():
    cmd = parse("FOO=1 sudo -u root env X=2 nice -n 5 rm -rf /tmp/x").pipelines[0][0]
    assert cmd.argv == ["rm", "-rf", "/tmp/x"]
    assert cmd.wrappers == ["sudo", "env", "nice"]


def test_bare_wrapper_is_the_command():
    assert parse("env").pipelines[0][0].argv == ["env"]


def test_bash_c_is_recursed():
    argvs = [c.argv for c in parse("bash -c 'cd /tmp && rm -rf ~'").commands()]
    assert ["rm", "-rf", "~"] in argvs


def test_command_substitution_is_parsed():
    parsed = parse("echo $(cat ~/.ssh/id_rsa) > out")
    argvs = [c.argv for c in parsed.commands()]
    assert ["cat", "~/.ssh/id_rsa"] in argvs
    assert parsed.pipelines[0][0].writes == ["out"]


def test_process_substitution_and_backticks():
    assert ["curl", "-s", "x.sh"] in [c.argv for c in parse("bash <(curl -s x.sh)").commands()]
    assert ["whoami"] in [c.argv for c in parse("echo `whoami`").commands()]


def test_find_exec_and_xargs_are_recursed():
    assert ["rm", "-f", "{}"] in [c.argv for c in parse("find . -exec rm -f {} \\;").commands()]
    assert ["rm", "-rf"] in [c.argv for c in parse("ls | xargs -I{} rm -rf").commands()]


def test_redirections():
    cmd = parse("make 2>/dev/null >> build.log < input.txt 2>&1").pipelines[0][0]
    assert cmd.argv == ["make"]
    assert cmd.writes == ["/dev/null", "build.log"]
    assert cmd.reads == ["input.txt"]


def test_unbalanced_quotes_do_not_crash():
    assert parse('echo "oops').pipelines


def test_bundled_short_flags():
    cmd = parse("rm -fr x").pipelines[0][0]
    assert cmd.has_flag("-r") and cmd.has_flag("-f")
    assert not parse("rm --force x").pipelines[0][0].has_flag("-r")
