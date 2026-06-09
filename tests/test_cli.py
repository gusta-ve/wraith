from wraith.cli import _with_default_command


def test_bare_target_gets_run_prepended():
    assert _with_default_command(["example.com"]) == ["run", "example.com"]
    assert _with_default_command(["example.com", "-p", "resolve"]) == \
        ["run", "example.com", "-p", "resolve"]


def test_global_option_before_target_is_preserved():
    # --theme takes a value; the bare target after it still defaults to run
    assert _with_default_command(["--theme", "ice", "example.com"]) == \
        ["--theme", "ice", "run", "example.com"]
    assert _with_default_command(["--no-color", "example.com"]) == \
        ["--no-color", "run", "example.com"]


def test_real_subcommands_are_left_alone():
    for cmd in ("run", "phases", "shell", "login", "aces"):
        assert _with_default_command([cmd]) == [cmd]
    assert _with_default_command(["run", "example.com"]) == ["run", "example.com"]


def test_help_and_version_pass_through_untouched():
    assert _with_default_command(["--help"]) == ["--help"]
    assert _with_default_command(["--version"]) == ["--version"]
    assert _with_default_command([]) == []
