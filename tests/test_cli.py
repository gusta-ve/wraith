from wraith.cli import _is_foothold, _normalize_target, _runs_dir, _with_default_command


def test_runs_dir_honours_env_then_xdg(monkeypatch, tmp_path):
    monkeypatch.setenv("WRAITH_RUNS", str(tmp_path / "mine"))
    assert _runs_dir() == str(tmp_path / "mine")            # explicit override wins
    monkeypatch.delenv("WRAITH_RUNS", raising=False)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    assert _runs_dir() == str(tmp_path / "xdg" / "wraith" / "runs")


def test_is_foothold_flags_code_execution():
    assert _is_foothold("Command Injection in 'host'") is True
    assert _is_foothold("Server-Side Template Injection in 'name'") is True
    assert _is_foothold("Reflected XSS in 'q'") is False
    assert _is_foothold("SQL Injection (boolean blind) in 'id'") is False


def test_normalize_target_accepts_url_and_host():
    assert _normalize_target("example.com") == ("example.com", None)
    assert _normalize_target("https://example.com") == ("example.com", None)
    assert _normalize_target("http://127.0.0.1:8080/path?q=1") == ("127.0.0.1", 8080)
    assert _normalize_target("127.0.0.1:9999") == ("127.0.0.1", 9999)


def test_dash_u_routes_to_run():
    assert _with_default_command(["-u", "https://x.com"]) == ["run", "-u", "https://x.com"]
    # flags before a bare target still default to run
    assert _with_default_command(["-p", "resolve", "x.com"]) == ["run", "-p", "resolve", "x.com"]


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
    for cmd in ("run", "showdown", "phases", "login", "hand"):
        assert _with_default_command([cmd]) == [cmd]
    assert _with_default_command(["run", "example.com"]) == ["run", "example.com"]


def test_help_and_version_pass_through_untouched():
    assert _with_default_command(["--help"]) == ["--help"]
    assert _with_default_command(["--version"]) == ["--version"]
    assert _with_default_command([]) == []
